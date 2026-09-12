const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const CFG = require("../emu_cfg.js");
const Emtr = require("../emu_core.js");
const { frame: f, calls } = require("./cfg-fixtures.cjs");
function index(frames) {
  const i = CFG.createIndex(frames);
  while (!i.advance(2)) {}
  return i;
}
const blocks = (g) => g.blocks.filter((b) => !b.external);
const blockAt = (g, address) =>
  blocks(g).find((b) => b.address === BigInt(address));

test("real x86-64 trace collapses repeated loop frames into three blocks", async () => {
  const bytes = fs.readFileSync(
    path.join(__dirname, "../examples/trace_x86_64.emtr"),
  );
  const trace = await Emtr.parse(
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  );
  const g = CFG.buildGraph(index(trace.frames), 10);
  assert.deepEqual(
    blocks(g).map((b) => b.instructions.length),
    [2, 4, 3],
  );
  const loop = blockAt(g, 0x1000e);
  assert.equal(loop.visits.length, 8);
  assert.ok(
    g.edges.some(
      (e) =>
        e.from === loop.id &&
        e.to === loop.id &&
        e.type === "taken" &&
        e.count === 7,
    ),
  );
  assert.ok(g.edges.some((e) => e.type === "not-taken" && e.count === 1));
  assert.equal(g.blocks.length, 3);
});

test("missing conditional paths are explicit unobserved destinations", () => {
  const g = CFG.buildGraph(
    index([f(0x100, "jne", "0x200", 4, 2), f(0x102, "nop"), f(0x103, "ret")]),
    0,
  );
  const taken = g.edges.find((e) => e.type === "taken");
  assert.equal(taken.count, 0);
  assert.equal(g.blocks.find((b) => b.id === taken.to).address, 0x200n);
  assert.equal(g.edges.find((e) => e.type === "not-taken").count, 1);
  // A final branch still has two inferred edges, without fabricated executions.
  const end = CFG.buildGraph(index([f(0x100, "jne", "0x200", 4, 2)]), 0);
  assert.equal(end.edges.length, 2);
  assert.ok(end.edges.every((e) => e.count === 0));
});

test("call scopes exclude callees and return to the matching caller", () => {
  const i = index(calls());
  assert.deepEqual(Array.from(i.owners), [0, 1, 1, 1, 2, 2, 1, 0, 0]);
  const root = CFG.buildGraph(i, 0),
    child = CFG.buildGraph(i, 2);
  assert.equal(root.scope.inferred, false);
  assert.equal(child.scope.entry, 0x200n);
  assert.equal(child.scope.inferred, true);
  assert.deepEqual(
    blocks(child).flatMap((b) => b.instructions.map((n) => n.frame.address)),
    [0x200n, 0x203n, 0x210n, 0x215n],
  );
  assert.ok(root.edges.some((e) => e.type === "continuation" && e.count === 1));
  assert.deepEqual(child.blocks.find((b) => b.type === "call").visits, [4]);
  assert.deepEqual(child.blocks.find((b) => b.type === "return").visits, [7]);
});

test("recursive calls aggregate function code without connecting separate invocations", () => {
  const i = index([
    f(0x100, "call", "0x200", 4, 5),
    f(0x200, "jne", "0x210", 4, 2),
    f(0x202, "call", "0x200", 4, 5),
    f(0x200, "jne", "0x210", 4, 2),
    f(0x210, "ret"),
    f(0x207, "ret"),
    f(0x105, "hlt"),
  ]);
  assert.deepEqual(Array.from(i.owners), [0, 1, 1, 1, 1, 1, 0]);
  assert.deepEqual(Array.from(i.invocations), [0, 1, 1, 2, 2, 1, 0]);
  const g = CFG.buildGraph(i, 1);
  const branch = blockAt(g, 0x200);
  assert.equal(branch.visits.length, 2);
  assert.deepEqual(
    g.edges
      .filter((e) => e.from === branch.id)
      .map((e) => [e.type, e.count])
      .sort(),
    [
      ["not-taken", 1],
      ["taken", 1],
    ],
  );
  assert.ok(
    !g.edges.some(
      (e) => e.from === blockAt(g, 0x210).id && e.to === blockAt(g, 0x207).id,
    ),
  );
});

test("MIPS branch delay slots stay in the block and do not count as branch destinations", () => {
  const branch = () => f(0x100, "bne", "$a0, $zero, 0x100", 6, 4);
  const slot = () => f(0x104, "addiu", "$a0, $a0, -1", 6, 4);
  const i = index([
    branch(),
    slot(),
    branch(),
    slot(),
    f(0x108, "nop", "", 6, 4),
  ]);
  const g = CFG.buildGraph(i, 1);
  assert.deepEqual(
    blockAt(g, 0x100).instructions.map((n) => n.frame.address),
    [0x100n, 0x104n],
  );
  assert.equal(blockAt(g, 0x100).flow.delay, 1);
  assert.deepEqual(g.edges.map((e) => [e.type, e.count]).sort(), [
    ["not-taken", 1],
    ["taken", 1],
  ]);
});

test("SPARC call and return delay slots retain their execution context", () => {
  const i = index([
    f(0x100, "call", "0x200", 12, 4),
    f(0x104, "nop", "", 12, 4),
    f(0x200, "retl", "", 12, 4),
    f(0x204, "nop", "", 12, 4),
    f(0x108, "nop", "", 12, 4),
  ]);
  assert.deepEqual(Array.from(i.owners), [0, 0, 1, 1, 0]);
  const root = CFG.buildGraph(i, 0),
    child = CFG.buildGraph(i, 2);
  assert.equal(blocks(root)[0].instructions.length, 2);
  assert.equal(blocks(child)[0].instructions.length, 2);
  assert.equal(child.blocks.find((b) => b.type === "return").address, 0x108n);
});

test("branch-likely paths with annulled delay slots use the architectural fallthrough", () => {
  const g = CFG.buildGraph(
    index([
      f(0x100, "bnel", "$a0, $zero, 0x200", 6, 4),
      f(0x108, "nop", "", 6, 4),
    ]),
    0,
  );
  assert.equal(g.edges.find((e) => e.type === "not-taken").count, 1);
  assert.equal(blocks(g)[0].instructions.length, 1);
});

test("high addresses stay exact; observed indirect branches do not gain invented targets", () => {
  const address = 0xfffffffffffff000n;
  assert.equal(
    CFG.classify(f(address, "jne", "0xfffffffffffffabc")).target,
    0xfffffffffffffabcn,
  );
  const g = CFG.buildGraph(
    index([f(address, "jmp", "rax"), f(address + 0xabcn, "ret")]),
    0,
  );
  assert.equal(g.edges.filter((e) => e.type === "jump").length, 1);
  assert.equal(g.edges.find((e) => e.type === "jump").count, 1);
  assert.equal(CFG.classify(f(0x100, "jalr", "ra, t0, 0", 16, 4)).target, null);
});

test("ARM/Thumb calls share family scopes while instruction versions remain distinct", () => {
  const i = index([
    f(0x100, "blx", "#0x201", 1, 4),
    f(0x200, "bx", "lr", 0, 2),
    f(0x104, "nop", "", 1, 4),
  ]);
  assert.deepEqual(Array.from(i.owners), [0, 1, 0]);
  assert.equal(i.instructions[0].flow.target, 0x200n);
  const versions = CFG.buildGraph(
    index([f(0x100, "jmp", "0x100"), f(0x100, "ret", "", 4, 1, 0xc3)]),
    0,
  );
  assert.equal(versions.variants, true);
  assert.equal(versions.membership.size, 2);
});

test("Capstone 5 RISC-V displacements become absolute targets, including compressed and backward branches", () => {
  assert.equal(
    CFG.classify(f(0x10000, "beqz", "a0, 8", 16, 4)).target,
    0x10008n,
  );
  assert.equal(
    CFG.classify(f(0x10004, "beqz", "a0, -4", 16, 4)).target,
    0x10000n,
  );
  assert.equal(CFG.classify(f(0x10008, "j", "0", 16, 4)).target, 0x10008n);
  assert.equal(
    CFG.classify(f(0x1000c, "c.beqz", "a0, 8", 16, 2)).target,
    0x10014n,
  );
  assert.equal(CFG.classify(f(0x1000e, "c.jr", "ra", 16, 2)).kind, "return");
});

test("common control flow classification spans all ten architecture families", () => {
  for (const [arch, mnemonic, operands, kind, conditional] of [
    [4, "loop", "0x100", "conditional", true],
    [1, "bls", "#0x100", "conditional", true],
    [1, "bic", "r0, r0, r1", "next", false],
    [0, "b.w", "#0x100", "jump", false],
    [2, "tbz", "w0, #1, #0x100", "conditional", true],
    [2, "b.al", "#0x100", "jump", false],
    [6, "jr", "$ra", "return", false],
    [10, "bdnz", "0x100", "conditional", true],
    [12, "bne,a", "0x100", "conditional", true],
    [14, "bne.b", "$100", "conditional", true],
    [16, "c.bnez", "a0, 0x100", "conditional", true],
    [17, "jne", "0x100", "conditional", true],
    [18, "jeq", "d0, d1, 0x100", "conditional", true],
  ]) {
    const flow = CFG.classify(f(0x80, mnemonic, operands, arch, 4));
    assert.equal(flow.kind, kind, mnemonic);
    assert.equal(flow.conditional, conditional, mnemonic);
  }
});

test("undecoded instructions expose only observed transitions", () => {
  const g = CFG.buildGraph(index([f(0x100, ""), f(0x200, "")]), 0);
  assert.equal(g.raw, 2);
  assert.equal(g.edges.length, 1);
  assert.equal(g.edges[0].type, "observed");
  assert.equal(g.edges[0].count, 1);
});

test("empty, unfinished and oversized graphs are handled explicitly", () => {
  assert.equal(CFG.buildGraph(index([]), 0), null);
  const pending = CFG.createIndex([f(1)]);
  assert.throws(() => CFG.buildGraph(pending, 0), /still being built/);
  const i = index([f(1, "jne", "0x3"), f(2), f(3)]);
  assert.match(
    CFG.buildGraph(i, 0, { maxInstructions: 2 }).error,
    /instruction graph limit/,
  );
  assert.match(CFG.buildGraph(i, 0, { maxBlocks: 1 }).error, /graph limit/);
  assert.equal(CFG.nearestVisit([], 0), null);
  assert.equal(CFG.nearestVisit([2, 10, 20], 0), 2);
  assert.equal(CFG.nearestVisit([2, 10, 20], 30), 20);
  assert.equal(CFG.nearestVisit([2, 10, 20], 7), 10);
  assert.equal(CFG.nearestVisit([2, 10, 20], 6), 2);
});

test("prefixed x86 returns and indirect branches retain control-flow semantics", () => {
  assert.equal(CFG.classify(f(0x100, "repz ret")).kind, "return");
  assert.equal(CFG.classify(f(0x100, "bnd jmp", "rax")).kind, "jump");
});

test("graph budgets include unseen destinations and edges", () => {
  const i = index([f(0x100, "jne", "0x200", 4, 2)]);
  assert.match(
    CFG.buildGraph(i, 0, { maxBlocks: 2 }).error,
    /including external/,
  );
  assert.match(CFG.buildGraph(i, 0, { maxEdges: 1 }).error, /edges/);
});
