const { test } = require("node:test");
const assert = require("node:assert/strict");
const { deflateSync } = require("node:zlib");
const fs = require("node:fs");
const Emtr = require("../emu_core.js");
function metadataBlock(metadata) {
  const json = Buffer.from(JSON.stringify(metadata));
  const size = Buffer.alloc(4);
  size.writeUInt32LE(json.length);
  return Buffer.concat([size, json]);
}
function file(payload, count = 1, version = 1, arch = 4, metadata = {}) {
  const header = Buffer.alloc(16);
  header.write("EMTR");
  header.writeUInt32LE(version, 4);
  header.writeUInt32LE(arch, 8);
  header.writeUInt32LE(count, 12);
  const data = Buffer.concat([
    header,
    deflateSync(
      version >= 2
        ? Buffer.concat([
            Buffer.alloc(4),
            payload,
            ...(version === 3 ? [metadataBlock(metadata)] : []),
          ])
        : payload,
    ),
  ]);
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
}
function frame() {
  const address = Buffer.alloc(10);
  address.writeBigUInt64LE(0xffffffffffffffffn);
  address.writeUInt16LE(1, 8);
  const registers = Buffer.from([1, 0, 3, 82, 65, 88]);
  const value = Buffer.alloc(8);
  value.writeBigUInt64LE(0xfedcba9876543210n);
  const stack = Buffer.alloc(12);
  stack.writeBigUInt64LE(0xfffffffffffffff0n);
  stack.writeUInt32LE(3, 8);
  return Buffer.concat([
    address,
    Buffer.from([0x90]),
    registers,
    value,
    stack,
    Buffer.from("abc"),
  ]);
}
test("keeps all 64 bits through parsing, formatting and JSON export", async () => {
  const trace = await Emtr.parse(file(frame()));
  const f = trace.frames[0];
  assert.equal(f.address, 0xffffffffffffffffn);
  assert.equal(f.regs.RAX, 0xfedcba9876543210n);
  assert.equal(Emtr.hex(f.address, 4), "0xffffffffffffffff");
  assert.equal(
    JSON.parse(Emtr.frameJSON(f, 0)).registers.RAX,
    "0xfedcba9876543210",
  );
});
test("v2 preserves embedded disassembly and frame architecture", async () => {
  const extension = Buffer.alloc(8);
  extension.writeUInt32LE(16);
  extension.writeUInt16LE(4, 4);
  extension.writeUInt16LE(2, 6);
  const trace = await Emtr.parse(
    file(Buffer.concat([frame(), extension, Buffer.from("addira")]), 1, 2, 16),
  );
  assert.equal(trace.frames[0].archId, 16);
  assert.equal(trace.frames[0].mnemonic, "addi");
  assert.equal(trace.frames[0].operands, "ra");
});
test("v3 carries bounded analysis metadata without changing frames", async () => {
  const extension = Buffer.alloc(8);
  extension.writeUInt32LE(4);
  const metadata = {
    decompilation: {
      version: 1,
      engine: { name: "angr", version: "9.3.4" },
      functions: [{ address: "0x1000", pseudocode: "void f(void) {}" }],
    },
  };
  const trace = await Emtr.parse(
    file(Buffer.concat([frame(), extension]), 1, 3, 4, metadata),
  );
  assert.equal(trace.version, 3);
  assert.equal(trace.frames[0].address, 0xffffffffffffffffn);
  assert.deepEqual(trace.metadata, metadata);
  await assert.rejects(
    () => Emtr.parse(file(Buffer.alloc(0), 0, 3, 4, [])),
    /metadata must be an object/i,
  );
});
test("rejects malformed headers, truncated frames, unknown IDs, and trailing bytes", async () => {
  for (const data of [
    new ArrayBuffer(0),
    file(frame(), 2),
    file(frame(), 1, 4),
    file(frame(), 1, 1, 99),
    file(frame().subarray(0, -1)),
    file(Buffer.concat([frame(), Buffer.from("x")])),
  ])
    await assert.rejects(() => Emtr.parse(data));
});
test("bounds decompression and frame allocation", async () => {
  await assert.rejects(
    () => Emtr.parse(file(Buffer.alloc(100000)), { maxBytes: 1000 }),
    /decompression limit/,
  );
  await assert.rejects(
    () => Emtr.parse(file(frame()), { maxFrames: 0 }),
    /frame limit/,
  );
  assert.equal((await Emtr.parse(file(Buffer.alloc(0), 0))).frames.length, 0);
});
test("register changes use the preceding frame and stack changes use absolute addresses", () => {
  const previous = {
    regs: { RAX: 0xfffffffffffffff0n },
    sp: 0x1000n,
    stack: Uint8Array.from([1, 2, 3, 4]),
  };
  const current = {
    regs: { RAX: 0xfffffffffffffff1n },
    sp: 0x1002n,
    stack: Uint8Array.from([3, 8, 9]),
  };
  assert.deepEqual(Emtr.registerChanges(current, previous), ["RAX"]);
  assert.deepEqual(Emtr.registerChanges(current, undefined), []);
  assert.deepEqual(Emtr.stackChanges(current, previous), [
    "same",
    "changed",
    "new",
  ]);
});
test("bundled legacy traces parse", async () => {
  for (const name of ["trace_arm32.emtr", "trace_mipsel.emtr"]) {
    const bytes = fs.readFileSync(
      require("node:path").join(__dirname, "../examples", name),
    );
    const trace = await Emtr.parse(
      bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    );
    assert.ok(trace.nFrames > 0);
  }
});

test("v2 reports capture limits and rejects reserved metadata flags", async () => {
  const header = Buffer.alloc(16);
  header.write("EMTR");
  header.writeUInt32LE(2, 4);
  header.writeUInt32LE(4, 8);
  const data = (flags) => {
    const metadata = Buffer.alloc(4);
    metadata.writeUInt32LE(flags);
    const bytes = Buffer.concat([header, deflateSync(metadata)]);
    return bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    );
  };
  assert.equal((await Emtr.parse(data(1))).truncated, true);
  await assert.rejects(() => Emtr.parse(data(2)), /Unknown trace flags/);
});

test("stack words decode target endianness without reversing stored memory", () => {
  const bytes = Uint8Array.from([
    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  ]);
  assert.equal(Emtr.stackWord(bytes, 4).hex, "0102030405060708");
  assert.equal(Emtr.stackWord(bytes, 7).hex, "0807060504030201");
  assert.equal(Emtr.stackWord(bytes.subarray(0, 4), 3).hex, "05060708");
  assert.equal(Emtr.stackWord(bytes.subarray(0, 4), 5).hex, "08070605");
  assert.equal(Emtr.stackWord(bytes.subarray(0, 2), 9).hex, "0708");
  assert.deepEqual(
    Emtr.stackWord(bytes, 4).bytes.map((byte) => byte.offset),
    [7, 6, 5, 4, 3, 2, 1, 0],
  );
  assert.deepEqual(Array.from(bytes), [8, 7, 6, 5, 4, 3, 2, 1]);
});

test("partial stack words mark uncaptured bytes as unknown", () => {
  assert.equal(
    Emtr.stackWord(Uint8Array.from([0x12, 0x34]), 4).hex,
    "????????????3412",
  );
  assert.equal(
    Emtr.stackWord(Uint8Array.from([0x12, 0x34]), 5).hex,
    "1234????",
  );
});

test("latest register and stack highlights persist independently and replace on the next change", () => {
  const frame = (pc, rax, rbx, stack, sp = 0x1000n) => ({
    archId: 4,
    regs: { RIP: BigInt(pc), RAX: BigInt(rax), RBX: BigInt(rbx) },
    sp,
    stack: Uint8Array.from(stack),
  });
  const frames = [
    frame(0, 0, 0, [0, 0]),
    frame(1, 1, 0, [0, 0]),
    frame(2, 1, 0, [2, 0]),
    frame(3, 1, 0, [2, 0]),
    frame(4, 1, 3, [2, 4]),
    frame(5, 1, 3, [4, 5], 0x1001n),
    frame(6, 1, 3, [4, 5], 0x1001n),
    frame(7, 1, 3, [5], 0x1002n),
  ];
  const highlights = Emtr.createChangeHistory(frames);
  assert.equal(highlights(0).registers.size, 0);
  assert.equal(highlights(0).stack.size, 0);
  assert.equal(highlights(1).registers.get("RAX"), 0n);
  assert.equal(highlights(3).registers.get("RAX"), 0n);
  assert.deepEqual([...highlights(3).stack], [0]);
  assert.equal(highlights(4).registers.has("RAX"), false);
  assert.equal(highlights(4).registers.get("RBX"), 0n);
  assert.deepEqual([...highlights(4).stack], [1]);
  assert.deepEqual([...highlights(6).stack], [1]);
  assert.deepEqual([...highlights(7).stack], [0]);
  // Direct and backward navigation agree with stepping through the trace.
  assert.deepEqual(highlights(2), Emtr.createChangeHistory(frames)(2));
  assert.deepEqual(highlights(7), Emtr.createChangeHistory(frames)(7));
});
