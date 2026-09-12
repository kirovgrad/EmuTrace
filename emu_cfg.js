/* Trace-based control-flow recovery. No binary or symbol table is available:
 * function scopes and unobserved edges are explicitly inferred, never decoded
 * from memory that was not captured. Both addresses and targets stay BigInt.
 */
"use strict";
const EmtrCFG = (() => {
  const core = typeof module !== "undefined" ? require("./emu_core.js") : Emtr;
  const addressKey = (frame) =>
    `${core.architectures[frame.archId].family}:${frame.address}`;
  const instructionKey = (frame) =>
    `${frame.archId}:${frame.address}:${core.opcodeHex(frame.opcode)}`;

  function directTarget(operands) {
    const last = operands.split(",").at(-1).trim().replace(/^#/, "");
    if (!/^-?(?:0x[0-9a-f]+|\$[0-9a-f]+|[0-9]+)$/i.test(last)) return null;
    try {
      const value = last.replace(/^-/, "");
      return (
        BigInt(value.startsWith("$") ? "0x" + value.slice(1) : value) *
        (last.startsWith("-") ? -1n : 1n)
      );
    } catch {
      return null;
    }
  }

  function classify(frame) {
    const family = core.architectures[frame.archId].family;
    const decoded = (frame.mnemonic || "").toLowerCase();
    const original =
      family === "x86"
        ? decoded.replace(/^(?:(?:rep(?:e|ne|z|nz)?|bnd|notrack)\s+)+/, "")
        : decoded;
    const mnemonic = original.replace(/\.(?:w|n|s|l|b)$/, "");
    const operands = (frame.operands || "").toLowerCase();
    let kind = "next",
      conditional = false;
    const set = (type, condition = false) => {
      kind = type;
      conditional = condition;
    };
    if (family === "x86") {
      if (/^(?:call|lcall)$/.test(mnemonic)) set("call");
      else if (/^(?:ret[fqwl]?|iret[qwd]?)$/.test(mnemonic)) set("return");
      else if (/^(?:jmp|ljmp)$/.test(mnemonic)) set("jump");
      else if (
        /^j[a-z]+$/.test(mnemonic) ||
        /^loop(?:e|ne|z|nz)?$/.test(mnemonic)
      )
        set("conditional", true);
      else if (/^(?:hlt|ud2)$/.test(mnemonic)) set("stop");
    } else if (family === "arm" || family === "arm64") {
      if (family === "arm64") {
        if (/^(?:bl|blr)$/.test(mnemonic)) set("call");
        else if (/^(?:ret|eret)$/.test(mnemonic)) set("return");
        else if (/^(?:b|br|b\.al|b\.nv)$/.test(mnemonic)) set("jump");
        else if (
          /^b\./.test(mnemonic) ||
          /^(?:cbz|cbnz|tbz|tbnz)$/.test(mnemonic)
        )
          set("conditional", true);
      } else {
        const condition = "(?:eq|ne|hs|cs|lo|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)";
        if (new RegExp(`^blx?(?:${condition})?$`).test(mnemonic))
          set("call", !["bl", "blx"].includes(mnemonic));
        else if (
          (/^bx/.test(mnemonic) && operands.trim() === "lr") ||
          (mnemonic === "pop" && /\bpc\b/.test(operands)) ||
          (mnemonic === "mov" && /^pc,\s*lr$/.test(operands))
        )
          set("return", mnemonic !== "bx" && mnemonic.startsWith("bx"));
        else if (/^(?:b|bx)$/.test(mnemonic)) set("jump");
        else if (
          new RegExp(`^bx?${condition}$`).test(mnemonic) ||
          /^(?:cbz|cbnz|tbb|tbh)$/.test(mnemonic)
        )
          set("conditional", true);
      }
    } else if (family === "mips") {
      if (/^(?:jal|jalr|bal)$/.test(mnemonic)) set("call");
      else if (/^(?:bgezal|bltzal)(?:l)?$/.test(mnemonic)) set("call", true);
      else if (mnemonic === "jr" && /^(?:\$?ra|\$31)$/.test(operands.trim()))
        set("return");
      else if (/^(?:j|jr|b)$/.test(mnemonic)) set("jump");
      else if (
        /^(?:beq|bne|bgtz|blez|bltz|bgez|beqz|bnez|bc[012][tf])l?$/.test(
          mnemonic,
        )
      )
        set("conditional", true);
    } else if (family === "ppc") {
      if (/^(?:bl|bla|bctrl|blrl)$/.test(mnemonic)) set("call");
      else if (mnemonic === "blr") set("return");
      else if (/^(?:b|ba|bctr)$/.test(mnemonic)) set("jump");
      else if (
        /^(?:bc|beq|bne|blt|ble|bgt|bge|bso|bns|bun|bnu|bdnz|bdz)/.test(
          mnemonic,
        )
      )
        set("conditional", true);
    } else if (family === "sparc") {
      const base = mnemonic.split(",")[0];
      if (/^(?:ret|retl|return)$/.test(base)) set("return");
      else if (base === "call") set("call");
      else if (base === "jmpl") {
        if (/^%[oi]7\s*\+\s*(?:8|0x8),\s*%g0$/.test(operands)) set("return");
        else set(/,\s*%o7$/.test(operands) ? "call" : "jump");
      } else if (/^(?:ba|b|fba)$/.test(base)) set("jump");
      else if (
        /^(?:fb|b)(?:n|ne|e|g|le|ge|l|gu|leu|cc|cs|pos|neg|vc|vs|u|lg|ue|ug|ul|uge|ule|o)$/.test(
          base,
        )
      )
        set("conditional", true);
    } else if (family === "m68k") {
      if (/^(?:jsr|bsr)$/.test(mnemonic)) set("call");
      else if (/^(?:rts|rte|rtr)$/.test(mnemonic)) set("return");
      else if (/^(?:bra|jmp)$/.test(mnemonic)) set("jump");
      else if (
        /^(?:b|db)(?:cc|cs|eq|ne|ge|gt|hi|le|ls|lt|mi|pl|vc|vs|ra|f|t)$/.test(
          mnemonic,
        )
      )
        set("conditional", true);
    } else if (family === "riscv") {
      const base = mnemonic.replace(/^c\./, "");
      if (base === "ret" || (base === "jr" && operands.trim() === "ra"))
        set("return");
      else if (base === "jal" || base === "jalr")
        set(/^(?:zero|x0),/.test(operands) ? "jump" : "call");
      else if (/^(?:j|jr)$/.test(base)) set("jump");
      else if (
        /^b(?:eq|ne|lt|ge|ltu|geu|eqz|nez|lez|gez|ltz|gtz|gt|le|gtu|leu)$/.test(
          base,
        )
      )
        set("conditional", true);
    } else if (family === "s390x") {
      if (/^(?:brasl|bras|basr|bas)$/.test(mnemonic)) set("call");
      else if (mnemonic === "br" && operands.trim() === "%r14") set("return");
      else if (/^(?:j|jg|br|b)$/.test(mnemonic)) set("jump");
      else if (
        /^(?:brc|brcl|bcr|j(?:g)?(?:e|ne|h|l|he|le|z|nz|p|m|o|no))$/.test(
          mnemonic,
        )
      )
        set("conditional", true);
    } else if (family === "tricore") {
      if (/^(?:call|calla|calli|fcall|fcalla|fcalli)$/.test(mnemonic))
        set("call");
      else if (/^(?:ret|fret|rfe)$/.test(mnemonic)) set("return");
      else if (/^(?:j|ja|ji|loopu)$/.test(mnemonic)) set("jump");
      else if (/^(?:j(?:eq|ne|lt|ge|z|nz|lez|gez|gtz|ltz)|loop)/.test(mnemonic))
        set("conditional", true);
    }
    const delay =
      ["mips", "sparc"].includes(family) &&
      ["jump", "conditional", "call", "return"].includes(kind)
        ? 1
        : 0;
    let target = ["jump", "conditional", "call"].includes(kind)
      ? directTarget(operands)
      : null;
    // An immediate operand on an indirect branch can be a displacement, not
    // an absolute destination (e.g. RISC-V jalr ra, t0, 0).
    if (
      (family === "riscv" && /^(?:c\.)?(?:jr|jalr)$/.test(mnemonic)) ||
      (family === "mips" && /^(?:jr|jalr)$/.test(mnemonic))
    )
      target = null;
    // Capstone 5 prints RISC-V direct branches as signed PC-relative offsets.
    if (family === "riscv" && target !== null)
      target = BigInt.asUintN(
        core.architectures[frame.archId].bits,
        frame.address + target,
      );
    if (family === "arm" && target !== null) target &= ~1n;
    return {
      kind,
      conditional,
      target,
      delay,
      fallthrough:
        frame.address + BigInt(frame.opcode.length) + BigInt(delay * 4),
    };
  }

  function createIndex(frames) {
    const owners = new Uint32Array(frames.length);
    const invocations = new Uint32Array(frames.length);
    const effective = new Int32Array(frames.length).fill(-1);
    const instructions = new Array(frames.length);
    const functions = [],
      byEntry = new Map(),
      known = new Map();
    let offset = 0,
      invocation = 0;
    let stack = [],
      pending = null;
    const functionAt = (frame, inferred) => {
      const key = addressKey(frame);
      if (!byEntry.has(key)) {
        byEntry.set(key, functions.length);
        functions.push({
          id: functions.length,
          entry: frame.address,
          archId: frame.archId,
          inferred,
          indices: [],
        });
      }
      return byEntry.get(key);
    };
    function advance(batch = 10000) {
      const end = Math.min(frames.length, offset + batch);
      for (; offset < end; offset++) {
        const frame = frames[offset];
        if (!stack.length)
          stack.push({
            owner: functionAt(frame, false),
            invocation: invocation++,
            returnAddress: null,
          });
        const key = instructionKey(frame);
        if (!known.has(key))
          known.set(key, { key, frame, flow: classify(frame) });
        instructions[offset] = known.get(key);
        const scope = stack.at(-1);
        owners[offset] = scope.owner;
        invocations[offset] = scope.invocation;
        functions[scope.owner].indices.push(offset);
        let source = -1;
        if (pending !== null) {
          source = pending;
          pending = null;
        } else if (instructions[offset].flow.kind !== "next") {
          const flow = instructions[offset].flow;
          if (
            flow.delay &&
            frames[offset + 1]?.address ===
              frame.address + BigInt(frame.opcode.length)
          )
            pending = offset;
          else source = offset;
        }
        if (source < 0) continue;
        effective[offset] = source;
        const flow = instructions[source].flow,
          next = frames[offset + 1];
        if (!next) continue;
        if (flow.conditional && next.address === flow.fallthrough) continue;
        if (flow.kind === "call" && next.address !== flow.fallthrough) {
          stack.push({
            owner: functionAt(next, true),
            invocation: invocation++,
            returnAddress: flow.fallthrough,
          });
        } else if (flow.kind === "return") {
          // Match known return addresses, including unwinding more than one call.
          let depth = stack.length - 1;
          while (depth > 0 && stack[depth].returnAddress !== next.address)
            depth--;
          if (depth > 0) stack.length = depth;
          else stack = []; // Return outside captured calling context: new region.
        }
      }
      return offset === frames.length;
    }
    return {
      frames,
      owners,
      invocations,
      effective,
      instructions,
      functions,
      advance,
      get done() {
        return offset === frames.length;
      },
      get progress() {
        return frames.length ? offset / frames.length : 1;
      },
    };
  }

  function buildGraph(
    index,
    frameIndex,
    { maxInstructions = 5000, maxBlocks = 300, maxEdges = 1000 } = {},
  ) {
    if (!index.done) throw new Error("CFG index is still being built.");
    if (!index.frames[frameIndex]) return null;
    const scope = index.functions[index.owners[frameIndex]];
    const nodes = new Map(),
      byAddress = new Map(),
      transfers = new Map();
    const leaders = new Set(),
      flowAt = new Map();
    let raw = 0,
      variants = false;
    for (const i of scope.indices) {
      const info = index.instructions[i];
      if (!nodes.has(info.key)) {
        if (nodes.size >= maxInstructions)
          return {
            scope,
            error: `This function exceeds the ${maxInstructions.toLocaleString()}-instruction graph limit. Use Disassembly to inspect it.`,
          };
        nodes.set(info.key, { ...info, visits: [] });
        const addr = addressKey(info.frame);
        if (!byAddress.has(addr)) byAddress.set(addr, []);
        byAddress.get(addr).push(info.key);
        if (byAddress.get(addr).length > 1) variants = true;
        if (!info.frame.mnemonic) raw++;
      }
      nodes.get(info.key).visits.push(i);
      const source = index.effective[i];
      if (source >= 0)
        flowAt.set(info.key, {
          ...index.instructions[source].flow,
          instruction: index.instructions[source],
        });
      if (i === 0 || index.invocations[i] !== index.invocations[i - 1])
        leaders.add(info.key);
    }
    const lookup = (address, frame) => {
      const keys = byAddress.get(
        `${core.architectures[frame.archId].family}:${address}`,
      );
      return keys?.length === 1 ? keys[0] : null;
    };
    // A delayed branch without its delay slot is still a block terminator.
    for (const [key, node] of nodes) {
      if (node.flow.kind !== "next" && !node.flow.delay)
        flowAt.set(key, { ...node.flow, instruction: node });
      if (node.flow.target !== null) {
        const target = lookup(node.flow.target, node.frame);
        if (target) leaders.add(target);
      }
      if (node.flow.kind !== "next") {
        const continuation = lookup(node.flow.fallthrough, node.frame);
        if (continuation) leaders.add(continuation);
      }
    }
    const addTransfer = (from, to, type, count = 1) => {
      const key = `${from}|${to}|${type}`;
      if (!transfers.has(key)) transfers.set(key, { from, to, type, count: 0 });
      transfers.get(key).count += count;
    };
    // Only connect frames in the same invocation; callee bodies are excluded.
    const previousByInvocation = new Map();
    for (const i of scope.indices) {
      const previous = previousByInvocation.get(index.invocations[i]);
      const current = index.instructions[i];
      if (previous !== undefined) {
        const source = index.instructions[previous],
          flow = flowAt.get(source.key);
        let type = "flow";
        if (flow) {
          if (flow.kind === "call") type = "continuation";
          else if (flow.conditional)
            type =
              current.frame.address === flow.fallthrough
                ? "not-taken"
                : "taken";
          else if (flow.kind === "jump") type = "jump";
          else type = "observed";
        } else if (
          current.frame.address !==
          source.frame.address + BigInt(source.frame.opcode.length)
        )
          type = "observed";
        addTransfer(source.key, current.key, type);
        if (flow || type === "observed" || current.key === source.key)
          leaders.add(current.key);
      } else leaders.add(current.key);
      previousByInvocation.set(index.invocations[i], i);
    }
    const incoming = new Map(),
      outgoing = new Map();
    for (const transfer of transfers.values()) {
      if (!incoming.has(transfer.to)) incoming.set(transfer.to, new Set());
      if (!outgoing.has(transfer.from)) outgoing.set(transfer.from, new Set());
      incoming.get(transfer.to).add(transfer.from);
      outgoing.get(transfer.from).add(transfer.to);
    }
    for (const [key, sources] of incoming)
      if (sources.size > 1) leaders.add(key);
    const blocks = [],
      membership = new Map();
    for (const [key] of nodes) {
      if (membership.has(key)) continue;
      const block = {
        id: `b${blocks.length}`,
        instructions: [],
        visits: [],
        external: false,
      };
      let cursor = key;
      while (cursor && !membership.has(cursor)) {
        const node = nodes.get(cursor);
        membership.set(cursor, block.id);
        block.instructions.push(node);
        if (flowAt.has(cursor)) {
          block.flow = flowAt.get(cursor);
          break;
        }
        const next = outgoing.get(cursor);
        if (next?.size !== 1) break;
        const nextKey = next.values().next().value;
        if (leaders.has(nextKey) || membership.has(nextKey)) break;
        const candidate = nodes.get(nextKey);
        if (
          candidate.frame.address !==
          node.frame.address + BigInt(node.frame.opcode.length)
        )
          break;
        cursor = nextKey;
      }
      block.address = block.instructions[0].frame.address;
      block.archId = block.instructions[0].frame.archId;
      block.visits = block.instructions[0].visits;
      blocks.push(block);
    }
    if (blocks.length > maxBlocks)
      return {
        scope,
        error: `This function has ${blocks.length} blocks (graph limit: ${maxBlocks}). Use Disassembly to inspect it.`,
      };
    const edges = new Map(),
      observedDestinations = new Map();
    const blockById = new Map(blocks.map((block) => [block.id, block]));
    const addEdge = (from, to, type, count = 0) => {
      const key = `${from}|${to}|${type}`;
      if (!edges.has(key))
        edges.set(key, { id: `e${edges.size}`, from, to, type, count: 0 });
      edges.get(key).count += count;
      if (count) {
        const source = `${from}|${type}`;
        if (!observedDestinations.has(source))
          observedDestinations.set(source, new Set());
        observedDestinations.get(source).add(to);
      }
    };
    for (const transfer of transfers.values()) {
      const from = membership.get(transfer.from),
        to = membership.get(transfer.to);
      if (from !== to || transfer.type !== "flow")
        addEdge(from, to, transfer.type, transfer.count);
    }
    const externals = new Map();
    const external = (owner, address, type, visits = []) => {
      const key = `${owner}|${type}|${address}`;
      if (!externals.has(key)) {
        const id = `x${externals.size}`;
        externals.set(key, id);
        blocks.push({
          id,
          address,
          archId: scope.archId,
          external: true,
          type,
          visits,
          instructions: [],
        });
        blockById.set(id, blocks.at(-1));
      }
      return externals.get(key);
    };
    const internalBlocks = blocks.slice();
    for (const block of internalBlocks) {
      const flow = block.flow;
      if (!flow) continue;
      const last = block.instructions.at(-1);
      const destinations = new Map();
      for (const i of last.visits) {
        if (index.effective[i] < 0) continue;
        const next = index.frames[i + 1];
        if (!next) continue;
        if (
          (flow.kind === "call" || flow.kind === "return") &&
          (!flow.conditional || next.address !== flow.fallthrough)
        ) {
          if (!destinations.has(next.address))
            destinations.set(next.address, []);
          destinations.get(next.address).push(i + 1);
        }
      }
      if (flow.kind === "call" || flow.kind === "return") {
        for (const [address, visits] of destinations)
          addEdge(
            block.id,
            external(block.id, address, flow.kind, visits),
            flow.kind,
            visits.length,
          );
        if (!destinations.size)
          addEdge(
            block.id,
            external(
              block.id,
              flow.kind === "call" ? flow.target : null,
              flow.kind,
            ),
            flow.kind,
          );
      }
      const expected = [];
      if (flow.kind === "conditional")
        expected.push([flow.target, "taken"], [flow.fallthrough, "not-taken"]);
      if (flow.kind === "jump") expected.push([flow.target, "jump"]);
      if (flow.kind === "call")
        expected.push([flow.fallthrough, "continuation"]);
      if (flow.kind === "return" && flow.conditional)
        expected.push([flow.fallthrough, "not-taken"]);
      for (const [address, type] of expected) {
        // An indirect destination may have multiple observed targets. Do not
        // invent another unknown destination when those edges already exist.
        const observed = observedDestinations.get(`${block.id}|${type}`);
        if (address === null && observed?.size) continue;
        // Ambiguous code versions at a target address are resolved by observed
        // edges when possible; they must not become a fictitious missing block.
        if (
          address !== null &&
          observed &&
          Array.from(observed).some(
            (id) => blockById.get(id).address === address,
          )
        )
          continue;
        const target =
          address === null ? null : lookup(address, flow.instruction.frame);
        const destination = target
          ? membership.get(target)
          : external(block.id, address, "unseen");
        addEdge(block.id, destination, type);
      }
    }
    // Include external destinations in the layout budget. Indirect calls may
    // reach many functions even when the caller itself has only a few blocks.
    if (blocks.length > maxBlocks || edges.size > maxEdges)
      return {
        scope,
        error: `This function exceeds the graph limit (${maxBlocks} nodes / ${maxEdges} edges, including external destinations). Use Disassembly to inspect it.`,
      };
    return {
      scope,
      blocks,
      edges: Array.from(edges.values()),
      membership,
      raw,
      variants,
    };
  }

  function nearestVisit(visits, index) {
    if (!visits.length) return null;
    let low = 0,
      high = visits.length;
    while (low < high) {
      const mid = (low + high) >>> 1;
      if (visits[mid] < index) low = mid + 1;
      else high = mid;
    }
    if (low === visits.length) return visits.at(-1);
    if (!low) return visits[0];
    return index - visits[low - 1] <= visits[low] - index
      ? visits[low - 1]
      : visits[low];
  }
  return { classify, instructionKey, createIndex, buildGraph, nearestVisit };
})();
if (typeof module !== "undefined") module.exports = EmtrCFG;
