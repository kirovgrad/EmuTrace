/* Binary parsing and comparison logic, shared by the browser and Node tests. */
"use strict";
const Emtr = (() => {
  const architectures =
    typeof module !== "undefined"
      ? require("./emu_architectures.js")
      : EMTR_ARCHITECTURES;
  const MAX_BYTES = 256 * 1024 * 1024;
  const MAX_FRAMES = 1000000;
  const MAX_METADATA_BYTES = 16 * 1024 * 1024;
  const hexByte = (value) => value.toString(16).padStart(2, "0");
  const hex = (value, archId) =>
    "0x" +
    value.toString(16).padStart((architectures[archId]?.bits || 32) / 4, "0");
  const opcodeHex = (bytes) => Array.from(bytes, hexByte).join(" ");

  async function inflate(compressed, limit) {
    if (typeof DecompressionStream === "undefined")
      throw new Error(
        "This browser needs DecompressionStream support. Open in a current Safari, Firefox, Chrome, or Edge.",
      );
    const reader = new Blob([compressed])
      .stream()
      .pipeThrough(new DecompressionStream("deflate"))
      .getReader();
    const chunks = [];
    let length = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > limit) {
          await reader.cancel();
          throw new Error("Trace exceeds the decompression limit.");
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const result = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }

  async function parse(
    buffer,
    { maxBytes = MAX_BYTES, maxFrames = MAX_FRAMES } = {},
  ) {
    if (buffer.byteLength < 16)
      throw new Error("Truncated EMTR header (expected 16 bytes).");
    if (buffer.byteLength > maxBytes + 16)
      throw new Error("File exceeds the size limit.");
    const header = new DataView(buffer);
    if (header.getUint32(0, true) !== 0x52544d45)
      throw new Error("This is not an EMTR trace.");
    const version = header.getUint32(4, true);
    if (![1, 2, 3].includes(version))
      throw new Error(`Unsupported EMTR version ${version}.`);
    const archId = header.getUint32(8, true),
      nFrames = header.getUint32(12, true);
    if (!Object.hasOwn(architectures, archId))
      throw new Error(`Unknown architecture ID ${archId}.`);
    if (nFrames > maxFrames) throw new Error("Trace exceeds the frame limit.");
    let data;
    try {
      data = await inflate(new Uint8Array(buffer, 16), maxBytes);
    } catch (error) {
      throw new Error(`Cannot decompress trace: ${error.message}`);
    }
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let offset = 0;
    const take = (length) => {
      if (length > data.length - offset)
        throw new Error(`Truncated frame at payload byte ${offset}.`);
      const start = offset;
      offset += length;
      return start;
    };
    const u8 = () => view.getUint8(take(1));
    const u16 = () => view.getUint16(take(2), true);
    const u32 = () => view.getUint32(take(4), true);
    const u64 = () => view.getBigUint64(take(8), true);
    const bytes = (n) => {
      const start = take(n);
      return data.subarray(start, start + n);
    };
    const decoder = new TextDecoder("utf-8", { fatal: true });
    const text = (n) => decoder.decode(bytes(n));
    const flags = version >= 2 ? u32() : 0;
    if (flags & ~1) throw new Error("Unknown trace flags.");
    const frames = [];
    for (let i = 0; i < nFrames; i++) {
      const address = u64(),
        size = u16();
      if (size < 1 || size > 32) throw new Error("Invalid opcode length.");
      const opcode = bytes(size),
        count = u16(),
        regs = Object.create(null);
      if (count > 512) throw new Error("Too many registers in a frame.");
      for (let r = 0; r < count; r++) {
        const name = text(u8());
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || Object.hasOwn(regs, name))
          throw new Error("Invalid or duplicate register name.");
        regs[name] = u64();
      }
      const sp = u64(),
        stackSize = u32();
      if (stackSize > 1024 * 1024)
        throw new Error("Stack snapshot exceeds the size limit.");
      const stack = bytes(stackSize);
      let frameArch = archId,
        mnemonic = "",
        operands = "";
      if (version >= 2) {
        frameArch = u32();
        if (!Object.hasOwn(architectures, frameArch))
          throw new Error(`Unknown frame architecture ID ${frameArch}.`);
        const mnemonicSize = u16(),
          operandsSize = u16();
        mnemonic = text(mnemonicSize);
        operands = text(operandsSize);
      } else if (
        architectures[archId].family === "arm" &&
        archId !== 22 &&
        regs.CPSR !== undefined
      ) {
        const thumb = Boolean(regs.CPSR & 32n);
        frameArch =
          architectures[archId].endian === "big"
            ? thumb
              ? 19
              : 20
            : thumb
              ? 0
              : 1;
      }
      frames.push({
        address,
        opcode,
        regs,
        sp,
        stack,
        archId: frameArch,
        mnemonic,
        operands,
      });
      // Keep loading cancellable and let progress messages paint for large traces.
      if (i > 0 && i % 10000 === 0)
        await new Promise((resolve) => setTimeout(resolve, 0));
    }
    let metadata = {};
    if (version === 3) {
      const metadataSize = u32();
      if (metadataSize > MAX_METADATA_BYTES)
        throw new Error("Trace metadata exceeds the size limit.");
      try {
        metadata = JSON.parse(text(metadataSize));
      } catch (error) {
        throw new Error(`Invalid trace metadata: ${error.message}`);
      }
      if (!metadata || Array.isArray(metadata) || typeof metadata !== "object")
        throw new Error("Trace metadata must be an object.");
    }
    if (offset !== data.length)
      throw new Error("Unexpected bytes after the final frame.");
    return {
      version,
      truncated: Boolean(flags & 1),
      archId,
      archName: architectures[archId].name,
      nFrames,
      frames,
      metadata,
    };
  }

  function registerChanges(frame, previous) {
    return Object.entries(frame.regs)
      .filter(
        ([name, value]) =>
          previous &&
          Object.hasOwn(previous.regs, name) &&
          previous.regs[name] !== value,
      )
      .map(([name]) => name);
  }

  function stackChanges(frame, previous) {
    // Compare the same addresses, not offsets from a moving stack pointer.
    return Array.from(frame.stack, (value, offset) => {
      if (!previous) return "same";
      const index = frame.sp + BigInt(offset) - previous.sp;
      if (index < 0n || index >= BigInt(previous.stack.length)) return "new";
      return previous.stack[Number(index)] !== value ? "changed" : "same";
    });
  }

  function createChangeHistory(frames) {
    // Cache event indices, not navigation state, so backtracking and jumps
    // produce the same highlights as sequential playback.
    const registerEvents = new Int32Array(frames.length).fill(-1);
    const stackEvents = new Int32Array(frames.length).fill(-1);
    let scanned = 0;
    let registerFrame = -1,
      stackFrame = -1;

    return function highlightsAt(index) {
      for (let i = scanned + 1; i <= index; i++) {
        const frame = frames[i],
          previous = frames[i - 1];
        const pc = architectures[frame.archId].pc;
        // Normal PC advancement should not erase the last data-register change.
        if (registerChanges(frame, previous).some((name) => name !== pc))
          registerFrame = i;
        if (stackChanges(frame, previous).some((change) => change !== "same"))
          stackFrame = i;
        registerEvents[i] = registerFrame;
        stackEvents[i] = stackFrame;
      }
      scanned = Math.max(scanned, index);
      const frame = frames[index],
        previous = frames[index - 1];
      const regIndex = registerEvents[index],
        stackIndex = stackEvents[index];
      const registers = new Map();
      if (regIndex >= 0) {
        const source = frames[regIndex],
          before = frames[regIndex - 1];
        for (const name of registerChanges(source, before)) {
          if (
            name !== architectures[source.archId].pc &&
            Object.hasOwn(frame.regs, name)
          )
            registers.set(name, before.regs[name]);
        }
      }
      const pc = architectures[frame.archId].pc;
      if (
        previous &&
        Object.hasOwn(frame.regs, pc) &&
        Object.hasOwn(previous.regs, pc) &&
        frame.regs[pc] !== previous.regs[pc]
      )
        registers.set(pc, previous.regs[pc]);
      const stack = new Set();
      if (stackIndex >= 0) {
        const source = frames[stackIndex];
        const changes = stackChanges(source, frames[stackIndex - 1]);
        for (let offset = 0; offset < changes.length; offset++) {
          if (changes[offset] === "same") continue;
          const currentOffset = source.sp + BigInt(offset) - frame.sp;
          if (currentOffset >= 0n && currentOffset < BigInt(frame.stack.length))
            stack.add(Number(currentOffset));
        }
      }
      return {
        registers,
        stack,
        registerFrame: regIndex,
        stackFrame: stackIndex,
      };
    };
  }

  function stackWord(bytes, archId) {
    const spec = architectures[archId];
    const width = spec.bits / 8;
    // Display a numeric word most-significant byte first, while retaining
    // each byte's original memory offset for change highlights and tooltips.
    // Missing bytes stay unknown; a partial snapshot must never imply zeros.
    const ordered = Array.from({ length: width }, (_, position) => {
      const offset = spec.endian === "little" ? width - position - 1 : position;
      return { offset, value: bytes[offset] };
    });
    return {
      bytes: ordered,
      hex: ordered
        .map(({ value }) => (value === undefined ? "??" : hexByte(value)))
        .join(""),
    };
  }

  function frameJSON(frame, index) {
    return JSON.stringify(
      {
        frame: index + 1,
        state_timing: "before instruction",
        architecture: architectures[frame.archId].name,
        address: hex(frame.address, frame.archId),
        opcode: opcodeHex(frame.opcode),
        mnemonic: frame.mnemonic,
        operands: frame.operands,
        registers: Object.fromEntries(
          Object.entries(frame.regs).map(([name, value]) => [
            name,
            hex(value, frame.archId),
          ]),
        ),
        stack_address: hex(frame.sp, frame.archId),
        stack: opcodeHex(frame.stack),
      },
      null,
      2,
    );
  }
  return {
    architectures,
    MAX_BYTES,
    MAX_FRAMES,
    parse,
    hexByte,
    hex,
    opcodeHex,
    registerChanges,
    stackChanges,
    createChangeHistory,
    stackWord,
    frameJSON,
  };
})();
if (typeof module !== "undefined") module.exports = Emtr;
