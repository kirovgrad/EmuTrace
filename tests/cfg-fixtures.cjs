// Instruction-entry snapshots used to exercise graph recovery and the file viewer.
const { deflateSync } = require("node:zlib");
function frame(
  address,
  mnemonic = "nop",
  operands = "",
  archId = 4,
  size = 1,
  byte = 0x90,
) {
  return {
    address: BigInt(address),
    mnemonic,
    operands,
    archId,
    opcode: Uint8Array.from({ length: size }, () => byte),
    regs: { RAX: BigInt(address) },
    sp: 0x8000n,
    stack: new Uint8Array(8),
  };
}
function calls() {
  return [
    frame(0x100, "call", "0x200", 4, 5),
    frame(0x200, "cmp", "rax, 0", 4, 3),
    frame(0x203, "jne", "0x210", 4, 2),
    frame(0x210, "call", "0x300", 4, 5),
    frame(0x300, "nop"),
    frame(0x301, "ret"),
    frame(0x215, "ret"),
    frame(0x105, "nop"),
    frame(0x106, "hlt"),
  ];
}
function encode(frames) {
  const header = Buffer.alloc(16);
  header.write("EMTR");
  header.writeUInt32LE(2, 4);
  header.writeUInt32LE(frames[0]?.archId ?? 4, 8);
  header.writeUInt32LE(frames.length, 12);
  const chunks = [Buffer.alloc(4)];
  for (const f of frames) {
    const location = Buffer.alloc(10);
    location.writeBigUInt64LE(f.address);
    location.writeUInt16LE(f.opcode.length, 8);
    const registers = Buffer.alloc(14);
    registers.writeUInt16LE(1);
    registers[2] = 3;
    registers.write("RAX", 3);
    registers.writeBigUInt64LE(f.regs.RAX, 6);
    const stack = Buffer.alloc(12);
    stack.writeBigUInt64LE(f.sp);
    stack.writeUInt32LE(f.stack.length, 8);
    const mnemonic = Buffer.from(f.mnemonic),
      operands = Buffer.from(f.operands);
    const extension = Buffer.alloc(8);
    extension.writeUInt32LE(f.archId);
    extension.writeUInt16LE(mnemonic.length, 4);
    extension.writeUInt16LE(operands.length, 6);
    chunks.push(
      location,
      Buffer.from(f.opcode),
      registers,
      stack,
      Buffer.from(f.stack),
      extension,
      mnemonic,
      operands,
    );
  }
  return Buffer.concat([header, deflateSync(Buffer.concat(chunks))]);
}
module.exports = { frame, calls, encode };
