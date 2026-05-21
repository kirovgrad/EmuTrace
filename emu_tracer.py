"""
Supported architectures
-----------------------
  ARM16   – Thumb / ARM  (UC_ARCH_ARM  + UC_MODE_THUMB)
  ARM32   – ARM          (UC_ARCH_ARM  + UC_MODE_ARM)
  ARM64   – AArch64      (UC_ARCH_ARM64)
  X86     – IA-32        (UC_ARCH_X86  + UC_MODE_32)
  X86_64  – AMD64        (UC_ARCH_X86  + UC_MODE_64)
  MIPS    – MIPS32 BE    (UC_ARCH_MIPS + UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
  MIPSEL  – MIPS32 LE    (UC_ARCH_MIPS + UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
  MIPS64  – MIPS64 BE    (UC_ARCH_MIPS + UC_MODE_MIPS64 + UC_MODE_BIG_ENDIAN)
  MIPS64EL– MIPS64 LE    (UC_ARCH_MIPS + UC_MODE_MIPS64 + UC_MODE_LITTLE_ENDIAN)

Wire format  (little-endian integers throughout)
-------------------------------------------------
File header  (16 bytes)
  [0:4]   magic      b"EMTR"
  [4:8]   version    uint32  = 1
  [8:12]  arch_id    uint32  (see ARCH_IDS below)
  [12:16] n_frames   uint32  total instruction count

Per-frame  (variable size)
  [0:8]   address    uint64
  [8:10]  opcode_len uint16  (1-15)
  [10:]   opcode     bytes[opcode_len]
  then    reg_block  (see below)
  then    stack_block

reg_block
  [0:2]  n_regs    uint16
  repeat n_regs times:
  [0:1]  name_len  uint8
  [1:]   name      bytes[name_len]   (ASCII)
  [n:]   value     uint64

stack_block
  [0:8]   sp_value   uint64
  [8:12]  n_bytes    uint32            (number of stack bytes captured)
  [12:]   raw_bytes  bytes[n_bytes]    (from SP upward in memory)

The file is then zlib-compressed (level 9) after the header so that on
large traces the size stays manageable.  The header itself is NOT
compressed so the viewer can read arch/count without decompressing.

Usage
-----
  from emu_tracer import Tracer, ARCH

  # Create a Unicorn emulator however you like:
  import unicorn
  mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
  # ... map memory, write code, set registers ...

  tracer = Tracer(mu, ARCH.X86_64)
  tracer.attach()          # installs the hook

  mu.emu_start(start, end)

  tracer.save("trace.emtr")
  # – or –
  raw_bytes = tracer.dump()   # returns bytes
"""

from __future__ import annotations

import io
import struct
import zlib
from enum import IntEnum
from typing import Dict, List, Tuple

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

try:
    import unicorn
    import unicorn.arm_const as uc_arm
    import unicorn.arm64_const as uc_arm64
    import unicorn.x86_const as uc_x86
    import unicorn.mips_const as uc_mips
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False
    unicorn = None

class ARCH(IntEnum):
    ARM16   = 0   # Thumb
    ARM32   = 1
    ARM64   = 2
    X86     = 3
    X86_64  = 4
    MIPS    = 5
    MIPSEL  = 6
    MIPS64  = 7
    MIPS64EL= 8


ARCH_NAMES: Dict[ARCH, str] = {
    ARCH.ARM16:    "ARM16 (Thumb)",
    ARCH.ARM32:    "ARM32",
    ARCH.ARM64:    "ARM64",
    ARCH.X86:      "x86",
    ARCH.X86_64:   "x86-64",
    ARCH.MIPS:     "MIPS (BE)",
    ARCH.MIPSEL:   "MIPS (LE)",
    ARCH.MIPS64:   "MIPS64 (BE)",
    ARCH.MIPS64EL: "MIPS64 (LE)",
}

# Register definitions per architecture: list of (name, unicorn_const)
def _build_reg_maps() -> Dict[ARCH, List[Tuple[str, int]]]:
    if not HAS_UNICORN:
        return {}

    arm_regs = [
        ("R0",  uc_arm.UC_ARM_REG_R0),  ("R1",  uc_arm.UC_ARM_REG_R1),
        ("R2",  uc_arm.UC_ARM_REG_R2),  ("R3",  uc_arm.UC_ARM_REG_R3),
        ("R4",  uc_arm.UC_ARM_REG_R4),  ("R5",  uc_arm.UC_ARM_REG_R5),
        ("R6",  uc_arm.UC_ARM_REG_R6),  ("R7",  uc_arm.UC_ARM_REG_R7),
        ("R8",  uc_arm.UC_ARM_REG_R8),  ("R9",  uc_arm.UC_ARM_REG_R9),
        ("R10", uc_arm.UC_ARM_REG_R10), ("R11", uc_arm.UC_ARM_REG_R11),
        ("R12", uc_arm.UC_ARM_REG_R12), ("SP",  uc_arm.UC_ARM_REG_SP),
        ("LR",  uc_arm.UC_ARM_REG_LR),  ("PC",  uc_arm.UC_ARM_REG_PC),
        ("CPSR",uc_arm.UC_ARM_REG_CPSR),
    ]
    arm64_regs = [
        ("X0",  uc_arm64.UC_ARM64_REG_X0),  ("X1",  uc_arm64.UC_ARM64_REG_X1),
        ("X2",  uc_arm64.UC_ARM64_REG_X2),  ("X3",  uc_arm64.UC_ARM64_REG_X3),
        ("X4",  uc_arm64.UC_ARM64_REG_X4),  ("X5",  uc_arm64.UC_ARM64_REG_X5),
        ("X6",  uc_arm64.UC_ARM64_REG_X6),  ("X7",  uc_arm64.UC_ARM64_REG_X7),
        ("X8",  uc_arm64.UC_ARM64_REG_X8),  ("X9",  uc_arm64.UC_ARM64_REG_X9),
        ("X10", uc_arm64.UC_ARM64_REG_X10), ("X11", uc_arm64.UC_ARM64_REG_X11),
        ("X12", uc_arm64.UC_ARM64_REG_X12), ("X13", uc_arm64.UC_ARM64_REG_X13),
        ("X14", uc_arm64.UC_ARM64_REG_X14), ("X15", uc_arm64.UC_ARM64_REG_X15),
        ("X16", uc_arm64.UC_ARM64_REG_X16), ("X17", uc_arm64.UC_ARM64_REG_X17),
        ("X18", uc_arm64.UC_ARM64_REG_X18), ("X19", uc_arm64.UC_ARM64_REG_X19),
        ("X20", uc_arm64.UC_ARM64_REG_X20), ("X21", uc_arm64.UC_ARM64_REG_X21),
        ("X22", uc_arm64.UC_ARM64_REG_X22), ("X23", uc_arm64.UC_ARM64_REG_X23),
        ("X24", uc_arm64.UC_ARM64_REG_X24), ("X25", uc_arm64.UC_ARM64_REG_X25),
        ("X26", uc_arm64.UC_ARM64_REG_X26), ("X27", uc_arm64.UC_ARM64_REG_X27),
        ("X28", uc_arm64.UC_ARM64_REG_X28), ("X29", uc_arm64.UC_ARM64_REG_X29),
        ("X30", uc_arm64.UC_ARM64_REG_X30), ("SP",  uc_arm64.UC_ARM64_REG_SP),
        ("PC",  uc_arm64.UC_ARM64_REG_PC),
    ]
    x86_regs = [
        ("EAX", uc_x86.UC_X86_REG_EAX), ("EBX", uc_x86.UC_X86_REG_EBX),
        ("ECX", uc_x86.UC_X86_REG_ECX), ("EDX", uc_x86.UC_X86_REG_EDX),
        ("ESI", uc_x86.UC_X86_REG_ESI), ("EDI", uc_x86.UC_X86_REG_EDI),
        ("EBP", uc_x86.UC_X86_REG_EBP), ("ESP", uc_x86.UC_X86_REG_ESP),
        ("EIP", uc_x86.UC_X86_REG_EIP), ("EFLAGS", uc_x86.UC_X86_REG_EFLAGS),
        ("CS",  uc_x86.UC_X86_REG_CS),  ("DS",  uc_x86.UC_X86_REG_DS),
        ("ES",  uc_x86.UC_X86_REG_ES),  ("FS",  uc_x86.UC_X86_REG_FS),
        ("GS",  uc_x86.UC_X86_REG_GS),  ("SS",  uc_x86.UC_X86_REG_SS),
    ]
    x86_64_regs = [
        ("RAX", uc_x86.UC_X86_REG_RAX), ("RBX", uc_x86.UC_X86_REG_RBX),
        ("RCX", uc_x86.UC_X86_REG_RCX), ("RDX", uc_x86.UC_X86_REG_RDX),
        ("RSI", uc_x86.UC_X86_REG_RSI), ("RDI", uc_x86.UC_X86_REG_RDI),
        ("RBP", uc_x86.UC_X86_REG_RBP), ("RSP", uc_x86.UC_X86_REG_RSP),
        ("RIP", uc_x86.UC_X86_REG_RIP), ("R8",  uc_x86.UC_X86_REG_R8),
        ("R9",  uc_x86.UC_X86_REG_R9),  ("R10", uc_x86.UC_X86_REG_R10),
        ("R11", uc_x86.UC_X86_REG_R11), ("R12", uc_x86.UC_X86_REG_R12),
        ("R13", uc_x86.UC_X86_REG_R13), ("R14", uc_x86.UC_X86_REG_R14),
        ("R15", uc_x86.UC_X86_REG_R15), ("EFLAGS", uc_x86.UC_X86_REG_EFLAGS),
        ("CS",  uc_x86.UC_X86_REG_CS),  ("FS",  uc_x86.UC_X86_REG_FS),
        ("GS",  uc_x86.UC_X86_REG_GS),
    ]
    mips_regs = [
        ("zero", uc_mips.UC_MIPS_REG_0),  ("at",  uc_mips.UC_MIPS_REG_1),
        ("v0",   uc_mips.UC_MIPS_REG_2),  ("v1",  uc_mips.UC_MIPS_REG_3),
        ("a0",   uc_mips.UC_MIPS_REG_4),  ("a1",  uc_mips.UC_MIPS_REG_5),
        ("a2",   uc_mips.UC_MIPS_REG_6),  ("a3",  uc_mips.UC_MIPS_REG_7),
        ("t0",   uc_mips.UC_MIPS_REG_8),  ("t1",  uc_mips.UC_MIPS_REG_9),
        ("t2",   uc_mips.UC_MIPS_REG_10), ("t3",  uc_mips.UC_MIPS_REG_11),
        ("t4",   uc_mips.UC_MIPS_REG_12), ("t5",  uc_mips.UC_MIPS_REG_13),
        ("t6",   uc_mips.UC_MIPS_REG_14), ("t7",  uc_mips.UC_MIPS_REG_15),
        ("s0",   uc_mips.UC_MIPS_REG_16), ("s1",  uc_mips.UC_MIPS_REG_17),
        ("s2",   uc_mips.UC_MIPS_REG_18), ("s3",  uc_mips.UC_MIPS_REG_19),
        ("s4",   uc_mips.UC_MIPS_REG_20), ("s5",  uc_mips.UC_MIPS_REG_21),
        ("s6",   uc_mips.UC_MIPS_REG_22), ("s7",  uc_mips.UC_MIPS_REG_23),
        ("t8",   uc_mips.UC_MIPS_REG_24), ("t9",  uc_mips.UC_MIPS_REG_25),
        ("k0",   uc_mips.UC_MIPS_REG_26), ("k1",  uc_mips.UC_MIPS_REG_27),
        ("gp",   uc_mips.UC_MIPS_REG_28), ("sp",  uc_mips.UC_MIPS_REG_29),
        ("fp",   uc_mips.UC_MIPS_REG_30), ("ra",  uc_mips.UC_MIPS_REG_31),
        ("PC",   uc_mips.UC_MIPS_REG_PC),
    ]

    return {
        ARCH.ARM16:    arm_regs,
        ARCH.ARM32:    arm_regs,
        ARCH.ARM64:    arm64_regs,
        ARCH.X86:      x86_regs,
        ARCH.X86_64:   x86_64_regs,
        ARCH.MIPS:     mips_regs,
        ARCH.MIPSEL:   mips_regs,
        ARCH.MIPS64:   mips_regs,
        ARCH.MIPS64EL: mips_regs,
    }


# SP register name per arch (used to locate the stack)
SP_REG: Dict[ARCH, str] = {
    ARCH.ARM16:    "SP",
    ARCH.ARM32:    "SP",
    ARCH.ARM64:    "SP",
    ARCH.X86:      "ESP",
    ARCH.X86_64:   "RSP",
    ARCH.MIPS:     "sp",
    ARCH.MIPSEL:   "sp",
    ARCH.MIPS64:   "sp",
    ARCH.MIPS64EL: "sp",
}

# How many bytes to capture above the SP
STACK_CAPTURE_BYTES = 128

# File format constants
MAGIC   = b"EMTR"
VERSION = 1

# Header packer: magic(4) + version(4) + arch_id(4) + n_frames(4)
HDR_STRUCT = struct.Struct("<4sIII")

class Tracer:
    """
    Attaches to a live Unicorn emulator instance and records a trace.

    Parameters
    ----------
    mu      : unicorn.Uc    – already-configured emulator
    arch    : ARCH          – architecture selector
    stack_capture : int     – how many bytes above SP to snapshot (default 128)
    """

    def __init__(
        self,
        mu,
        arch: ARCH,
        stack_capture: int = STACK_CAPTURE_BYTES,
    ) -> None:
        if not HAS_UNICORN:
            raise ImportError("unicorn-engine is not installed.")
        self._mu            = mu
        self._arch          = arch
        self._stack_capture = stack_capture
        self._reg_map       = _build_reg_maps().get(arch, [])
        self._sp_name       = SP_REG[arch]
        self._frames: List[bytes] = []
        self._hook_handle   = None

    def attach(self) -> None:
        """Install the instruction hook into the emulator."""
        self._hook_handle = self._mu.hook_add(
            unicorn.UC_HOOK_CODE, self._on_insn
        )

    def detach(self) -> None:
        """Remove the hook (called automatically by save/dump)."""
        if self._hook_handle is not None:
            self._mu.hook_del(self._hook_handle)
            self._hook_handle = None

    def save(self, path: str) -> None:
        """Serialise the trace to *path*."""
        with open(path, "wb") as fh:
            fh.write(self.dump())

    def dump(self) -> bytes:
        """Return the serialised trace as a bytes object."""
        payload = b"".join(self._frames)
        compressed = zlib.compress(payload, level=9)
        header = HDR_STRUCT.pack(MAGIC, VERSION, int(self._arch), len(self._frames))
        return header + compressed

    @property
    def frame_count(self) -> int:
        return len(self._frames)

    def _on_insn(self, mu, address: int, size: int, user_data) -> None:
        buf = io.BytesIO()

        # --- address (8 bytes) + opcode ---
        opcode = mu.mem_read(address, size)
        opcode_bytes = bytes(opcode)
        buf.write(struct.pack("<QH", address, len(opcode_bytes)))
        buf.write(opcode_bytes)

        # --- registers ---
        reg_vals: List[Tuple[str, int]] = []
        sp_val = 0
        for name, uc_id in self._reg_map:
            try:
                val = mu.reg_read(uc_id)
            except Exception:
                val = 0
            reg_vals.append((name, val))
            if name == self._sp_name:
                sp_val = val

        buf.write(struct.pack("<H", len(reg_vals)))
        for name, val in reg_vals:
            enc = name.encode("ascii")
            buf.write(struct.pack("<B", len(enc)))
            buf.write(enc)
            buf.write(struct.pack("<Q", val))

        # --- stack snapshot ---
        try:
            stack_raw = bytes(mu.mem_read(sp_val, self._stack_capture))
        except Exception:
            stack_raw = b""
        buf.write(struct.pack("<QI", sp_val, len(stack_raw)))
        buf.write(stack_raw)

        self._frames.append(buf.getvalue())

class TraceReader:
    """
    Parses a .emtr file produced by :class:`Tracer`.

    Attributes
    ----------
    arch        : ARCH
    arch_name   : str
    n_frames    : int
    frames      : list of dicts  (populated after calling load() / loads())

    Each frame dict::

        {
          "address":  int,
          "opcode":   bytes,
          "regs":     { name: value, ... },
          "sp":       int,
          "stack":    bytes,
        }
    """

    def __init__(self) -> None:
        self.arch: ARCH = ARCH.X86_64
        self.arch_name: str = ""
        self.n_frames: int = 0
        self.frames: List[dict] = []

    def load(self, path: str) -> None:
        with open(path, "rb") as fh:
            self.loads(fh.read())

    def loads(self, data: bytes) -> None:
        hdr_size = HDR_STRUCT.size          # 16
        magic, version, arch_id, n_frames = HDR_STRUCT.unpack_from(data, 0)
        if magic != MAGIC:
            raise ValueError(f"Bad magic: {magic!r}")
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")

        self.arch      = ARCH(arch_id)
        self.arch_name = ARCH_NAMES.get(self.arch, str(self.arch))
        self.n_frames  = n_frames

        payload = zlib.decompress(data[hdr_size:])
        off = 0
        frames = []

        for _ in range(n_frames):
            address, opcode_len = struct.unpack_from("<QH", payload, off)
            off += 10
            opcode = payload[off:off + opcode_len]
            off += opcode_len

            (n_regs,) = struct.unpack_from("<H", payload, off); off += 2
            regs: Dict[str, int] = {}
            for _ in range(n_regs):
                (name_len,) = struct.unpack_from("<B", payload, off); off += 1
                name = payload[off:off + name_len].decode("ascii"); off += name_len
                (val,) = struct.unpack_from("<Q", payload, off); off += 8
                regs[name] = val

            sp_val, n_stack = struct.unpack_from("<QI", payload, off); off += 12
            stack_raw = payload[off:off + n_stack]; off += n_stack

            frames.append({
                "address": address,
                "opcode":  opcode,
                "regs":    regs,
                "sp":      sp_val,
                "stack":   stack_raw,
            })

        self.frames = frames

def _to_json(path: str) -> str:
    import json
    r = TraceReader()
    r.load(path)
    out = {
        "arch":     r.arch_name,
        "n_frames": r.n_frames,
        "frames": [
            {
                "address": f["address"],
                "opcode":  f["opcode"].hex(),
                "regs":    {k: v for k, v in f["regs"].items()},
                "sp":      f["sp"],
                "stack":   f["stack"].hex(),
            }
            for f in r.frames
        ],
    }
    return json.dumps(out, indent=2)


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "dump":
        print(_to_json(sys.argv[2]))
    else:
        print(__doc__)
