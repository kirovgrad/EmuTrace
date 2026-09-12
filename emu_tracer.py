"""Record Unicorn instruction-entry state and read portable EMTR traces.

EMTR v2 retains the 16-byte v1 header and zlib payload. Each v1 frame
(address, opcode, named uint64 registers, stack address and bytes) is followed
by <IHH: instruction architecture ID, mnemonic byte length, operand byte
length, then both UTF-8 strings. V3 appends a length-prefixed JSON metadata
object for optional analyses such as angr decompilation. Readers accept all
three versions. All integers are little endian, independent of the emulated
target. V2 and v3 payloads begin with a uint32 flags word (bit 0: capture limit
reached).
"""

from __future__ import annotations

import argparse
import io
import json
import struct
import zlib
from functools import lru_cache
from pathlib import Path

from architectures import ARCH, ARCH_NAMES, ARCHITECTURES, detect_arch
from architectures import SP_REG as SP_REG

MAGIC = b"EMTR"
VERSION = 2
HDR_STRUCT = struct.Struct("<4sIII")
STACK_CAPTURE_BYTES = 128
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
MAX_FRAMES = 1_000_000
MAX_STACK_BYTES = 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
UINT64_MASK = (1 << 64) - 1


def _encode_metadata(metadata):
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise ValueError("Trace metadata must be an object")
    try:
        encoded = json.dumps(metadata, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Trace metadata must be JSON serializable") from exc
    if len(encoded) > MAX_METADATA_BYTES:
        raise ValueError("Trace metadata exceeds size limit")
    return encoded


def _encode_frame(frame, default_arch):
    opcode = bytes(frame["opcode"])
    if not 1 <= len(opcode) <= 32:
        raise ValueError("Invalid opcode length")
    regs = frame["regs"]
    if len(regs) > 512:
        raise ValueError("Too many registers")
    buf = io.BytesIO()
    buf.write(struct.pack("<QH", frame["address"], len(opcode)))
    buf.write(opcode)
    buf.write(struct.pack("<H", len(regs)))
    for name, value in regs.items():
        encoded = name.encode("ascii")
        if not name.isidentifier() or not 1 <= len(encoded) <= 255:
            raise ValueError("Invalid register name")
        buf.write(struct.pack("<B", len(encoded)) + encoded + struct.pack("<Q", value))
    stack = bytes(frame["stack"])
    if len(stack) > MAX_STACK_BYTES:
        raise ValueError("Stack snapshot exceeds limit")
    buf.write(struct.pack("<QI", frame["sp"], len(stack)))
    buf.write(stack)
    mnemonic = frame.get("mnemonic", "").encode("utf-8")
    operands = frame.get("operands", "").encode("utf-8")
    if len(mnemonic) > 0xFFFF or len(operands) > 0xFFFF:
        raise ValueError("Disassembly text exceeds size limit")
    extension = (
        struct.pack("<IHH", int(frame.get("arch", default_arch)), len(mnemonic), len(operands))
        + mnemonic
        + operands
    )
    return buf.getvalue(), extension


class Tracer:
    """Record scalar CPU registers and memory immediately BEFORE instructions.

    ``arch`` defaults to detection from the Unicorn instance. ARM/Thumb
    transitions are recorded per frame. ``max_frames`` stops recording at the
    limit, not emulation; ``truncated`` reports this. dump/save are snapshots
    and do not detach. Use a context manager for exception-safe hook cleanup.
    """

    def __init__(
        self,
        mu,
        arch=None,
        stack_capture=STACK_CAPTURE_BYTES,
        *,
        max_frames=MAX_FRAMES,
        disassemble=True,
    ):
        import unicorn

        detected = detect_arch(mu)
        self._arch = detected if arch is None else ARCH(arch)
        spec = ARCHITECTURES[self._arch]
        actual = ARCHITECTURES[detected]
        # Thumb state can change between construction and emu_start().
        arm_pair = (
            spec.family == actual.family == "arm"
            and spec.endian == actual.endian
            and ("MCLASS" in spec.uc_modes) == ("MCLASS" in actual.uc_modes)
        )
        if self._arch != detected and not arm_pair:
            raise ValueError(f"{spec.name} does not match emulator mode {actual.name}")
        if type(stack_capture) is not int or not 0 <= stack_capture <= MAX_STACK_BYTES:
            raise ValueError(f"stack_capture must be between 0 and {MAX_STACK_BYTES}")
        if type(max_frames) is not int or not 1 <= max_frames <= MAX_FRAMES:
            raise ValueError(f"max_frames must be between 1 and {MAX_FRAMES}")
        self._mu = mu
        self._spec = spec
        self._stack_capture = stack_capture
        self._max_frames = max_frames
        self._reg_map = spec.registers()
        self._frames = []
        self._hook_handle = None
        self._decoders = {}
        self._decode = lru_cache(maxsize=16384)(self._decode)
        self._payload_size = 4
        self._disassemble = disassemble
        self.truncated = False
        self._uc_error = unicorn.UcError
        if disassemble:
            import capstone  # Fail before emulation when a dependency is missing.

            self._capstone = capstone
            self._decoder(self._arch)

    def _decoder(self, arch):
        if arch not in self._decoders:
            spec = ARCHITECTURES[arch]
            cs_arch, mode = spec.capstone_config()
            if arch == ARCH.ARM64BE:
                mode = 0  # A64 instruction encoding does not follow data endianness.
            self._decoders[arch] = self._capstone.Cs(cs_arch, mode)
        return self._decoders[arch]

    def attach(self):
        """Install the hook once; repeated calls are harmless."""
        import unicorn

        if self._hook_handle is None:
            self._hook_handle = self._mu.hook_add(unicorn.UC_HOOK_CODE, self._on_insn)
        return self

    def detach(self):
        if self._hook_handle is not None:
            self._mu.hook_del(self._hook_handle)
            self._hook_handle = None

    def __enter__(self):
        return self.attach()

    def __exit__(self, *_exc):
        self.detach()

    def clear(self):
        """Discard captured frames; an attached tracer continues recording."""
        self._frames.clear()
        self._payload_size = 4
        self.truncated = False
        self._decode.cache_clear()

    @property
    def frame_count(self):
        return len(self._frames)

    def _decode(self, arch, address, opcode):
        if not self._disassemble:
            return "", ""
        instruction = next(self._decoder(arch).disasm_lite(opcode, address, count=1), None)
        return (instruction[2], instruction[3]) if instruction else ("", "")

    def _read_stack(self, address):
        if not self._stack_capture:
            return b""
        try:
            return bytes(self._mu.mem_read(address, self._stack_capture))
        except self._uc_error:
            # Preserve the readable prefix, even across adjacent memory mappings.
            result = bytearray()
            cursor = address
            for start, end, _permissions in sorted(self._mu.mem_regions()):
                if start <= cursor <= end:
                    count = min(end - cursor + 1, self._stack_capture - len(result))
                    try:
                        result.extend(self._mu.mem_read(cursor, count))
                    except self._uc_error:
                        break
                    cursor += count
                    if len(result) == self._stack_capture:
                        break
                elif start > cursor:
                    break
            return bytes(result)

    def _on_insn(self, mu, address, size, _user_data):
        if self.frame_count >= self._max_frames:
            self.truncated = True
            self.detach()
            return
        # Some invalid instructions report a sentinel size (e.g. 0xf1f1f1f1).
        if not 1 <= size <= 32:
            raise ValueError(f"Invalid instruction size {size} at {address:#x}")
        opcode = bytes(mu.mem_read(address, size))
        # Do not silently replace failed register reads with fictitious zeros.
        regs = {name: int(mu.reg_read(reg)) & UINT64_MASK for name, reg in self._reg_map}
        arch = self._arch
        if self._spec.family == "arm" and arch != ARCH.ARM_MCLASS:
            thumb = bool(regs["CPSR"] & (1 << 5))
            arch = (
                (ARCH.ARM16BE if thumb else ARCH.ARM32BE)
                if self._spec.endian == "big"
                else (ARCH.ARM16 if thumb else ARCH.ARM32)
            )
        sp = regs[self._spec.sp]
        # x86 real-mode stack addresses include the SS segment base.
        if arch == ARCH.X86_16:
            sp += regs["SS"] << 4
        # SPARC V9 uses a biased stack pointer under the 64-bit ABI.
        if arch == ARCH.SPARC64 and sp & 1:
            sp = (sp + 2047) & UINT64_MASK
        stack = self._read_stack(sp)
        buf = io.BytesIO()
        buf.write(struct.pack("<QH", address, len(opcode)))
        buf.write(opcode)
        buf.write(struct.pack("<H", len(regs)))
        for name, value in regs.items():
            encoded = name.encode("ascii")
            buf.write(struct.pack("<B", len(encoded)) + encoded + struct.pack("<Q", value))
        buf.write(struct.pack("<QI", sp, len(stack)))
        buf.write(stack)
        mnemonic, operands = (text.encode("utf-8") for text in self._decode(arch, address, opcode))
        extension = (
            struct.pack("<IHH", int(arch), len(mnemonic), len(operands)) + mnemonic + operands
        )
        frame = buf.getvalue()
        if self._payload_size + len(frame) + len(extension) > MAX_PAYLOAD_BYTES:
            self.truncated = True
            self.detach()
            return
        self._payload_size += len(frame) + len(extension)
        self._frames.append((frame, extension))

    def dump(self, *, version=VERSION, metadata=None):
        """Serialize current frames without changing attachment state."""
        if version not in (1, 2, 3):
            raise ValueError(f"Unsupported version: {version}")
        if metadata is not None and version != 3:
            raise ValueError("Trace metadata requires EMTR version 3")
        compressor = zlib.compressobj(level=6)
        chunks = [HDR_STRUCT.pack(MAGIC, version, int(self._arch), self.frame_count)]
        if version >= 2:
            chunks.append(compressor.compress(struct.pack("<I", int(self.truncated))))
        for frame, extension in self._frames:
            chunks.append(compressor.compress(frame))
            if version >= 2:
                chunks.append(compressor.compress(extension))
        if version == 3:
            encoded = _encode_metadata(metadata)
            if self._payload_size + 4 + len(encoded) > MAX_PAYLOAD_BYTES:
                raise ValueError("Trace and metadata exceed payload size limit")
            chunks.append(compressor.compress(struct.pack("<I", len(encoded)) + encoded))
        chunks.append(compressor.flush())
        return b"".join(chunks)

    def save(self, path, *, version=VERSION, metadata=None):
        Path(path).write_bytes(self.dump(version=version, metadata=metadata))


class _Cursor:
    def __init__(self, payload):
        self.data = payload
        self.offset = 0

    def take(self, size):
        end = self.offset + size
        if end > len(self.data):
            raise ValueError(f"Truncated frame at payload byte {self.offset}")
        result = self.data[self.offset : end]
        self.offset = end
        return result

    def unpack(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))

    def text(self, size, encoding="utf-8"):
        try:
            return self.take(size).decode(encoding)
        except UnicodeDecodeError as exc:
            raise ValueError(f"Invalid {encoding} text in trace") from exc


class TraceReader:
    """Bounded, strict v1-v3 reader. Failed loads retain the previous trace."""

    def __init__(self, *, max_payload_bytes=MAX_PAYLOAD_BYTES, max_frames=MAX_FRAMES):
        if max_payload_bytes < 0 or max_frames < 0:
            raise ValueError("Reader limits must be nonnegative")
        self.max_payload_bytes = max_payload_bytes
        self.max_frames = max_frames
        self.arch = ARCH.X86_64
        self.arch_name = ""
        self.version = VERSION
        self.n_frames = 0
        self.frames = []
        self.truncated = False
        self.metadata = {}

    def load(self, path):
        with open(path, "rb") as file:
            self.loads(file.read(self.max_payload_bytes + HDR_STRUCT.size + 1))
        return self

    def loads(self, data):
        if len(data) < HDR_STRUCT.size:
            raise ValueError("Truncated EMTR header (expected 16 bytes)")
        if len(data) > self.max_payload_bytes + HDR_STRUCT.size:
            raise ValueError("Compressed trace exceeds size limit")
        magic, version, arch_id, count = HDR_STRUCT.unpack_from(data)
        if magic != MAGIC:
            raise ValueError("Not an EMTR trace (bad magic)")
        if version not in (1, 2, 3):
            raise ValueError(f"Unsupported EMTR version: {version}")
        try:
            arch = ARCH(arch_id)
        except ValueError as exc:
            raise ValueError(f"Unknown architecture ID: {arch_id}") from exc
        if count > self.max_frames:
            raise ValueError("Trace exceeds frame limit")
        try:
            inflater = zlib.decompressobj()
            payload = inflater.decompress(data[HDR_STRUCT.size :], self.max_payload_bytes + 1)
        except zlib.error as exc:
            raise ValueError("Invalid compressed trace payload") from exc
        if len(payload) > self.max_payload_bytes or inflater.unconsumed_tail:
            raise ValueError("Trace exceeds decompression limit")
        if not inflater.eof or inflater.unused_data:
            raise ValueError("Truncated or trailing compressed data")
        cur = _Cursor(payload)
        flags = cur.unpack("<I")[0] if version >= 2 else 0
        if flags & ~1:
            raise ValueError("Unknown trace flags")
        frames = []
        for _ in range(count):
            address, size = cur.unpack("<QH")
            if not 1 <= size <= 32:
                raise ValueError("Invalid opcode length")
            opcode = cur.take(size)
            (n_regs,) = cur.unpack("<H")
            if n_regs > 512:
                raise ValueError("Too many registers")
            regs = {}
            for _ in range(n_regs):
                (name_len,) = cur.unpack("<B")
                name = cur.text(name_len, "ascii")
                if not name or not name.isidentifier() or name in regs:
                    raise ValueError("Invalid or duplicate register name")
                (regs[name],) = cur.unpack("<Q")
            sp, stack_size = cur.unpack("<QI")
            if stack_size > MAX_STACK_BYTES:
                raise ValueError("Stack snapshot exceeds limit")
            stack = cur.take(stack_size)
            frame = dict(address=address, opcode=opcode, regs=regs, sp=sp, stack=stack)
            if version >= 2:
                frame_arch, mnemonic_size, operands_size = cur.unpack("<IHH")
                if frame_arch not in ARCHITECTURES:
                    raise ValueError(f"Unknown frame architecture ID: {frame_arch}")
                frame.update(
                    arch=ARCH(frame_arch),
                    mnemonic=cur.text(mnemonic_size),
                    operands=cur.text(operands_size),
                )
            frames.append(frame)
        metadata = {}
        if version == 3:
            (metadata_size,) = cur.unpack("<I")
            if metadata_size > MAX_METADATA_BYTES:
                raise ValueError("Trace metadata exceeds size limit")
            try:
                metadata = json.loads(cur.text(metadata_size))
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid trace metadata JSON") from exc
            if not isinstance(metadata, dict):
                raise ValueError("Trace metadata must be an object")
        if cur.offset != len(payload):
            raise ValueError("Unexpected bytes after final frame")
        self.arch, self.arch_name, self.version = arch, ARCH_NAMES[arch], version
        self.n_frames, self.frames = count, frames
        self.truncated = bool(flags & 1)
        self.metadata = metadata
        return self

    def dump(self, *, version=3, metadata=None):
        """Serialize a loaded trace, optionally replacing its metadata."""
        if version not in (1, 2, 3):
            raise ValueError(f"Unsupported version: {version}")
        if metadata is not None and version != 3:
            raise ValueError("Trace metadata requires EMTR version 3")
        compressor = zlib.compressobj(level=6)
        chunks = [HDR_STRUCT.pack(MAGIC, version, int(self.arch), self.n_frames)]
        payload_size = 4 if version >= 2 else 0
        if version >= 2:
            chunks.append(compressor.compress(struct.pack("<I", int(self.truncated))))
        for frame in self.frames:
            base, extension = _encode_frame(frame, self.arch)
            chunks.append(compressor.compress(base))
            payload_size += len(base)
            if version >= 2:
                chunks.append(compressor.compress(extension))
                payload_size += len(extension)
        if version == 3:
            encoded = _encode_metadata(self.metadata if metadata is None else metadata)
            payload_size += 4 + len(encoded)
            if payload_size > self.max_payload_bytes:
                raise ValueError("Trace and metadata exceed payload size limit")
            chunks.append(compressor.compress(struct.pack("<I", len(encoded)) + encoded))
        chunks.append(compressor.flush())
        return b"".join(chunks)

    def save(self, path, *, version=3, metadata=None):
        Path(path).write_bytes(self.dump(version=version, metadata=metadata))


def _to_json(path):
    reader = TraceReader().load(path)
    # Hex strings preserve all 64 bits in JavaScript and other JSON consumers.
    return json.dumps(
        {
            "arch": reader.arch_name,
            "version": reader.version,
            "n_frames": reader.n_frames,
            "state_timing": "before instruction",
            "truncated": reader.truncated,
            "metadata": reader.metadata,
            "frames": [
                {
                    "address": hex(f["address"]),
                    "opcode": f["opcode"].hex(),
                    "regs": {k: hex(v) for k, v in f["regs"].items()},
                    "sp": hex(f["sp"]),
                    "stack": f["stack"].hex(),
                    **(
                        {
                            "arch": int(f["arch"]),
                            "mnemonic": f["mnemonic"],
                            "operands": f["operands"],
                        }
                        if "arch" in f
                        else {}
                    ),
                }
                for f in reader.frames
            ],
        },
        indent=2,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["dump"])
    parser.add_argument("path")
    args = parser.parse_args()
    try:
        print(_to_json(args.path))
    except (ValueError, OSError) as exc:
        parser.exit(1, f"emu_tracer: {exc}\n")
