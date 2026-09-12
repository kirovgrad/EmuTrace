import json
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest
import unicorn
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RSP

from architectures import ARCH
from emu_tracer import HDR_STRUCT, Tracer, TraceReader, _to_json

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("arch", list(ARCH))
def test_architecture_executes_and_decodes(arch):
    # Isolate native engine state and crashes between architecture families.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            f"""
from example_trace import make_trace
from emu_tracer import ARCH, TraceReader
tracer = make_trace(ARCH({int(arch)}))
reader = TraceReader().loads(tracer.dump())
assert reader.arch == ARCH({int(arch)})
assert reader.n_frames == (37 if ARCH({int(arch)}) == ARCH.X86_64 else 2)
assert all(f['mnemonic'] for f in reader.frames), reader.frames
assert all(f['stack'] for f in reader.frames)
assert reader.frames[0]['address'] == 0x10000
assert any(reader.frames[0]['regs'][k] != reader.frames[1]['regs'][k] for k in reader.frames[0]['regs'])
""",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def engine(code=b"\x48\xff\xc0\x90"):
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    mu.mem_map(0x1000, 0x1000)
    mu.mem_map(0x8000, 0x1000)
    mu.mem_write(0x1000, code)
    mu.reg_write(UC_X86_REG_RSP, 0x8800)
    return mu


def test_snapshot_timing_full_precision_and_hook_lifecycle():
    mu = engine()
    mu.reg_write(UC_X86_REG_RAX, 0xFFFFFFFFFFFFFFF0)
    tracer = Tracer(mu)
    with tracer:
        tracer.attach()  # Must not install a second hook.
        mu.emu_start(0x1000, 0x1004)
        first = TraceReader().loads(tracer.dump())
        mu.emu_start(0x1003, 0x1004)
    assert first.n_frames == 2
    assert first.frames[0]["regs"]["RAX"] == 0xFFFFFFFFFFFFFFF0
    assert first.frames[1]["regs"]["RAX"] == 0xFFFFFFFFFFFFFFF1
    assert tracer.frame_count == 3  # dump did not detach.
    mu.emu_start(0x1003, 0x1004)
    assert tracer.frame_count == 3
    tracer.detach()
    tracer.clear()
    assert tracer.frame_count == 0


def test_context_detaches_on_error():
    mu = engine()
    tracer = Tracer(mu)
    with pytest.raises(RuntimeError):
        with tracer:
            raise RuntimeError("test")
    mu.emu_start(0x1000, 0x1004)
    assert tracer.frame_count == 0


def test_stack_boundary_and_disabled_capture():
    mu = engine()
    mu.reg_write(UC_X86_REG_RSP, 0x8FFB)
    mu.mem_write(0x8FFB, b"hello")
    with Tracer(mu) as tracer:
        mu.emu_start(0x1000, 0x1004)
    assert TraceReader().loads(tracer.dump()).frames[0]["stack"] == b"hello"
    with Tracer(mu, stack_capture=0) as tracer:
        mu.emu_start(0x1000, 0x1004)
    assert TraceReader().loads(tracer.dump()).frames[0]["stack"] == b""


def test_stack_unmapped_and_capture_limit():
    mu = engine()
    mu.reg_write(UC_X86_REG_RSP, 0xFF000)
    with Tracer(mu, max_frames=1) as tracer:
        mu.emu_start(0x1000, 0x1004)
    assert tracer.frame_count == 1 and tracer.truncated
    assert TraceReader().loads(tracer.dump()).truncated
    assert TraceReader().loads(tracer.dump()).frames[0]["stack"] == b""
    assert mu.reg_read(UC_X86_REG_RAX) == 1  # Emulation continues at the limit.


def test_real_mode_stack_uses_segment_base():
    from unicorn.x86_const import UC_X86_REG_SP, UC_X86_REG_SS

    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_16)
    mu.mem_map(0x1000, 0x1000)
    mu.mem_map(0x8000, 0x1000)
    mu.mem_write(0x1000, b"\x90")
    mu.mem_write(0x8100, b"test")
    mu.reg_write(UC_X86_REG_SS, 0x800)
    mu.reg_write(UC_X86_REG_SP, 0x100)
    with Tracer(mu, stack_capture=4) as tracer:
        mu.emu_start(0x1000, 0x1001)
    frame = TraceReader().loads(tracer.dump()).frames[0]
    assert frame["regs"]["SP"] == 0x100
    assert frame["sp"] == 0x8100 and frame["stack"] == b"test"


def test_arm_thumb_interworking():
    from unicorn.arm_const import UC_ARM_REG_R0

    mu = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    mu.mem_map(0x1000, 0x1000)
    mu.mem_write(0x1000, bytes.fromhex("10ff2fe100000000012100bf"))
    mu.reg_write(UC_ARM_REG_R0, 0x1009)
    with Tracer(mu) as tracer:
        mu.emu_start(0x1000, 0x100C, count=3)
    frames = TraceReader().loads(tracer.dump()).frames
    assert [f["arch"] for f in frames] == [ARCH.ARM32, ARCH.ARM16, ARCH.ARM16]
    assert [f["mnemonic"] for f in frames] == ["bx", "movs", "nop"]


@pytest.mark.parametrize(
    "kwargs",
    [{"stack_capture": -1}, {"stack_capture": 1.5}, {"max_frames": 0}, {"arch": ARCH.RISCV64}],
)
def test_reject_bad_configuration(kwargs):
    with pytest.raises(ValueError):
        Tracer(engine(), **kwargs)


def frame_payload():
    return (
        struct.pack("<QH", 0xFFFFFFFFFFFFFFFF, 1)
        + b"\x90"
        + struct.pack("<H", 1)
        + b"\x03RAX"
        + struct.pack("<Q", 0xFEDCBA9876543210)
        + struct.pack("<QI", 0x8800, 3)
        + b"abc"
    )


def file_bytes(payload=None, count=1, version=1, arch=4, metadata=None):
    body = (b"\0" * 4 if version >= 2 else b"") + (frame_payload() if payload is None else payload)
    if version == 3:
        encoded = json.dumps({} if metadata is None else metadata).encode()
        body += struct.pack("<I", len(encoded)) + encoded
    return HDR_STRUCT.pack(b"EMTR", version, arch, count) + zlib.compress(body)


def test_legacy_roundtrip_and_json_precision(tmp_path):
    reader = TraceReader().loads(file_bytes())
    assert reader.frames[0]["regs"]["RAX"] == 0xFEDCBA9876543210
    path = tmp_path / "precise.emtr"
    path.write_bytes(file_bytes())
    assert json.loads(_to_json(path))["frames"][0]["address"] == "0xffffffffffffffff"
    mu = engine()
    with Tracer(mu, disassemble=False) as tracer:
        mu.emu_start(0x1000, 0x1004)
    assert TraceReader().loads(tracer.dump(version=1)).version == 1
    assert TraceReader().loads(tracer.dump()).frames[0]["mnemonic"] == ""


def test_v3_metadata_and_reader_reserialization():
    metadata = {"decompilation": {"version": 1, "functions": [{"name": "main"}]}}
    reader = TraceReader().loads(
        file_bytes(
            payload=frame_payload() + struct.pack("<IHH", int(ARCH.X86_64), 0, 0),
            version=3,
            metadata=metadata,
        )
    )
    assert reader.version == 3 and reader.metadata == metadata
    copy = TraceReader().loads(reader.dump())
    assert copy.metadata == metadata
    assert copy.frames == reader.frames
    with pytest.raises(ValueError, match="metadata requires"):
        reader.dump(version=2, metadata=metadata)
    with pytest.raises(ValueError, match="JSON serializable"):
        reader.dump(metadata={"bad": object()})

    mu = engine()
    with Tracer(mu) as tracer:
        mu.emu_start(0x1000, 0x1004)
    captured = TraceReader().loads(tracer.dump(version=3, metadata=metadata))
    assert captured.n_frames == 2 and captured.metadata == metadata


@pytest.mark.parametrize("path", list((ROOT / "examples").glob("*.emtr")))
def test_existing_traces(path):
    reader = TraceReader().load(path)
    assert reader.n_frames == len(reader.frames) > 0


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"EMTR",
        file_bytes()[:-1],
        file_bytes() + b"junk",
        file_bytes(version=8),
        file_bytes(arch=999),
        file_bytes(count=2),
        file_bytes(payload=frame_payload()[:-1]),
        file_bytes(payload=frame_payload() + b"x"),
        file_bytes(payload=struct.pack("<QH", 0, 500)),
        file_bytes(payload=struct.pack("<QH", 0, 1) + b"\x90" + struct.pack("<H", 513)),
        file_bytes(payload=frame_payload() + struct.pack("<IHH", 999, 0, 0), version=2),
    ],
)
def test_malformed_files_fail_atomically(data):
    reader = TraceReader().loads(file_bytes())
    old_frames = reader.frames
    old_metadata = reader.metadata
    with pytest.raises(ValueError):
        reader.loads(data)
    assert reader.frames is old_frames and reader.metadata is old_metadata and reader.n_frames == 1


def test_decompression_and_frame_limits():
    with pytest.raises(ValueError, match="decompression limit"):
        TraceReader(max_payload_bytes=1000).loads(file_bytes(payload=b"\0" * 100000))
    with pytest.raises(ValueError, match="frame limit"):
        TraceReader(max_frames=0).loads(file_bytes())
    assert TraceReader().loads(file_bytes(payload=b"", count=0)).frames == []


def test_browser_registry_is_current():
    from scripts.build_architectures import render

    assert (ROOT / "emu_architectures.js").read_text() == render()
