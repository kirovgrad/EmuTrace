"""Generate runnable traces: python example_trace.py --help."""

import argparse
from pathlib import Path

import unicorn

from architectures import ARCH, ARCHITECTURES
from emu_tracer import Tracer

# Small, side-effect-free programs for each supported configuration.
SAMPLES = {
    ARCH.ARM16: bytes.fromhex("01200230"),  # movs r0,1; adds r0,2
    ARCH.ARM32: bytes.fromhex("0100a0e3020080e2"),  # mov r0,1; add r0,r0,2
    ARCH.ARM64: bytes.fromhex("200080d200080091"),  # mov x0,1; add x0,x0,2
    ARCH.X86: bytes.fromhex("b80100000083c002"),  # mov eax,1; add eax,2
    ARCH.X86_64: bytes.fromhex("48c7c00000000048c7c1080000004801c85048ffc975f7488b1c244883c44090"),
    ARCH.MIPS: bytes.fromhex("2402000124420002"),
    ARCH.MIPSEL: bytes.fromhex("0100022402004224"),
    ARCH.MIPS64: bytes.fromhex("6402000164420002"),
    ARCH.MIPS64EL: bytes.fromhex("0100026402004264"),
    ARCH.X86_16: bytes.fromhex("b8010083c002"),
    ARCH.PPC: bytes.fromhex("3860000138630002"),
    ARCH.PPC64: bytes.fromhex("3860000138630002"),
    ARCH.SPARC: bytes.fromhex("8200200182006002"),
    ARCH.SPARC64: bytes.fromhex("8200200182006002"),
    ARCH.M68K: bytes.fromhex("70015280"),  # moveq #1,d0; addq.l #1,d0
    ARCH.RISCV32: bytes.fromhex("9300100093802000"),
    ARCH.RISCV64: bytes.fromhex("9300100093802000"),
    ARCH.S390X: bytes.fromhex("a7090001a70b0002"),  # lghi r0,1; aghi r0,2
    ARCH.TRICORE: bytes.fromhex("82118222"),  # mov d1,1; mov d2,2
    ARCH.ARM16BE: bytes.fromhex("20013002"),
    ARCH.ARM32BE: bytes.fromhex("e3a00001e2800002"),
    ARCH.ARM64BE: bytes.fromhex("200080d200080091"),
    ARCH.ARM_MCLASS: bytes.fromhex("01200230"),
}


def make_trace(arch=ARCH.X86_64):
    spec = ARCHITECTURES[arch]
    mu = unicorn.Uc(*spec.unicorn_config())
    if arch == ARCH.PPC64:
        # Unicorn 2.1 needs an explicit model to initialize PPC64 correctly.
        from unicorn.ppc_const import UC_CPU_PPC64_POWER9_V2_0

        mu.ctl_set_cpu_model(UC_CPU_PPC64_POWER9_V2_0)
    base = 0x10000
    stack = 0x80000
    mu.mem_map(base, 0x10000)
    mu.mem_map(stack, 0x10000)
    code = SAMPLES[arch]
    mu.mem_write(base, code)
    registers = dict(spec.registers())
    if arch == ARCH.X86_16:
        from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_SS

        mu.reg_write(UC_X86_REG_CS, base >> 4)
        mu.reg_write(UC_X86_REG_SS, stack >> 4)
        mu.reg_write(registers[spec.sp], 0x1000)
    else:
        mu.reg_write(registers[spec.sp], stack + 0x1000)
    # Deterministic initial memory makes changed stack bytes easy to inspect.
    mu.mem_write(stack + 0xF80, b"EmuTrace stack snapshot\0".ljust(256, b"\0"))
    start = base | (1 if "THUMB" in spec.uc_modes else 0)
    with Tracer(mu, arch, max_frames=1000) as tracer:
        # Unicorn 2.1.4 repeats SPARC64's second PC with code hooks. Bound
        # this two-instruction smoke example; never alter emulator state.
        count = 2 if arch == ARCH.SPARC64 else 1000
        mu.emu_start(start, base + len(code), count=count)
    return tracer


def main():
    aliases = {"arm": "arm32", "mips": "mipsel", "mipsbe": "mips", "riscv": "riscv64"}
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "architecture",
        nargs="?",
        default="x86_64",
        help="ARCH enum name, e.g. riscv64, ppc, s390x, tricore",
    )
    parser.add_argument("--all", action="store_true", help="Generate every architecture example")
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    args = parser.parse_args()
    name = aliases.get(args.architecture.lower(), args.architecture.lower()).upper()
    if name not in ARCH.__members__:
        parser.error("Unknown architecture. Choose: " + ", ".join(a.name.lower() for a in ARCH))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for arch in ARCH if args.all else [ARCH[name]]:
        tracer = make_trace(arch)
        path = args.output_dir / f"trace_{arch.name.lower()}.emtr"
        tracer.save(path)
        print(f"{ARCHITECTURES[arch].name}: {tracer.frame_count} frames → {path}")


if __name__ == "__main__":
    main()
