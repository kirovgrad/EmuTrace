"""Architecture registry. Wire IDs 0–8 are retained for legacy EMTR files.

Only scalar integer and status registers are captured; SIMD/FPU state is not
part of the trace format. Run scripts/build_architectures.py after editing.
"""

from dataclasses import dataclass
from enum import IntEnum
from importlib import import_module


class ARCH(IntEnum):
    ARM16 = 0
    ARM32 = 1
    ARM64 = 2
    X86 = 3
    X86_64 = 4
    MIPS = 5
    MIPSEL = 6
    MIPS64 = 7
    MIPS64EL = 8
    X86_16 = 9
    PPC = 10
    PPC64 = 11
    SPARC = 12
    SPARC64 = 13
    M68K = 14
    RISCV32 = 15
    RISCV64 = 16
    S390X = 17
    TRICORE = 18
    ARM16BE = 19
    ARM32BE = 20
    ARM64BE = 21
    ARM_MCLASS = 22


@dataclass(frozen=True)
class Architecture:
    name: str
    bits: int
    endian: str
    family: str
    uc_modes: tuple
    cs_arch: str
    cs_modes: tuple
    sp: str
    pc: str = "PC"
    flags: str = ""

    def unicorn_config(self):
        import unicorn

        return getattr(unicorn, "UC_ARCH_" + self.family.upper()), _mode(
            unicorn, "UC_MODE_", self.uc_modes
        )

    def capstone_config(self):
        import capstone

        return getattr(capstone, "CS_ARCH_" + self.cs_arch), _mode(
            capstone, "CS_MODE_", self.cs_modes
        )

    def registers(self):
        module = import_module("unicorn." + self.family + "_const")
        prefix = "UC_" + self.family.upper() + "_REG_"
        groups = {
            "arm": [*(f"R{i}" for i in range(13)), "SP", "LR", "PC", "CPSR"],
            "arm64": [*(f"X{i}" for i in range(31)), "SP", "PC", "NZCV"],
            "mips": [*(str(i) for i in range(32)), "PC", "HI", "LO"],
            "ppc": [*(str(i) for i in range(32)), "PC", "LR", "CTR", "CR", "XER", "MSR"],
            "sparc": [*(f"{bank}{i}" for bank in "GOLI" for i in range(8)), "PC"],
            "m68k": [*(f"D{i}" for i in range(8)), *(f"A{i}" for i in range(8)), "PC", "SR"],
            "riscv": [*(f"X{i}" for i in range(32)), "PC"],
            "s390x": [*(f"R{i}" for i in range(16)), "PC", "PSWM"],
            "tricore": [*(f"D{i}" for i in range(16)), *(f"A{i}" for i in range(16)), "PC", "PSW"],
        }
        if self.family == "x86":
            general = ["AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP", "IP"]
            names = [
                ("R" if self.bits == 64 else "E" if self.bits == 32 else "") + n for n in general
            ]
            if self.bits == 64:
                names += [f"R{i}" for i in range(8, 16)]
            names += ["EFLAGS", "CS", "DS", "ES", "FS", "GS", "SS"]
        else:
            names = groups[self.family]
            if "MCLASS" in self.uc_modes:
                names = ["XPSR" if name == "CPSR" else name for name in names]
        result = []
        mips_aliases = "zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 k0 k1 gp sp fp ra".split()
        for name in names:
            label = name
            if self.family == "mips" and name.isdigit():
                label = mips_aliases[int(name)]
            elif self.family == "ppc" and name.isdigit():
                label = "R" + name
            result.append((label, getattr(module, prefix + name)))
        return result


def _mode(module, prefix, names):
    result = 0
    for name in names:
        result |= getattr(module, prefix + name)
    return result


def _spec(name, bits, family, uc, cs, sp, pc="PC", flags="", be=False, cs_arch=None):
    endian = ("BIG_ENDIAN",) if be else ()
    return Architecture(
        name,
        bits,
        "big" if be else "little",
        family,
        tuple(uc) + endian,
        cs_arch or family.upper(),
        tuple(cs) + endian,
        sp,
        pc,
        flags,
    )


ARCHITECTURES = {
    ARCH.ARM16: _spec("Thumb", 32, "arm", ["THUMB"], ["THUMB"], "SP", flags="CPSR"),
    ARCH.ARM32: _spec("ARM32", 32, "arm", ["ARM"], ["ARM"], "SP", flags="CPSR"),
    ARCH.ARM64: _spec("AArch64", 64, "arm64", [], [], "SP", flags="NZCV"),
    ARCH.X86: _spec("x86", 32, "x86", ["32"], ["32"], "ESP", "EIP", "EFLAGS"),
    ARCH.X86_64: _spec("x86-64", 64, "x86", ["64"], ["64"], "RSP", "RIP", "EFLAGS"),
    ARCH.MIPS: _spec("MIPS32 · BE", 32, "mips", ["MIPS32"], ["MIPS32"], "sp", be=True),
    ARCH.MIPSEL: _spec("MIPS32 · LE", 32, "mips", ["MIPS32"], ["MIPS32"], "sp"),
    ARCH.MIPS64: _spec("MIPS64 · BE", 64, "mips", ["MIPS64"], ["MIPS64"], "sp", be=True),
    ARCH.MIPS64EL: _spec("MIPS64 · LE", 64, "mips", ["MIPS64"], ["MIPS64"], "sp"),
    ARCH.X86_16: _spec("x86 · 16-bit", 16, "x86", ["16"], ["16"], "SP", "IP", "EFLAGS"),
    ARCH.PPC: _spec("PowerPC32", 32, "ppc", ["PPC32"], ["32"], "R1", flags="CR", be=True),
    ARCH.PPC64: _spec("PowerPC64", 64, "ppc", ["PPC64"], ["64"], "R1", flags="CR", be=True),
    ARCH.SPARC: _spec("SPARC32", 32, "sparc", ["SPARC32"], [], "O6", be=True),
    ARCH.SPARC64: _spec("SPARC64", 64, "sparc", ["SPARC64"], ["V9"], "O6", be=True),
    ARCH.M68K: _spec("Motorola 68000", 32, "m68k", [], ["M68K_000"], "A7", flags="SR", be=True),
    ARCH.RISCV32: _spec("RISC-V32", 32, "riscv", ["RISCV32"], ["RISCV32", "RISCVC"], "X2"),
    ARCH.RISCV64: _spec("RISC-V64", 64, "riscv", ["RISCV64"], ["RISCV64", "RISCVC"], "X2"),
    ARCH.S390X: _spec(
        "S390X / SystemZ", 64, "s390x", [], [], "R15", flags="PSWM", be=True, cs_arch="SYSZ"
    ),
    ARCH.TRICORE: _spec("TriCore", 32, "tricore", [], ["TRICORE_162"], "A10", flags="PSW"),
    ARCH.ARM16BE: _spec("Thumb · BE", 32, "arm", ["THUMB"], ["THUMB"], "SP", flags="CPSR", be=True),
    ARCH.ARM32BE: _spec("ARM32 · BE", 32, "arm", ["ARM"], ["ARM"], "SP", flags="CPSR", be=True),
    # AArch64 instructions are always little endian; data can be big endian.
    ARCH.ARM64BE: _spec("AArch64 · BE", 64, "arm64", [], [], "SP", flags="NZCV", be=True),
    ARCH.ARM_MCLASS: _spec(
        "ARM Cortex-M", 32, "arm", ["THUMB", "MCLASS"], ["THUMB", "MCLASS"], "SP", flags="XPSR"
    ),
}
ARCH_NAMES = {arch: spec.name for arch, spec in ARCHITECTURES.items()}
SP_REG = {arch: spec.sp for arch, spec in ARCHITECTURES.items()}


def detect_arch(mu):
    """Resolve the initial engine mode; never guess an incompatible target."""
    import unicorn

    uc_arch, mode = mu.query(unicorn.UC_QUERY_ARCH), mu.query(unicorn.UC_QUERY_MODE)
    if uc_arch == unicorn.UC_ARCH_ARM and mode & unicorn.UC_MODE_MCLASS:
        mode |= unicorn.UC_MODE_THUMB
    # ARM's query reports the current Thumb state, not only constructor flags.
    for arch, spec in ARCHITECTURES.items():
        candidate, expected = spec.unicorn_config()
        if candidate == uc_arch and mode == expected:
            return arch
    raise ValueError(
        f"Unsupported Unicorn architecture/mode: {uc_arch}/{mode:#x}; pass a supported engine mode"
    )
