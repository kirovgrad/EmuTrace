"""
example_trace.py  –  Example usage of emu_tracer.py
=====================================================
Traces a tiny x86-64 snippet and saves a .emtr file
ready to be loaded into emu_viewer.html.

Requirements
------------
  pip install unicorn capstone

Run
---
  python example_trace.py                # produces trace_x86_64.emtr
  python example_trace.py arm            # produces trace_arm32.emtr
  python example_trace.py mips           # produces trace_mips.emtr
"""

import sys
import struct

# ── unicorn ──────────────────────────────────────────────────────────────────
try:
    import unicorn
    from unicorn import *
    from unicorn.x86_const import *
    from unicorn.arm_const import *
    from unicorn.mips_const import *
except ImportError:
    print("ERROR: unicorn-engine not installed.  Run:  pip install unicorn")
    sys.exit(1)

from emu_tracer import Tracer, ARCH

# ════════════════════════════════════════════════════════════════════════════
#  Example 1 – x86-64
# ════════════════════════════════════════════════════════════════════════════

def trace_x86_64():
    """
    Simple loop:
        mov rax, 0
        mov rcx, 5
    loop:
        inc rax
        dec rcx
        jnz loop
        nop
    """
    CODE = (
        b"\x48\xC7\xC0\x00\x00\x00\x00"   # mov rax, 0
        b"\x48\xC7\xC1\x05\x00\x00\x00"   # mov rcx, 5
        b"\x48\xFF\xC0"                     # inc rax
        b"\x48\xFF\xC9"                     # dec rcx
        b"\x75\xF8"                         # jnz -8  (back to inc rax)
        b"\x90"                             # nop
    )

    BASE  = 0x400000
    STACK = 0x700000
    SIZE  = 0x100000

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(BASE,  SIZE)
    mu.mem_map(STACK, SIZE)
    mu.mem_write(BASE, CODE)
    mu.reg_write(UC_X86_REG_RSP, STACK + 0x8000)
    mu.reg_write(UC_X86_REG_RBP, STACK + 0x8000)

    tracer = Tracer(mu, ARCH.X86_64)
    tracer.attach()
    mu.emu_start(BASE, BASE + len(CODE))
    tracer.detach()

    out = "trace_x86_64.emtr"
    tracer.save(out)
    print(f"[x86-64]  {tracer.frame_count} frames  →  {out}")


# ════════════════════════════════════════════════════════════════════════════
#  Example 2 – ARM32
# ════════════════════════════════════════════════════════════════════════════

def trace_arm32():
    """
    mov r0, #0
    mov r1, #5
  loop:
    add r0, r0, #1
    sub r1, r1, #1
    cmp r1, #0
    bne loop
    nop
    """
    CODE = (
        b"\x00\x00\xa0\xe3"   # mov r0, #0
        b"\x05\x10\xa0\xe3"   # mov r1, #5
        b"\x01\x00\x80\xe2"   # add r0, r0, #1
        b"\x01\x10\x41\xe2"   # sub r1, r1, #1
        b"\x00\x00\x51\xe3"   # cmp r1, #0
        b"\xfb\xff\xff\x1a"   # bne -5  (back to add)
        b"\x00\x00\xa0\xe1"   # nop (mov r0, r0)
    )

    BASE  = 0x10000
    STACK = 0x80000
    SIZE  = 0x10000

    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    mu.mem_map(BASE,  SIZE)
    mu.mem_map(STACK, SIZE)
    mu.mem_write(BASE, CODE)
    mu.reg_write(UC_ARM_REG_SP, STACK + 0x8000)

    tracer = Tracer(mu, ARCH.ARM32)
    tracer.attach()
    mu.emu_start(BASE, BASE + len(CODE))
    tracer.detach()

    out = "trace_arm32.emtr"
    tracer.save(out)
    print(f"[ARM32]   {tracer.frame_count} frames  →  {out}")


# ════════════════════════════════════════════════════════════════════════════
#  Example 3 – MIPS32 LE
# ════════════════════════════════════════════════════════════════════════════

def trace_mips():
    """
    addiu $v0, $zero, 0
    addiu $t0, $zero, 5
  loop:
    addiu $v0, $v0, 1
    addiu $t0, $t0, -1
    bne   $t0, $zero, loop
    nop   (delay slot)
    nop
    """
    CODE = (
        b"\x00\x00\x02\x24"   # addiu v0, zero, 0
        b"\x05\x00\x08\x24"   # addiu t0, zero, 5
        b"\x01\x00\x42\x24"   # addiu v0, v0, 1
        b"\xff\xff\x08\x25"   # addiu t0, t0, -1
        b"\xfd\xff\x08\x15"   # bne t0, zero, -3
        b"\x00\x00\x00\x00"   # nop (delay slot)
        b"\x00\x00\x00\x00"   # nop
    )

    BASE  = 0x10000
    STACK = 0x80000
    SIZE  = 0x10000

    mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN)
    mu.mem_map(BASE,  SIZE)
    mu.mem_map(STACK, SIZE)
    mu.mem_write(BASE, CODE)
    mu.reg_write(UC_MIPS_REG_29, STACK + 0x8000)  # $sp

    tracer = Tracer(mu, ARCH.MIPSEL)
    tracer.attach()
    mu.emu_start(BASE, BASE + len(CODE))
    tracer.detach()

    out = "trace_mipsel.emtr"
    tracer.save(out)
    print(f"[MIPSEL]  {tracer.frame_count} frames  →  {out}")


# ════════════════════════════════════════════════════════════════════════════
#  Entry
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    arg = sys.argv[1].lower() if len(sys.argv) > 1 else "x86_64"
    if arg in ("arm", "arm32"):
        trace_arm32()
    elif arg in ("mips", "mipsel"):
        trace_mips()
    else:
        trace_x86_64()
    print("\nOpen emu_viewer.html in your browser and drag-drop the .emtr file.")
