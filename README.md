# EmuTrace

[![CI](https://github.com/kirovgrad/EmuTrace/actions/workflows/ci.yml/badge.svg)](https://github.com/kirovgrad/EmuTrace/actions/workflows/ci.yml)

EmuTrace records instructions executed by [Unicorn](https://www.unicorn-engine.org/) and lets you inspect the trace in a local web viewer. Step through execution, compare registers and stack memory, explore a control-flow graph, and view optional angr pseudocode without uploading the trace.

![EmuTrace execution inspector](examples/EmuTraceUI.png)

## Install

Clone the repository and install the tracing dependencies. EmuTrace requires Python 3.9 or newer.

```bash
git clone https://github.com/kirovgrad/EmuTrace.git
cd EmuTrace
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

The viewer has no build step or server. Open `emu_viewer.html` in a current Safari, Chrome, Edge, or Firefox.

Decompilation is optional and requires Python 3.12 or newer. Install it in a separate environment because angr has a larger dependency set:

```bash
python3.12 -m venv .venv-angr
source .venv-angr/bin/activate
python3 -m pip install -r requirements-decompiler.txt
```

## Use

Generate the included x86-64 example:

```bash
python3 example_trace.py
```

Open `emu_viewer.html`, then select `trace_x86_64.emtr` with **Open trace** or drag it onto the page. The viewer also has an **Explore an example** option.

To record your own Unicorn session, wrap emulation with `Tracer`:

```python
import unicorn
from unicorn.x86_const import UC_X86_REG_RSP

from emu_tracer import Tracer

mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
mu.mem_map(0x400000, 0x1000)
mu.mem_map(0x700000, 0x1000)
mu.mem_write(0x400000, b"\x48\xff\xc0\x90")  # inc rax; nop
mu.reg_write(UC_X86_REG_RSP, 0x700800)

with Tracer(mu) as tracer:
    mu.emu_start(0x400000, 0x400004)

tracer.save("my_trace.emtr")
```

`Tracer` detects the Unicorn architecture and records instruction bytes, registers, and a stack snapshot before each instruction. Use `stack_capture=0` to omit the stack or `max_frames=N` to bound long traces.

To attach angr decompilation results, process the trace and open the generated file:

```bash
python3 emu_decompiler.py my_trace.emtr
```

Supplying the executable that Unicorn ran usually produces better pseudocode and control-flow recovery:

```bash
python3 emu_decompiler.py my_trace.emtr ./program
```

Run `python3 emu_decompiler.py --help` for raw binary, load-address, output, and overwrite options.

## Features

- Compact disassembly with opcode, mnemonic, operand, and address search.
- Per-instruction register and stack snapshots with changed values highlighted.
- Trace-based control-flow graphs with basic blocks, conditional edges, execution counts, and call navigation.
- Optional current-function pseudocode generated locally by angr.
- Frame breakpoints, playback controls, keyboard navigation, and JSON frame export.
- Light and dark themes, responsive panels, and virtualized rows for large traces.
- Local file processing with no server, account, CDN, or upload.

EmuTrace records all architecture families shared by Unicorn and Capstone 5:

- x86: 16, 32, and 64 bit
- ARM: Thumb, ARM32, Cortex-M, and AArch64, including supported big-endian modes
- MIPS: 32 and 64 bit, little and big endian
- PowerPC 32/64, SPARC 32/64, M68K, RISC-V 32/64, SystemZ, and TriCore

angr supports decompilation for a smaller subset. Architectures without an angr lifter remain available in the Disassembly and CFG views.

## How it works

`Tracer` installs a Unicorn code hook and writes each instruction-entry state to a compressed `.emtr` file. A frame contains the address, opcode, decoded instruction, integer registers, and captured stack bytes. Values are preserved as unsigned 64-bit integers, and stack words are displayed using the emulated architecture's byte order.

The browser reads the file locally and derives register changes, stack changes, playback indexes, and the partial CFG. Because a frame is captured before its instruction executes, its highlighted changes describe the state difference from the preceding frame. The final instruction's resulting state is outside the trace unless another instruction is recorded afterward.

The CFG is based on executed instructions and inferred branch targets, so it represents the captured run rather than every possible path. Decompilation is produced separately by `emu_decompiler.py` and embedded into an EMTR v3 file for the viewer.

## Shortcuts

| Shortcut                                   | Action                |
| ------------------------------------------ | --------------------- |
| `→` / `n`, `←` / `p`                       | Next / previous frame |
| `Space`                                    | Play / pause          |
| `Home` / `End`                             | First / last frame    |
| `b` / `F2`, double-click a disassembly row | Toggle breakpoint     |
| `/`                                        | Focus search          |
| `Enter` / `Shift+Enter` in search          | Next / previous match |
