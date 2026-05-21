# EmuTrace

A binary trace viewer for [Unicorn Engine](https://www.unicorn-engine.org/) emulation sessions.

Trace every executed instruction together with CPU register state and a snapshot of the stack, then visualise the result in a browser-based disassembly viewer.

## Components

| File | Description |
|------|-------------|
| `emu_tracer.py` | Python library – attaches to a Unicorn emulator and records execution traces |
| `emu_viewer.html` | Standalone HTML viewer – open it directly in a browser, no server needed |
| `example_trace.py` | Ready-to-run examples for x86-64, ARM32, and MIPS |

## Supported Architectures

- ARM16 (Thumb)
- ARM32
- ARM64 (AArch64)
- x86
- x86-64 (AMD64)
- MIPS32 (Big/Little Endian)
- MIPS64 (Big/Little Endian)

## File Format (.emtr)

The tracer outputs a compact binary format:

```
Header (16 bytes, uncompressed)
  magic     – "EMTR" 
  version   – 1
  arch_id   – architecture selector
  n_frames  – total instruction count

Payload (zlib-compressed)
  Per-frame:
    address     (uint64)
    opcode_len  (uint16)
    opcode      (bytes[opcode_len])
    registers   (name/value pairs)
    sp_value    (uint64)
    stack_bytes (raw memory from SP)
```

## Quick Start

### 1. Install dependencies

```bash
pip install unicorn capstone
```

### 2. Generate a trace

```bash
python example_trace.py         # x86-64 trace → trace_x86_64.emtr
python example_trace.py arm     # ARM32 trace  → trace_arm32.emtr
python example_trace.py mips    # MIPS LE trace → trace_mipsel.emtr
```

### 3. View the trace

Open `emu_viewer.html` in your browser and drag-and-drop the `.emtr` file onto the window.

## Usage Example

```python
import unicorn
from unicorn.x86_const import *
from emu_tracer import Tracer, ARCH

# Create and configure a Unicorn emulator
mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

BASE  = 0x400000
STACK = 0x700000
mu.mem_map(BASE,  0x100000)
mu.mem_map(STACK, 0x100000)

# Write some code to trace
code = b"\x48\xC7\xC0\x00\x00\x00\x00"     # mov rax, 0
     + b"\x48\xFF\xC0"                     # inc rax
     + b"\x90"                             # nop
mu.mem_write(BASE, code)
mu.reg_write(UC_X86_REG_RSP, STACK + 0x8000)

# Attach tracer and run
tracer = Tracer(mu, ARCH.X86_64)
tracer.attach()
mu.emu_start(BASE, BASE + len(code))
tracer.detach()

# Save or use the trace
tracer.save("my_trace.emtr")
# or: data = tracer.dump()  # returns bytes
```

## Emu_viewer Features

- **Disassembly panel** – instruction address, opcode bytes, mnemonic, operands
- **Registers panel** – all CPU registers with change highlighting
- **Stack panel** – hex dump with ASCII representation
- **Playback controls** – step forward/back, play/pause, keyboard shortcuts
- **Breakpoints** – double-click a row or press `b` to toggle
- **Search** – filter by address, mnemonic, or operand
- **Drag & drop** – drop a `.emtr` file anywhere on the window
- **Capstone disassembly** – if `capstone.min.js` is present, instructions are decoded; otherwise raw bytes are shown

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `→` / `n`   | Next frame |
| `←` / `p`   | Previous frame |
| `Space`     | Play / Pause |
| `Home`      | First frame |
| `End`       | Last frame |
| `b` / `F2`  | Toggle breakpoint |
| `Enter`     | Find / find next |