from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

from state_collector import hook_code

uc = Uc(UC_ARCH_X86, UC_MODE_32)

base_addr = 0x1000000
instr = b"\xB8\x0A\x00\x00\x00\x40"

uc.mem_map(base_addr, 0x1000)
uc.mem_write(base_addr, instr)

uc.hook_add(UC_HOOK_CODE, hook_code)

for begin, end, perms in uc.mem_regions():
	print(f"Begin: {hex(begin)}, End: {hex(end)}, Perms: {perms}")

uc.emu_start(base_addr, base_addr + len(instr))
