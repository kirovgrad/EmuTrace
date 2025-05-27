from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

import capstone

import pickle

global collector
global x86_64_reg_list
global x86_reg_list
global arm32_reg_list
global arm64_reg_list

x86_64_reg_list = [
			UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
			UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
			UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
			UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
			UC_X86_REG_RIP, UC_X86_REG_EFLAGS, UC_X86_REG_CS, UC_X86_REG_DS,
			UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_SS
		]

x86_reg_list = [
			UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, 
			UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_ESP, UC_X86_REG_EBP, 
			UC_X86_REG_EIP, UC_X86_REG_EFLAGS, UC_X86_REG_CS, UC_X86_REG_DS,
			UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_SS
		]

arm32_reg_list = [
			UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
			UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
			UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
			UC_ARM_REG_R12, UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR, 
			UC_X86_REG_EFLAGS, UC_ARM_REG_CPSR
		]

arm64_reg_list = [
			UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, 
			UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7, 
			UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11, 
			UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15, 
			UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19, 
			UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23, 
			UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27, 
			UC_ARM64_REG_X28, UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_FP, 
			UC_ARM64_REG_LR, UC_ARM_REG_CPSR, UC_ARM64_REG_NZCV
		]


class StateCollector:
	def __init__(self, arch, mode):
		self.arch = arch
		self.mode = mode

		self._set_reg_list()

	def _set_reg_list(self):
		global x86_64_reg_list
		global x86_reg_list
		global arm32_reg_list
		global arm64_reg_list

		if self.arch == UC_ARCH_X86:
			if self.mode == UC_MODE_32:
				self.reg_list = x86_reg_list
			elif self.mode == UC_MODE_64:
				self.reg_list = x86_64_reg_list

		elif self.arch == UC_ARCH_ARM:
			self.reg_list = arm32_reg_list

		elif self.arch == UC_ARCH_ARM64:
			self.reg_list = arm64_reg_list

		else:
			print(f"{self.arch} is not supported.")
			self.reg_list = None

	def define_stack_addr(self, uc):
		stack_addr = uc.reg_read(UC_X86_REG_ESP)

		for begin, end, perm in uc.mem_regions():
			if begin == 0:
				print(f"Stack is not mapped.")
				self.stack_addr = None
			else:
				if begin <= stack_addr <= end:
					self.stack_addr = begin
					uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_stack_write, begin=begin, end=end)
				else:
					continue

	def _hook_stack_write(self, uc, access, address, size, value, user_data):
		pass


	def get_registers(self, uc):
		regs = uc.reg_read_batch(tuple(self.reg_list))
		print(regs)


collector = None


def hook_code(uc, address, size, user_data):
	global collector

	if collector:
		collector.get_registers(uc)

	else:
		collector = StateCollector(uc._arch, uc._mode)
		collector.define_stack_addr(uc)
		
		collector.get_registers(uc)