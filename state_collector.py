from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

import capstone
import pickle
import struct

global collector
global x86_64_reg_list
global x86_reg_list
global arm32_reg_list
global arm64_reg_list

collector = None

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
            UC_ARM_REG_CPSR
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
            UC_ARM64_REG_LR, UC_ARM64_REG_NZCV
        ]


def encode_tuples(tuple_sequence):
    if not tuple_sequence:
        return (0, (), b"", [])
    
    # Get tuple length k
    k = len(tuple_sequence[0])
    if any(len(t) != k for t in tuple_sequence):
        raise ValueError("All tuples must have the same length")
    
    # Store the first tuple
    first_tuple = tuple_sequence[0]
    
    # Initialize bitstream and changes
    bits = []
    changes = []
    
    # Process each tuple after the first
    for i in range(1, len(tuple_sequence)):
        prev_tuple = tuple_sequence[i - 1]
        curr_tuple = tuple_sequence[i]
        
        # Find differences
        diffs = [(j, curr_tuple[j]) for j in range(k) if curr_tuple[j] != prev_tuple[j]]
        
        if len(diffs) > 24:
            raise ValueError(f"Tuple {i} differs by more than 24 values from previous tuple")
        
        # Encode number of changes as 4 bits (0 to 10)
        num_changes = len(diffs)
        # Convert num_changes to 4-bit binary (e.g., 5 = 0101)
        bits.extend([(num_changes >> 3) & 1, (num_changes >> 2) & 1, 
                     (num_changes >> 1) & 1, num_changes & 1])
        
        # Add changes (index, value) pairs
        changes.extend(diffs)
    
    # Convert bits to bytes
    bitstream = b""
    if bits:
        # Pack bits into bytes (8 bits per byte)
        for i in range(0, len(bits), 8):
            byte_bits = bits[i:i+8]
            byte_value = 0
            for bit in byte_bits:
                byte_value = (byte_value << 1) | bit
            # Pad with zeros if needed
            if len(byte_bits) < 8:
                byte_value <<= (8 - len(byte_bits))
            bitstream += struct.pack("B", byte_value)
    
    return (k, first_tuple, bitstream, changes)


def diff_exec_instructions(previous_snapshot, new_snapshot):
    return [
        (i, new_snapshot[i])
        for i in range(min(len(previous_snapshot), len(new_snapshot)))
        if previous_snapshot[i] != new_snapshot[i]
    ] + [
        (i, new_snapshot[i])
        for i in range(len(previous_snapshot), len(new_snapshot))
    ]



class StateCollector:
    REG_CONFIG = {
        (UC_ARCH_X86, UC_MODE_32): (UC_X86_REG_ESP, UC_X86_REG_EIP, 'x86_reg_list'),
        (UC_ARCH_X86, UC_MODE_64): (UC_X86_REG_RSP, UC_X86_REG_RIP, 'x86_64_reg_list'),
        (UC_ARCH_ARM, None):       (UC_ARM_REG_SP, UC_ARM_REG_PC, 'arm32_reg_list'),
        (UC_ARCH_ARM64, None):     (UC_ARM64_REG_SP, UC_ARM64_REG_PC, 'arm64_reg_list'),
    }

    def __init__(self, arch, mode):
        self.arch = arch
        self.mode = mode
        self.stack_pointer = None
        self.instruction_pointer = None
        self.reg_list = None
        self.stack = None

        self.reg_state_list = []
        self.exec_instructions = b""
        self.current_snapshot = b""

        self._set_reg_list()


    def _set_reg_list(self):
        key = (self.arch, self.mode) if (self.arch, self.mode) in self.REG_CONFIG else (self.arch, None)
        config = self.REG_CONFIG.get(key)

        if config:
            self.stack_pointer, self.instruction_pointer, reg_list_name = config
            self.reg_list = globals().get(reg_list_name)
        else:
            raise ValueError(f"{self.arch} is not supported.")


    def define_stack_addr(self, uc):
        stack_addr = uc.reg_read(self.stack_pointer)

        if stack_addr > 0:
            for begin, end, perm in uc.mem_regions():
                if begin <= stack_addr <= end:
                    self.stack = (begin, end, perm)
                    self.current_snapshot = b"\x00" * (end - begin)
                    uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_stack_write, begin=begin, end=end)
                else:
                    continue

        if self.stack == None:
            print(f"Stack mapping was not found.")


    def _hook_stack_write(self, uc, access, address, size, value, user_data):
        print(f"Stack write --> {hex(address)} : {hex(value)} : {hex(uc.reg_read(self.instruction_pointer))}")
        pass


    def get_registers(self, uc):
        regs = uc.reg_read_batch(tuple(self.reg_list))
        self.reg_state_list.append(regs)


    def encode_state(self):
        self.reg_state_list = encode_tuples(self.reg_state_list)


def serialize_reg_state():
    global collector

    collector.encode_state()
    with open('prettycorn.pkl', 'wb') as f:
        pickle.dump(collector, f)


def prettycorn_hook_code(uc, address, size, user_data):
    global collector

    if not collector:
        collector = StateCollector(uc._arch, uc._mode)
        collector.define_stack_addr(uc)

    collector.get_registers(uc)
    code = uc.mem_read(address, size)
    collector.exec_instructions += str(len(code)).encode()
    collector.exec_instructions += code
