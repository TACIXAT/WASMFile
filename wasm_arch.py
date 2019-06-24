from binaryninja import *
from binaryninja.enums import *

class WASMArch(Architecture):
    def __init__(self, *args , **kwargs):
        Architecture.__init__(self, *args, **kwargs)

    stack_pointer = "SP"
    name = 'wasm'
    address_size = 2
    default_int_size = 2

    max_instr_length = 4
    endianness = Endianness.LittleEndian

    regs = {
        stack_pointer  : RegisterInfo(stack_pointer, 2)
    }

WASMArch.register()