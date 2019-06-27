from binaryninja import *
from binaryninja.enums import *

class WASMArch(Architecture):
    def __init__(self, *args , **kwargs):
        Architecture.__init__(self, *args, **kwargs)

    stack_pointer = "SP"
    name = 'wasm'
    address_size = 2
    default_int_size = 2

    max_instr_length = 15
    endianness = Endianness.LittleEndian

    regs = {
        stack_pointer  : RegisterInfo(stack_pointer, 2)
    }

    switch = {
        0x00: 'unreachable',
        0x01: 'nop',
        0x04: 'if',
        0x2a: 'f32.load',
        0x41: 'i32.const',
        0x0b: 'end',
    }

    def get_instruction_info(self, data, addr):
        print('A')
        length = self.instruction_length(addr, data)
        if len(data) < length:
            return None

        iinfo = InstructionInfo()
        iinfo.length = length

        bytes = map(ord, data)
        opcode = self.instruction_text_of_opcode(data)

        return iinfo

    def instruction_text_of_opcode(self, data):
        # 01 04 00 41 2a 0b
        return self.switch[0x00]

    def instruction_length(self, addr, data):
        return 1

    def get_instruction_text(self, data, addr):
        print('B')
        size = self.instruction_length(addr, data)

        op_token = InstructionTextToken(
            InstructionTextTokenType.InstructionToken,
            self.instruction_text_of_opcode(data).ljust(opcode_col)
        )

        param_tokens = [operand_expression.append(
            InstructionTextToken(
                InstructionTextTokenType.RegisterToken,
                'SP'
            )
        )]

        tokens = [ op_token ] + param_tokens

        return tkn_list, 1

WASMArch.register()