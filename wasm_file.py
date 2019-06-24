from binaryninja import *
from binaryninja.enums import *

class WASMFile(BinaryView):
    name = "wasm"
    long_name = "Web Assembly"
    arch = "wasm"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)

    def init(self):
        self.platform = Architecture['wasm'].standalone_platform
        self.arch = Architecture['wasm']


        # SectionSemantics
        # https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.BinaryView.add_auto_section
        # self.add_auto_section(name, start, sz, sem)

        # SegmentFlag
        # https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.BinaryView.add_auto_segment
        # self.add_auto_segment(start, sz, start, sz, r|w|e)

        return True

    @classmethod
    def is_valid_for_data(self, bv):
        magic = bv.read(0,4)
        return magic == '\x00asm'

WASMFile.register()