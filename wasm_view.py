from binaryninja import *
from binaryninja.enums import *
from .wasm_file import WASMFile, WASMSectionCode
import struct

class WASMView(BinaryView):
    name = "wasm"
    long_name = "Web Assembly"
    arch = "wasm"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)
        self.raw = data

    def init(self):
        self.platform = Architecture['wasm'].standalone_platform
        self.arch = Architecture['wasm']

        self.wasm_file = WASMFile(self.raw)

        for section in self.wasm_file.sections:
            if section.__class__ != WASMSectionCode:
                continue

            start = section.data_start
            size = section.data_size
            self.add_auto_section('code', start, size, SectionSemantics.ReadOnlyCodeSectionSemantics)

            self.add_auto_segment(start, size, start, size, SegmentFlag.SegmentReadable)

        return True

    @classmethod
    def is_valid_for_data(self, bv):
        wasm_file = WASMFile(bv, process=False)
        return wasm_file.check_magic()

WASMView.register()