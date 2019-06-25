from binaryninja import *
from binaryninja.enums import *
import struct

class WASMView(BinaryView):
    name = "wasm"
    long_name = "Web Assembly"
    arch = "wasm"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)
        self.raw = data

    def leb128Parse(self, off):
        b = ord(self.raw.read(off, 1))
        print 'B', b
        shift = 0
        val = 0
        while b & 0x80:
            val |= (b & 0x7F) << shift
            shift += 7
            b = ord(self.raw.read(off+count, 1))

        val |= (b & 0x7F) << shift
        shift += 7

        return val, shift / 7

    section_types = {
        0: 'custom', # u32 name_len, utf8 name, data
        1: 'type', # u32 type_count, function types
        2: 'import', # vec imports, 
        3: 'function',
        4: 'table',
        5: 'memory',
        6: 'global',
        7: 'export',
        8: 'start',
        9: 'element',
        10: 'code',
        11: 'data',
    }

    def handle_custom(self):
        pass

    def init(self):
        self.platform = Architecture['wasm'].standalone_platform
        self.arch = Architecture['wasm']

        self.add_auto_section("magic", 0, 8, SectionSemantics.DefaultSectionSemantics)

        off = 8
        bv = self.raw
        while off < len(bv):
            start = off
            section_id = ord(bv.read(off, 1))
            off += 1
            size, count = self.leb128Parse(off)
            off += count

            self.add_auto_section(self.section_types[section_id], start, 1+count+size, SectionSemantics.DefaultSectionSemantics)

            self.add_auto_segment(off, size, off, size, SegmentFlag.SegmentReadable)
            off += size

        return True

    @classmethod
    def is_valid_for_data(self, bv):
        # magic + version + section id + section size
        if len(bv) < 4 + 4 + 1 + 4:
            return False
        magic = bv.read(0,4)
        version = struct.unpack('<I', bv.read(4,4))[0]
        return magic == '\x00asm' and version == 1

WASMView.register()