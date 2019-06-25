import sys
import struct

class FileInterface():
	def __init__(self, contents):
		self.contents = contents

	def read(self, offset, size):
		return self.contents[offset:offset+size]

	def __len__(self):
		return len(self.contents)

def leb128Parse(off, file_interface):
	b = ord(file_interface.read(off, 1))
	shift = 0
	val = 0
	while b & 0x80:
		val |= (b & 0x7F) << shift
		shift += 7
		b = ord(file_interface.read(off+count, 1))

	val |= (b & 0x7F) << shift
	shift += 7

	return val, shift // 7

class WASMError(Exception):
	pass

class WASMSection():
	def __init__(self, start, file_interface):
		self.section_id = ord(file_interface.read(start, 1))
		self.start = start
		self.data_size, count = leb128Parse(self.start+1, file_interface)
		self.data_start = start + 1 + count

	def __repr__(self):
		return 'WASMSection(%s)' % self.section_id

def nameParse(off, file_interface):
	name_len, count = leb128Parse(off, file_interface)
	name = file_interface.read(off+count, name_len)
	return name, count + name_len

class WASMSectionCustom(WASMSection):
	def __init__(self, start, file_interface):
		WASMSection.__init__(self, start, file_interface)
		self.name, consumed = nameParse(self.data_start, file_interface)
		self.custom_data_start = self.data_start + consumed

class WASMValType():
	def __init__(self, start, file_interface):
		pass

class WASMFunctionType():
	var_type_lookups = {
		0x7F: 'i32',
		0x7E: 'i64',
		0x7D: 'f32',
		0x7C: 'f64',
	}

	def __init__(self, start, file_interface):
		self.start = start
		magic = ord(file_interface.read(start, 1))
		if magic != 0x60:
			raise WASMError('invalid magic on function type: %02x' % magic)
		
		off = start + 1
		# args
		args_len, count = leb128Parse(off, file_interface)
		off += count
		self.arg_types = []
		for i in range(args_len):
			self.arg_types.append(self.var_type_lookups[ord(file_interface.read(off, 1))])
			off += 1

		# returns
		rets_len, count = leb128Parse(off, file_interface)
		off += count
		self.ret_types = []
		for i in range(rets_len):
			self.ret_types.append(self.var_type_lookups[ord(file_interface.read(off, 1))])
			off += 1
		self.end = off


class WASMSectionType(WASMSection):
	def __init__(self, start, file_interface):
		WASMSection.__init__(self, start, file_interface)
		self.type_count, count = leb128Parse(self.data_start, file_interface)
		self.function_prototypes = []
		off = self.data_start + count
		for i in range(self.type_count):
			fnproto = WASMFunctionType(off, file_interface)
			self.function_prototypes.append(fnproto)
			off = fnproto.end


class WASMFile():
	section_type_by_id = {
		0: WASMSectionCustom,
		1: WASMSectionType,
		# 2: WASMSectionImport,
		3: WASMSectionFunction,
		# 4: WASMSectionTable,
		# 5: WASMSectionMemory,
		# 6: WASMSectionGlobal,
		# 7: WASMSectionExport,
		# 8: WASMSectionStart,
		# 9: WASMSectionElement,
		# 10: WASMSectionCode,
		# 11: WASMSectionData,
	}

	def __init__(self, file_interface, process=True):
		self.raw = file_interface
		self.sections = []

		if not process:
			return 

		if not self.check_magic():
			raise WASMError('incorrect magic bytes or version')

		self.process_sections()

	def check_magic(self):
		# magic + version + section id + section size
		if len(self.raw) < 4 + 4 + 1 + 4:
			return False

		version = struct.unpack('<I', self.raw.read(4,4))[0]
		if self.raw.read(0, 4) == b'\x00asm' and version == 1:
			return True

		return False

	def process_sections(self):
		off = 8
		while off < len(self.raw):
			start = off
			section_id = ord(self.raw.read(off, 1))

			if section_id in self.section_type_by_id:
				section_type = self.section_type_by_id[section_id]
			else:
				section_type = WASMSection

			section = section_type(start, self.raw)
			self.sections.append(section)
			off = section.data_start + section.data_size

def main():
	if len(sys.argv) < 2:
		print('USAGE: %s file.wasm' % sys.argv[0])
		return 1

	with open(sys.argv[1], 'rb+') as f:
		file_interface = FileInterface(f.read())

	wasm = WASMFile(file_interface)
	print(wasm.sections)

if __name__ == '__main__':
	main()