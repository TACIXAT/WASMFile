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
		b = ord(file_interface.read(off+shift//7, 1))

	val |= (b & 0x7F) << shift
	shift += 7

	return val, shift // 7

class WASMError(Exception):
	pass

class WASMSection():
	def __init__(self, start, file_interface):
		self.section_id = ord(file_interface.read(start, 1))
		self.start = start
		self.data_size, consumed = leb128Parse(self.start+1, file_interface)
		self.data_start = start + 1 + consumed

	def __repr__(self):
		return 'WASMSection(%s)' % self.section_id

def nameParse(off, file_interface):
	name_len, consumed = leb128Parse(off, file_interface)
	name = file_interface.read(off+consumed, name_len)
	return name, consumed + name_len

class WASMSectionCustom(WASMSection):
	def __init__(self, start, file_interface):
		WASMSection.__init__(self, start, file_interface)
		self.name, consumed = nameParse(self.data_start, file_interface)
		self.custom_data_start = self.data_start + consumed

class WASMValType():
	val_type_lookup = {
		0x7F: 'i32',
		0x7E: 'i64',
		0x7D: 'f32',
		0x7C: 'f64',
	}

	def __init__(self, start, file_interface):
		self.start = start
		self.type_id = ord(file_interface.read(self.start, 1))
		if self.type_id not in self.val_type_lookup:
			raise WASMError('invalid val type %02x at %x' % (self.type_id, off))
		self.type = self.val_type_lookup[self.type_id]
		self.end = self.start + 1

class WASMFunctionType():
	def __init__(self, start, file_interface):
		self.start = start
		magic = ord(file_interface.read(start, 1))
		if magic != 0x60:
			raise WASMError('invalid magic on function type: %02x' % magic)
		
		off = start + 1
		# args
		args_len, consumed = leb128Parse(off, file_interface)
		off += consumed
		self.arg_types = []
		for i in range(args_len):
			val_type, consumed = WASMValType(off, file_interface)
			self.arg_types.append(val_type)
			off = val_type.end

		# returns
		rets_len, consumed = leb128Parse(off, file_interface)
		off += consumed
		self.ret_types = []
		for i in range(rets_len):
			val_type = WASMValType(off, file_interface)
			self.arg_types.append(val_type)
			off = val_type.end
		self.end = off


class WASMSectionType(WASMSection):
	def __init__(self, start, file_interface):
		WASMSection.__init__(self, start, file_interface)
		self.type_count, consumed = leb128Parse(self.data_start, file_interface)
		self.function_prototypes = []
		off = self.data_start + consumed
		for i in range(self.type_count):
			function_proto = WASMFunctionType(off, file_interface)
			self.function_prototypes.append(function_proto)
			off = function_proto.end

	def __repr__(self):
		return 'WASMSectionType'

class WASMSectionFunction(WASMSection):
	def __init__(self, start, file_interface):
		WASMSection.__init__(self, start, file_interface)
		index_count, consumed = leb128Parse(self.data_start, file_interface)
		off = self.data_start + consumed
		self.indices = []
		for i in range(index_count):
			index, consumed = leb128Parse(off, file_interface)
			self.indices.append(index)
			off += consumed

	def __repr__(self):
		return 'WASMSectionFunction'

class WASMExportDesriptor():
	index_type_lookup = {
		0: 'function',
		1: 'table',
		2: 'memory',
		3: 'global',
	}

	def __init__(self, start, file_interface):
		off = start
		type_id = ord(file_interface.read(off, 1))
		if type_id not in self.index_type_lookup:
			raise WASMError('invalid export type %02x at %x' % (type_id, off))
		self.type = self.index_type_lookup[type_id]
		off += 1

		self.index, consumed = leb128Parse(off, file_interface)
		off += consumed

		self.end = off

class WASMExport():
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		name, consumed = nameParse(off, file_interface)
		off += consumed
		self.export_descriptor = WASMExportDesriptor(off, file_interface)
		self.end = self.export_descriptor.end

class WASMSectionExport(WASMSection):
	def __init__(self, start, file_interface):
		WASMSection.__init__(self, start, file_interface)
		self.exports = []

		export_count, consumed = leb128Parse(self.data_start, file_interface)
		off = self.data_start + consumed
		for i in range(export_count):
			export = WASMExport(off, file_interface)
			self.exports.append(export)
			off = export.end

	def __repr__(self):
		return 'WASMSectionExport'

class WASMLocal():
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		self.count, consumed = leb128Parse(off, file_interface)
		off += consumed
		self.val_type = WASMValType(off, file_interface)
		self.end = self.val_type.end

class WASMFunction():
	def __init__(self, start, size, file_interface):
		self.start = start
		self.size = size
		self.locals = []
		off = self.start 
		local_count, consumed = leb128Parse(off, file_interface)
		off += consumed
		for i in range(local_count):
			local = WASMLocal(off,file_interface)
			self.locals.append(local)
			off = local.end
		self.end = self.start + self.size
		self.code = file_interface.read(off, self.end-off)

class WASMCode():
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		self.size, consumed = leb128Parse(start, file_interface)
		off += consumed
		self.function = WASMFunction(off, self.size, file_interface)
		self.end = self.function.end

class WASMSectionCode(WASMSection):
	def __init__(self, start, file_interface):
		WASMSection.__init__(self, start, file_interface)
		self.codes = []

		code_count, consumed = leb128Parse(self.data_start, file_interface)
		off = self.data_start + consumed
		for i in range(code_count):
			code = WASMCode(off, file_interface)
			self.codes.append(code)
			off = code.end

	def __repr__(self):
		return 'WASMSectionCode'

class WASMSectionTemplate(WASMSection):
	def __init__(self, start, file_interface):
		WASMSection.__init__(self, start, file_interface)

	def __repr__(self):
		return 'WASMSectionTemplate'

class WASMFile():
	section_type_by_id = {
		0: WASMSectionCustom,
		1: WASMSectionType,
		# 2: WASMSectionImport,
		3: WASMSectionFunction,
		# 4: WASMSectionTable,
		# 5: WASMSectionMemory,
		# 6: WASMSectionGlobal,
		7: WASMSectionExport,
		# 8: WASMSectionStart,
		# 9: WASMSectionElement,
		10: WASMSectionCode,
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