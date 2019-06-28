#  parsing library made 
# Author: TACIXAT
import sys
import struct
import wasm_disas

class FileInterface():
	def __init__(self, contents):
		self.contents = contents

	def read(self, offset, size):
		return self.contents[offset:offset+size]

	def __len__(self):
		return len(self.contents)

class WASMError(Exception):
	pass

class Section():
	def __init__(self, start, file_interface):
		self.section_id = ord(file_interface.read(start, 1))
		self.start = start
		self.data_size, consumed = wasm_disas.uleb128Parse(self.start+1, file_interface)
		self.data_start = start + 1 + consumed

	def __repr__(self):
		return 'Section(%s)' % self.section_id

def nameParse(off, file_interface):
	name_len, consumed = wasm_disas.uleb128Parse(off, file_interface)
	name = file_interface.read(off+consumed, name_len)
	return name, consumed + name_len

class SectionCustom(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		self.name, consumed = nameParse(self.data_start, file_interface)
		self.custom_data_start = self.data_start + consumed
		self.custom_data = file_interface.read(self.custom_data_start, self.data_size-consumed)
		self.end = self.data_start + self.data_size

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Custom Section')
		print(' '*(indent+2), end='')
		print(self.name.decode('utf8'))
		print_bytes(self.custom_data, indent+4)
		
def print_bytes(data, indent, width=8):
	for idx in range(0, len(data), width):
		print(' '*(indent), end='')
		for b in data[idx:idx+width]:
			print('%02x ' % b, end='')
		print()

class ValueType():
	value_type_lookup = {
		0x7F: 'i32',
		0x7E: 'i64',
		0x7D: 'f32',
		0x7C: 'f64',
	}

	def __init__(self, start, file_interface):
		self.start = start
		self.type_id = ord(file_interface.read(self.start, 1))
		if self.type_id not in self.value_type_lookup:
			raise WASMError('invalid val type %02x at %x' % (self.type_id, off))
		self.type = self.value_type_lookup[self.type_id]
		self.end = self.start + 1

	def __repr__(self):
		return self.type

class FunctionType():
	def __init__(self, start, file_interface):
		self.start = start
		magic = ord(file_interface.read(start, 1))
		if magic != 0x60:
			raise WASMError('invalid magic on function type: %02x' % magic)
		
		off = start + 1
		# args
		params_len, consumed = wasm_disas.uleb128Parse(off, file_interface)
		off += consumed
		self.param_types = []
		for i in range(params_len):
			value_type = ValueType(off, file_interface)
			self.param_types.append(value_type)
			off = value_type.end

		# returns
		results_len, consumed = wasm_disas.uleb128Parse(off, file_interface)
		off += consumed
		self.result_types = []
		for i in range(results_len):
			value_type = ValueType(off, file_interface)
			self.result_types.append(value_type)
			off = value_type.end
		self.end = off

	def pretty_print(self, indent=0):
		print(' '*indent + 'func ', end='')
		if not len(self.param_types) and not len(self.result_types):
			print('(empty) ', end='')

		for param in self.param_types:
			print('(param %s) ' % param.type, end='')

		for result in self.result_types:
			print('(result %s) ' % result.type, end='')

		print()


class SectionType(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		type_count, consumed = wasm_disas.uleb128Parse(self.data_start, file_interface)
		self.function_prototypes = []
		off = self.data_start + consumed
		for i in range(type_count):
			function_proto = FunctionType(off, file_interface)
			self.function_prototypes.append(function_proto)
			off = function_proto.end
		self.end = off

	def __repr__(self):
		return 'SectionType'

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Type Section (0x%x - 0x%x)' % (self.start, self.end))
		for proto in self.function_prototypes:
			proto.pretty_print(indent+2)

class Limits():
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		self.type_id = ord(file_interface.read(off, 1))
		off += 1
		self.minimum, consumed = wasm_disas.uleb128Parse(off, file_interface)
		off += consumed

		if self.type_id == 1:
			self.maximum, consumed = wasm_disas.uleb128Parse(off, file_interface)
			off += consumed
		else:
			self.maximum = None

		self.end = off

	def __repr__(self):
		if self.maximum is not None:
			return 'min %d,  max %d' % (self.minimum, self.maximum)
		return 'min %d, max inf' % self.minimum


class TableType():
	def __init__(self, start, file_interface):
		self.start = start
		off = start
		self.element_type_id = ord(file_interface.read(off, 1))
		off += 1
		if self.element_type_id != 0x70:
			raise WASMError('invalid element type')
		self.element_type = 'funcref'
		self.limits = Limits(off, file_interface)
		self.end = self.limits.end

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('TableType(%s %s)' % (self.element_type, self.limits))

class MemoryType():
	def __init__(self, start, file_interface):
		self.start = start
		self.limits = Limits(start, file_interface)
		self.end = self.limits.end

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('MemType(%s)' % self.limits)

class GlobalType():
	mutability_lookup = {
		0x00: 'constant',
		0x01: 'variable',
	}
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		self.value_type = ValueType(off, file_interface)
		off = self.value_type.end
		self.mutability_id = ord(file_interface.read(off, 1))
		off += 1
		self.mutability = self.mutability_lookup[self.mutability_id]
		self.end = off

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('GlobalType(%s %s)' % (self.value_type, self.mutability))

class ImportDescriptor():
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		self.type_id = ord(file_interface.read(off, 1))
		off += 1
		if self.type_id == 0x00:
			self.type_index = wasm_disas.Index(off, file_interface)
			off = self.type_index.end
		elif self.type_id == 0x01:
			self.tabel_type = TabelType(off, file_interface)
			off = self.tabel_type.end
		elif self.type_id == 0x02:
			self.memory_type = MemoryType(off, file_interface)
			off = self.memory_type.end
		elif self.type_id == 0x03:
			self.global_type = GlobalType(off, file_interface)
			off = self.global_type.end
		else:
			raise WASMError('invalid type id')
		self.end = off

	def pretty_print(self, indent=0):
		if self.type_id == 0x00:
			print('Type %s' % self.type_index)
		elif self.type_id == 0x01:
			self.table_type.pretty_print()
		elif self.type_id == 0x02:
			self.memory_type.pretty_print()
		elif self.type_id == 0x03:
			self.global_type.pretty_print()


class Import():
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		self.import_module, consumed = nameParse(off, file_interface)
		off += consumed
		self.import_name, consumed = nameParse(off, file_interface)
		off += consumed
		self.import_descriptor = ImportDescriptor(off, file_interface)
		self.end = self.import_descriptor.end

	def pretty_print(self, indent=0):
		print(' '*indent + '%s.%s ' % (self.import_module.decode('utf8'), self.import_name.decode('utf8')), end='')
		self.import_descriptor.pretty_print()

class SectionImport(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		off = self.data_start
		import_count, consumed = wasm_disas.uleb128Parse(self.data_start, file_interface)
		off += consumed
		self.imports = []
		for i in range(import_count):
			self.imports.append(Import(off, file_interface))
			off = self.imports[-1].end

		self.end = off

	def __repr__(self):
		return 'SectionImport'

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Import Section (0x%x - 0x%x)' % (self.start, self.end))
		for imp in self.imports:
			imp.pretty_print(indent+2)


class SectionFunction(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		index_count, consumed = wasm_disas.uleb128Parse(self.data_start, file_interface)
		off = self.data_start + consumed
		self.indices = []
		for i in range(index_count):
			index = wasm_disas.Index(off, file_interface)
			self.indices.append(index)
			off = self.indices[-1].end
		self.end = off

	def __repr__(self):
		return 'SectionFunction'

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Function Section')
		for idx in range(len(self.indices)):
			print(' '*(indent+2), end='')
			print('Function %d: Type %s' % (idx, self.indices[idx]))


class Local():
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		self.count, consumed = wasm_disas.uleb128Parse(off, file_interface)
		off += consumed
		self.value_type = ValueType(off, file_interface)
		self.end = self.value_type.end

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print("Locals %d %s" % (self.count, self.value_type))

class Function():
	def __init__(self, start, size, file_interface):
		self.start = start
		self.size = size
		self.locals = []
		off = self.start 
		local_count, consumed = wasm_disas.uleb128Parse(off, file_interface)
		off += consumed
		for i in range(local_count):
			local = Local(off,file_interface)
			self.locals.append(local)
			off = local.end
		self.end = self.start + self.size
		self.expression = wasm_disas.Expression(off, file_interface, end=self.end)
		if self.expression.end != self.end:
			raise WASMError('end of expression not at expected offset (0x%x != 0x%x' % (self.expression.end, self.end))

		b = ord(file_interface.read(self.expression.end-1, 1))
		if b != 0x0b:
			raise WASMError('expression ended with 0x%x' % b)

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Function')
		for local in self.locals:
			local.pretty_print(indent+2)

		self.expression.pretty_print(indent+2)

class SectionTable(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		self.tables = []
		table_count, consumed = wasm_disas.uleb128Parse(self.data_start, file_interface)
		off = self.data_start + consumed
		for i in range(table_count):
			self.tables.append(TableType(off, file_interface))
			off = self.tables[-1].end
		self.end = off

	def __repr__(self):
		return 'SectionTable'

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Table Section')
		for table in self.tables:
			table.pretty_print(indent+2)

class SectionMemory(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		self.memories = []
		memory_count, consumed = wasm_disas.uleb128Parse(self.data_start, file_interface)
		off = self.data_start + consumed
		for i in range(memory_count):
			self.memories.append(MemoryType(off, file_interface))
			off = self.memories[-1].end
		self.end = off

	def __repr__(self):
		return 'SectionMemory'

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Memory Section')
		for mem in self.memories:
			mem.pretty_print(indent+2)

class Global():
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		self.global_type = GlobalType(off, file_interface)
		off = self.global_type.end
		self.expression = wasm_disas.Expression(off, file_interface)
		self.end = self.expression.end

	def pretty_print(self, indent=0):
		self.global_type.pretty_print(indent)
		self.expression.pretty_print(indent)

class SectionGlobal(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		self.globals = []
		global_count, consumed = wasm_disas.uleb128Parse(self.data_start, file_interface)
		off = self.data_start + consumed
		for i in range(global_count):
			self.globals.append(Global(off, file_interface))
			off = self.globals[-1].end
		self.end = off

	def __repr__(self):
		return 'SectionGlobal'

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Global Section')
		for glob in self.globals:
			glob.pretty_print(indent+2)

class ExportDesriptor():
	index_type_lookup = {
		0: 'function',
		1: 'table',
		2: 'memory',
		3: 'global',
	}

	def __init__(self, start, file_interface):
		self.start = start
		off = start
		self.type_id = ord(file_interface.read(off, 1))
		if self.type_id not in self.index_type_lookup:
			raise WASMError('invalid export type %02x at %x' % (self.type_id, off))
		self.type = self.index_type_lookup[self.type_id]
		off += 1

		self.index, consumed = wasm_disas.uleb128Parse(off, file_interface)
		off += consumed

		self.end = off

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print(self.type, self.index)


class Export():
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		self.name, consumed = nameParse(off, file_interface)
		off += consumed
		self.export_descriptor = ExportDesriptor(off, file_interface)
		self.end = self.export_descriptor.end

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Export %s' % self.name.decode('utf8'))
		self.export_descriptor.pretty_print(indent+2)

class SectionExport(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		self.exports = []

		export_count, consumed = wasm_disas.uleb128Parse(self.data_start, file_interface)
		off = self.data_start + consumed
		for i in range(export_count):
			export = Export(off, file_interface)
			self.exports.append(export)
			off = export.end
		self.end = off

	def __repr__(self):
		return 'SectionExport'

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Export Section')
		for export in self.exports:
			export.pretty_print(indent+2)

class SectionStart(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		off = self.data_start
		self.function_index = wasm_disas.Index(off, file_interface)
		self.end = self.function_index.end

	def __repr__(self):
		return 'SectionStart'

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Start Section')
		print(' '*(indent+2), end='')
		print('Function %s' % self.function_index)

class Element():
	def __init__(self, start, file_interface):
		self.start = start
		off = start
		self.table_index = wasm_disas.Index(off, file_interface)
		off = self.table_index.end

		self.expression = wasm_disas.Expression(off, file_interface)
		off = self.expression.end

		function_index_count, consumed = wasm_disas.uleb128Parse(off, file_interface)
		off += consumed

		self.function_indices = []
		for i in range(function_index_count):
			self.function_indices.append(wasm_disas.Index(off, file_interface))
			off = self.function_indices[-1].end
		self.end = off

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Table ', end='')
		self.table_index.pretty_print()
		self.expression.pretty_print(indent)
		for func_idx in self.function_indices:
			print(' '*indent, end='')
			print('Function ', end='')
			func_idx.pretty_print()


class SectionElement(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		off = self.data_start
		self.elements = []
		element_count, consumed = wasm_disas.uleb128Parse(off, file_interface)
		off += consumed
		for i in range(element_count):
			self.elements.append(Element(off, file_interface))
			off = self.elements[-1].end
		self.end = off

	def __repr__(self):
		return 'SectionElement'

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Element Section')
		for element in self.elements:
			element.pretty_print(indent+2)


class Code():
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		self.size, consumed = wasm_disas.uleb128Parse(start, file_interface)
		off += consumed
		self.function = Function(off, self.size, file_interface)
		self.end = self.function.end

	def pretty_print(self, indent=0):
		self.function.pretty_print(indent)

class SectionCode(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		self.codes = []

		code_count, consumed = wasm_disas.uleb128Parse(self.data_start, file_interface)
		off = self.data_start + consumed
		for i in range(code_count):
			code = Code(off, file_interface)
			self.codes.append(code)
			off = code.end
		self.end = off

	def __repr__(self):
		return 'SectionCode'

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Code Section')
		for code in self.codes:
			code.pretty_print(indent+2)

class Data():
	def __init__(self, start, file_interface):
		self.start = start
		off = self.start
		self.memory_index = wasm_disas.Index(off, file_interface)
		off = self.memory_index.end
		self.expression = wasm_disas.Expression(off, file_interface)
		off = self.expression.end
		byte_count, consumed = wasm_disas.uleb128Parse(off, file_interface)
		off += consumed
		self.bytes = file_interface.read(off, byte_count)
		off += byte_count
		self.end = off

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Memory Index %s' % (self.memory_index))
		print(' '*indent, end='')
		print('Offset')
		self.expression.pretty_print(indent+2)
		print_bytes(self.bytes, indent+2)

class SectionData(Section):
	def __init__(self, start, file_interface):
		Section.__init__(self, start, file_interface)
		off = self.data_start
		data_count, consumed = wasm_disas.uleb128Parse(off, file_interface)
		off += consumed
		self.data = []
		for i in range(data_count):
			self.data.append(Data(off, file_interface))
			off = self.data[-1].end

		self.end = off

	def __repr__(self):
		return 'SectionData'

	def pretty_print(self, indent=0):
		print(' '*indent, end='')
		print('Data Section')
		for datum in self.data:
			datum.pretty_print(indent+2)

class File():
	section_type_by_id = {
		0: SectionCustom,
		1: SectionType,
		2: SectionImport,
		3: SectionFunction,
		4: SectionTable,
		5: SectionMemory,
		6: SectionGlobal,
		7: SectionExport,
		8: SectionStart,
		9: SectionElement,
		10: SectionCode,
		11: SectionData,
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
				section_type = Section

			section = section_type(start, self.raw)
			self.sections.append(section)
			off = section.data_start + section.data_size
			if self.sections[-1].end != off:
				raise WASMError('bad ending for section %s' % self.sections[-1])

# TODO: add a vector type? would clean up code

def main():
	if len(sys.argv) < 2:
		print('USAGE: %s file.wasm' % sys.argv[0])
		return 1

	with open(sys.argv[1], 'rb+') as f:
		file_interface = FileInterface(f.read())

	wasm = File(file_interface)
	for section in wasm.sections:
		section.pretty_print()

if __name__ == '__main__':
	main()
