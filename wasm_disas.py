import struct
from wasm_file import WASMError, WASMValType

def uleb128Parse(off, file_interface):
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

def sleb128Parse(off, file_interface):
	b = ord(file_interface.read(off, 1))
	shift = 0
	val = 0
	while b & 0x80:
		val |= (b & 0x7F) << shift
		shift += 7
		b = ord(file_interface.read(off+shift//7, 1))
	val |= (b & 0x7F) << shift
	shift += 7
	if b & 0x40:
		mask = (1 << shift) - 1
		val = val ^ mask
		val = -val - 1
	return val, shift//7

def f32Parse(off, file_interface):
	f32_bytes = file_interface.read(off, 4)
	f32, = struct.unpack('<f', f32_bytes)
	return f32, 4

def f64Parse(off, file_interface):
	f64_bytes = file_interface.read(off, 8)
	f64, = struct.unpack('<d', f64_bytes)
	return f64, 8

class WASMInstruction():
	def __init__(self, start, file_interface):
		self.start = start
		self.opcode = ord(file_interface.read(start, 1))
		self.end = start + 1

class WASMMemarg():
	def __init__(self, start, file_interface):
		off = start
		self.alignment, consumed = uleb128Parse(off, file_interface)
		off += consumed
		self.offset, consumed = uleb128Parse(off, file_interface)
		self.end = off + consumed

	def __repr__(self):
		return 'o:%d, a:%d' % (self.offset, self.alignment)

class WASMInstructionMemory(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start+1
		self.memarg = WASMMemarg(off, file_interface)
		self.end = self.memarg.end

class Index():
	def __init__(self, start, file_interface):
		self.index, consumed = uleb128Parse(start, file_interface)
		self.end = start + consumed

	def __repr__(self):
		return '%d' % self.index

class WASMInstructionLocal(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start + 1
		self.local_index = Index(off, file_interface)
		self.end = self.local_index.end

class WASMInstructionGlobal(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start + 1
		self.global_index = Index(off, file_interface)
		self.end = self.global_index.end

class WASMInstructionBranch(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start + 1
		self.label_index = Index(off, file_interface)
		self.end = self.label_index.end

class Unreachable(WASMInstruction):
	def __repr__(self):
		return 'unreachable'

class Nop(WASMInstruction):
	def __repr__(self):
		return 'nop'

class WASMBlocktype():
	def __init__(self, start, file_interface):
		b = file_interface.read(start, 1)
		if b == b'\x40':
			self.type = None
		else:
			self.type = WASMValType(start, file_interface)
		self.end = start + 1

class Block(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start + 1
		self.block_type = WASMBlocktype(off, file_interface)
		off = self.block_type.end
		self.block_instructions = WASMExpression(off, file_interface)

		off = self.block_instructions.end
		b = ord(file_interface.read(off, 1))
		if b != 0x0b:
			raise WASMError('block ended with 0x%x' % b)

		self.end = off + 1

	def __repr__(self):
		return '\n'.join(['block', str(self.block_instructions), 'end'])

class Loop(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start + 1
		self.block_type = WASMBlocktype(off, file_interface)
		off = self.block_type.end
		self.loop_instructions = WASMExpression(off, file_interface)

		off = self.loop_instructions.end
		b = ord(file_interface.read(off, 1))
		if b != 0x0b:
			raise WASMError('loop ended with 0x%x' % b)

		self.end = off + 1

	def __repr__(self):
		return '\n'.join(['block', str(self.loop_instructions), 'end'])

class If(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start + 1

		self.block_type = WASMBlocktype(off, file_interface)
		off = self.block_type.end

		self.if_instructions = WASMExpression(off, file_interface)
		off = self.if_instructions.end

		self.else_instructions = None

		b = ord(file_interface.read(off, 1))
		off += 1
		if b == 0x05:
			self.else_instructions = WASMExpression(off, file_interface)
			off = self.else_instructions.end
			b = ord(file_interface.read(off, 1))
			off += 1

		if b != 0x0b:
			raise WASMError('if ended with 0x%x' % b)

		self.end = off

	def __repr__(self):
		output = 'if\n%s' % self.if_instructions
		if self.else_instructions != None:
			output += '\nelse\n%s' % self.else_instructions
		return output

class Branch(WASMInstructionBranch):
	def __repr__(self):
		return 'br'

class BranchIf(WASMInstructionBranch):
	def __repr__(self):
		return 'br_if'

class BranchTable(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start + 1
		label_count, consumed = uleb128Parse(off, file_interface)
		off += consumed
		self.labels = []
		for i in range(label_count):
			self.labels.append(Index(off, file_interface))
			off = self.labels[-1].end
		self.default_label = Index(off, file_interface)
		self.end = self.default_label.end

	def __repr__(self):
		return 'br_table'

class Call(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start + 1
		self.function_index = Index(off, file_interface)
		self.end = self.function_index.end

	def __repr__(self):
		return 'call'

class CallIndirect(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start + 1
		self.type_index = Index(off, file_interface)
		b = file_interface.read(self.type_index.end, 1)
		if b != b'\x00':
			raise WASMError('terminating byte not null')
		self.end = self.type_index.end + 1

	def __repr__(self):
		return 'call_indirect'

class End(WASMInstruction):
	def __repr__(self):
		return 'end'

class Return(WASMInstruction):
	def __repr__(self):
		return 'return'

class Drop(WASMInstruction):
	def __repr__(self):
		return 'drop'

class Select(WASMInstruction):
	def __repr__(self):
		return 'select'

class LocalGet(WASMInstructionLocal):
	def __repr__(self):
		return 'local.get %s' % self.local_index

class LocalSet(WASMInstructionLocal):
	def __repr__(self):
		return 'local.set %s' % self.local_index

class LocalTee(WASMInstructionLocal):
	def __repr__(self):
		return 'local.tee %s' % self.local_index

class GlobalGet(WASMInstructionGlobal):
	def __repr__(self):
		return 'global.get %s' % self.global_index

class GlobalSet(WASMInstructionGlobal):
	def __repr__(self):
		return 'global.set %s' % self.global_index

class I32Load(WASMInstructionMemory):
	def __repr__(self):
		return 'i32.load ' + str(self.memarg)
		
class I64Load(WASMInstructionMemory):
	def __repr__(self):
		return 'i64.load ' + str(self.memarg)
		
class F32Load(WASMInstructionMemory):
	def __repr__(self):
		return 'f32.load ' + str(self.memarg)
		
class F64Load(WASMInstructionMemory):
	def __repr__(self):
		return 'f64.load ' + str(self.memarg)
		
class I32Load8_s(WASMInstructionMemory):
	def __repr__(self):
		return 'i32.load8_s ' + str(self.memarg)
		
class I32Load8_u(WASMInstructionMemory):
	def __repr__(self):
		return 'i32.load8_u ' + str(self.memarg)
		
class I32Load16S(WASMInstructionMemory):
	def __repr__(self):
		return 'i32.load16_s ' + str(self.memarg)
		
class I32Load16U(WASMInstructionMemory):
	def __repr__(self):
		return 'i32.load16_u ' + str(self.memarg)
		
class I64Load8S(WASMInstructionMemory):
	def __repr__(self):
		return 'i64.load8_s ' + str(self.memarg)
		
class I64Load8U(WASMInstructionMemory):
	def __repr__(self):
		return 'i64.load8_u ' + str(self.memarg)
		
class I64Load16S(WASMInstructionMemory):
	def __repr__(self):
		return 'i64.load16_s ' + str(self.memarg)
		
class I64Load16U(WASMInstructionMemory):
	def __repr__(self):
		return 'i64.load16_u ' + str(self.memarg)
		
class I64Load32S(WASMInstructionMemory):
	def __repr__(self):
		return 'i64.load32_s ' + str(self.memarg)
		
class I64Load32U(WASMInstructionMemory):
	def __repr__(self):
		return 'i64.load32_u ' + str(self.memarg)
		
class I32Store(WASMInstructionMemory):
	def __repr__(self):
		return 'i32.store ' + str(self.memarg)
		
class I64Store(WASMInstructionMemory):
	def __repr__(self):
		return 'i64.store ' + str(self.memarg)
		
class F32Store(WASMInstructionMemory):
	def __repr__(self):
		return 'f32.store ' + str(self.memarg)
		
class F64Store(WASMInstructionMemory):
	def __repr__(self):
		return 'f64.store ' + str(self.memarg)
		
class I32Store8(WASMInstructionMemory):
	def __repr__(self):
		return 'i32.store8 ' + str(self.memarg)
		
class I32Store16(WASMInstructionMemory):
	def __repr__(self):
		return 'i32.store16 ' + str(self.memarg)
		
class I64Store8(WASMInstructionMemory):
	def __repr__(self):
		return 'i64.store8 ' + str(self.memarg)
		
class I64Store16(WASMInstructionMemory):
	def __repr__(self):
		return 'i64.store16 ' + str(self.memarg)
		
class I64Store32(WASMInstructionMemory):
	def __repr__(self):
		return 'i64.store32 ' + str(self.memarg)

class MemorySize(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		b = file_interface.read(start+1, 1)
		if b != b'\x00':
			raise WASMError('second byte not null')
		self.end = start + 2

	def __repr__(self):
		return 'memory.size'

class MemoryGrow(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		b = file_interface.read(start+1, 1)
		if b != b'\x00':
			raise WASMError('second byte not null')
		self.end = start + 2

	def __repr__(self):
		return 'memory.grow'

class I32Const(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start+1
		self.constant, consumed = sleb128Parse(off, file_interface)
		self.end = off + consumed

	def __repr__(self):
		return 'i32.const %d' % self.constant

class I64Const(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start+1
		self.constant, consumed = sleb128Parse(off, file_interface)
		self.end = off + consumed

	def __repr__(self):
		return 'i64.const %f' % self.constant

class F32Const(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start+1
		self.constant, consumed = f32Parse(off, file_interface)
		self.end = off + consumed

	def __repr__(self):
		return 'f32.const %f' % self.constant

class F64Const(WASMInstruction):
	def __init__(self, start, file_interface):
		WASMInstruction.__init__(self, start, file_interface)
		off = start+1
		self.constant, consumed = f64Parse(off, file_interface)
		self.end = off + consumed

	def __repr__(self):
		return 'f64.const %d' % self.constant

class I32Eqz(WASMInstruction): 
	def __repr__(self):
		return 'i32.eqz'

class I32Eq(WASMInstruction): 
	def __repr__(self):
		return 'i32.eq'

class I32Ne(WASMInstruction): 
	def __repr__(self):
		return 'i32.ne'

class I32LtS(WASMInstruction): 
	def __repr__(self):
		return 'i32.lt_s'

class I32LtS(WASMInstruction): 
	def __repr__(self):
		return 'i32.lt_u'

class I32GtS(WASMInstruction): 
	def __repr__(self):
		return 'i32.gt_s'

class I32GtS(WASMInstruction): 
	def __repr__(self):
		return 'i32.gt_u'

class I32LeS(WASMInstruction): 
	def __repr__(self):
		return 'i32.le_s'

class I32LeS(WASMInstruction): 
	def __repr__(self):
		return 'i32.le_u'

class I32GeS(WASMInstruction): 
	def __repr__(self):
		return 'i32.ge_s'

class I32GeS(WASMInstruction): 
	def __repr__(self):
		return 'i32.ge_u'

class I64Eqz(WASMInstruction): 
	def __repr__(self):
		return 'i64.eqz'

class I64Eq(WASMInstruction): 
	def __repr__(self):
		return 'i64.eq'

class I64Ne(WASMInstruction): 
	def __repr__(self):
		return 'i64.ne'

class I64LtS(WASMInstruction): 
	def __repr__(self):
		return 'i64.lt_s'

class I64LtU(WASMInstruction): 
	def __repr__(self):
		return 'i64.lt_u'

class I64GtS(WASMInstruction): 
	def __repr__(self):
		return 'i64.gt_s'

class I64GtU(WASMInstruction): 
	def __repr__(self):
		return 'i64.gt_u'

class I64LeS(WASMInstruction): 
	def __repr__(self):
		return 'i64.le_s'

class I64LeU(WASMInstruction): 
	def __repr__(self):
		return 'i64.le_u'

class I64GeS(WASMInstruction): 
	def __repr__(self):
		return 'i64.ge_s'

class I64GeU(WASMInstruction): 
	def __repr__(self):
		return 'i64.ge_u'

class F32Eq(WASMInstruction): 
	def __repr__(self):
		return 'f32.eq'

class F32Ne(WASMInstruction): 
	def __repr__(self):
		return 'f32.ne'

class F32Lt(WASMInstruction): 
	def __repr__(self):
		return 'f32.lt'

class F32Gt(WASMInstruction): 
	def __repr__(self):
		return 'f32.gt'

class F32Le(WASMInstruction): 
	def __repr__(self):
		return 'f32.le'

class F32Ge(WASMInstruction): 
	def __repr__(self):
		return 'f32.ge'

class F64Eq(WASMInstruction): 
	def __repr__(self):
		return 'f64.eq'

class F64Ne(WASMInstruction): 
	def __repr__(self):
		return 'f64.ne'

class F64Lt(WASMInstruction): 
	def __repr__(self):
		return 'f64.lt'

class F64Gt(WASMInstruction): 
	def __repr__(self):
		return 'f64.gt'

class F64Le(WASMInstruction): 
	def __repr__(self):
		return 'f64.le'

class F64Ge(WASMInstruction): 
	def __repr__(self):
		return 'f64.ge'

class I32Clz(WASMInstruction): 
	def __repr__(self):
		return 'i32.clz'

class I32Ctz(WASMInstruction): 
	def __repr__(self):
		return 'i32.ctz'

class I32Popcnt(WASMInstruction): 
	def __repr__(self):
		return 'i32.popcnt'

class I32Add(WASMInstruction): 
	def __repr__(self):
		return 'i32.add'

class I32Sub(WASMInstruction): 
	def __repr__(self):
		return 'i32.sub'

class I32Mul(WASMInstruction): 
	def __repr__(self):
		return 'i32.mul'

class I32DivS(WASMInstruction): 
	def __repr__(self):
		return 'i32.div_s'

class I32DivU(WASMInstruction): 
	def __repr__(self):
		return 'i32.div_u'

class I32RemS(WASMInstruction): 
	def __repr__(self):
		return 'i32.rem_s'

class I32RemU(WASMInstruction): 
	def __repr__(self):
		return 'i32.rem_u'

class I32And(WASMInstruction): 
	def __repr__(self):
		return 'i32.and'

class I32Or(WASMInstruction): 
	def __repr__(self):
		return 'i32.or'

class I32Xor(WASMInstruction): 
	def __repr__(self):
		return 'i32.xor'

class I32Shl(WASMInstruction): 
	def __repr__(self):
		return 'i32.shl'

class I32ShrS(WASMInstruction): 
	def __repr__(self):
		return 'i32.shr_s'

class I32ShrU(WASMInstruction): 
	def __repr__(self):
		return 'i32.shr_u'

class I32Rotl(WASMInstruction): 
	def __repr__(self):
		return 'i32.rotl'

class I32Rotr(WASMInstruction): 
	def __repr__(self):
		return 'i32.rotr'

class I64Clz(WASMInstruction): 
	def __repr__(self):
		return 'i64.clz'

class I64Ctz(WASMInstruction): 
	def __repr__(self):
		return 'i64.ctz'

class I64Popcnt(WASMInstruction): 
	def __repr__(self):
		return 'i64.popcnt'

class I64Add(WASMInstruction): 
	def __repr__(self):
		return 'i64.add'

class I64Sub(WASMInstruction): 
	def __repr__(self):
		return 'i64.sub'

class I64Mul(WASMInstruction): 
	def __repr__(self):
		return 'i64.mul'

class I64DivS(WASMInstruction): 
	def __repr__(self):
		return 'i64.div_s'

class I64DivU(WASMInstruction): 
	def __repr__(self):
		return 'i64.div_u'

class I64RemS(WASMInstruction): 
	def __repr__(self):
		return 'i64.rem_s'

class I64RemU(WASMInstruction): 
	def __repr__(self):
		return 'i64.rem_u'

class I64And(WASMInstruction): 
	def __repr__(self):
		return 'i64.and'

class I64Or(WASMInstruction): 
	def __repr__(self):
		return 'i64.or'

class I64Xor(WASMInstruction): 
	def __repr__(self):
		return 'i64.xor'

class I64Shl(WASMInstruction): 
	def __repr__(self):
		return 'i64.shl'

class I64ShrS(WASMInstruction): 
	def __repr__(self):
		return 'i64.shr_s'

class I64ShrU(WASMInstruction): 
	def __repr__(self):
		return 'i64.shr_u'

class I64Rotl(WASMInstruction): 
	def __repr__(self):
		return 'i64.rotl'

class I64Rotr(WASMInstruction): 
	def __repr__(self):
		return 'i64.rotr'

class F32Abs(WASMInstruction): 
	def __repr__(self):
		return 'f32.abs'

class F32Neg(WASMInstruction): 
	def __repr__(self):
		return 'f32.neg'

class F32Ceil(WASMInstruction): 
	def __repr__(self):
		return 'f32.ceil'

class F32Floor(WASMInstruction): 
	def __repr__(self):
		return 'f32.floor'

class F32Trunc(WASMInstruction): 
	def __repr__(self):
		return 'f32.trunc'

class F32Nearest(WASMInstruction): 
	def __repr__(self):
		return 'f32.nearest'

class F32Sqrt(WASMInstruction): 
	def __repr__(self):
		return 'f32.sqrt'

class F32Add(WASMInstruction): 
	def __repr__(self):
		return 'f32.add'

class F32Sub(WASMInstruction): 
	def __repr__(self):
		return 'f32.sub'

class F32Mul(WASMInstruction): 
	def __repr__(self):
		return 'f32.mul'

class F32Div(WASMInstruction): 
	def __repr__(self):
		return 'f32.div'

class F32Min(WASMInstruction): 
	def __repr__(self):
		return 'f32.min'

class F32Max(WASMInstruction): 
	def __repr__(self):
		return 'f32.max'

class F32Copysign(WASMInstruction): 
	def __repr__(self):
		return 'f32.copysign'

class F64Abs(WASMInstruction): 
	def __repr__(self):
		return 'f64.abs'

class F64Neg(WASMInstruction): 
	def __repr__(self):
		return 'f64.neg'

class F64Ceil(WASMInstruction): 
	def __repr__(self):
		return 'f64.ceil'

class F64Floor(WASMInstruction): 
	def __repr__(self):
		return 'f64.floor'

class F64Trunc(WASMInstruction): 
	def __repr__(self):
		return 'f64.trunc'

class F64Nearest(WASMInstruction): 
	def __repr__(self):
		return 'f64.nearest'

class F64Sqrt(WASMInstruction): 
	def __repr__(self):
		return 'f64.sqrt'

class F64Add(WASMInstruction): 
	def __repr__(self):
		return 'f64.add'

class F64Sub(WASMInstruction): 
	def __repr__(self):
		return 'f64.sub'

class F64Mul(WASMInstruction): 
	def __repr__(self):
		return 'f64.mul'

class F64Div(WASMInstruction): 
	def __repr__(self):
		return 'f64.div'

class F64Min(WASMInstruction): 
	def __repr__(self):
		return 'f64.min'

class F64Max(WASMInstruction): 
	def __repr__(self):
		return 'f64.max'

class F64Copysign(WASMInstruction): 
	def __repr__(self):
		return 'f64.copysign'

class I32WrapI64(WASMInstruction): 
	def __repr__(self):
		return 'i32.wrap_i64'

class I32TruncF32S(WASMInstruction): 
	def __repr__(self):
		return 'i32.trunc_f32_s'

class I32TruncF32U(WASMInstruction): 
	def __repr__(self):
		return 'i32.trunc_f32_u'

class I32TruncF64S(WASMInstruction): 
	def __repr__(self):
		return 'i32.trunc_f64_s'

class I32TruncF64U(WASMInstruction): 
	def __repr__(self):
		return 'i32.trunc_f64_u'

class I64ExtendI32S(WASMInstruction): 
	def __repr__(self):
		return 'i64.extend_i32_s'

class I64ExtendI32U(WASMInstruction): 
	def __repr__(self):
		return 'i64.extend_i32_u'

class I64TruncF32S(WASMInstruction): 
	def __repr__(self):
		return 'i64.trunc_f32_s'

class I64TruncF32U(WASMInstruction): 
	def __repr__(self):
		return 'i64.trunc_f32_u'

class I64TruncF64S(WASMInstruction): 
	def __repr__(self):
		return 'i64.trunc_f64_s'

class I64TruncF64U(WASMInstruction): 
	def __repr__(self):
		return 'i64.trunc_f64_u'

class F32ConvertI32S(WASMInstruction): 
	def __repr__(self):
		return 'f32.convert_i32_s'

class F32ConvertI32U(WASMInstruction): 
	def __repr__(self):
		return 'f32.convert_i32_u'

class F32ConvertI64S(WASMInstruction): 
	def __repr__(self):
		return 'f32.convert_i64_s'

class F32ConvertI64U(WASMInstruction): 
	def __repr__(self):
		return 'f32.convert_i64_u'

class F32DemoteF64(WASMInstruction): 
	def __repr__(self):
		return 'f32.demote_f64'

class F64ConvertI32S(WASMInstruction): 
	def __repr__(self):
		return 'f64.convert_i32_s'

class F64ConvertI32U(WASMInstruction): 
	def __repr__(self):
		return 'f64.convert_i32_u'

class F64ConvertI64S(WASMInstruction): 
	def __repr__(self):
		return 'f64.convert_i64_s'

class F64ConvertI64U(WASMInstruction): 
	def __repr__(self):
		return 'f64.convert_i64_u'

class F64PromoteF32(WASMInstruction): 
	def __repr__(self):
		return 'f64.promote_f32'

class I32ReinterpretF32(WASMInstruction): 
	def __repr__(self):
		return 'i32.reinterpret_f32'

class I64ReinterpretF64(WASMInstruction): 
	def __repr__(self):
		return 'i64.reinterpret_f64'

class F32ReinterpretI32(WASMInstruction): 
	def __repr__(self):
		return 'f32.reinterpret_i32'

class F64ReinterpretI64(WASMInstruction): 
	def __repr__(self):
		return 'f64.reinterpret_i64'

class WASMExpression():
	instruction_lookup = {
		0x00: Unreachable,
		0x01: Nop,
		0x02: Block,
		0x03: Loop,
		0x04: If,
		0x0b: End,
		0x0c: Branch,
		0x0d: BranchIf,
		0x0e: BranchTable,
		0x0f: Return,
		0x10: Call,
		0x11: CallIndirect,
		0x1a: Drop,
		0x1b: Select,
		0x20: LocalGet,
		0x21: LocalSet,
		0x22: LocalTee,
		0x23: GlobalGet,
		0x24: GlobalSet,
		0x28: I32Load,
		0x29: I64Load,
		0x2a: F32Load,
		0x2b: F64Load,
		0x2c: I32Load8_s,
		0x2d: I32Load8_u,
		0x2e: I32Load16S,
		0x2f: I32Load16U,
		0x30: I64Load8S,
		0x31: I64Load8U,
		0x32: I64Load16S,
		0x33: I64Load16U,
		0x34: I64Load32S,
		0x35: I64Load32U,
		0x36: I32Store,
		0x37: I64Store,
		0x38: F32Store,
		0x39: F64Store,
		0x3a: I32Store8,
		0x3b: I32Store16,
		0x3c: I64Store8,
		0x3d: I64Store16,
		0x3e: I64Store32,
		0x3f: MemorySize,
		0x40: MemoryGrow,
		0x41: I32Const,
		0x42: I64Const,
		0x43: F32Const,
		0x44: F64Const,
		0x45: I32Eqz,
		0x46: I32Eq,
		0x47: I32Ne,
		0x48: I32LtS,
		0x49: I32LtS,
		0x4A: I32GtS,
		0x4B: I32GtS,
		0x4C: I32LeS,
		0x4D: I32LeS,
		0x4E: I32GeS,
		0x4F: I32GeS,
		0x50: I64Eqz,
		0x51: I64Eq,
		0x52: I64Ne,
		0x53: I64LtS,
		0x54: I64LtU,
		0x55: I64GtS,
		0x56: I64GtU,
		0x57: I64LeS,
		0x58: I64LeU,
		0x59: I64GeS,
		0x5A: I64GeU,
		0x5B: F32Eq,
		0x5C: F32Ne,
		0x5D: F32Lt,
		0x5E: F32Gt,
		0x5F: F32Le,
		0x60: F32Ge,
		0x61: F64Eq,
		0x62: F64Ne,
		0x63: F64Lt,
		0x64: F64Gt,
		0x65: F64Le,
		0x66: F64Ge,
		0x67: I32Clz,
		0x68: I32Ctz,
		0x69: I32Popcnt,
		0x6A: I32Add,
		0x6B: I32Sub,
		0x6C: I32Mul,
		0x6D: I32DivS,
		0x6E: I32DivU,
		0x6F: I32RemS,
		0x70: I32RemU,
		0x71: I32And,
		0x72: I32Or,
		0x73: I32Xor,
		0x74: I32Shl,
		0x75: I32ShrS,
		0x76: I32ShrU,
		0x77: I32Rotl,
		0x78: I32Rotr,
		0x79: I64Clz,
		0x7A: I64Ctz,
		0x7B: I64Popcnt,
		0x7C: I64Add,
		0x7D: I64Sub,
		0x7E: I64Mul,
		0x7F: I64DivS,
		0x80: I64DivU,
		0x81: I64RemS,
		0x82: I64RemU,
		0x83: I64And,
		0x84: I64Or,
		0x85: I64Xor,
		0x86: I64Shl,
		0x87: I64ShrS,
		0x88: I64ShrU,
		0x89: I64Rotl,
		0x8A: I64Rotr,
		0x8B: F32Abs,
		0x8C: F32Neg,
		0x8D: F32Ceil,
		0x8E: F32Floor,
		0x8F: F32Trunc,
		0x90: F32Nearest,
		0x91: F32Sqrt,
		0x92: F32Add,
		0x93: F32Sub,
		0x94: F32Mul,
		0x95: F32Div,
		0x96: F32Min,
		0x97: F32Max,
		0x98: F32Copysign,
		0x99: F64Abs,
		0x9A: F64Neg,
		0x9B: F64Ceil,
		0x9C: F64Floor,
		0x9D: F64Trunc,
		0x9E: F64Nearest,
		0x9F: F64Sqrt,
		0xA0: F64Add,
		0xA1: F64Sub,
		0xA2: F64Mul,
		0xA3: F64Div,
		0xA4: F64Min,
		0xA5: F64Max,
		0xA6: F64Copysign,
		0xA7: I32WrapI64,
		0xA8: I32TruncF32S,
		0xA9: I32TruncF32U,
		0xAA: I32TruncF64S,
		0xAB: I32TruncF64U,
		0xAC: I64ExtendI32S,
		0xAD: I64ExtendI32U,
		0xAE: I64TruncF32S,
		0xAF: I64TruncF32U,
		0xB0: I64TruncF64S,
		0xB1: I64TruncF64U,
		0xB2: F32ConvertI32S,
		0xB3: F32ConvertI32U,
		0xB4: F32ConvertI64S,
		0xB5: F32ConvertI64U,
		0xB6: F32DemoteF64,
		0xB7: F64ConvertI32S,
		0xB8: F64ConvertI32U,
		0xB9: F64ConvertI64S,
		0xBA: F64ConvertI64U,
		0xBB: F64PromoteF32,
		0xBC: I32ReinterpretF32,
		0xBD: I64ReinterpretF64,
		0xBE: F32ReinterpretI32,
		0xBF: F64ReinterpretI64,
	}

	def __init__(self, start, file_interface):
		self.start = start
		self.instructions = []
		off = start 
		while True:
			opcode = ord(file_interface.read(off, 1))
			# else or end
			if opcode == 0x05 or opcode == 0x0b:
				break

			if opcode not in self.instruction_lookup:
				raise WASMError('unknown instruction %x' % opcode)

			instruction = self.instruction_lookup[opcode](off, file_interface)
			self.instructions.append(instruction)
			off = instruction.end

		self.end = off
		self.raw = file_interface.read(start, off-start)

	def __repr__(self):
		return '\n'.join(map(str, self.instructions))