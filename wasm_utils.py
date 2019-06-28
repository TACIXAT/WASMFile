import struct

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
