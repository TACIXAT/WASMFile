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

def sleb128Dump(value):
    data = []
    while True:
        byte = value & 0x7F
        value >>= 7  
        sign_bit = bool(byte & 0x40)

        if (value == 0 and not sign_bit) or (value == -1 and sign_bit):
            data.append(byte)
            break
        else:
            data.append(byte | 0x80)
    return bytes(data)

def uleb128Dump(value):
    data = []  
    while True:
        byte = value & 0x7F
        value >>= 7
        if value == 0:
            # We are done!
            data.append(byte)
            break
        else:
            data.append(byte | 0x80) 
    return bytes(data)

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

def f32Dump(value):
	return struct.pack('<f', value)

def f64Dump(value):
	return struct.pack('<d', value)

def makeSectionBytes(section_id, payload):
	b = struct.pack('b', section_id)
	b += uleb128Dump(len(payload))
	b += payload
	return b