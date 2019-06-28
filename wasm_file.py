#  parsing library made 
# Author: TACIXAT
import sys
from wasm_classes import File, FileInterface

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
