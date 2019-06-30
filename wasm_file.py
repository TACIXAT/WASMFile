#  parsing library made 
# Author: TACIXAT
from wasm_classes import File, FileInterface
import argparse

def main():
	parser = argparse.ArgumentParser(description='Dump file information for WASM binary files.')
	parser.add_argument('--file', metavar='file.wasm', type=str, help='wasm file to be dumped', required=True)
	parser.add_argument('--output-file', metavar='file.wasm', type=str, help='wasm file to be written', required=False)
	args = parser.parse_args()

	with open(args.file, 'rb+') as f:
		file_interface = FileInterface(f.read())

	wasm = File(file_interface)
	wasm.pretty_print()

	if args.output_file:
		with open(args.output_file, 'wb+') as f:
			f.write(wasm.bin())

if __name__ == '__main__':
	main()
