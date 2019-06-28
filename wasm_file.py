#  parsing library made 
# Author: TACIXAT
import sys
from wasm_classes import File, FileInterface
import argparse

def main():
	parser = argparse.ArgumentParser(description='Dump file information for WASM binary files.')
	parser.add_argument('--file', metavar='file.wasm', type=str, help='wasm file to be dumped', required=True)
	args = parser.parse_args()

	with open(args.file, 'rb+') as f:
		file_interface = FileInterface(f.read())

	wasm = File(file_interface)
	wasm.pretty_print()

if __name__ == '__main__':
	main()
