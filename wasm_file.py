#  parsing library for wasm file
# Author: TACIXAT
from wasm_classes import File, FileInterface
import argparse

def main():
    parser = argparse.ArgumentParser(description='Dump file information for WASM binary files.')
    parser.add_argument('--file', metavar='file.wasm', type=str, help='wasm file to be dumped', required=True)
    parser.add_argument('--output-file', metavar='file.wasm', type=str, help='wasm file to be written', required=False)
    parser.add_argument('--output-uint8', action='store_true', default=False)
    args = parser.parse_args()

    with open(args.file, 'rb+') as f:
        file_interface = FileInterface(f.read())

    wasm = File(file_interface)
    wasm.pretty_print()

    if args.output_file:
        with open(args.output_file, 'wb+') as f:
            f.write(wasm.bin())

    if args.output_uint8:
        b = wasm.bin()
        arr = ['%d' % ea for ea in b]
        print('const buf = new Uint8Array([%s]);' % ', '.join(arr))


if __name__ == '__main__':
    main()
