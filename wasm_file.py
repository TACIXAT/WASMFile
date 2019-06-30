# dumping utility for wasm file
# Author: TACIXAT
import argparse
from wasm_classes import File, FileInterface

def main():
    parser = argparse.ArgumentParser(
        description='Dump file information for WASM binary files.')
    parser.add_argument(
        '--file',
        metavar='file.wasm',
        type=str,
        help='wasm file to be dumped',
        required=True)
    parser.add_argument(
        '--output-file',
        metavar='file.wasm',
        type=str,
        help='wasm file to be written',
        required=False)
    parser.add_argument(
        '--output-uint8',
        action='store_true',
        default=False,
        help='output a javascript uint8 array')
    parser.add_argument(
        '--no-print',
        action='store_true',
        default=False,
        help='do not pretty print the module contents')
    args = parser.parse_args()

    with open(args.file, 'rb+') as in_file:
        file_interface = FileInterface(in_file.read())

    wasm = File(file_interface)

    if not args.no_print:
        wasm.pretty_print()

    if args.output_file:
        with open(args.output_file, 'wb+') as out_file:
            out_file.write(wasm.bin())

    if args.output_uint8:
        out = wasm.bin()
        arr = ['%d' % ea for ea in out]
        print('const buf = new Uint8Array([%s]);' % ', '.join(arr))

if __name__ == '__main__':
    main()
