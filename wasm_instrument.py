# parsing library made 
# Author: TACIXAT
from wasm_classes import File, FileInterface, SectionType
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

    signatures = set()
    for section in wasm.sections:
        if type(section) is SectionType:
            section.pretty_print()
            for proto in section.function_prototypes:
                param_types = []
                for param in proto.param_types:
                    param_types.append(param.type)
                signatures.add(tuple(param_types))

                result_types = []
                for param in proto.result_types:
                    result_types.append(param.type)
                signatures.add(tuple(result_types))

    print(signatures)
    for sig in signatures:
        for param in sig:
            print(param, end=' ')
        print()
        # create param memory serialization function

    # for param type
        # create restore function

    if args.output_file:
        with open(args.output_file, 'wb+') as f:
            f.write(wasm.bin())

    if args.output_uint8:
        b = wasm.bin()
        arr = ['%d' % ea for ea in b]
        print('const buf = new Uint8Array([%s]);' % ', '.join(arr))


if __name__ == '__main__':
    main()

# add imports functions that take those as args and return them 
# generate js for those imports
# callback interface

