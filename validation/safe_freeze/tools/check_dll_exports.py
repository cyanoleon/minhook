# SPDX-License-Identifier: BSD-2-Clause
"""Read the built PE32/PE32+ export table without loading a DLL."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

EXPECTED = {'MH_Initialize', 'MH_Uninitialize', 'MH_CreateHook', 'MH_RemoveHook',
            'MH_EnableHook', 'MH_DisableHook', 'MH_QueueEnableHook', 'MH_QueueDisableHook',
            'MH_ApplyQueued', 'MH_CreateHookApi', 'MH_CreateHookApiEx', 'MH_StatusToString'}


def inspect(path, architecture):
    data = path.read_bytes()
    def get(fmt, offset):
        return struct.unpack_from('<' + fmt, data, offset)
    assert data[:2] == b'MZ'
    pe, = get('I', 0x3c)
    assert data[pe:pe+4] == b'PE\0\0'
    machine, count = get('HH', pe+4)
    assert machine == (0x8664 if architecture == 'x64' else 0x14c)
    optional_size, = get('H', pe+20)
    optional = pe+24
    magic, = get('H', optional)
    assert magic == (0x20b if architecture == 'x64' else 0x10b)
    directory = optional + (112 if magic == 0x20b else 96)
    export_rva, export_size = get('II', directory)
    assert export_rva and export_size >= 40 and 0 < count < 97
    sections = []
    for i in range(count):
        start = optional + optional_size + 40*i
        virtual_size, address, raw_size, raw_offset = get('IIII', start+8)
        characteristics, = get('I', start+36)
        sections.append((address, virtual_size, raw_size, raw_offset, characteristics))
    def offset(rva, size=1, executable=False):
        matches = [(raw_offset+rva-address, characteristics)
                   for address, virtual_size, raw_size, raw_offset, characteristics in sections
                   if address <= rva and rva+size <= address+max(raw_size, virtual_size)
                   and rva+size <= address+raw_size]
        assert len(matches) == 1, ('unmapped/ambiguous export RVA', rva)
        result, flags = matches[0]
        assert result+size <= len(data)
        assert not executable or flags & 0x20000000
        return result
    exported = offset(export_rva, 40)
    functions, names, function_table, name_table, ordinals = get('IIIII', exported+20)
    assert functions == names == len(EXPECTED)
    actual = []
    for i in range(names):
        name_rva, = get('I', offset(name_table+4*i, 4))
        at = offset(name_rva)
        end = data.index(b'\0', at, min(at+256, len(data)))
        name = data[at:end].decode('ascii')
        ordinal, = get('H', offset(ordinals+2*i, 2))
        assert ordinal < functions
        function_rva, = get('I', offset(function_table+4*ordinal, 4))
        assert not export_rva <= function_rva < export_rva+export_size
        offset(function_rva, executable=True)
        actual.append(name)
    assert len(set(actual)) == len(EXPECTED) and set(actual) == EXPECTED
    return {'path': str(path), 'architecture': architecture, 'sha256': hashlib.sha256(data).hexdigest(),
            'exports': sorted(actual), 'result': 'PASS'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', required=True, choices=['x64', 'Win32'])
    parser.add_argument('--configuration', required=True)
    parser.add_argument('--build', type=Path, required=True)
    args = parser.parse_args()
    dlls = list((args.build / args.configuration).glob('*.dll'))
    assert len(dlls) == 1, dlls
    result = inspect(dlls[0], args.architecture)
    (args.build / 'public-exports.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
