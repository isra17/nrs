from nrs.nsisfile import NSIS, HeaderNotFound
from nrs import fileform
import pefile
import sys
import os

FH_FLAGS = [
    'FH_FLAGS_UNINSTALL',
    'FH_FLAGS_SILENT',
    'FH_FLAGS_NO_CRC',
    'FH_FLAGS_FORCE_CRC',
]

def print_header(header):
    print(os.linesep + header)

def print_property(key, value):
    key_fmt = '\t{:<15}' .format(key + ': ')
    if isinstance(value, int):
        print('{}0x{:08x}'.format(key_fmt, value))
    else:
        print('{}{}'.format(key_fmt, value))

def print_property_flag(key, value, flags_set):
    key_fmt = '\t{:<15}' .format(key + ': ')
    flags = ' | '.join([flag for flag in flags_set
                if value & eval(flag, fileform.__dict__)])
    print('{}0x{:08x} ( {} )'.format(key_fmt, value, flags))

def dump_all(path):
    try:
        nsis = NSIS(path)

        # NSISDump version info.
        print('NSISDump v0.1' + os.linesep)

        # NSIS basic information.
        print('Installer path: ' + path)
        nsis_version = nsis.get_version()
        if nsis_version:
            print('NSIS version: ' + nsis_version)
        else:
            print('NSIS version not found')

        # NSIS firstheader.
        print_header('FirstHeader @ 0x{:x}'
                .format(nsis._firstheader.header_offset))
        print_property_flag('Flags', nsis._firstheader.flags, FH_FLAGS)
        print_property('Siginfo', nsis._firstheader.siginfo)
        print_property('Magics', nsis._firstheader.magics)
        print_property('Header Size', nsis._firstheader.c_size)
        print_property('Inflated Size', nsis._firstheader.u_size)


    except HeaderNotFound:
        sys.stderr.write('Error: Target it not an NSIS installer.' + os.linesep)
        sys.exit(1)


if __name__ == '__main__':
    nsis_target = sys.argv[1]
    dump_all(nsis_target)
