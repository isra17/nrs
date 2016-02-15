from nrs.nsisfile import NSIS, HeaderNotFound
import pefile
import sys
import os

def print_header(header):
    print(os.linesep + header)

def print_property(key, value):
    key_fmt = '\t{:<15}' .format(key + ':')
    if isinstance(value, int):
        print('{}0x{:08x}'.format(key_fmt, value))
    else:
        print('{}{}'.format(key_fmt, value))

if __name__ == '__main__':
    nsis_target = sys.argv[1]
    try:
        nsis = NSIS(nsis_target)

        # NSISDump version info.
        print('NSISDump v0.1' + os.linesep)

        # NSIS basic information.
        print('Installer path: ' + nsis_target)
        nsis_version = nsis.get_version()
        if nsis_version:
            print('NSIS version: ' + nsis_version)
        else:
            print('NSIS version not found')

        # NSIS firstheader.
        print_header('FirstHeader @ 0x{:x}'
                .format(nsis._firstheader.header_offset))
        print_property('Flags', nsis._firstheader.flags)
        print_property('Siginfo', nsis._firstheader.siginfo)
        print_property('Magics', nsis._firstheader.magics)
        print_property('Header Size', nsis._firstheader.c_size)
        print_property('Inflated Size', nsis._firstheader.u_size)
    except HeaderNotFound:
        sys.stderr.write('Error: Target it not an NSIS installer.' + os.linesep)
        sys.exit(1)
