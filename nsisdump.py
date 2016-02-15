from nrs.nsisfile import NSIS, HeaderNotFound
import pefile
import sys
import os

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
    except HeaderNotFound:
        sys.stderr.write('Error: Target it not an NSIS installer.' + os.linesep)
        sys.exit(1)
