import struct
import zlib
from collections import namedtuple
class FirstHeader(
        namedtuple('FirstHeader', 'flags siginfo magics '
            'u_size c_size')):
    header_offset = 0
    data_offset = 0

BlocHeader = namedtuple('BlockHeader', 'offset num')

NB_PAGES = 0
NB_SECTIONS = 1
NB_ENTRIES = 2
NB_STRINGS = 3
NB_LANGTABLES = 4
NB_CTLCOLORS = 5
NB_BGFONT = 6
NB_DATA = 7

BLOCKS_NUM = 8

Header = namedtuple('Header',
        'flags '
        'blocks ' # BlockHeader * BLOCKS_NUM
        'install_reg_rootkey '
        'install_reg_key_ptr install_reg_value_ptr '
        'bg_color1 bg_color2 bg_textcolor '
        'lb_bg lb_fg '
        'langtable_size '
        'license_bg '
        'code_onInit '
        'code_onInstSuccess '
        'code_onInstFailed '
        'code_onUserAbort '
        'code_onGUIInit '
        'code_onGUIEnd '
        'code_onMouseOverSection '
        'code_onVerifyInstDir '
        'code_onSelChange '
        'code_onRebootFailed '
        'install_types ' # int * 32 + 1
        'install_directory_ptr '
        'install_directory_auto_append '
        'str_uninstchild '
        'str_uninstcmd '
        'str_wininit')

_header_pack = struct.Struct("<I64s20I132s5I")
_firstheader_pack = struct.Struct("<II12sII")

def _find_firstheader(nsis_file):
    firstheader_offset = 0
    pos = 0
    while True:
        chunk = nsis_file.read(32768 if firstheader_offset else 512)
        if len(chunk) < _firstheader_pack.size:
            return None

        if firstheader_offset == 0:
            firstheader = FirstHeader._make(
                    _firstheader_pack.unpack_from(chunk))
            firstheader.header_offset = pos
            firstheader.data_offset = pos + _firstheader_pack.size

            if firstheader.siginfo == 0xDEADBEEF and \
                    firstheader.magics == b'NullsoftInst':
                # NSIS header found.
                print("First header found at 0x{:x}".format(pos))
                return firstheader

        pos += len(chunk)

def _extract_header(nsis_file, firstheader):
    nsis_file.seek(firstheader.data_offset)
    data_size = struct.unpack('<I', nsis_file.read(4))[0]
    print('Data size: 0x{:x}'.format(data_size))

    if data_size & 0x80000000:
        # Data is deflated.
        data_size &= 0x7fffffff
        deflated_data = nsis_file.read(data_size)
        inflated_data = zlib.decompress(deflated_data, -zlib.MAX_WBITS)
    else:
        inflated_data = nsis_file.read(data_size)

    assert(len(inflated_data) == firstheader.u_size)

    return Header._make(_header_pack.unpack_from(inflated_data))

if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as nsis_file:
        firstheader = _find_firstheader(nsis_file)
        print(repr(_extract_header(nsis_file, firstheader)))
        print(repr(firstheader))
