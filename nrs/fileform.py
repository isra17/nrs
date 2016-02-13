import struct
import zlib
from collections import namedtuple

# Block type enumaration.
NB_PAGES = 0
NB_SECTIONS = 1
NB_ENTRIES = 2
NB_STRINGS = 3
NB_LANGTABLES = 4
NB_CTLCOLORS = 5
NB_BGFONT = 6
NB_DATA = 7

BLOCKS_COUNT = 8

# First header with magic constant found in any NSIS executable.
class FirstHeader(
        namedtuple('FirstHeader', 'flags siginfo magics '
            'u_size c_size')):
    header_offset = 0
    data_offset = 0
    header = None

# Compressed header with the installer's sections and properties.
class Header(namedtuple('Header', [
            'flags',
            'raw_blocks', # BlockHeader * BLOCKS_NUM
            'install_reg_rootkey',
            'install_reg_key_ptr', 'install_reg_value_ptr',
            'bg_color1s', 'bg_color2', 'bg_textcolor',
            'lb_bg', 'lb_fg',
            'langtable_size',
            'license_bg',
            'code_onInit',
            'code_onInstSuccess',
            'code_onInstFailed',
            'code_onUserAbort',
            'code_onGUIInit',
            'code_onGUIEnd',
            'code_onMouseOverSection',
            'code_onVerifyInstDir',
            'code_onSelChange',
            'code_onRebootFailed',
            'raw_install_types', # int * 32 + 1
            'install_directory_ptr',
            'install_directory_auto_append',
            'str_uninstchild',
            'str_uninstcmd',
            'str_wininit'
        ])):
    blocks = []
    install_types = []

# Block header with location and size.
BlockHeader = namedtuple('BlockHeader', 'offset num')

_firstheader_pack = struct.Struct("<II12sII")
_header_pack = struct.Struct("<I64s20I132s5I")
_blockheader_pack = struct.Struct("<II")

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
                return firstheader

        pos += len(chunk)

def _extract_header(nsis_file, firstheader):
    nsis_file.seek(firstheader.data_offset)
    data_size = struct.unpack('<I', nsis_file.read(4))[0]

    if data_size & 0x80000000:
        # Data is deflated.
        data_size &= 0x7fffffff
        deflated_data = nsis_file.read(data_size)
        inflated_data = zlib.decompress(deflated_data, -zlib.MAX_WBITS)
    else:
        inflated_data = nsis_file.read(data_size)

    assert(len(inflated_data) == firstheader.u_size)

    header = Header._make(_header_pack.unpack_from(inflated_data))
    firstheader.header = header
    firstheader.raw_header = inflated_data
    firstheader.raw_header_c_size = data_size

    # Parse the block headers.
    block_headers = []
    for i in range(BLOCKS_COUNT):
        header_offset = i * _blockheader_pack.size
        block_header = BlockHeader._make(_blockheader_pack.unpack_from(
            header.raw_blocks[header_offset:]))
        block_headers.append(block_header)
    header.blocks = block_headers

    # Parse the install types.
    header.install_types = [
            struct.unpack_from('<I', header.raw_install_types[i:])
                for i in range(0, len(header.raw_install_types), 4)]

    return header

def _extract_block(nsis_file, firstheader, block_id):
    header = firstheader.header
    if block_id == NB_DATA:
        nsis_file.seek(firstheader.data_offset + firstheader.raw_header_c_size)
        return nsis_file.read()

    return firstheader.raw_header[header.blocks[block_id].offset:]


if __name__ == '__main__':
    import sys
    with open(sys.argv[1], 'rb') as nsis_file:
        firstheader = _find_firstheader(nsis_file)
        print(repr(_extract_header(nsis_file, firstheader)))
        print(repr(firstheader))
