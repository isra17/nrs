import struct
import zlib
from collections import namedtuple

# First header flags.
FH_FLAGS_UNINSTALL = 1
FH_FLAGS_SILENT = 2
FH_FLAGS_NO_CRC = 4
FH_FLAGS_FORCE_CRC = 8

# First header signature.
FH_SIG = 0xDEADBEEF
FH_MAGICS = b'NullsoftInst'

# Common flags.
CH_FLAGS_DETAILS_SHOWDETAILS = 1
CH_FLAGS_DETAILS_NEVERSHOW = 2
CH_FLAGS_PROGRESS_COLORED = 4
CH_FLAGS_SILENT = 8
CH_FLAGS_SILENT_LOG = 16
CH_FLAGS_AUTO_CLOSE = 32
CH_FLAGS_DIR_NO_SHOW = 64
CH_FLAGS_NO_ROOT_DIR = 128
CH_FLAGS_COMP_ONLY_ON_CUSTOM = 256
CH_FLAGS_NO_CUSTOM = 512

# Block type enumaration.
NB_PAGES = 0
NB_SECTIONS = 1
NB_ENTRIES = 2
NB_STRINGS = 3
NB_LANGTABLES = 4
NB_CTLCOLORS = 5
NB_BGFONT = 6
NB_DATA = 7

# Callback enumeration.
CB_ONINIT = 0
CB_ONINSTSUCCESS = 1
CB_ONINSTFAILED = 2
CB_ONUSERABORT = 3
#ifdef NSIS_CONFIG_ENHANCEDUI_SUPPORT
CB_ONGUIINIT = 4
CB_ONGUIEND = 5
CB_ONMOUSEOVERSECTION = 6
#endif NSIS_CONFIG_ENHANCEDUI_SUPPORT
CB_ONVERIFYINSTDIR = 7
#ifdef NSIS_CONFIG_COMPONENTPAGE
CB_ONSELCHANGE = 8
#endif NSIS_CONFIG_COMPONENTPAGE
#ifdef NSIS_SUPPORT_REBOOT
CB_ONREBOOTFAILED = 9
#endif NSIS_SUPPORT_REBOOT

# Section flags.
SF_SELECTED = 1
SF_SECGRP = 2
SF_SECGRPEND = 4
SF_BOLD = 8
SF_RO = 16
SF_EXPAND = 32
SF_PSELECTED = 64
SF_TOGGLED = 128
SF_NAMECHG = 256

# Page window proc.
#ifdef NSIS_CONFIG_LICENSEPAGE
PWP_LICENSE = 0
#endif NSIS_CONFIG_LICENSEPAGE
#ifdef NSIS_CONFIG_COMPONENTPAGE
PWP_SELCOM = 1
#endif NSIS_CONFIG_COMPONENTPAGE
PWP_DIR = 2
PWP_INSTFILES = 3
#ifdef NSIS_CONFIG_UNINSTALL_SUPPORT
PWP_UNINST = 4
#endif NSIS_CONFIG_UNINSTALL_SUPPORT
PWP_COMPLETED = 5
PWP_CUSTOM = 6

# Page flags.
PF_LICENSE_SELECTED = 1
PF_NEXT_ENABLE = 2
PF_CANCEL_ENABLE = 4
PF_BACK_SHOW = 8
PF_LICENSE_STREAM = 16
PF_LICENSE_FORCE_SELECTION = 32
PF_LICENSE_NO_FORCE_SELECTION = 64
PF_NO_NEXT_FOCUS = 128
PF_BACK_ENABLE = 256
PF_PAGE_EX = 512
PF_DIR_NO_BTN_DISABLE = 1024

# Text and background color.
CC_TEXT = 1
CC_TEXT_SYS = 2
CC_BK = 4
CC_BK_SYS = 8
CC_BKB = 16

# Delete flags.
DEL_DIR = 1
DEL_RECURSE = 2
DEL_REBOOT = 4
DEL_SIMPLE = 8

# Strings escape characters.
NS_LANG_CODE = 1
NS_SHELL_CODE = 2
NS_VAR_CODE = 3
NS_SKIP_CODE = 4

NSIS_MAX_STRLEN = 1024
NSIS_MAX_INST_TYPES = 32

MAX_ENTRY_OFFSETS = 6

BLOCKS_COUNT = 8

# First header with magic constant found in any NSIS executable.
class FirstHeader(namedtuple('FirstHeader', ['flags', 'siginfo', 'magics',
                                             'u_size', 'c_size'])):
    header_offset = 0
    data_offset = 0
    header = None

# Compressed header with the installer's sections and properties.
class Header(namedtuple('Header', [
            'flags',
            'raw_blocks',
            'install_reg_rootkey',
            'install_reg_key_ptr', 'install_reg_value_ptr',
            #ifdef NSIS_SUPPORT_BGBG
                'bg_color1s',
                'bg_color2',
                'bg_textcolor',
            #ifdef NSIS_CONFIG_VISIBLE_SUPPORT
                'lb_bg',
                'lb_fg',
            'langtable_size',
            #ifdef NSIS_CONFIG_LICENSEPAGE
                'license_bg',
            #ifdef NSIS_SUPPORT_CODECALLBACKS
                'code_onInit',
                'code_onInstSuccess',
                'code_onInstFailed',
                'code_onUserAbort',
                #ifdef NSIS_CONFIG_ENHANCEDUI_SUPPORT
                    'code_onGUIInit',
                    'code_onGUIEnd',
                    'code_onMouseOverSection',
                'code_onVerifyInstDir',
                #ifdef NSIS_CONFIG_COMPONENTPAGE
                    'code_onSelChange',
                #ifdef NSIS_SUPPORT_REBOOT
                    'code_onRebootFailed',
            #ifdef NSIS_CONFIG_COMPONENTPAGE
                'raw_install_types', # int * 32 + 1
            'install_directory_ptr',
            'install_directory_auto_append',
            #ifdef NSIS_CONFIG_UNINSTALL_SUPPORT
                'str_uninstchild',
                'str_uninstcmd',
            #ifdef NSIS_SUPPORT_MOVEONREBOOT
                'str_wininit'
        ])):
    blocks = []
    install_types = []

# Block header with location and size.
BlockHeader = namedtuple('BlockHeader', 'offset num')

Section = namedtuple('Section', [
        'name_ptr', # Initial name pointer.
        'install_types', # Bitset for the install types.
        'flags', # Flags from SF_*.
        'code', # Code location.
        'code_size', # Size of the code.
        'size_kb',
        'name' # Empty for invisible sections.
    ])

Entry = namedtuple('Entry', [
        'which', # EW_* enum.
        'offset', # Meaning depends on |which|.
    ])

Page = namedtuple('Page', [
        'dlg_id', # Dialog resource ID.
        'wndproc_id',
        #ifdef NSIS_SUPPORT_CODECALLBACKS
            'prefunc', # Called before the page is created.
            'showfunc', # Called right before the page is shown.
            'leavefunc', # Called when the user leaves the page.
        'flags',
        'caption',
        'back',
        'next',
        'clicknext',
        'cancel',
        'params'
    ])

CtlColors32 = namedtuple('CtlColors32', [
        'text',
        'bkc',
        'lbStyle',
        'bkb',
        'bkmode',
        'flags'
    ])


_firstheader_pack = struct.Struct("<II12sII")
_header_pack = struct.Struct("<I64s20I{}s5I".format(4*(NSIS_MAX_INST_TYPES+1)))
_blockheader_pack = struct.Struct("<II")
_section_pack = struct.Struct("<6I{}s".format(NSIS_MAX_STRLEN))
_entry_pack = struct.Struct("<I{}s".format(MAX_ENTRY_OFFSETS*4))
_page_pack = struct.Struct("<11I20s")
_ctlcolors32_pack = struct.Struct("<6I")

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

            if firstheader.siginfo == FH_SIG and \
                    firstheader.magics == FH_MAGICS:
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
            struct.unpack_from('<I', header.raw_install_types[i:])[0]
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
