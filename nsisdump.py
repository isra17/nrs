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

CF_FLAGS = [
    'CH_FLAGS_DETAILS_SHOWDETAILS',
    'CH_FLAGS_DETAILS_NEVERSHOW',
    'CH_FLAGS_PROGRESS_COLORED',
    'CH_FLAGS_SILENT',
    'CH_FLAGS_SILENT_LOG',
    'CH_FLAGS_AUTO_CLOSE',
    'CH_FLAGS_DIR_NO_SHOW',
    'CH_FLAGS_NO_ROOT_DIR',
    'CH_FLAGS_COMP_ONLY_ON_CUSTOM',
    'CH_FLAGS_NO_CUSTOM',
]

BLOCK_NAMES = [
    'Pages',
    'Sections',
    'Entries',
    'Strings',
    'Langtables',
    'CtlColors',
    'BgFont',
    'Data'
]

def print_header(header, indent=0):
    print('\t'*indent + header)

def print_property(key, value, indent=0):
    key_fmt = '\t'*(indent+1) + '{:<15}' .format(key + ': ')
    if isinstance(value, int):
        print('{}0x{:08x}'.format(key_fmt, value))
    else:
        print('{}{}'.format(key_fmt, value))

def print_property_flag(key, value, flags_set, indent=0):
    key_fmt = '\t'*(indent*1) + '{:<15}' .format(key + ': ')
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
        print('')
        print_header('FirstHeader @ 0x{:x}'
                .format(nsis._firstheader.header_offset))
        print_property_flag('Flags', nsis._firstheader.flags, FH_FLAGS)
        print_property('Siginfo', nsis._firstheader.siginfo)
        print_property('Magics', nsis._firstheader.magics)
        print_property('Header Size', nsis._firstheader.c_size)
        print_property('Inflated Size', nsis._firstheader.u_size)

        # NSIS inflated header.
        header = nsis._header
        print('')
        print_header('Inflated header')
        print_property_flag('Flags', header.flags, CF_FLAGS)
        print_header('Blocks[{}]:'.format(len(header.blocks)))
        for block, name, i in zip(header.blocks, BLOCK_NAMES, range(8)):
            print_header('Block[{}] - {}:'.format(i, name), indent=1)
            print_property('Offset', block.offset, indent=1)
            print_property('Num', block.num, indent=1)

        print_property('install_reg_rootkey', header.install_reg_rootkey)
        print_property('install_reg_key_ptr', header.install_reg_key_ptr)
        print_property('install_reg_value_ptr', header.install_reg_value_ptr)
        print_property('bg_color1s', header.bg_color1s)
        print_property('bg_color2', header.bg_color2)
        print_property('bg_textcolor', header.bg_textcolor)
        print_property('lb_bg', header.lb_bg)
        print_property('lb_fg', header.lb_fg)
        print_property('langtable_size', header.langtable_size)
        print_property('license_bg', header.license_bg)
        print_property('code_onInit', header.code_onInit)
        print_property('code_onInstSucess', header.code_onInstSuccess)
        print_property('code_onInstFailed', header.code_onInstFailed)
        print_property('code_onUserAbort', header.code_onUserAbort)
        print_property('code_onGUIInit', header.code_onGUIInit)
        print_property('code_onGUIEnd', header.code_onGUIEnd)
        print_property('code_onMouseOverSection',
                header.code_onMouseOverSection)
        print_property('code_onVerifyInstDir', header.code_onVerifyInstDir)
        print_property('code_onSelChange', header.code_onSelChange)
        print_property('code_onRebootFailed', header.code_onRebootFailed)
        print_header('install_types:', indent=1)
        for i, t in enumerate(header.install_types):
            if t:
                print_property('install_types[{}]'.format(i), t, indent=1)
        print_property('install_directory_ptr', header.install_directory_ptr)
        print_property('install_directory_auto_append',
                header.install_directory_auto_append)
        print_property('str_uninstchild', header.str_uninstchild)
        print_property('str_uninstcmd', header.str_uninstcmd)
        print_property('str_wininit', header.str_wininit)

    except HeaderNotFound:
        sys.stderr.write('Error: Target it not an NSIS installer.' + os.linesep)
        sys.exit(1)


if __name__ == '__main__':
    nsis_target = sys.argv[1]
    dump_all(nsis_target)
