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

SF_FLAGS = [
    'SF_SELECTED',
    'SF_SECGRP',
    'SF_SECGRPEND',
    'SF_BOLD',
    'SF_RO',
    'SF_EXPAND',
    'SF_PSELECTED',
    'SF_TOGGLED',
    'SF_NAMECHG',
]

PF_FLAGS = [
    'PF_LICENSE_SELECTED',
    'PF_NEXT_ENABLE',
    'PF_CANCEL_ENABLE',
    'PF_BACK_SHOW',
    'PF_LICENSE_STREAM',
    'PF_LICENSE_FORCE_SELECTION',
    'PF_LICENSE_NO_FORCE_SELECTION',
    'PF_NO_NEXT_FOCUS',
    'PF_BACK_ENABLE',
    'PF_PAGE_EX',
    'PF_DIR_NO_BTN_DISABLE',
]

PWP_ENUM = [
    'PWP_LICENSE',
    'PWP_SELCOM',
    'PWP_DIR',
    'PWP_INSTFILES',
    'PWP_UNINST',
    'PWP_COMPLETED',
    'PWP_CUSTOM',
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

def format_key(key, indent=0):
    return '\t'*(indent+1) + '{:<15}' .format(key + ': ')


def print_property(key, value, indent=0):
    if isinstance(value, int):
        print(format_key(key, indent) + '0x{:08x}'.format(value))
    elif isinstance(value, list):
        print(format_key(key, indent) +
                '[' + ', '.join(hex(x) for x in value) + ']')
    else:
        print(format_key(key, indent) + value)

def print_property_flag(key, value, flags_set, indent=0):
    flags = ' | '.join([flag for flag in flags_set
                if value & eval(flag, fileform.__dict__)])
    print(format_key(key, indent) + '0x{:08x} ( {} )'.format(value, flags))

def print_property_enum(key, value, enum_set, indent=0):
    flag = '<unknown>'
    if value < len(enum_set):
        flag = enum_set[value]
    print(format_key(key, indent) + '0x{:08x} ( {} )'.format(value, flag))

def print_property_string(key, value, nsis, indent=0):
    if value != 0xffffffff:
        string = nsis.get_string(value)
        print(format_key(key, indent) + '{!r} @ 0x{:08x}'.format(string, value))
    else:
        print_property(key, "''")

def print_string(value, indent=0):
    print(('\t'*indent) + '"' + (value) + '"')

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
                .format(nsis.firstheader.header_offset))
        print_property_flag('Flags', nsis.firstheader.flags, FH_FLAGS)
        print_property('Siginfo', nsis.firstheader.siginfo)
        print_property('Magics', nsis.firstheader.magics.decode())
        print_property('Header Size', nsis.firstheader.c_size)
        print_property('Inflated Size', nsis.firstheader.u_size)

        # NSIS inflated header.
        header = nsis.header
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
        print_property_string('install_directory_ptr',
                header.install_directory_ptr, nsis)
        print_property_string('install_directory_auto_append',
                header.install_directory_auto_append, nsis)
        print_property_string('str_uninstchild', header.str_uninstchild, nsis)
        print_property_string('str_uninstcmd', header.str_uninstcmd, nsis)
        print_property_string('str_wininit', header.str_wininit, nsis)

        # Dump installer strings.
        print()
        print_header('Strings')
        for string in nsis.get_all_strings():
            print_string(string, indent=1)

        # Dump installer page.
        print()
        print_header('Pages')
        for i, page in enumerate(nsis.pages):
            print_header('Page[{}]' .format(i), indent=1)
            print_property('dlg_id', page.dlg_id, indent=1)
            print_property_enum('wndproc_id', page.flags, PWP_ENUM, indent=1)
            print_property('prefunc', page.prefunc, indent=1)
            print_property('showfunc', page.showfunc, indent=1)
            print_property('leavefunc', page.leavefunc, indent=1)
            print_property_flag('flags', page.flags, PF_FLAGS, indent=1)
            print_property('caption', page.caption, indent=1)
            print_property('back', page.back, indent=1)
            print_property('next', page.next, indent=1)
            print_property('clicknext', page.clicknext, indent=1)
            print_property('cancel', page.cancel, indent=1)
            print_property('params', page.params, indent=1)

        # Dump installer entries.
        print()
        print_header('Entries')
        print_property('size', len(nsis.entries))

        # Dump installer sections.
        print()
        print_header('Sections')
        for i, section in enumerate(nsis.sections):
            print_header('Section[{}] - {}'
                .format(i, nsis.get_string(section.name_ptr)), indent=1)
            print_property_string('name_ptr', section.name_ptr, nsis, indent=1)
            print_property('install_types', section.install_types, indent=1)
            print_property_flag('flags', section.flags, SF_FLAGS, indent=1)
            print_property('code', section.code, indent=1)
            print_property('code_size', section.code_size, indent=1)
            print_property('size_kb', section.size_kb, indent=1)
            print_property('name', section.name.decode(), indent=1)


    except HeaderNotFound:
        sys.stderr.write('Error: Target it not an NSIS installer.' + os.linesep)
        sys.exit(1)


if __name__ == '__main__':
    nsis_target = sys.argv[1]
    dump_all(nsis_target)
