import nrs
import idaapi
import string
import nrs
from nrs import fileform, nsisfile

PTR_NONE = 0xffffffff

BLOCKS = [
    ('PAGES', fileform.NB_PAGES, 'DATA'),
    ('SECTIONS', fileform.NB_SECTIONS, 'DATA'),
    ('ENTRIES', fileform.NB_ENTRIES, 'CODE'),
    ('STRINGS', fileform.NB_STRINGS, 'DATA'),
    ('LANGTABLES', fileform.NB_LANGTABLES, 'DATA'),
    ('CTLCOLORS', fileform.NB_CTLCOLORS, 'DATA'),
    ('BGFONT', fileform.NB_BGFONT, 'DATA'),
    ('DATA', fileform.NB_DATA, 'DATA'),
]

allowed_name_char = string.ascii_letters + string.digits + '$'
def canonize_name(name):
    """ Limit names to a subset of ascii character. """
    return str(''.join([c if c in allowed_name_char else '_' for c in name]))

def align(addr):
    return (addr + 0xfff) & 0xfffff000

def accept_file(li, n):
    li.seek(0)
    if n == 0 and fileform._find_firstheader(li):
        return "NSIS (NullSoft Installer)"
    return 0

def load_file(li, netflags, format):
    nsis = nsisfile.NSIS.from_path(idaapi.get_input_file_path())

    # Create NSIS netnode.
    nsis_netnode = idaapi.netnode('$ NSIS', 0, True)
    nsis_netnode.hashset('VERSION_MAJOR', nsis.version_major)
    nsis_netnode.hashset('VERSION_MINOR', nsis.version_minor)

    # Create blocks segments.
    for name, n, sclass in BLOCKS:
        offset = nsis.header.blocks[n].offset
        if offset == 0:
            continue
        content = nsis.block(n)
        # Create block segment
        seg = idaapi.segment_t()
        seg.startEA = offset
        seg.endEA = offset + len(content)
        idaapi.add_segm_ex(seg, name, sclass, 0)
        idaapi.mem2base(content, offset)

    # Add one virtual segment to hold variables.
    var_seg = idaapi.segment_t()
    var_start = align(nsis.size())
    var_seg.startEA = var_start
    var_seg.endEA = var_start + 0x1000 # Size chosen arbitrarily, should be enough.
    idaapi.add_segm_ex(var_seg, 'VARS', 'BSS', 0)
    # Create standard vars.
    for i, v in enumerate(nrs.strings.SYSVAR_NAMES.values()):
        idaapi.do_name_anyway(var_seg.startEA + i + 20, '$' + v)

    code_base = nsis.header.blocks[fileform.NB_ENTRIES].offset
    # Create sections functions.
    for i, section in enumerate(nsis.sections):
        if section.code == PTR_NONE:
            continue
        name = nsis.get_string(section.name_ptr)
        if not name:
            name = '_section' + str(i)
        ea = code_base + nrs.entry_to_offset(section.code)
        cname = canonize_name(name)
        AddEntryPoint(ea, ea, cname, 1)

    # Mark pages handlers.
    for i, page in enumerate(nsis.pages):
        for fn in ['prefunc', 'showfunc', 'leavefunc']:
            addr = getattr(page, fn)
            if addr != PTR_NONE:
                name = '_page_{}_{}'.format(i, fn)
                ea = code_base + nrs.entry_to_offset(addr)
                AddEntryPoint(ea, ea, name, 1)

    # Mark installer handlers.
    for event in ['Init', 'InstSuccess', 'InstFailed', 'UserAbort', 'GUIInit',
                  'GUIEnd', 'MouseOverSection', 'VerifyInstDir', 'SelChange',
                  'RebootFailed']:
        addr = getattr(nsis.header, 'code_on'+event)
        if addr != PTR_NONE:
            name = '_on' + event
            ea = code_base + nrs.entry_to_offset(addr)
            AddEntryPoint(ea, ea, name, 1)

    # Create strings.
    """
    strings_data = nsis.block(fileform.NB_STRINGS)
    strings_off = nsis.header.blocks[fileform.NB_STRINGS].offset
    i = 0
    while i < len(strings_data):
        decoded_string, length = \
            nrs.strings.decode(strings_data, i, nsis.version_major)
        decoded_string = str(decoded_string)
        string_name = canonize_name(decoded_string)
        idaapi.make_ascii_string(strings_off + i, length, ASCSTR_C)
        idaapi.set_cmt(strings_off + i, decoded_string, True)
        idaapi.do_name_anyway(strings_off + i, string_name)
        i += length
    #"""


    # Set processor to nsis script.
    SetProcessorType("nsis", SETPROC_ALL|SETPROC_FATAL)
    return 1

