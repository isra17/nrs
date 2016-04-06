from nrs import fileform, nsisfile

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

def accept_file(li, n):
    li.seek(0)
    if n == 0 and fileform._find_firstheader(li):
        return "NSIS (NullSoft Installer)"
    return 0

def load_file(li, netflags, format):
    li.seek(0)
    nsis = nsisfile.NSIS(li)
    for name, n, sclass in BLOCKS:
        offset = nsis.header.blocks[n].offset
        content = nsis.block(n)
        # Create block segment
        seg = idaapi.segment_t()
        seg.startEA = offset
        seg.endEA = offset + len(content)
        idaapi.add_segm_ex(seg, name, sclass, 0)
        idaapi.mem2base(content, offset)
    return 1

