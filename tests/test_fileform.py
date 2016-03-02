from nrs import fileform
import os
import utils

def test_findheader_not_found():
    # Header should not be found in non-nsisi files.
    with open(os.path.join(utils.SAMPLES_DIR, 'empty'), 'rb') as empty:
        assert fileform._find_firstheader(empty) is None

def test_findheader_found():
    # Header found in NSIS installer.
    with open(os.path.join(utils.SAMPLES_DIR, 'example1.exe'), 'rb') \
            as nsis_file:
        firstheader = fileform._find_firstheader(nsis_file)
        assert firstheader is not None
        assert firstheader.siginfo == 0xDEADBEEF
        assert firstheader.magics == b'NullsoftInst'
        assert firstheader.c_size < firstheader.u_size

def test_extract_header():
    with open(os.path.join(utils.SAMPLES_DIR, 'example1.exe'), 'rb') \
            as nsis_file:
        firstheader = fileform._find_firstheader(nsis_file)
        header = fileform._extract_header(nsis_file, firstheader)
        assert header is not None
        assert len(header.blocks) == fileform.BLOCKS_COUNT
        assert len(header.install_types) == 33

def test_extract_blocks():
    with open(os.path.join(utils.SAMPLES_DIR, 'example1.exe'), 'rb') \
            as nsis_file:
        firstheader = fileform._find_firstheader(nsis_file)
        header = fileform._extract_header(nsis_file, firstheader)

        for block_id in [fileform.NB_PAGES, fileform.NB_SECTIONS,
                fileform.NB_ENTRIES, fileform.NB_STRINGS,
                fileform.NB_LANGTABLES, fileform.NB_CTLCOLORS]:
            pages_block = fileform._extract_block(nsis_file, firstheader, block_id)
            assert pages_block is not None

def test_extract_vopackage():
    with open(os.path.join(utils.SAMPLES_DIR, 'vopackage'), 'rb') \
            as nsis_file:
        firstheader = fileform._find_firstheader(nsis_file)
        header = fileform._extract_header(nsis_file, firstheader)

        assert header is not None

