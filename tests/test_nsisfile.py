from nrs import nsisfile
import pytest
import utils
import os

def test_non_nsis():
    with pytest.raises(nsisfile.HeaderNotFound):
        nsis = nsisfile.NSIS(os.path.join(utils.SAMPLES_DIR, 'empty'))

def test_get_version():
    with nsisfile.NSIS(os.path.join(utils.SAMPLES_DIR, 'example1.exe')) as nsis:
        assert nsis.get_version() == '3.0b3'

def test_get_string():
    with nsisfile.NSIS(os.path.join(utils.SAMPLES_DIR, 'example1.exe')) as nsis:
        assert nsis.get_string(0x4e) == 'Example1'
        assert nsis.get_string(0x4a) == '$__SHELL_16_25__\\Example1'
        assert nsis.get_string(0x57) == '$INSTALLDIR'
        assert nsis.get_string(0x87) == '$(LangString2) Setup'

def test_get_raw_string():
    with nsisfile.NSIS(os.path.join(utils.SAMPLES_DIR, 'example1.exe')) as nsis:
        assert nsis.get_raw_string(0x4e) == b'Example1'
        assert nsis.get_raw_string(0x4a) == b'\x02\x10\x19\\Example1'
        assert nsis.get_raw_string(0x57) == b'\x03\x95\x80'
        assert nsis.get_raw_string(0x87) == b'\x01\x82\x80 Setup'

def test_get_all_strings():
    with nsisfile.NSIS(os.path.join(utils.SAMPLES_DIR, 'example1.exe')) as nsis:
        strings = nsis.get_all_strings()
        assert 'example1.nsi' in strings
        assert '$INSTALLDIR' in strings

def test_block():
    with nsisfile.NSIS(os.path.join(utils.SAMPLES_DIR, 'example1.exe')) as nsis:
        assert len(nsis.block(nsisfile.NB_PAGES)) == 0xc0
        assert len(nsis.block(nsisfile.NB_SECTIONS)) == 0x418
        assert len(nsis.block(nsisfile.NB_ENTRIES)) == 0x54
        assert len(nsis.block(nsisfile.NB_STRINGS)) == 0x362
        assert len(nsis.block(nsisfile.NB_LANGTABLES)) == 0xe6
        assert len(nsis.block(nsisfile.NB_CTLCOLORS)) == 0x0
        assert len(nsis.block(nsisfile.NB_BGFONT)) == 0x8
        assert len(nsis.block(nsisfile.NB_DATA)) == 0x8
