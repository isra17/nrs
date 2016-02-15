from nrs import nsisfile
import pytest
import utils
import os

def test_non_nsis():
    with pytest.raises(nsisfile.HeaderNotFound):
        nsis = nsisfile.NSIS(os.path.join(utils.SAMPLES_DIR, 'empty'))

def test_get_version():
    nsis = nsisfile.NSIS(os.path.join(utils.SAMPLES_DIR, 'example1.exe'))
    assert nsis.get_version() == '3.0b3'

