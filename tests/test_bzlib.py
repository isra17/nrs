from nrs.ext import bzlib
from nrs import nsisfile
import os, utils

def test_decompress():
    with open(os.path.join(utils.SAMPLES_DIR, 'bz2.exe'), 'rb') as fd:
        nsisfile.NSIS(fd)
