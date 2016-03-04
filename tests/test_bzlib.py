from nrs.ext import bzlib
from nrs import nsisfile
import os, utils

def test_decompress():
    #assert None == bzlib.decompress(b'')
    nsisfile.NSIS(os.path.join(utils.SAMPLES_DIR, 'bz2.exe'))
