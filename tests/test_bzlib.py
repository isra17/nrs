from nrs.ext import bzlib

def test_decompress():
    assert None == bzlib.decompress(b'')
