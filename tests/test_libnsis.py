from libnsis import bzip2

def test_bzip2():
    assert None == bzip2.decompress(b'')
