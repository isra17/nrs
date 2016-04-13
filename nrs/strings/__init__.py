import struct
from . import nsis2, nsis3
from .common import SYSVAR_NAMES

def symbolize(block, offset, version='3'):
    if version == '3':
        return nsis3.symbolize(block, offset)
    elif version == '2':
        return nsis2.symbolize(block, offset)
    else:
        raise Exception('Unknown NSIS version: ' + repr(version))

def decode(block, offset=0, version='3'):
    symbols, i = symbolize(block, offset, version)
    string = ''
    for s in symbols:
        string += str(s)
    return string, i

