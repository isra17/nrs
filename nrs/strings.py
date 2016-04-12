import struct
from . import fileform

# Strings escape characters.
NS_LANG_CODE = 1
NS_SHELL_CODE = 2
NS_VAR_CODE = 3
NS_SKIP_CODE = 4

SYSVAR_NAMES = {
    20: b'COMMANDLINE',
    21: b'INSTALLDIR',
    22: b'OUTPUTDIR',
    23: b'EXEDIR',
    24: b'LANGUAGE',
    25: b'TEMPDIR',
    26: b'PLUGINSDIR',
    27: b'EXEPATH',
    28: b'EXEFILE',
    29: b'HWNDPARENT',
    30: b'CLICKNEXT',
}

ESCAPE_MAP = {
    0x9: b'$\\t',
    0xa: b'$\\n',
    0xd: b'$\\r',
    0x24:b'$$',
}


def _nvar_name(nvar):
    if nvar in SYSVAR_NAMES:
        return b'$' + SYSVAR_NAMES[nvar]
    elif nvar < 10:
        return b'$' + str(nvar).encode()
    elif nvar < 20:
        return b'$R' + str(nvar - 10).encode()
    else:
        return '$__var{}__'.format(nvar).encode()

def _langcode_name(nlang):
    return '$(LangString{})'.format(nlang).encode()

def _shell_name(param1, param2):
    return '$__SHELL_{}_{}__'.format(param1, param2).encode()

def decode(block, offset=0):
    """ Decode special characters found in NSIS strings. """
    string = bytearray()
    data = block[offset:]
    i = 0
    size = min(fileform.NSIS_MAX_STRLEN, len(data))
    while i < size:
        c = data[i]
        i += 1

        if c == 0:
            break

        if c < NS_SKIP_CODE:
            param1 = data[i]
            param2 = data[i+1]
            param = struct.unpack('<H', data[i:i+2])[0]
            param = (param1 & 0x7f) | ((param2 & 0x7f) << 7)

            i += 2
            if c == NS_SHELL_CODE:
                string += _shell_name(param1, param2)
            elif c == NS_VAR_CODE:
                string += _nvar_name(param)
            elif c == NS_LANG_CODE:
                string += _langcode_name(param)
        elif c == NS_SKIP_CODE:
            string += data[i]
            i += 1
        elif c in ESCAPE_MAP:
            string += ESCAPE_MAP[c]
        else:
            string.append(c)

    try:
        return (string.decode(), i)
    except UnicodeDecodeError:
        return (repr(str(string)), i)

