from builtins import bytes
import struct
from . import nsis2, nsis3
from .. import fileform

SYSVAR_NAMES = {
    20: 'COMMANDLINE',
    21: 'INSTALLDIR',
    22: 'OUTPUTDIR',
    23: 'EXEDIR',
    24: 'LANGUAGE',
    25: 'TEMPDIR',
    26: 'PLUGINSDIR',
    27: 'EXEPATH',
    28: 'EXEFILE',
    29: 'HWNDPARENT',
    30: 'CLICKNEXT',
}

ESCAPE_MAP = {
    0x9: '$\\t',
    0xa: '$\\n',
    0xd: '$\\r',
    0x22: '$\\"',
    0x24:'$$',
}

class Symbol(object):
    def is_reg(self):
        return False
    def is_var(self):
        return False
    def is_nvar(self):
        return False
    def is_lang_code(self):
        return False
    def is_shell(self):
        return False
    def is_string(self):
        return False

class NVar(Symbol):
    def __init__(self, nvar):
        self.nvar = nvar

    def __str__(self):
        if self.nvar in SYSVAR_NAMES:
            return '$' + SYSVAR_NAMES[self.nvar]
        elif self.nvar < 10:
            return '$' + str(self.nvar)
        elif self.nvar < 20:
            return '$R' + str(self.nvar - 10)
        else:
            return '$__var{}__'.format(self.nvar)

    def is_nvar(self):
        return True

    def is_reg(self):
        return self.nvar < 20

    def is_var(self):
        return self.nvar >= 20

class LangCode(Symbol):
    def __init__(self, nlang):
        self.nlang = nlang

    def __str__(self):
        return '$(LangString{})'.format(self.nlang)

    def is_lang_code(self):
        return True

class Shell(Symbol):
    def __init__(self, param1, param2):
        self.param1 = param1
        self.param2 = param2

    def __str__(self):
        return '$__SHELL_{}_{}__'.format(self.param1, self.param2)

    def is_shell(self):
        return True

class String(Symbol, str):
    def is_string(self):
        return True

def _symbolize(block, offset, code_helper):
    """ Decode special characters found in NSIS strings. """

    symbols = []
    cur_string = ""
    data = bytes(block[offset:offset + fileform.NSIS_MAX_STRLEN])
    i = 0
    while i < len(data):
        c = data[i]
        i += 1

        if c == 0:
            break

        if code_helper.is_code(c):
            if cur_string:
                symbols.append(String(cur_string))
                cur_string = ""

            param1 = data[i]
            param2 = data[i+1]
            param = (param1 & 0x7f) | ((param2 & 0x7f) << 7)

            i += 2
            if c == code_helper.NS_SHELL_CODE:
                symbols.append(Shell(param1, param2))
            elif c == code_helper.NS_VAR_CODE:
                symbols.append(NVar(param))
            elif c == code_helper.NS_LANG_CODE:
                symbols.append(LangCode(param))
        elif c == code_helper.NS_SKIP_CODE:
            cur_string += data[i]
            i += 1
        elif c in ESCAPE_MAP:
            cur_string += ESCAPE_MAP[c]
        else:
            cur_string += chr(c)

    if cur_string:
        symbols.append(String(cur_string))

    return symbols, i

def symbolize(block, offset, version='3'):
    if version == '3':
        return _symbolize(block, offset, nsis3)
    elif version == '2':
        return _symbolize(block, offset, nsis2)
    else:
        raise Exception('Unknown NSIS version: ' + repr(version))

def decode(block, offset=0, version='3'):
    symbols, i = symbolize(block, offset, version)
    string = ''
    for s in symbols:
        string += str(s)
    return string, i

