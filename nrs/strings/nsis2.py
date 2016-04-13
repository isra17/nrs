from .. import fileform
from . import common

# Strings escape characters.
NS_LANG_CODE = 255
NS_SHELL_CODE = 254
NS_VAR_CODE = 253
NS_SKIP_CODE = 252

def symbolize(block, offset):
    """ Decode special characters found in NSIS strings. """

    symbols = []
    cur_string = ""
    data = block[offset:offset + fileform.NSIS_MAX_STRLEN]
    i = 0
    while i < len(data):
        c = data[i]
        i += 1

        if c == 0:
            break

        if c > NS_SKIP_CODE:
            if cur_string:
                symbols.append(cur_string)
                cur_string = ""

            param1 = data[i]
            param2 = data[i+1]
            param = (param1 & 0x7f) | ((param2 & 0x7f) << 7)

            i += 2
            if c == NS_SHELL_CODE:
                symbols.append(common.Shell(param1, param2))
            elif c == NS_VAR_CODE:
                symbols.append(common.NVar(param))
            elif c == NS_LANG_CODE:
                symbols.append(common.LangCode(param))
        elif c == NS_SKIP_CODE:
            cur_string += data[i]
            i += 1
        elif c in common.ESCAPE_MAP:
            cur_string += common.ESCAPE_MAP[c]
        else:
            cur_string += chr(c)

    if cur_string:
        symbols.append(cur_string)

    return symbols, i

