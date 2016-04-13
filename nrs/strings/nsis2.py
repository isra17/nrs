# Strings escape characters.
NS_LANG_CODE = 255
NS_SHELL_CODE = 254
NS_VAR_CODE = 253
NS_SKIP_CODE = 252

def is_code(c):
    return c > NS_SKIP_CODE

