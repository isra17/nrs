# Strings escape characters.
NS_LANG_CODE = 1
NS_SHELL_CODE = 2
NS_VAR_CODE = 3
NS_SKIP_CODE = 4

def is_code(c):
    return c < NS_SKIP_CODE

