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
    0x24:'$$',
}

class NVar:
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

    def is_reg(self):
        return self.nvar < 20

class LangCode:
    def __init__(self, nlang):
        self.nlang = nlang

    def __str__(self):
        return '$(LangString{})'.format(self.nlang)

class Shell:
    def __init__(self, param1, param2):
        self.param1 = param1
        self.param2 = param2

    def __str__(self):
        return '$__SHELL_{}_{}__'.format(self.param1, self.param2)

