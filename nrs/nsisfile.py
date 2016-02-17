import pefile
import re
from . import fileform

from .fileform import NB_BGFONT, NB_DATA, NB_PAGES, NB_ENTRIES, NB_ENTRIES, \
                      NB_STRINGS, NB_SECTIONS, NB_CTLCOLORS, NB_LANGTABLES

def _flatten(l):
    return [i for sl in l for i in sl]

class HeaderNotFound(Exception):
    pass

class NSIS:
    #
    def __init__(self, path):
        """
        Create a new NSIS instance given an NSIS installer located at |path|.
        """
        self.path = path
        if not self._parse(path):
            raise HeaderNotFound()

    def get_version(self):
        """ Lookup for the NSIS version of the NSIS installer. """
        pe = self._pe()
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            manifest_entries = [
                d for d in pe.DIRECTORY_ENTRY_RESOURCE.entries
                    if d.id == pefile.RESOURCE_TYPE['RT_MANIFEST']
            ]

            def get_entry_datas(entry):
                if hasattr(entry, 'data'):
                    return [entry.data]
                else:
                    return _flatten(get_entry_datas(entry) for entry
                                        in entry.directory.entries)

            version_regex = re.compile(r'Nullsoft Install System v(\w+\.\w+)<')

            for entry in manifest_entries:
                for data in get_entry_datas(entry):
                    string = pe.get_data(data.struct.OffsetToData,
                                         data.struct.Size).decode()
                    match = version_regex.search(string)
                    if match:
                        return match.group(1)

    def get_string(self, address):
        """ Returns an NSIS expanded string given its |address|. """
        string = ''
        for c in self.block(NB_STRINGS)[address:]:
            if c == 0:
                break
            string += chr(c)
        return string

    def block(self, n):
        """ Return a block data given a NB_* enum |n| value. """
        return self._firstheader.raw_header[self._header.blocks[n].offset:]

    # Lazilly load a PE instance from the NSIS installer.
    def _pe(self):
        import pefile
        if not hasattr(self, '__pe'):
            self.__pe = pefile.PE(self.path)

        return self.__pe

    def _parse(self, path):
        self._fd = open(path, 'rb')
        self._firstheader = fileform._find_firstheader(self._fd)
        if self._firstheader is None:
            return False

        self._header = fileform._extract_header(self._fd, self._firstheader)
        return True
