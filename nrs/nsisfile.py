import re
from builtins import bytes
from . import fileform, strings

from .fileform import NB_BGFONT, NB_DATA, NB_PAGES, NB_ENTRIES, NB_ENTRIES, \
                      NB_STRINGS, NB_SECTIONS, NB_CTLCOLORS, NB_LANGTABLES

def _flatten(l):
    return [i for sl in l for i in sl]

class HeaderNotFound(Exception):
    pass

class NSIS:
    @staticmethod
    def from_path(path):
        with open(path, 'rb') as fd:
            return NSIS(fd)

    def __init__(self, fd):
        """
        Create a new NSIS instance given an NSIS installer loaded in |fd|.
        """
        self._block_cache = {}
        self._pe = None

        self.fd = fd
        """ Parsed installer file. """

        self.firstheader = None
        """ Firstheader structure found at the beginning of the NSIS blob. """

        self.header = None
        """
        Header structure found at the beginning of the uncompressed NSIS blob.
        """

        self.sections = []
        """ List of sections installable by the installer. """

        self.entries = []
        """ Installer instructions. """

        self.pages = []
        """ Installer pages. """

        if not self._parse():
            raise HeaderNotFound()

    def get_version(self):
        """ Lookup for the NSIS version of the NSIS installer. """
        version_regex = re.compile(r'Nullsoft Install System v(\w+\.\w+)')

        for string in self.get_all_strings():
            match = version_regex.search(string)
            if match:
                return match.group(1)

        pe = self._get_pe()
        if pe:
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

                for entry in manifest_entries:
                    for data in get_entry_datas(entry):
                        string = pe.get_data(data.struct.OffsetToData,
                                             data.struct.Size).decode()
                        match = version_regex.search(string)
                        if match:
                            return match.group(1)

    def get_string(self, address):
        """ Returns an NSIS expanded string given its |address|. """
        return self._parse_string(address)[0]

    def get_raw_string(self, address):
        """ Returns a raw NSIS string given its |address|. """
        string = bytearray()
        for c in self.block(NB_STRINGS)[address:]:
            if c == 0:
                break
            string.append(c)
        return string

    def get_all_strings(self):
        """ Returns all NSIS strings extracted from the strings section. """
        string_block_size = len(self.block(NB_STRINGS))
        offset = 0
        strings = []
        while offset < string_block_size:
            string, processed = self._parse_string(offset)
            if string:
                strings.append(string)
            offset += processed

        return strings

    def block(self, n):
        """ Return a block data given a NB_* enum |n| value. """
        if n not in self._block_cache:
            start = self.header.blocks[n].offset
            try:
                end = next(b.offset for b
                        in self.header.blocks[n+1:] if b.offset > 0)
            except StopIteration:
                end = len(self.header.blocks)
            self._block_cache[n] = self.firstheader._raw_header[start:end]
        return self._block_cache[n]

    def close(self):
        if self._pe is not None:
            self._pe.close()

    def _parse_string(self, address):
        """ Returns an NSIS expanded string given its |address|. """
        return strings.decode(self.block(NB_STRINGS), address)


    def _get_pe(self):
        """ Lazilly load a PE instance from the NSIS installer. """
        try:
            import pefile
            if self._pe is None:
                self._pe = pefile.PE(self.path)
        except:
            pass

        return self._pe

    def _parse(self):
        self.firstheader = fileform._find_firstheader(self.fd)
        if self.firstheader is None:
            return False

        self.header = fileform._extract_header(self.fd, self.firstheader)

        self.pages = fileform._parse_pages(
                self.block(NB_PAGES),
                self.header.blocks[NB_PAGES].num)

        self.sections = fileform._parse_sections(
                self.block(NB_SECTIONS),
                self.header.blocks[NB_SECTIONS].num)

        self.entries = fileform._parse_entries(
                self.block(NB_ENTRIES),
                self.header.blocks[NB_ENTRIES].num)
        return True
