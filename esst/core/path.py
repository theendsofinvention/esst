# coding=utf-8
# This is a copy-paste from another project, I won't update the dosctrings and everything here
# pylint: disable-all
import os

import pefile


class Win32FileInfo:
    def __init__(self, _path):

        self.__path = os.path.abspath(_path)
        self.__props = None
        self.__read_props()

    @property
    def comments(self):
        return self.__props.get('Comments')

    @property
    def internal_name(self):
        return self.__props.get('InternalName')

    @property
    def product_name(self):
        return self.__props.get('ProductName')

    @property
    def company_name(self):
        return self.__props.get('CompanyName')

    @property
    def copyright(self):
        return self.__props.get('LegalCopyright')

    @property
    def product_version(self):
        return self.__props.get('ProductVersion')

    @property
    def file_description(self):
        return self.__props.get('FileDescription')

    @property
    def trademark(self):
        return self.__props.get('LegalTrademarks')

    @property
    def private_build(self):
        return self.__props.get('PrivateBuild')

    @property
    def file_version(self):
        return self.__props.get('FileVersion')

    @property
    def fixed_version(self):
        return self.__props.get('fixed_version')

    @property
    def original_filename(self):
        return self.__props.get('OriginalFilename')

    @property
    def special_build(self):
        return self.__props.get('SpecialBuild')

    def __read_props(self):

        def _loword(dword):
            return dword & 0x0000ffff

        def _hiword(dword):
            return dword >> 16

        self.__props = {}

        try:
            pe = pefile.PE(self.__path)
        except pefile.PEFormatError as e:
            raise ValueError(e.value)
        else:
            ms = pe.VS_FIXEDFILEINFO.ProductVersionMS
            ls = pe.VS_FIXEDFILEINFO.ProductVersionLS
            self.__props['fixed_version'] = '.'.join(map(str, (_hiword(ms), _loword(ms), _hiword(ls), _loword(ls))))
            for file_info in pe.FileInfo:
                if file_info.Key == b'StringFileInfo':
                    for st in file_info.StringTable:
                        for entry in st.entries.items():
                            self.__props[entry[0].decode('latin_1')] = entry[1].decode('latin_1')
