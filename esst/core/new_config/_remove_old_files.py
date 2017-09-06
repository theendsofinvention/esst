# coding=utf-8
"""
Clean folders of old files
"""

from elib.config import ConfigProp


class RemoveOldFile:
    """
    Clean folders of old files
    """

    @ConfigProp(list, default='')
    def remove_files(self) -> list:
        """
        List of folders to clean
        """
        pass
