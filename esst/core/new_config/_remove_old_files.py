# coding=utf-8
"""
Clean folders of old files
"""

from elib.config import ConfigProp


class RemoveOldFile:  # pylint: disable=too-few-public-methods
    """
    Clean folders of old files
    """

    remove_files = ConfigProp(list, default='')
