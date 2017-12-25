# coding=utf-8
"""
Manages config params for Univers Radio
"""

from elib.config import ConfigProp

NAMESPACE = 'UR'


# pylint: disable=too-few-public-methods
class URConfig:
    """
    Manages config params for Univers Radio
    """

    @ConfigProp(str, '', namespace=NAMESPACE)
    def ur_path(self):
        """
        Path of the UR installation
        """
        pass
