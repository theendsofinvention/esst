# coding=utf-8
"""
Manages config params for Univers Radio
"""

from elib.config import ConfigProp

NAMESPACE = 'ATIS'


# pylint: disable=too-few-public-methods
class ATISConfig:
    """
    Manages config params for Univers Radio
    """

    @ConfigProp(bool, True, namespace=NAMESPACE)
    def atis_create(self):
        """
        Path of the UR installation
        """
        pass
