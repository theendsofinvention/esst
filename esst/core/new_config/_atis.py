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

    atis_create = ConfigProp(bool, default='true', namespace=NAMESPACE)
