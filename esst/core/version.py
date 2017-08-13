# coding=utf-8
"""
Manages ESST version
"""

from pkg_resources import get_distribution, DistributionNotFound

try:
    __version__ = get_distribution('esst').version
except DistributionNotFound:
    __version__ = 'script'

__all__ = ['__version__']
