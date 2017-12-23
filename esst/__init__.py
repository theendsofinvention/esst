# coding=utf-8
"""
Etcher's Server Startup Tool
"""

from ._e_version import get_versions
__version__ = get_versions()['version']
del get_versions
