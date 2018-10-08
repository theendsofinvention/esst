# coding=utf-8
"""
Etcher's Server Startup Tool
"""

from pkg_resources import DistributionNotFound, get_distribution

try:
    __version__ = get_distribution('esst').version
except DistributionNotFound:  # pragma: no cover
    # package is not installed
    __version__ = 'not installed'

from ._esst_logging import LOGGER, LOGGING_CONSOLE_HANDLER
from esst.fs_paths import FS
