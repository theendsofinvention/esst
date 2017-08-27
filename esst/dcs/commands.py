# coding=utf-8
# pylint: disable=missing-docstring

from esst.core import CTX, MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


class DCS:
    """
    Manages commands for the DCS application
    """

    @staticmethod
    def restart():
        """
        Sets the context to restart the DCS application
        """
        LOGGER.debug('setting context for DCS restart')
        CTX.dcs_do_restart = True

    @staticmethod
    def kill():
        LOGGER.debug('killing DCS application')
        CTX.dcs_do_kill = True

    @staticmethod
    def show_cpu_usage_once():
        LOGGER.debug('show cpu usage once')
        CTX.dcs_show_cpu_usage_once = True

    @staticmethod
    def show_cpu_usage_once_done():
        LOGGER.debug('show cpu usage once: done')
        CTX.dcs_show_cpu_usage_once = False

    @staticmethod
    def show_cpu_usage_start():
        LOGGER.debug('show cpu usage: start')
        CTX.dcs_show_cpu_usage = True

    @staticmethod
    def show_cpu_usage_stop():
        LOGGER.debug('show cpu usage: stop')
        CTX.dcs_show_cpu_usage = False

    @staticmethod
    def can_start():
        LOGGER.debug('DCS can start')
        CTX.dcs_can_start = True

    @staticmethod
    def cannot_start():
        LOGGER.debug('DCS can NOT start')
        CTX.dcs_can_start = False

    @staticmethod
    def get_mission_list():
        return []
        # yield from list_available_missions()
