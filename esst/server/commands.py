# coding=utf-8
# pylint: disable=missing-docstring


import os

from esst.commands import DCS
from esst.core import CTX, MAIN_LOGGER
from esst.commands import DISCORD

from esst.utils.historygraph import make_history_graph

LOGGER = MAIN_LOGGER.getChild(__name__)


class SERVER:

    @staticmethod
    def reboot(force: bool = False):
        if DCS.there_are_connected_players():
            if not force:
                return 'there are connected players; cannot restart the server now (use "--force" to restart anyway)'
            else:
                LOGGER.warning('forcing restart with connected players')
        os.system('shutdown /r /t 30 /c "Reboot initialized by ESST"')

    @staticmethod
    def show_cpu_usage_once():
        LOGGER.debug('show cpu usage once')
        CTX.server_show_cpu_usage_once = True

    @staticmethod
    def show_cpu_usage_once_done():
        LOGGER.debug('show cpu usage once: done')
        CTX.server_show_cpu_usage_once = False

    @staticmethod
    def show_cpu_usage_start():
        LOGGER.debug('show cpu usage: start')
        CTX.server_show_cpu_usage = True

    @staticmethod
    def show_cpu_usage_stop():
        LOGGER.debug('show cpu usage: stop')
        CTX.server_show_cpu_usage = False

    @staticmethod
    def show_cpu_graph():
        LOGGER.debug('show cpu usage: graph')
        graph_file = make_history_graph()
        DISCORD.send(graph_file)
