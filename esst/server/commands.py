# coding=utf-8
"""
Server machine commands
"""

import os

from esst import LOGGER
from esst.commands import DCS, DISCORD
from esst.core import CTX
from esst.utils.historygraph import make_history_graph


class SERVER:
    """
    Server machine commands
    """

    @staticmethod
    def reboot(force: bool = False):
        """Reboots the server computer"""
        if DCS.there_are_connected_players():
            if not force:
                return 'there are connected players; cannot restart the server now (use "--force" to restart anyway)'

            LOGGER.warning('forcing restart with connected players')
        os.system('shutdown /r /t 30 /c "Reboot initialized by ESST"')  # nosec
        return ''

    @staticmethod
    def show_cpu_usage_once():
        """Show CPU usage once"""
        LOGGER.debug('show cpu usage once')
        CTX.server_show_cpu_usage_once = True

    @staticmethod
    def show_cpu_usage_once_done():
        """Stop showing CPU usage once"""
        LOGGER.debug('show cpu usage once: done')
        CTX.server_show_cpu_usage_once = False

    @staticmethod
    def show_cpu_usage_start():
        """Starts showing CPU usage continuously"""
        LOGGER.debug('show cpu usage: start')
        CTX.server_show_cpu_usage = True

    @staticmethod
    def show_cpu_usage_stop():
        """Stops showing CPU usage continuously"""
        LOGGER.debug('show cpu usage: stop')
        CTX.server_show_cpu_usage = False

    @staticmethod
    def show_graph(days, hours, minutes):
        """Show resources usage graph"""

        def _show_graph(graph):
            if graph:
                DISCORD.send_file(graph)
            else:
                LOGGER.warning('failed to create the graph')

        make_history_graph(callback=_show_graph, days=days, hours=hours, minutes=minutes)

        # def _callback(future):
        #     if future.result():
        #         DISCORD.send_file(future.result())
        #     else:
        #         LOGGER.warning('failed to create the graph')
        #
        # LOGGER.debug('show cpu usage: graph')
        # make_history_graph(_callback, days, hours, minutes)
