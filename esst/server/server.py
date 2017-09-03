# coding=utf-8
"""
Manages the server computer
"""

import datetime
import time

import psutil

from esst.commands import DISCORD
from esst.core import CTX, MAIN_LOGGER, ServerStatus

LOGGER = MAIN_LOGGER.getChild(__name__)


class App:
    """
    Manages the server computer
    """

    def __init__(self):

        if not CTX.start_server_loop:
            LOGGER.debug('skipping server loop init')
            return

        ServerStatus.logical_cpus = psutil.cpu_count()
        ServerStatus.physical_cpus = psutil.cpu_count(logical=False)
        ServerStatus.cpu_frequency = psutil.cpu_freq().max
        ServerStatus.total_memory = psutil.virtual_memory().total
        ServerStatus.swap_size = psutil.swap_memory().total
        ServerStatus.boot_time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _update_status():
        while not CTX.exit:
            cpu_usage = psutil.cpu_percent(1)
            CTX.server_cpu_history.append(cpu_usage)
            ServerStatus.cpu_usage = cpu_usage
            ServerStatus.free_memory = psutil.virtual_memory().free
            ServerStatus.mem_usage = ServerStatus.free_memory / ServerStatus.total_memory * 100
            CTX.server_mem_history.append(ServerStatus.mem_usage)
            ServerStatus.swap_used = psutil.swap_memory().used
            if CTX.server_show_cpu_usage or CTX.server_show_cpu_usage_once:
                DISCORD.say(f'Server cpu usage: {cpu_usage}%')
                CTX.server_show_cpu_usage_once = False
            time.sleep(5)

    async def run(self):
        """
        Entry point of the loop
        """
        if not CTX.start_server_loop:
            LOGGER.debug('skipping server loop')
            return
        CTX.loop.run_in_executor(None, self._update_status)

        LOGGER.debug('end of Server computer loop')
