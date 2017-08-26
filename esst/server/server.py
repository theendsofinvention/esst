# coding=utf-8

import datetime
import time

import psutil

from esst.commands import DISCORD
from esst.core import CTX, MAIN_LOGGER, ServerStatus

LOGGER = MAIN_LOGGER.getChild(__name__)


class App:
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
            ServerStatus.cpu_usage = cpu_usage
            ServerStatus.free_memory = psutil.virtual_memory().free
            ServerStatus.swap_used = psutil.swap_memory().used
            if CTX.server_show_cpu_usage or CTX.server_show_cpu_usage_once:
                DISCORD.say(f'DCS cpu usage: {cpu_usage}%')
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
