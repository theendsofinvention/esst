# coding=utf-8
"""
Manages the server computer
"""

import datetime
import time

import psutil

from esst import LOGGER
from esst.commands import DISCORD
from esst.core import CTX, ServerStatus
from esst.utils import now


# pylint: disable=too-few-public-methods


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
        ServerStatus.boot_time = datetime.datetime.fromtimestamp(
            psutil.boot_time()
        ).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _update_status():
        while not CTX.exit:

            cpu_usage = psutil.cpu_percent(1)

            net_io = psutil.net_io_counters()
            bytes_sent = net_io.bytes_sent
            bytes_recv = net_io.bytes_recv

            ServerStatus.cpu_usage = cpu_usage
            if CTX.server_show_cpu_usage or CTX.server_show_cpu_usage_once:
                DISCORD.say(f'Server cpu usage: {cpu_usage}%')
                CTX.server_show_cpu_usage_once = False

            ServerStatus.used_memory = ServerStatus.total_memory - psutil.virtual_memory().free
            ServerStatus.mem_usage = round(
                ServerStatus.used_memory / ServerStatus.total_memory * 100, 2)
            ServerStatus.swap_used = psutil.swap_memory().used

            now_ = now()
            CTX.server_cpu_history.append((now_, cpu_usage))
            CTX.server_mem_history.append((now_, ServerStatus.mem_usage))

            # noinspection PyProtectedMember
            if ServerStatus.bytes_recv_ != 0:
                bytes_sent_ = bytes_sent - ServerStatus.bytes_sent_
                bytes_recv_ = bytes_recv - ServerStatus.bytes_recv_
                ServerStatus.bytes_sent = bytes_sent_
                ServerStatus.bytes_recv = bytes_recv_
                CTX.server_bytes_sent_history.append((now_, bytes_sent_))
                CTX.server_bytes_recv_history.append((now_, bytes_recv_))
            ServerStatus.bytes_recv_ = bytes_recv
            ServerStatus.bytes_sent_ = bytes_sent

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
