# coding=utf-8
"""
Represents the global context
"""

import inspect
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from queue import Queue


# TODO: Split context into the relevant modules
class Context:  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    """
    Represents the global context
    """
    @classmethod
    def get_context(cls) -> dict:
        """

        Returns: dict context for Sentry

        """
        return {
            member: value
            for member, value in inspect.getmembers(cls, lambda a: not inspect.ismethod(a))
            if not (member.startswith('_') or 'history' in member)
        }

    exit = False
    restart = False
    loop = None
    sentry = None
    wan = False
    process_pool = ProcessPoolExecutor(max_workers=1)

    start_listener_loop = True
    start_discord_loop = True
    start_server_loop = True
    start_dcs_loop = True

    discord_can_start = False
    discord_msg_queue = Queue()
    discord_file_queue = Queue()

    dcs_install_hooks = True
    dcs_setup_dedi_config = True
    dcs_auto_mission = True

    dcs_can_start = False
    dcs_blocker = []
    dcs_show_cpu_usage = False
    dcs_show_cpu_usage_once = False
    dcs_do_kill = False
    dcs_do_queued_kill = False
    dcs_do_restart = False
    dcs_cpu_history = deque(maxlen=17280)
    dcs_mem_history = deque(maxlen=17280)

    listener_cmd_queue = Queue()
    listener_monitor_server_startup = False

    server_show_cpu_usage = False
    server_show_cpu_usage_once = False
    server_cpu_history = deque(maxlen=17280)
    server_mem_history = deque(maxlen=17280)
    server_bytes_sent_history = deque(maxlen=17280)
    server_bytes_recv_history = deque(maxlen=17280)

    players_history = deque(maxlen=17280)

    atis_speech = ''
