# coding=utf-8
"""
Represents the global context
"""

import inspect
from asyncio import AbstractEventLoop
from queue import Queue


class Context:
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
            if not member.startswith('_')
        }

    exit: bool = False
    loop: AbstractEventLoop = None
    sentry = None

    start_listener_loop: bool = True
    start_discord_loop: bool = True
    start_server_loop: bool = True
    start_dcs_loop: bool = True

    discord_msg_queue: Queue = Queue()
    discord_file_queue: Queue = Queue()

    dcs_install_hooks: bool = True
    dcs_setup_dedi_config: bool = True
    dcs_auto_mission: bool = True

    dcs_can_start: bool = True
    dcs_show_cpu_usage: bool = False
    dcs_show_cpu_usage_once: bool = False
    dcs_do_kill: bool = False
    dcs_do_restart: bool = False

    listener_cmd_queue: Queue = Queue()
    listener_monitor_server_startup: bool = False

    server_show_cpu_usage: bool = False
    server_show_cpu_usage_once: bool = False
