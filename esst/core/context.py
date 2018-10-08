# coding=utf-8
"""
Represents the global context
"""
import inspect
import typing
from asyncio import AbstractEventLoop
from collections import deque
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
    loop: AbstractEventLoop
    sentry: typing.Any
    wan: bool = False

    start_listener_loop: bool = True
    start_discord_loop: bool = True
    start_server_loop: bool = True
    start_dcs_loop: bool = True

    discord_can_start: bool = False
    discord_msg_queue: Queue = Queue()
    discord_file_queue: Queue = Queue()

    dcs_install_hooks: bool = True
    dcs_setup_dedi_config: bool = True
    dcs_auto_mission: bool = True

    dcs_can_start: bool = False
    dcs_blocker: typing.List[str] = []
    dcs_show_cpu_usage: bool = False
    dcs_show_cpu_usage_once: bool = False
    dcs_do_kill: bool = False
    dcs_do_queued_kill: bool = False
    dcs_do_restart: bool = False
    dcs_cpu_history: deque = deque(maxlen=17280)
    dcs_mem_history: deque = deque(maxlen=17280)

    listener_cmd_queue: Queue = Queue()
    listener_monitor_server_startup: bool = False
    listener_server_port: int = -1
    listener_cmd_port: int = -1

    server_show_cpu_usage: bool = False
    server_show_cpu_usage_once: bool = False
    server_cpu_history: deque = deque(maxlen=17280)
    server_mem_history: deque = deque(maxlen=17280)
    server_bytes_sent_history: deque = deque(maxlen=17280)
    server_bytes_recv_history: deque = deque(maxlen=17280)

    players_history: deque = deque(maxlen=17280)

    atis_speech: str = ''
