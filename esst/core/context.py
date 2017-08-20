# coding=utf-8

from asyncio import AbstractEventLoop
from queue import Queue
from click import Context as ClickContext


class Context:

    exit: bool = False
    loop: AbstractEventLoop = None
    click_context: ClickContext = None

    discord_start_bot: bool = False
    discord_msg_queue: Queue = Queue()

    dcs_start: bool = True
    dcs_install_hooks: bool = True
    dcs_setup_dedi_config: bool = True
    dcs_auto_mission: bool = True

    dcs_server_start: bool = True
    dcs_can_start: bool = True
    dcs_show_cpu_usage: bool = False
    dcs_show_cpu_usage_once: bool = False
    dcs_do_kill: bool = False
    dcs_do_restart: bool = False

    socket_start: bool = True
    socket_cmd_q: Queue = Queue()
    socket_monitor_server_startup: bool = False
