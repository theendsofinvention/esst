# coding=utf-8
"""
Manages DCS application Window process
"""
import asyncio
from collections import deque
from pathlib import Path

import psutil

from esst.commands import DISCORD, LISTENER
from esst.core import CFG, CTX, MAIN_LOGGER, Status
from esst.utils import Win32FileInfo, now
from .dedicated import setup_config_for_dedicated_run
from .game_gui import install_game_gui_hooks
from .missions_manager import get_latest_mission_from_github

LOGGER = MAIN_LOGGER.getChild(__name__)

KNOWN_DCS_VERSIONS = ['1.5.6.5199']


# => 2.1.1.8491: use DCS.exe --old-login


async def get_dcs_process_pid():
    """
    Tries to obtain "DCS.exe" PID

    Returns: "DCS.exe" PID or False
    """
    for process in psutil.process_iter():
        if process.name().lower() == 'dcs.exe':
            return process.pid

    return False


class App:  # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """
    Manages DCS application Window process
    """

    def __init__(self):
        self._app = None
        self.process_pid = None
        self._restart_ok = True

        if not CTX.dcs_start:
            LOGGER.debug('skipping startup of DCS application')
            return

        LOGGER.debug('starting DCS application thread')

    @property
    def app(self) -> psutil.Process:
        return self._app

    async def _execute_cmd_chain(self, cmd_chain: list):
        while not CTX.exit:
            try:
                cmd = cmd_chain.pop(0)
                await cmd()
                await asyncio.sleep(0.1)
            except IndexError:
                return

    async def _get_dcs_version_from_executable(self):
        dcs_exe = Path(CFG.dcs_path)
        if not dcs_exe.exists():
            raise RuntimeError(f'dcs.exe not found: {dcs_exe}')
        # noinspection PyBroadException
        try:
            Status.dcs_version = Win32FileInfo(str(dcs_exe.absolute())).file_version
            if Status.dcs_version not in KNOWN_DCS_VERSIONS:
                LOGGER.error(f'sorry, but I am unable to manage this version of DCS: {Status.dcs_version}\n'
                             f'This safety check exists so ESST does not screw your DCS installation '
                             f'by installing hooks into an unsupported DCS installation.')
                CTX.exit = True
            else:
                setup_config_for_dedicated_run()
            LOGGER.debug(f'DCS version: {Status.dcs_version}')
        except:  # pylint: disable=bare-except
            LOGGER.error('unable to retrieve version from dcs.exe')
            Status.dcs_version = 'unknown'
            raise

    async def _check_if_dcs_is_running(self):
        self.process_pid = await get_dcs_process_pid()
        if self.process_pid:
            await self._update_application_status('running')
        else:
            await self._update_application_status('not running')

    async def _try_to_connect_to_existing_dcs_application(self):
        if self.app and self.app.is_running():
            return
        LOGGER.debug('connecting to existing DCS application')
        await self._check_if_dcs_is_running()
        if self.process_pid:
            self._app = psutil.Process(self.process_pid)
            await self._wait_for_dcs_to_start()

    async def _wait_for_dcs_to_start(self):  # noqa: C901

        async def _wait_for_process():
            while True:
                if CTX.exit:
                    return
                await asyncio.sleep(0.1)
                if self.app.is_running():
                    break

        LOGGER.debug('waiting for DCS to spool up')
        await _wait_for_process()
        LOGGER.debug('process is ready')

    async def _start_new_dcs_application_if_needed(self):

        async def _start_dcs_app():
            LOGGER.debug(f'starting DCS application process: {CFG.dcs_path}')
            self._app = psutil.Popen(CFG.dcs_path)

        if self.app and self.app.is_running():
            return
        LOGGER.debug('starting new DCS application')
        cmd_chain = [
            _start_dcs_app,
            self._wait_for_dcs_to_start,
        ]
        await self._execute_cmd_chain(cmd_chain)
        await self._check_if_dcs_is_running()

    async def _update_application_status(self, status: str):
        if Status.dcs_application != status:
            Status.dcs_application = status
            LOGGER.info(f'DCS server is {status}')
            if status is 'starting':
                LISTENER.monitor_server_startup_start()

    async def _kill_running_app(self):  # noqa: C901

        async def _ask_politely():
            if not self.app or not self.app.is_running():
                return True
            LOGGER.debug('sending socket command to DCS for graceful exit')
            LISTENER.exit_dcs()
            await asyncio.sleep(1)
            LOGGER.debug('waiting on DCS to close itself')
            now_ = now()
            while self.app.is_running():
                await asyncio.sleep(1)
                if now() - now_ > 30:
                    return False
            else:
                return True

        async def _no_more_mr_nice_guy():
            if not self.app or not self.app.is_running():
                return True
            LOGGER.debug('killing dcs.exe application')
            self.app.kill()
            now_ = now()
            while self.app.is_running():
                await asyncio.sleep(1)
                if now() - now_ > 10:
                    return False
            else:
                return True

        CTX.dcs_do_kill = False
        await self._check_if_dcs_is_running()
        if not self.app or not self.app.is_running():
            LOGGER.debug('DCS process was not running')
            return
        LOGGER.info('closing DCS')
        if not await _ask_politely():
            LOGGER.info('DCS will not exit gracefully, killing it')
            if not await _no_more_mr_nice_guy():
                LOGGER.error('I was not able to kill DCS, something is wrong')
                raise RuntimeError()
        await self._check_if_dcs_is_running()

    async def restart(self):
        """
        Restarts DCS application
        """
        if CTX.exit:
            LOGGER.debug('restart interrupted by exit signal')
            return
        CTX.dcs_do_restart = False
        LOGGER.info('restarting DCS')
        await self._kill_running_app()
        Status.mission_file = 'unknown'
        Status.server_age = 'unknown'
        Status.mission_time = 'unknown'
        Status.paused = 'unknown'
        Status.mission_name = 'unknown'
        Status.players = []
        self._app = None
        self.process_pid = None
        cmd_chain = [
            self._start_new_dcs_application_if_needed,
        ]
        await self._execute_cmd_chain(cmd_chain)

    def monitor_cpu_usage(self):
        """
        Gets the CPU usage of "DCS.exe" over 5 seconds, and sends an alert if the given threshold is exceeded

        Threshold is set via the config value "DCS_HIGH_CPU_USAGE", and it defaults to 80%
        """
        collect = deque(maxlen=CFG.dcs_high_cpu_usage_interval)
        while True:
            if CTX.exit:
                break
            try:
                if self.app and self.app.is_running():
                    cpu_usage = int(self.app.cpu_percent(1)) / psutil.cpu_count()
                    collect.append(cpu_usage)
                    Status.dcs_cpu_usage = f'{cpu_usage}%'
                    if CTX.dcs_show_cpu_usage or CTX.dcs_show_cpu_usage_once:
                        DISCORD.say(f'DCS cpu usage: {cpu_usage}%')
                        CTX.dcs_show_cpu_usage_once = False
                    if sum(list(collect)) / CFG.dcs_high_cpu_usage_interval > CFG.dcs_high_cpu_usage:
                        if not Status.paused:
                            LOGGER.warning(
                                f'DCS cpu usage has been higher than {CFG.dcs_high_cpu_usage}%'
                                f' for {CFG.dcs_high_cpu_usage_interval} seconds')
            except psutil.NoSuchProcess:
                pass

    async def run(self):
        """
        Entry point of the thread
        """
        if not CTX.dcs_start:
            LOGGER.debug('skipping DCS application loop')
            return

        await CTX.loop.run_in_executor(None, install_game_gui_hooks)
        await CTX.loop.run_in_executor(None, get_latest_mission_from_github)

        LOGGER.debug('starting DCS monitoring thread')
        cmd_chain = [
            self._get_dcs_version_from_executable,
        ]
        if CTX.dcs_can_start:
            cmd_chain.extend(
                [
                    self._try_to_connect_to_existing_dcs_application,
                    self._start_new_dcs_application_if_needed,
                ]
            )
        await self._execute_cmd_chain(cmd_chain)
        cpu_monitor_thread = CTX.loop.run_in_executor(None, self.monitor_cpu_usage)
        while True:
            if CTX.exit:
                LOGGER.debug('interrupted by exit signal')
                await cpu_monitor_thread
                break
            if CTX.dcs_can_start:
                await self._check_if_dcs_is_running()
                if not self.process_pid:
                    LOGGER.debug('DCS has stopped, re-starting')
                    await self.restart()
            if CTX.dcs_do_kill:
                await self._kill_running_app()
            if CTX.dcs_do_restart:
                await self.restart()
            await asyncio.sleep(0.1)

        LOGGER.debug('end of DCS loop')

    async def exit(self):
        await self._kill_running_app()
