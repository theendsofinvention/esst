# coding=utf-8
"""
Manages DCS application Windows process
"""
import asyncio
import time
from pathlib import Path

import psutil

from esst.commands import DISCORD, LISTENER
from esst.core import CFG, CTX, MAIN_LOGGER, Status
from esst.dcs.rotate_logs import rotate_dcs_log
from esst.utils import Win32FileInfo, now

from .dedicated import setup_config_for_dedicated_run
from .game_gui import install_game_gui_hooks
from .missions_manager import get_latest_mission_from_github

LOGGER = MAIN_LOGGER.getChild(__name__)

KNOWN_DCS_VERSIONS = [
    '1.5.6.5199',
    '1.5.7.8899',
    '1.5.7.9459',
    '1.5.7.10175',
]


# => 2.1.1.8491: use DCS.exe --old-login


async def get_dcs_process_pid():
    """
    Tries to obtain "DCS.exe" PID

    Returns: "DCS.exe" PID or False
    """
    for process in psutil.process_iter():
        try:
            if process.name().lower() == 'dcs.exe':
                return process.pid
        except psutil.NoSuchProcess:
            pass

    return False


class App:  # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """
    Manages DCS application Window process
    """
    # noinspection SpellCheckingInspection
    valid_priorities = {
        'idle': psutil.IDLE_PRIORITY_CLASS,
        'below_normal': psutil.BELOW_NORMAL_PRIORITY_CLASS,
        'normal': psutil.NORMAL_PRIORITY_CLASS,
        'above_normal': psutil.ABOVE_NORMAL_PRIORITY_CLASS,
        'high': psutil.HIGH_PRIORITY_CLASS,
        'realtime': psutil.REALTIME_PRIORITY_CLASS,
    }

    def __init__(self):
        self._app = None
        self.process_pid = None
        self._restart_ok = True

    @property
    def app(self) -> psutil.Process:
        """Process instance"""
        return self._app

    # noinspection PyMethodMayBeStatic
    async def _execute_cmd_chain(self, cmd_chain: list):
        while not CTX.exit:
            try:
                cmd = cmd_chain.pop(0)
                await cmd()
                await asyncio.sleep(0.1)
            except IndexError:
                return

    # noinspection PyMethodMayBeStatic
    async def _get_dcs_version_from_executable(self):
        dcs_exe = Path(CFG.dcs_path)
        if not dcs_exe.exists():
            raise RuntimeError(f'dcs.exe not found: {dcs_exe}')
        # noinspection PyBroadException
        try:
            Status.dcs_version = Win32FileInfo(
                str(dcs_exe.absolute())).file_version
            # SKIPPING DCS VERSION CHECK
            # if Status.dcs_version not in KNOWN_DCS_VERSIONS:
            #     error = f'sorry, but I am unable to manage this version of DCS: {Status.dcs_version}\n' \
            #             f'This safety check exists so ESST does not screw your DCS installation by ' \
            #             f'installing hooks into an unsupported DCS installation.'
            #     LOGGER.error(error)
            #     if CTX.sentry:
            #         CTX.sentry.captureMessage(
            #             'Unmanaged DCS version',
            #             data={'extra': {'version': Status.dcs_version}})
            #     CTX.exit = True
            #     return False
            # else:
            #     setup_config_for_dedicated_run()
            ####################################
            setup_config_for_dedicated_run()
            LOGGER.debug(f'DCS version: {Status.dcs_version}')
            return True
        # pylint: disable=bare-except
        except:  # noqa: E722
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

    def set_affinity(self):
        """
        Sets the DCS process CPU affinity to the CFG value
        """
        warned = False
        while True:
            if CFG.dcs_cpu_affinity:
                if CTX.exit:
                    return
                try:
                    if list(self._app.cpu_affinity()) != list(CFG.dcs_cpu_affinity):
                        LOGGER.debug(f'setting DCS process affinity to: {CFG.dcs_cpu_affinity}')
                        self._app.cpu_affinity(list(CFG.dcs_cpu_affinity))
                    warned = False
                except psutil.NoSuchProcess:
                    if not CTX.exit and not warned:
                        LOGGER.warning('DCS process does not exist')
                        warned = True
            else:
                LOGGER.warning('no affinity given in config file')
                return
            time.sleep(30)

    def set_priority(self):
        """
        Sets the DCS process CPU priority to the CFG value
        """
        warned = False
        time.sleep(15)
        while True:
            if CFG.dcs_cpu_priority:
                if CTX.exit:
                    return
                if CFG.dcs_cpu_priority not in self.valid_priorities.keys():
                    LOGGER.error(f'invalid priority: {CFG.dcs_cpu_priority}\n'
                                 f'Choose one of: {self.valid_priorities.keys()}')
                    return
                try:
                    if self.app.nice() != self.valid_priorities[CFG.dcs_cpu_priority]:
                        LOGGER.debug(
                            f'setting DCS process priority to: {CFG.dcs_cpu_priority}')
                        self.app.nice(self.valid_priorities[CFG.dcs_cpu_priority])
                except psutil.NoSuchProcess:
                    if not CTX.exit and not warned:
                        LOGGER.warning('DCS process does not exist')
                        warned = True
            else:
                LOGGER.warning('no priority given in config file')
                return
            time.sleep(30)

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
        rotate_dcs_log()

    # noinspection PyMethodMayBeStatic
    async def _update_application_status(self, status: str):
        if Status.dcs_application != status:
            Status.dcs_application = status
            LOGGER.info(f'DCS application is {status}')
            if status == 'starting':
                LISTENER.monitor_server_startup_start()

    async def kill_running_app(self):  # noqa: C901
        """
        Kills the running DCS.exe process
        """

        async def _ask_politely():
            if not self.app or not self.app.is_running():
                return True
            LOGGER.debug('sending socket command to DCS for graceful exit')
            LISTENER.exit_dcs()
            await asyncio.sleep(1)
            LOGGER.debug(
                f'waiting on DCS to close itself (grace period: {CFG.dcs_grace_period})')
            now_ = now()
            while self.app.is_running():
                await asyncio.sleep(1)
                if now() - now_ > CFG.dcs_grace_period:
                    LOGGER.debug('grace period time out!')
                    return False

            LOGGER.info('DCS closed itself, nice')
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
        await self.kill_running_app()
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
        while not CTX.exit:
            try:
                if self.app and self.app.is_running():
                    cpu_usage = int(self.app.cpu_percent(CFG.dcs_high_cpu_usage_interval))
                    mem_usage = int(self.app.memory_percent())
                    Status.dcs_cpu_usage = f'{cpu_usage}%'
                    if CTX.dcs_show_cpu_usage or CTX.dcs_show_cpu_usage_once:
                        DISCORD.say(f'DCS cpu usage: {cpu_usage}%')
                        CTX.dcs_show_cpu_usage_once = False
                    if CFG.dcs_high_cpu_usage:
                        if cpu_usage > CFG.dcs_high_cpu_usage and not Status.paused:
                            LOGGER.warning(
                                f'DCS cpu usage has been higher than {CFG.dcs_high_cpu_usage}%'
                                f' for {CFG.dcs_high_cpu_usage_interval} seconds')

                    now_ = now()
                    CTX.dcs_mem_history.append((now_, mem_usage))
                    CTX.dcs_cpu_history.append((now_, cpu_usage))

            except psutil.NoSuchProcess:
                pass

    async def run(self):
        """
        Entry point of the thread
        """
        if not CTX.start_dcs_loop:
            LOGGER.debug('skipping DCS application loop')
            return
        if not await self._get_dcs_version_from_executable():
            return
        await CTX.loop.run_in_executor(None, install_game_gui_hooks)
        await CTX.loop.run_in_executor(None, get_latest_mission_from_github)

        LOGGER.debug('starting DCS monitoring thread')
        if CTX.dcs_can_start:
            await self._try_to_connect_to_existing_dcs_application()
            await self._start_new_dcs_application_if_needed()
        cpu_monitor_thread = CTX.loop.run_in_executor(None, self.monitor_cpu_usage)
        cpu_affinity_thread = CTX.loop.run_in_executor(None, self.set_affinity)
        cpu_priority_thread = CTX.loop.run_in_executor(None, self.set_priority)
        while True:
            if CTX.exit:
                LOGGER.debug('interrupted by exit signal')
                await cpu_monitor_thread
                await cpu_affinity_thread
                await cpu_priority_thread
                break
            if CTX.dcs_can_start:
                await self._check_if_dcs_is_running()
                if not self.process_pid:
                    LOGGER.debug('DCS has stopped, re-starting')
                    await self.restart()
            if CTX.dcs_do_kill:
                await self.kill_running_app()
            if CTX.dcs_do_restart:
                await self.restart()
            await asyncio.sleep(0.1)

        LOGGER.debug('end of DCS loop')
