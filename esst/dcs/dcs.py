# coding=utf-8
"""
Manages DCS application Windows process
"""
import asyncio
import time

import psutil

from esst import DCSConfig, FS, LOGGER, commands, core, utils
from esst.dcs import autoexec_cfg, mission_editor_lua, missions_manager, server_settings
from .commands import DCS
from .dedicated import setup_config_for_dedicated_run
from .game_gui import install_game_gui_hooks


async def get_dcs_process_pid():
    """
    Tries to obtain "DCS.exe" PID

    Returns: "DCS.exe" PID or False
    """
    try:
        for process in psutil.process_iter():
            try:
                if process.name().lower() == 'dcs.exe':
                    return process.pid
            except psutil.NoSuchProcess:
                pass

        return False
    except OSError:
        asyncio.sleep(5)
        return await get_dcs_process_pid()


# pylint: disable=too-few-public-methods,too-many-instance-attributes
class App:
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
        self._blockers_warned = set()
        self._warned = False
        # self._additional_parameters = []

    @property
    def app(self) -> psutil.Process:
        """Process instance"""
        return self._app

    # noinspection PyMethodMayBeStatic
    async def _execute_cmd_chain(self, cmd_chain: list):
        while not core.CTX.exit:
            try:
                cmd = cmd_chain.pop(0)
                await cmd()
                await asyncio.sleep(0.1)
            except IndexError:
                return

    # noinspection PyMethodMayBeStatic
    async def _get_dcs_version_from_executable(self):
        # noinspection PyBroadException
        core.Status.dcs_version = utils.get_product_version(str(FS.dcs_exe))
        LOGGER.debug('DCS version: %s', core.Status.dcs_version)
        simplified_version = int(''.join(core.Status.dcs_version.split('.')[:3]))
        LOGGER.debug('simplified version: %s', simplified_version)
        if simplified_version <= 157:
            pass
        elif simplified_version >= 158:
            mission_editor_lua.inject_mission_editor_code()
            autoexec_cfg.inject_silent_crash_report()
        setup_config_for_dedicated_run()
        return True

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

    async def _wait_for_dcs_to_start(self):

        async def _wait_for_process():
            while True:
                if core.CTX.exit:
                    return
                await asyncio.sleep(0.1)
                if self.app.is_running():
                    break

        LOGGER.debug('waiting for DCS to spool up')
        await _wait_for_process()
        LOGGER.debug('process is ready')

    def _work_with_dcs_process(self, func):
        if core.CTX.exit:
            return
        try:
            func()
            self._warned = False
        except (psutil.NoSuchProcess, AttributeError):
            if not core.CTX.exit and not self._warned:
                LOGGER.warning('DCS process does not exist')
                self._warned = True

    def set_affinity(self):
        """
        Sets the DCS process CPU affinity to the CFG value
        """

        def _command():
            if list(self._app.cpu_affinity()) != list(DCSConfig.DCS_CPU_AFFINITY()):
                LOGGER.debug('setting DCS process affinity to: %s', DCSConfig.DCS_CPU_AFFINITY())
                self._app.cpu_affinity(list(DCSConfig.DCS_CPU_AFFINITY()))

        while True:
            if DCSConfig.DCS_CPU_AFFINITY():
                if core.CTX.exit:
                    return
                self._work_with_dcs_process(_command)
            else:
                LOGGER.warning('no CPU affinity given in config file')
                return
            time.sleep(30)

    def set_priority(self):
        """
        Sets the DCS process CPU priority to the CFG value
        """

        def _command():
            if self.app.nice() != self.valid_priorities[DCSConfig.DCS_CPU_PRIORITY()]:
                LOGGER.debug('setting DCS process priority to: %s',
                             DCSConfig.DCS_CPU_PRIORITY()
                             )
                self.app.nice(self.valid_priorities[DCSConfig.DCS_CPU_PRIORITY()])

        time.sleep(15)
        while True:
            if DCSConfig.DCS_CPU_PRIORITY():
                if core.CTX.exit:
                    return
                if DCSConfig.DCS_CPU_PRIORITY() not in self.valid_priorities.keys():
                    LOGGER.error(f'invalid priority: %s\n'
                                 f'Choose one of: %s',
                                 DCSConfig.DCS_CPU_PRIORITY(),
                                 self.valid_priorities.keys(),
                                 )
                    return
                self._work_with_dcs_process(_command)
            else:
                LOGGER.warning('no CPU priority given in config file for dcs.exe')
                return
            time.sleep(30)

    async def _start_new_dcs_application_if_needed(self):

        async def _start_dcs_app():
            LOGGER.debug('starting DCS application process: %s', FS.dcs_exe)
            self._app = psutil.Popen(str(FS.dcs_exe))

        if self.app and self.app.is_running():
            return
        LOGGER.debug('starting new DCS application')
        cmd_chain = [
            _start_dcs_app,
            self._wait_for_dcs_to_start,
        ]
        # rotate_dcs_log()
        await self._execute_cmd_chain(cmd_chain)
        await self._check_if_dcs_is_running()

    # noinspection PyMethodMayBeStatic
    async def _update_application_status(self, status: str):
        if core.Status.dcs_application != status:
            core.Status.dcs_application = status
            LOGGER.info('DCS application is %s', status)
            if status == 'starting':
                commands.LISTENER.monitor_server_startup_start()

    async def kill_running_app(self):  # noqa: C901
        """
        Kills the running DCS.exe process
        """

        async def _ask_politely():
            if not self.app or not self.app.is_running():
                return True
            LOGGER.debug('sending socket command to DCS for graceful exit')
            commands.LISTENER.exit_dcs()
            await asyncio.sleep(1)
            LOGGER.debug('waiting on DCS to close itself (grace period: %s seconds)',
                         DCSConfig.DCS_CLOSE_GRACE_PERIOD()
                         )
            now_ = utils.now()
            while self.app.is_running():
                await asyncio.sleep(1)
                if utils.now() - now_ > DCSConfig.DCS_CLOSE_GRACE_PERIOD():
                    LOGGER.debug('grace period time out!')
                    return False

            LOGGER.info('DCS closed itself, nice')
            return True

        async def _no_more_mr_nice_guy():
            if not self.app or not self.app.is_running():
                return True
            LOGGER.debug('killing dcs.exe application')
            self.app.kill()
            now_ = utils.now()
            while self.app.is_running():
                await asyncio.sleep(1)
                if utils.now() - now_ > 10:
                    return False

            return True

        core.CTX.dcs_do_kill = False
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
        if core.CTX.exit:
            LOGGER.debug('restart interrupted by exit signal')
            return
        core.CTX.dcs_do_restart = False
        LOGGER.info('restarting DCS')
        await self.kill_running_app()
        core.Status.mission_file = 'unknown'
        core.Status.server_age = 'unknown'
        core.Status.mission_time = 'unknown'
        core.Status.paused = 'unknown'
        core.Status.mission_name = 'unknown'
        core.Status.players = []
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
        while not core.CTX.exit:
            try:
                if self.app and self.app.is_running():
                    cpu_usage = int(self.app.cpu_percent(DCSConfig.DCS_HIGH_CPU_USAGE_INTERVAL()))
                    mem_usage = int(self.app.memory_percent())
                    core.Status.dcs_cpu_usage = f'{cpu_usage}%'
                    if core.CTX.dcs_show_cpu_usage or core.CTX.dcs_show_cpu_usage_once:
                        commands.DISCORD.say(f'DCS cpu usage: {cpu_usage}%')
                        core.CTX.dcs_show_cpu_usage_once = False
                    if DCSConfig.DCS_HIGH_CPU_USAGE():
                        if cpu_usage > DCSConfig.DCS_HIGH_CPU_USAGE() and not core.Status.paused:
                            LOGGER.warning('DCS cpu usage has been higher than %s%% for %s seconds',
                                           DCSConfig.DCS_HIGH_CPU_USAGE(),
                                           DCSConfig.DCS_HIGH_CPU_USAGE_INTERVAL(),
                                           )

                    now_ = utils.now()
                    core.CTX.dcs_mem_history.append((now_, mem_usage))
                    core.CTX.dcs_cpu_history.append((now_, cpu_usage))

            except psutil.NoSuchProcess:
                pass

            # I didn't think it could, happen, but of course it did ...
            # See https://github.com/132nd-vWing/ESST/issues/59
            except AttributeError:
                pass

    # pylint: disable=too-many-branches
    async def run(self):  # noqa: C901
        """
        Entry point of the thread
        """
        if not core.CTX.start_dcs_loop:
            LOGGER.debug('skipping DCS application loop')
            return
        if not await self._get_dcs_version_from_executable():
            return
        await core.CTX.loop.run_in_executor(None, install_game_gui_hooks)
        await core.CTX.loop.run_in_executor(None, server_settings.write_server_settings)
        await core.CTX.loop.run_in_executor(None, missions_manager.get_latest_mission_from_github)
        await core.CTX.loop.run_in_executor(None, missions_manager.initial_setup)

        LOGGER.debug('starting DCS monitoring thread')
        if DCS.dcs_cannot_start():
            blockers = ", ".join(DCS.dcs_cannot_start())
            if blockers not in self._blockers_warned:
                self._blockers_warned.add(blockers)
                LOGGER.warning('DCS is prevented to start by: %s', ', '.join(DCS.dcs_cannot_start()))
        else:
            if self._blockers_warned:
                self._blockers_warned = set()
            await self._try_to_connect_to_existing_dcs_application()
            await self._start_new_dcs_application_if_needed()
        cpu_monitor_thread = core.CTX.loop.run_in_executor(None, self.monitor_cpu_usage)
        cpu_affinity_thread = core.CTX.loop.run_in_executor(None, self.set_affinity)
        cpu_priority_thread = core.CTX.loop.run_in_executor(None, self.set_priority)
        while True:
            if core.CTX.exit:
                LOGGER.debug('interrupted by exit signal')
                await cpu_monitor_thread
                await cpu_affinity_thread
                await cpu_priority_thread
                break
            if DCS.dcs_cannot_start():
                blockers = ", ".join(DCS.dcs_cannot_start())
                if blockers not in self._blockers_warned:
                    self._blockers_warned.add(blockers)
                    LOGGER.warning('DCS is prevented to start by: %s', ', '.join(DCS.dcs_cannot_start()))
            else:
                if self._blockers_warned:
                    self._blockers_warned = set()
                await self._check_if_dcs_is_running()
                if not self.process_pid:
                    LOGGER.debug('DCS has stopped, re-starting')
                    await self.restart()
            if core.CTX.dcs_do_kill:
                await self.kill_running_app()
            if core.CTX.dcs_do_restart:
                await self.restart()
            await asyncio.sleep(0.1)

        LOGGER.debug('end of DCS loop')
