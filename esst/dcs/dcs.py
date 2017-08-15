# coding=utf-8
"""
Manages DCS application Window process
"""
import queue
import threading
import time

import blinker
import psutil
import pywinauto

from esst.core.config import CFG
from esst.core.logger import MAIN_LOGGER
from esst.core.path import Path
from esst.core.status import Status
from .dedicated import setup_config_for_dedicated_run
from .game_gui import install_game_gui_hooks
from .missions_manager import get_latest_mission_from_github

LOGGER = MAIN_LOGGER.getChild(__name__)

DCS_CMD_QUEUE = queue.Queue()

KNOWN_DCS_VERSIONS = ['1.5.6.5199']


def get_dcs_process_pid():
    """
    Tries to obtain "DCS.exe" PID

    Returns: "DCS.exe" PID or False
    """
    for process in psutil.process_iter():
        if process.name().lower() == 'dcs.exe':
            return process.pid

    return False


class App(threading.Thread):  # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """
    Manages DCS application Window process
    """

    def __init__(self, ctx):
        if not ctx.params['server']:
            LOGGER.debug('skipping startup of DCS application thread')
            return

        LOGGER.debug('starting DCS application thread')
        ctx.obj['threads']['dcs']['ready_to_exit'] = False
        threading.Thread.__init__(self, daemon=True)
        install_game_gui_hooks(ctx)
        get_latest_mission_from_github(ctx)
        self.ctx = ctx
        self.app = pywinauto.Application()
        self.process_pid = None
        self._exiting = False
        self.cpu_usage = 'unknown'
        self._show_cpu_constantly = False
        self._restart_ok = True
        self.start()

    def _execute_cmd_chain(self, cmd_chain: list):
        while not self._should_exit():
            try:
                cmd = cmd_chain.pop(0)
                cmd()
                time.sleep(0.5)
            except IndexError:
                return True

    def _get_dcs_version_from_executable(self):
        dcs_exe = Path(CFG.dcs_path)
        if not dcs_exe.exists():
            raise RuntimeError(f'dcs.exe not found: {dcs_exe}')
        # noinspection PyBroadException
        try:
            Status.dcs_version = dcs_exe.get_win32_file_info().file_version
            if Status.dcs_version not in KNOWN_DCS_VERSIONS:
                LOGGER.error(f'sorry, but I am unable to manage this version of DCS: {Status.dcs_version}\n'
                             f'This safety check exists so ESST does not screw your DCS installation '
                             f'by installing hooks into an unsupported DCS installation.')
                self._exiting = True
            else:
                setup_config_for_dedicated_run(self.ctx)
            LOGGER.debug(f'DCS version: {Status.dcs_version}')
        except:  # pylint: disable=bare-except
            LOGGER.error('unable to retrieve version from dcs.exe')
            Status.dcs_version = 'unknown'

    def _check_if_dcs_is_running(self):
        self.process_pid = get_dcs_process_pid()
        if self.process_pid:
            self._update_application_status('running')
        else:
            self._update_application_status('not running')

    def _try_to_connect_to_existing_dcs_application(self):
        LOGGER.debug('connecting to existing DCS application')
        self._check_if_dcs_is_running()
        if self.process_pid:
            self.app.connect(process=self.process_pid)
            self._wait_for_dcs_to_start()

    def _wait_for_dcs_to_start(self):  # noqa: C901

        def _wait_for_process():
            while True:
                if self._should_exit():
                    return
                time.sleep(0.1)
                if self.app.is_process_running():
                    break

        def _wait_for_cpu():
            while True:
                if self._should_exit():
                    return
                time.sleep(0.1)
                try:
                    self.app.wait_cpu_usage_lower(
                        usage_interval=0.5,
                        threshold=CFG.dcs_idle_cpu_usage,
                        timeout=0.6)
                    break
                except RuntimeError as exception:
                    if 'timed out' in exception.args[0]:
                        # noinspection PyBroadException
                        try:
                            _wait_for_cpu()
                        except:  # pylint: disable=bare-except
                            LOGGER.error('DCS has died during startup')
                            self.restart()
                    else:
                        raise

        LOGGER.debug('waiting for DCS to spool up')
        _wait_for_process()
        LOGGER.debug('process is ready')

    def _start_new_dcs_application_if_needed(self):

        def _start_dcs_app():
            LOGGER.debug(f'starting DCS application process: {CFG.dcs_path}')
            self.app.start(CFG.dcs_path)

        if self.process_pid:
            return
        LOGGER.debug('starting new DCS application')
        self._update_application_status('starting')
        if self.app is None:
            self.app = pywinauto.Application()
        cmd_chain = [
            _start_dcs_app,
            self._wait_for_dcs_to_start,
            self._check_if_dcs_is_running,
        ]
        self._execute_cmd_chain(cmd_chain)
        self._check_if_dcs_is_running()

    @staticmethod
    def _update_application_status(status: str):
        if Status.dcs_application != status:
            Status.dcs_application = status
            LOGGER.info(f'DCS server is {status}')
            if status is 'starting':
                blinker.signal('socket command').send(__name__, cmd='monitor server start')

    def _should_exit(self) -> bool:
        return self.ctx.obj['threads']['dcs']['should_exit']

    def _kill_running_app(self):
        self.ctx.obj['dcs_kill'] = False
        self._check_if_dcs_is_running()
        if not self.process_pid:
            LOGGER.debug('DCS process was not running')
            return
        LOGGER.info('closing DCS')
        LOGGER.debug('sending socket command to DCS for graceful exit')
        blinker.signal('socket command').send(__name__, cmd='exit dcs')
        try:
            LOGGER.debug('waiting on DCS to close itself')
            self.app.wait_for_process_exit(timeout=30)
            LOGGER.debug('DCS has gracefully exited, nice')
            self._update_application_status('not running')
        except RuntimeError as exception:
            if 'timed out' in exception.args[0]:
                LOGGER.info('DCS server will not exit gracefully, killing it')
                self.app.kill()
                try:
                    self.app.wait_for_process_exit(timeout=10)
                    self._update_application_status('not running')
                except RuntimeError:
                    LOGGER.error('I was not able to kill DCS, something is wrong')
            else:
                raise

    def restart(self):
        """
        Restarts DCS application
        """
        if self._should_exit():
            LOGGER.debug('interrupted by exit signal')
            return
        self.ctx.obj['dcs_restart'] = False
        LOGGER.info('restarting DCS')
        self._kill_running_app()
        Status.mission_file = 'unknown'
        Status.server_age = 'unknown'
        Status.mission_time = 'unknown'
        Status.paused = 'unknown'
        Status.mission_name = 'unknown'
        Status.players = []
        self.app = None
        self.process_pid = None
        cmd_chain = [
            self._start_new_dcs_application_if_needed,
        ]
        self._execute_cmd_chain(cmd_chain)

    def monitor_cpu_usage(self):
        """
        Gets the CPU usage of "DCS.exe" over 5 seconds, and sends an alert if the given threshold is exceeded

        Threshold is set via the config value "DCS_HIGH_CPU_USAGE", and it defaults to 80%
        """
        try:
            self.cpu_usage = int(self.app.cpu_usage(interval=5))
            Status.dcs_cpu_usage = f'{self.cpu_usage}%'
            if self.ctx.obj['dcs_show_cpu_usage'] or self.ctx.obj['dcs_show_cpu_usage_once']:
                LOGGER.info(f'DCS cpu usage: {self.cpu_usage}%')
                self.ctx.obj['dcs_show_cpu_usage_once'] = False
        except RuntimeError:
            self._check_if_dcs_is_running()
            if self.process_pid:
                raise
            else:
                return

        if self._show_cpu_constantly:
            blinker.signal('discord message').send(__name__, msg=f'DCS cpu usage: {self.cpu_usage}%')
        if self.cpu_usage > CFG.dcs_high_cpu_usage:
            LOGGER.warning(f'DCS cpu usage has been higher than {CFG.dcs_high_cpu_usage}% for 5 seconds')

    def run(self):
        """
        Entry point of the thread
        """
        LOGGER.debug('starting DCS monitoring thread')
        cmd_chain = [
            self._get_dcs_version_from_executable,
        ]
        if self.ctx.obj['dcs_start_ok']:
            cmd_chain.extend(
                [
                    self._try_to_connect_to_existing_dcs_application,
                    self._start_new_dcs_application_if_needed,
                ]
            )
        self._execute_cmd_chain(cmd_chain)
        while True:
            if self._should_exit():
                LOGGER.debug('interrupted by exit signal')
                break
            if self.ctx.obj['dcs_start_ok']:
                self._check_if_dcs_is_running()
                if not self.process_pid:
                    LOGGER.debug('DCS has stopped, re-starting')
                    self.restart()
                self.monitor_cpu_usage()
            if self.ctx.obj['dcs_kill']:
                self._kill_running_app()
            if self.ctx.obj['dcs_restart']:
                self.restart()
            time.sleep(0.5)

        self._kill_running_app()
        self.ctx.obj['threads']['dcs']['ready_to_exit'] = True
        LOGGER.debug('closing DCS monitoring thread')
