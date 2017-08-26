# coding=utf-8

import asyncio
from esst.core import ServerStatus
from esst.core import CFG, MAIN_LOGGER, CTX


LOGGER = MAIN_LOGGER.getChild(__name__)


class ServerLoop:

    def __init__(self):
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

        LOGGER.debug('end of Server computer loop')

    async def exit(self):
        pass
