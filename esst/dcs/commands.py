# coding=utf-8
"""
Manages DCS commands
"""
import threading
import time
from queue import Queue

from esst.core import CTX, MAIN_LOGGER, Status

LOGGER = MAIN_LOGGER.getChild(__name__)
CANCEL_QUEUED_KILL: Queue = Queue()

_DCS_LOCK = threading.Lock()


class DCS:
    """
    Manages commands for the DCS application
    """

    @staticmethod
    def restart(force: bool = False):
        """
        Sets the context to restart the DCS application

        Returns: None if restart is OK, err as a str otherwise

        """
        CANCEL_QUEUED_KILL.put(1)
        if DCS.there_are_connected_players() and not force:
            LOGGER.error('there are connected players; cannot restart the server now '
                         ' (use "--force" to kill anyway)')
            return
        LOGGER.debug('setting context for DCS restart')
        CTX.dcs_do_restart = True

    @staticmethod
    def kill(force: bool = False, queue: bool = False):
        """Kills DCS application"""
        CANCEL_QUEUED_KILL.put(1)
        if DCS.there_are_connected_players():
            if not force:
                if queue:
                    DCS.queue_kill()
                else:
                    LOGGER.error('there are connected players; cannot kill the server now'
                                 ' (use "--force" to kill anyway)')
                return
            else:
                LOGGER.warning('forcing kill with connected players')
        LOGGER.debug('setting context for DCS kill')
        CTX.dcs_do_kill = True

    @staticmethod
    def queue_kill():
        """Kill DCS application when all players left"""

        def _queue_kill(queue: Queue):
            while DCS.there_are_connected_players():
                if not queue.empty():
                    queue.get_nowait()
                    LOGGER.debug('queued DCS kill has been cancelled')
                    return
                time.sleep(5)
            LOGGER.info('executing planned DCS restart')
            DCS.kill()

        LOGGER.warning('queuing DCS kill for when all players have left')
        CTX.loop.run_in_executor(None, _queue_kill, CANCEL_QUEUED_KILL)

    @staticmethod
    def show_cpu_usage_once():
        """Show CPU usage once"""
        LOGGER.debug('show cpu usage once')
        CTX.dcs_show_cpu_usage_once = True

    @staticmethod
    def show_cpu_usage_once_done():
        """Show CPU usage once"""
        LOGGER.debug('show cpu usage once: done')
        CTX.dcs_show_cpu_usage_once = False

    @staticmethod
    def show_cpu_usage_start():
        """Starts showing CPU usage continuously"""
        LOGGER.debug('show cpu usage: start')
        CTX.dcs_show_cpu_usage = True

    @staticmethod
    def show_cpu_usage_stop():
        """Stops showing CPU usage continuously"""
        LOGGER.debug('show cpu usage: stop')
        CTX.dcs_show_cpu_usage = False

    @staticmethod
    def block_start(reason: str):
        """
        Prevents DCS from starting

        Args:
            reason: reason for preventing DCS to start
        """
        with _DCS_LOCK:
            CTX.dcs_blocker.append(reason)

    @staticmethod
    def unblock_start(reason: str):
        """
        Allow DCS to start

        Args:
            reason: reason that was preventing DCS to start
        """
        with _DCS_LOCK:
            if reason in CTX.dcs_blocker:
                CTX.dcs_blocker.remove(reason)

    @staticmethod
    def dcs_cannot_start() -> list:
        """Returns the list of reasons preventing DCS to start"""
        return CTX.dcs_blocker

    @staticmethod
    def there_are_connected_players() -> bool:
        """

        Returns: bool indicating if there are connected players
        """
        connected_players = bool(Status.players)
        if connected_players:
            LOGGER.debug(f'there are {len(Status.players)} connected player(s)')
        else:
            LOGGER.debug('there is no connected players')
        return connected_players

    @staticmethod
    def check_for_connected_players() -> bool:
        """
        Returns: False if there are connected players
        """
        if DCS.there_are_connected_players():
            LOGGER.warning('there are connected players; cannot kill the server now')
            return False

        return True
