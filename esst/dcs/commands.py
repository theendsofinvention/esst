# coding=utf-8
# pylint: disable=missing-docstring
import time
import typing

from esst.core import CTX, MAIN_LOGGER, Status

LOGGER = MAIN_LOGGER.getChild(__name__)
CANCEL_QUEUED_KILL = False


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
        if DCS.there_are_connected_players():
            LOGGER.error('there are connected players; cannot restart the server now '
                         ' (use "--force" to kill anyway)')
            return
        LOGGER.debug('setting context for DCS restart')
        CTX.dcs_do_restart = True

    @staticmethod
    def kill(force: bool = False, queue: bool = False):
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

        def _queue_kill():
            global CANCEL_QUEUED_KILL
            while DCS.there_are_connected_players():
                if CANCEL_QUEUED_KILL:
                    LOGGER.debug('queued DCS kill has been cancelled')
                    CANCEL_QUEUED_KILL = False
                    return
                time.sleep(5)
            LOGGER.info('executing planned DCS restart')
            DCS.kill()

        LOGGER.warning('queuing DCS kill for when all players have left')
        CTX.loop.run_in_executor(None, _queue_kill)

    @staticmethod
    def show_cpu_usage_once():
        LOGGER.debug('show cpu usage once')
        CTX.dcs_show_cpu_usage_once = True

    @staticmethod
    def show_cpu_usage_once_done():
        LOGGER.debug('show cpu usage once: done')
        CTX.dcs_show_cpu_usage_once = False

    @staticmethod
    def show_cpu_usage_start():
        LOGGER.debug('show cpu usage: start')
        CTX.dcs_show_cpu_usage = True

    @staticmethod
    def show_cpu_usage_stop():
        LOGGER.debug('show cpu usage: stop')
        CTX.dcs_show_cpu_usage = False

    @staticmethod
    def can_start():
        if not CTX.dcs_can_start:
            LOGGER.debug('DCS can start')
        CTX.dcs_can_start = True

    @staticmethod
    def cannot_start():
        if CTX.dcs_can_start:
            LOGGER.debug('DCS can NOT start')
        CTX.dcs_can_start = False

    @staticmethod
    def get_mission_list():
        return []
        # yield from list_available_missions()

    @staticmethod
    def there_are_connected_players() -> bool:
        connected_players = bool(Status.players)
        if connected_players:
            LOGGER.debug(f'there are {len(Status.players)} connected player(s)')
        else:
            LOGGER.debug('there is no connected players')
        return connected_players

    @staticmethod
    def check_for_connected_players() -> bool:
        if DCS.there_are_connected_players():
            LOGGER.warning('there are connected players; cannot kill the server now')
            return False
        else:
            return True


