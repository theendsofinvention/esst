# coding=utf-8
# pylint: disable=missing-docstring
import typing

from esst.core import CTX, MAIN_LOGGER, Status

LOGGER = MAIN_LOGGER.getChild(__name__)


class DCS:
    """
    Manages commands for the DCS application
    """

    @staticmethod
    def restart(force: bool = False) -> typing.Union[str, None]:
        """
        Sets the context to restart the DCS application

        Returns: None if restart is OK, err as a str otherwise

        """
        if DCS.there_are_connected_players():
            if not force:
                return 'there are connected players; cannot restart the server now (use "--force" to restart anyway)'
            else:
                LOGGER.warning('forcing restart with connected players')
        LOGGER.debug('setting context for DCS restart')
        CTX.dcs_do_restart = True

    @staticmethod
    def kill(force: bool = False):
        if DCS.there_are_connected_players():
            if not force:
                return 'there are connected players; cannot kill the server now (use "--force" to kill anyway)'
            else:
                LOGGER.warning('forcing kill with connected players')
        LOGGER.debug('setting context for DCS kill')
        CTX.dcs_do_kill = True

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
