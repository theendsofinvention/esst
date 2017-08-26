# coding=utf-8


from esst.core import CTX, MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


class LISTENER:
    @staticmethod
    def monitor_server_startup_start():
        LOGGER.debug('monitor server startup: start')
        CTX.socket_monitor_server_startup = True

    @staticmethod
    def monitor_server_startup_stop():
        LOGGER.debug('monitor server startup: stop')
        CTX.socket_monitor_server_startup = False

    @staticmethod
    def exit_dcs():
        LOGGER.debug('sending socket message to close DCS')
        CTX.socket_cmd_q.put('exit dcs')
