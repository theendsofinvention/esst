# coding=utf-8


import os
from esst.core import MAIN_LOGGER, CTX

LOGGER = MAIN_LOGGER.getChild(__name__)



class SERVER:

    @staticmethod
    def reboot():
        os.system('shutdown /r /t 30 /c "Reboot initialized by ESST"')

    @staticmethod
    def show_cpu_usage_once():
        LOGGER.debug('show cpu usage once')
        CTX.server_show_cpu_usage_once = True

    @staticmethod
    def show_cpu_usage_once_done():
        LOGGER.debug('show cpu usage once: done')
        CTX.server_show_cpu_usage_once = False

    @staticmethod
    def show_cpu_usage_start():
        LOGGER.debug('show cpu usage: start')
        CTX.server_show_cpu_usage = True

    @staticmethod
    def show_cpu_usage_stop():
        LOGGER.debug('show cpu usage: stop')
        CTX.server_show_cpu_usage = False