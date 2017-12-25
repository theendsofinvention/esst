# coding=utf-8
"""
Manages UR voice service executable
"""
import os
import time
from pathlib import Path

import psutil

from esst.atis.univers_radio.ur_install_dir import UR_INSTALL_PATH
from esst.core import MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)

PROC_NAME = 'UR_VoiceServiceServer.exe'


class URVoiceService:
    """
    Manages UR voice service executable
    """

    exe_path = Path(UR_INSTALL_PATH, PROC_NAME)
    pid = None

    @staticmethod
    def _get_pid() -> bool:
        for proc in psutil.process_iter():
            if proc.name() == PROC_NAME:
                URVoiceService.pid = proc.pid
                return True
        return False

    @staticmethod
    def start_service():
        """
        Starts UR voice service
        """
        LOGGER.info('starting UR voice service')
        os.startfile(str(URVoiceService.exe_path))
        URVoiceService._get_pid()

    @staticmethod
    def poll():
        """
        Checks that UR voice service is running
        """
        LOGGER.debug('polling UR voice service')
        proc = psutil.Process(URVoiceService.pid)
        if not proc.status() == psutil.STATUS_RUNNING:
            raise RuntimeError('UR voice service stopped')

    @staticmethod
    def kill():
        """
        Kills UR voice service
        """
        if URVoiceService.pid:
            try:
                proc = psutil.Process(URVoiceService.pid)
                LOGGER.info('killing UR voice service')
                proc.terminate()
                while URVoiceService._get_pid():
                    LOGGER.debug('waiting on UR voice service to close')
                    time.sleep(1)
            except FileNotFoundError:
                LOGGER.debug('UR voice service not started')
