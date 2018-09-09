# coding=utf-8
"""
Manages UR voice service executable
"""
import os
import time
from pathlib import Path

import psutil

from esst.core import FS, MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)

PROC_NAME = 'UR_VoiceServiceServer.exe'


class URVoiceService:
    """
    Manages UR voice service executable
    """
    pid = None

    @staticmethod
    def is_running() -> bool:
        """Returns UR voice service status"""
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
        exe_path = Path(FS.ur_install_path, PROC_NAME)
        if not exe_path.exists():
            raise FileNotFoundError(exe_path)
        LOGGER.info(f'starting UR voice service: {exe_path}')
        os.startfile(str(exe_path))  # nosec
        URVoiceService.is_running()

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
        if URVoiceService.is_running():
            try:
                proc = psutil.Process(URVoiceService.pid)
                LOGGER.info('killing UR voice service')
                proc.terminate()
                while URVoiceService.is_running():
                    LOGGER.debug('waiting on UR voice service to close')
                    time.sleep(1)
            except FileNotFoundError:
                pass
            except psutil.NoSuchProcess:
                pass
