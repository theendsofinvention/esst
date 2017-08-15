# coding=utf-8

import os
import asyncio
from asyncio import subprocess
import typing

from esst.core.logger import MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


async def do_ex(cmd: typing.List[str], cwd: str = '.') -> typing.Tuple[str, str, int]:
    """
    Executes a given command

    Args:
        ctx: Click context
        cmd: command to run
        cwd: working directory (defaults to ".")

    Returns: stdout, stderr, exit_code

    """

    def _ensure_stripped_str(str_or_bytes):
        if isinstance(str_or_bytes, str):
            return '\n'.join(str_or_bytes.strip().splitlines())
        else:
            return '\n'.join(str_or_bytes.decode('utf-8', 'surogate_escape').strip().splitlines())

    LOGGER.debug(f'running cmd: {cmd}')
    process = await asyncio.create_subprocess_exec(*cmd,
                                                   stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE
                                                   )
    out, err = await process.communicate()
    LOGGER.debug(f'{cmd[0]} return code: {process.returncode}')
    return _ensure_stripped_str(out), _ensure_stripped_str(err), process.returncode
