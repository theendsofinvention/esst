# coding=utf-8

import os
import subprocess
import typing

from esst.core.logger import MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)


def do_ex(cmd: typing.List[str], cwd: str = '.') -> typing.Tuple[str, str, int]:
    """
    Executes a given command

    Args:
        ctx: Click context
        cmd: command to run
        cwd: working directory (defaults to ".")

    Returns: stdout, stderr, exit_code

    """

    def _popen_pipes(cmd_, cwd_):
        def _always_strings(env_dict):
            """
            On Windows and Python 2, environment dictionaries must be strings
            and not unicode.
            """
            env_dict.update(
                (key, str(value))
                for (key, value) in env_dict.items()
            )
            return env_dict

        return subprocess.Popen(
            cmd_,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd_),
            env=_always_strings(
                dict(
                    os.environ,
                    # try to disable i18n
                    LC_ALL='C',
                    LANGUAGE='',
                    HGPLAIN='1',
                )
            )
        )

    def _ensure_stripped_str(str_or_bytes):
        if isinstance(str_or_bytes, str):
            return '\n'.join(str_or_bytes.strip().splitlines())
        else:
            return '\n'.join(str_or_bytes.decode('utf-8', 'surogate_escape').strip().splitlines())

    LOGGER.debug(f'running cmd: {cmd}')
    p = _popen_pipes(cmd, cwd)
    out, err = p.communicate()
    LOGGER.debug(f'{cmd[0]} return code: {p.returncode}')
    return _ensure_stripped_str(out), _ensure_stripped_str(err), p.returncode
