# coding=utf-8
"""
Installs the necessary files to run in dedicated mode
"""
from pathlib import Path

import jinja2

from esst import DCSConfig, DiscordBotConfig, FS, LOGGER
from esst.core import CTX
from esst.utils import create_versioned_backup, read_template

DEDI_CFG = r"""dedicated =
{
    ["enabled"] = true,
}
"""


def _get_me_auth_path() -> Path:
    me_auth_path = Path(DCSConfig.DCS_PATH(), 'MissionEditor/modules/me_authorization.lua')
    if not me_auth_path.exists():
        raise FileNotFoundError(str(me_auth_path))
    return me_auth_path


def _write_dedi_config():
    dedi_cfg_path = Path(FS.variant_saved_games_path, 'Config/dedicated.lua')
    if not dedi_cfg_path.exists():
        LOGGER.info('writing %s', dedi_cfg_path)
        dedi_cfg_path.write_text(DEDI_CFG)
    else:
        LOGGER.debug('file already exists: %s', dedi_cfg_path)


def _write_auth_file():
    content = read_template('me_authorization.lua')
    LOGGER.debug('writing me_authorization.lua')
    _get_me_auth_path().write_text(jinja2.Template(content).render(server_name=DiscordBotConfig.DISCORD_BOT_NAME()))


def setup_config_for_dedicated_run():
    """
    Setup the server to automatically starts in multiplayer mode when DCS starts
    """
    if CTX.dcs_setup_dedi_config:
        LOGGER.debug('setting up dedicated config')
        create_versioned_backup(_get_me_auth_path())
        _write_auth_file()
        _write_dedi_config()
        LOGGER.debug('setting up dedicated config: all done!')
    else:
        LOGGER.debug('skipping installation of dedicated config')
