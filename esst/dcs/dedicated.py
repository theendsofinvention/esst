# coding=utf-8
"""
Installs the necessary files to run in dedicated mode
"""
from pathlib import Path

import jinja2

from esst.core import CFG, CTX, FS, MAIN_LOGGER
from esst.utils import create_versioned_backup, read_template

LOGGER = MAIN_LOGGER.getChild(__name__)

DEDI_CFG = r"""dedicated =
{
    ["enabled"] = true,
}
"""


def _get_me_auth_path() -> Path:
    me_auth_path = Path(CFG.dcs_path, 'MissionEditor/modules/me_authorization.lua')
    if not me_auth_path.exists():
        raise FileNotFoundError(str(me_auth_path))
    return me_auth_path


def _write_dedi_config():
    dedi_cfg_path = Path(FS.variant_saved_games_path, 'Config/dedicated.lua')
    if not dedi_cfg_path.exists():
        LOGGER.info(f'writing {dedi_cfg_path}')
        dedi_cfg_path.write_text(DEDI_CFG)
    else:
        LOGGER.debug(f'file already exists: {dedi_cfg_path}')


def _write_auth_file():
    content = read_template('me_authorization.lua')
    LOGGER.debug('writing me_authorization.lua')
    _get_me_auth_path().write_text(jinja2.Template(content).render(server_name=CFG.discord_bot_name))


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
