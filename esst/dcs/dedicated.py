# coding=utf-8
"""
Installs the necessary files to run in dedicated mode
"""
import os

import jinja2

from esst.core import CFG, CTX, MAIN_LOGGER
from esst.utils import create_versionned_backup, read_template

LOGGER = MAIN_LOGGER.getChild(__name__)

DEDI_CFG = r"""dedicated =
{
    ["enabled"] = true,
}
"""


def _get_me_auth_path() -> str:
    dcs_install_dir = os.path.dirname(os.path.dirname(CFG.dcs_path))
    me_auth_path = os.path.join(dcs_install_dir, 'MissionEditor/modules/me_authorization.lua')
    if not os.path.exists(me_auth_path):
        raise FileNotFoundError(str(me_auth_path))
    return me_auth_path


def _write_dedi_config():
    dedi_cfg_path = os.path.join(CFG.saved_games_dir, 'Config/dedicated.lua')
    if not os.path.exists(dedi_cfg_path):
        LOGGER.debug(f'writing {dedi_cfg_path}')
        with open(dedi_cfg_path, 'w') as handle:
            handle.write(DEDI_CFG)
    else:
        LOGGER.debug(f'file already exists: {dedi_cfg_path}')


def _write_auth_file():
    content = read_template('me_authorization.lua')
    LOGGER.debug('writing me_authorization.lua')
    with open(_get_me_auth_path(), 'w') as handle:
        handle.write(jinja2.Template(content).render(server_name=CFG.discord_bot_name))


def setup_config_for_dedicated_run():
    """
    Setup the server to automatically starts in multiplayer mode when DCS starts
    """
    if CTX.dcs_setup_dedi_config:
        LOGGER.debug('setting up dedicated config')
        create_versionned_backup(_get_me_auth_path())
        _write_auth_file()
        _write_dedi_config()
        LOGGER.debug('setting up dedicated config: all done!')
    else:
        LOGGER.debug('skipping installation of dedicated config')
