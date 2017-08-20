# coding=utf-8

from esst.core.config import CFG
from esst.core.logger import MAIN_LOGGER
import pkg_resources
import os
import jinja2
import shutil

from esst.core.context import Context

LOGGER = MAIN_LOGGER.getChild(__name__)

ME_AUTH_PATH = os.path.join(os.path.dirname(__file__), 'dedicated.template')
if not os.path.exists(ME_AUTH_PATH):
    ME_AUTH_PATH = pkg_resources.resource_filename('esst', '/dcs/dedicated.template')
if not os.path.exists(ME_AUTH_PATH):
    raise FileNotFoundError(ME_AUTH_PATH)
with open(ME_AUTH_PATH) as handle:
    ME_AUTH = handle.read()

DEDI_CFG = r"""dedicated = 
{
    ["enabled"] = true,
}
"""


def _backup_auth_file():
    me_auth_path = _get_me_auth_path()
    backup_path = me_auth_path + '_backup'
    if not os.path.exists(backup_path):
        LOGGER.debug('creating backup for me_authorization.lua')
        shutil.copy(me_auth_path, backup_path)


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


def setup_config_for_dedicated_run(ctx: Context):
    """
    Setup the server to automatically starts in multiplayer mode when DCS starts
    """
    if ctx.dcs_setup_dedi_config:
        LOGGER.debug('setting up dedicated config')
        _backup_auth_file()
        with open(_get_me_auth_path(), 'w') as handle:
            handle.write(jinja2.Template(ME_AUTH).render(server_name=CFG.discord_bot_name))
        _write_dedi_config()
    else:
        LOGGER.debug('skipping installation of dedicated config')
