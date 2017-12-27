# coding=utf-8
"""
Inject more code into DCS 1.5.8 and 2.x (new login mechanism)
"""
import re
import typing
from pathlib import Path

from esst import core, utils

LOGGER = core.MAIN_LOGGER.getChild(__name__)

# noinspection SpellCheckingInspection
INJECT_TEMPLATE = """function onShowMainInterface()
--print("--onShowMainInterface()---")
    if tooltipSkin_ == nil then
        tooltipSkin_ = Gui.GetTooltipSkin()
    else
        Gui.SetTooltipSkin(tooltipSkin_)
    end
    prepareMissionPath()
    mmw.setLastWallpaper()
    openReturnScreen()

    -- START DEDICATED CODE -  ADD FROM THIS LINE
    --
    if grgFirstRun == nil then
        grgFirstRun = true

        local net = require('net')
        local lfs = require('lfs')
        local Tools = require('tools')
        local mpConfig = Tools.safeDoFile(lfs.writedir() .. 'Config/serverSettings.lua', false)
        local dediConfig = Tools.safeDoFile(lfs.writedir() .. 'Config/dedicated.lua', false)

         if dediConfig and dediConfig.dedicated ~= nil and dediConfig.dedicated["enabled"] == true then
           net.set_name(dediConfig.dedicated["name"])
           net.start_server(mpConfig.cfg)
           net.log("Starting Dedicated Server...")
        end
    end
    --
    -- END DEDICATED CODE - ADD UP TO THIS LINE

end"""

RE_INJECT = re.compile(
    r"""^function onShowMainInterface\(\)\n\s*--.*(?:\n^.*?)*^end$""",
    re.MULTILINE
)


def inject_mission_editor_code(dcs_path: typing.Union[str, Path]) -> bool:
    """
    Injects code needed for the new login method in MissionEditor.lua

    Args:
        dcs_path: path to the DCS installation

    Returns:
        Bool indicating success of the operation

    """
    dcs_path = core.FS.ensure_path(dcs_path)

    LOGGER.debug(f'injecting MissionEditor.lua code in DCS installation: {dcs_path.absolute()}')
    if not dcs_path.exists():
        raise FileNotFoundError(dcs_path.absolute())

    mission_editor_lua_path = core.FS.get_mission_editor_lua_file(dcs_path)
    LOGGER.debug(f'MissionEditor.lua path: {mission_editor_lua_path.absolute()}')
    if not mission_editor_lua_path.exists():
        raise FileNotFoundError(mission_editor_lua_path.absolute())

    LOGGER.debug('backing up MissionEditor.lua')
    utils.create_versioned_backup(mission_editor_lua_path)

    LOGGER.debug('injecting code')
    output, count = RE_INJECT.subn(INJECT_TEMPLATE, mission_editor_lua_path.read_text(encoding='utf8'))

    if count == 0:
        LOGGER.warning('no replacement made')
        return False

    LOGGER.debug('writing resulting file')
    mission_editor_lua_path.write_text(output, encoding='utf8')
    return True
