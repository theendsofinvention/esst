# coding=utf-8
"""
Manages Discord chat commands
"""
import discord

from esst.core import CFG, MAIN_LOGGER
from esst.dcs import missions_manager
from esst.discord_bot import abstract

LOGGER = MAIN_LOGGER.getChild(__name__)


# noinspection PyAbstractClass
class DiscordEvents(abstract.AbstractDiscordBot):  # pylint: disable=abstract-method
    """
    Manages Discord chat commands
    """

    async def on_message_edit(self, _: discord.Message, after: discord.Message):
        """
        Dummy event catcher to re-transmit message when they're edited

        Messages are simply re-routed to the "on_message" event

        Args:
            _: message before edit
            after: message after edit
        """
        await self.on_message(after)

    # pylint: disable=too-many-branches
    async def on_message(self, message: discord.Message):  # noqa: C901
        """
        Triggers on any message received from the Discord server

        Args:
            message: message received

        """
        if message.author.id == self.member.id:
            return
        if message.channel != self.channel:
            return
        if CFG.discord_admin_role:
            is_admin = bool([role for role in CFG.discord_admin_role  # pylint: disable=not-an-iterable
                             if role in [role.name for role in message.author.roles]])
        else:
            is_admin = True
        if message.attachments:
            for attach in message.attachments:
                if attach['filename'].endswith('.miz'):
                    if not is_admin:
                        LOGGER.error(
                            f'only users with role "{CFG.discord_admin_role}" can load missions on the server')
                        return
                    overwrite = 'overwrite' in message.content
                    load = 'load' in message.content
                    force = 'force' in message.content
                    missions_manager.download_mission_from_discord(attach, overwrite, load, force)
        if message.content.startswith('!'):
            LOGGER.debug(f'received "{message.content}" command from: {message.author.display_name}'
                         f'{" (admin)" if is_admin else ""}')

            self.parser.parse_discord_message(message.content, is_admin)
