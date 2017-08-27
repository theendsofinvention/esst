# coding=utf-8
"""
Manages Discord chat commands
"""
import discord

from esst.core import MAIN_LOGGER
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

    async def on_message(self, message: discord.Message):  # noqa: C901  # pylint: disable=too-many-branches
        """
        Triggers on any message received from the Discord server

        Args:
            message: message received

        """
        if message.author.id == self.member.id:
            return
        if message.channel != self.channel:
            return
        if message.attachments:
            for attach in message.attachments:
                if attach['filename'].endswith('.miz'):
                    overwrite = 'overwrite' in message.content
                    load = 'load' in message.content
                    missions_manager.download_mission_from_discord(attach, overwrite, load)
        if message.content.startswith('!'):
            LOGGER.debug(f'received "{message.content}" command from: {message.author.display_name}')

            self.parser.parse_discord_message(message.content)
