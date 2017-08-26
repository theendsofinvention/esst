# coding=utf-8
"""
Manages background tasks for Discord bot
"""

import asyncio

import discord

from esst.core import MAIN_LOGGER, CTX
from .abstract import AbstractDiscordBot

LOGGER = MAIN_LOGGER.getChild(__name__)


# noinspection PyAbstractClass
class DiscordTasks(AbstractDiscordBot):  # pylint: disable=abstract-method
    """
    Abstract class that contains background tasks for :py:class:`esst.discord_bot.DiscordBot`
    """

    async def exit(self):
        if self.ready:
            await self.say('Bye bye !')
            await self.client.change_presence(status='offline')
        if self.client:
            if self.client.is_logged_in:
                await self.client.logout()
            while not self.client.is_closed:
                await asyncio.sleep(0.1)
        LOGGER.debug('Discord client is closed')

    async def _process_message_queue(self):
        if self.client.is_closed:
            return
        if not CTX.discord_msg_queue.empty():
            message = CTX.discord_msg_queue.get_nowait()
            # LOGGER.debug(f'received message to say: {message}')
            try:
                await self.say(message)
            except discord.errors.HTTPException:
                for message in message:
                    CTX.discord_msg_queue.put(message)

    async def monitor_queues(self):
        """
        Checks the message queue for pending messages to send
        """
        while not self.ready:
            if CTX.exit:
                break
            await asyncio.sleep(0.1)
        await self.client.wait_until_ready()
        while not self.client.is_closed:
            await self._process_message_queue()
            await asyncio.sleep(0.1)
            if CTX.exit:
                break
