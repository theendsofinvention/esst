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

    async def say(self, message: str):
        """
        Sends a message

        Args:
            message: message to send
        """
        content = f'```{message}```'
        # noinspection PyUnresolvedReferences
        await self.client.send_message(self.channel, content=content)

    async def send(self, file_path: str):
        # noinspection PyUnresolvedReferences
        await self.client.send_file(self.channel, file_path, content='There you go:')

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

    async def _process_file_queue(self):
        if self.client.is_closed:
            return
        if not CTX.discord_file_queue.empty():
            file = CTX.discord_file_queue.get_nowait()
            try:
                await self.send(file)
            except discord.errors.HTTPException:
                CTX.discord_msg_queue.put(file)

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
            await self._process_file_queue()
            await asyncio.sleep(0.1)
            if CTX.exit:
                break
