# coding=utf-8
"""
Manages background tasks for Discord bot
"""

import asyncio
import time

from esst.core import CTX
from .abstract import AbstractDiscordBot
from .catch_exc import catch_exc


# noinspection PyAbstractClass
class DiscordTasks(AbstractDiscordBot):  # pylint: disable=abstract-method
    """
    Abstract class that contains background tasks for :py:class:`esst.discord_bot.DiscordBot`
    """

    @catch_exc
    async def say(self, message: str):
        """
        Sends a message

        Args:
            message: message to send
        """
        time_stamp = time.strftime('%X')
        content = f'{time_stamp}```{message}```'
        if self.client and self.client.is_logged_in and self.channel:
            # noinspection PyUnresolvedReferences
            await self.client.send_message(self.channel, content=content)
            return True

    @catch_exc
    async def send(self, file_path: str):
        """Sends a file to a Discord channel"""
        if self.client and self.client.is_logged_in and self.channel:
            # noinspection PyUnresolvedReferences
            await self.client.send_file(self.channel, file_path, content='There you go:')
            return True

    async def _process_message_queue(self):
        if self.client.is_closed or not CTX.wan:
            return
        if not CTX.discord_msg_queue.empty():
            message = CTX.discord_msg_queue.get_nowait()
            if not await self.say(message):
                CTX.discord_msg_queue.put(message)

    async def _process_file_queue(self):
        if self.client.is_closed or not CTX.wan:
            return
        if not CTX.discord_file_queue.empty():
            file = CTX.discord_file_queue.get_nowait()
            if not await self.send(file):
                CTX.discord_msg_queue.put(file)

    @catch_exc
    async def _monitor_queues(self):
        while self.client is None:
            if CTX.exit:
                return True
            await asyncio.sleep(0.1)
        while not self.ready:
            if CTX.exit:
                return True
            await asyncio.sleep(0.1)
        await self.client.wait_until_ready()
        while not self.client.is_closed:
            await self._process_message_queue()
            await self._process_file_queue()
            await asyncio.sleep(0.1)
            if CTX.exit:
                return True

    async def monitor_queues(self):
        """
        Checks the message queue for pending messages to send
        """
        while not CTX.exit:
            if await self._monitor_queues():
                break
