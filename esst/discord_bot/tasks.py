# coding=utf-8
"""
Manages background tasks for Discord bot
"""

import asyncio
import queue

import blinker
import discord

from esst.core.logger import MAIN_LOGGER
from .abstract import AbstractDiscordBot
from esst.core.config import CFG

LOGGER = MAIN_LOGGER.getChild(__name__)

DISCORD_SEND_QUEUE = queue.Queue()

DISCORD_SEND_QUEUE.put(CFG.discord_motd)


def catch_message_signals(sender, **kwargs):
    """
    Listens for blinker.signal('discord message')

    Makes the Discord bot send a message

    Args:
        sender: name of the sender
        **kwargs: must contain "msg" as a string
    """
    LOGGER.debug(f'got message signal from {sender}: {kwargs}')
    if 'msg' not in kwargs:
        raise RuntimeError('missing message in signal')
    DISCORD_SEND_QUEUE.put(kwargs['msg'])


blinker.signal('discord message').connect(catch_message_signals)


# noinspection PyAbstractClass
class DiscordTasks(AbstractDiscordBot):  # pylint: disable=abstract-method
    """
    Abstract class that contains background tasks for :py:class:`esst.discord_bot.DiscordBot`
    """

    async def _on_exit(self):
        self._exiting = True  # pylint: disable=attribute-defined-outside-init
        if self.ready:
            await self.say('Bye bye !')
            await self.client.change_presence(status='offline')
        await self.client.logout()
        while not self.client.is_closed:
            await asyncio.sleep(0.1)
        self.ctx.obj['threads']['discord']['ready_to_exit'] = True
        LOGGER.debug('closing Discord thread')

    async def _process_message_queue(self):
        if self.exiting:
            return
        if not DISCORD_SEND_QUEUE.empty():
            message = DISCORD_SEND_QUEUE.get_nowait()
            LOGGER.debug(f'received message to say: {message}')
            try:
                await self.say(message)
            except discord.errors.HTTPException:
                for message in message:
                    DISCORD_SEND_QUEUE.put(message)
            LOGGER.debug('message sent')

    async def monitor_exit_signal(self):
        while not self.client.is_closed:
            if self.ctx.obj['threads']['discord']['should_exit']:
                await self._on_exit()
            await asyncio.sleep(0.1)

    async def monitor_queues(self):
        """
        Checks the message queue for pending messages to send
        """
        while not self.ready:
            await asyncio.sleep(0.1)
        await self.client.wait_until_ready()
        while not self.client.is_closed:
            await self._process_message_queue()
            await asyncio.sleep(0.1)
