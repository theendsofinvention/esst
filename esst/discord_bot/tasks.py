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
DISCORD_CMD_QUEUE = queue.Queue()

DISCORD_SEND_QUEUE.put(CFG.discord_motd)


def catch_command_signals(sender, **kwargs):
    """
    Listens for blinker.signal('discord command')

    Executes a command on the Discord bot

    Args:
        sender: name of the sender
        **kwargs: must contain "cmd" as a string
    """
    LOGGER.debug(f'got command signal from {sender}: {kwargs}')
    if 'cmd' not in kwargs:
        raise RuntimeError('missing command in signal')
    DISCORD_CMD_QUEUE.put(kwargs['cmd'])


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


blinker.signal('discord command').connect(catch_command_signals)
blinker.signal('discord message').connect(catch_message_signals)


# noinspection PyAbstractClass
class DiscordTasks(AbstractDiscordBot):  # pylint: disable=abstract-method
    """
    Abstract class that contains background tasks for :py:class:`esst.discord_bot.DiscordBot`
    """

    async def _on_exit(self):
        self._exiting = True  # pylint: disable=attribute-defined-outside-init
        await self.say('Bye bye !')
        await self.client.change_presence(status='offline')
        await self.client.logout()
        while not self.client.is_closed:
            await asyncio.sleep(0.1)
        blinker.signal('discord ready to exit').send('discord')

    async def _process_message_queue(self):
        if self.exiting:
            return
        if not DISCORD_SEND_QUEUE.empty():
            message = DISCORD_SEND_QUEUE.get_nowait()
            LOGGER.debug(f'received message to say: {message}')
            try:
                await self.say(message)
            except discord.errors.HTTPException:
                DISCORD_SEND_QUEUE.put(message)
            LOGGER.debug('message sent')

    async def _parse_command(self, command):
        if command == 'exit':
            await self._on_exit()
        else:
            raise RuntimeError(f'unknown discord command: {command}')

    async def _process_command_queue(self):
        if not DISCORD_CMD_QUEUE.empty():
            command = DISCORD_CMD_QUEUE.get_nowait()
            LOGGER.debug(f'received command: {command}')
            await self._parse_command(command)

    async def monitor_queues(self):
        """
        Checks the message queue for pending messages to send
        """
        while not self.ready:
            await asyncio.sleep(0.1)
        await self.client.wait_until_ready()
        while not self.client.is_closed:
            await self._process_message_queue()
            await self._process_command_queue()
            await asyncio.sleep(0.1)
