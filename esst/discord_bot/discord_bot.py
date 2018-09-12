# coding=utf-8
"""
Runs a Discord bot using the discord.py library
"""

import asyncio
import os
import random

import aiohttp
import aiohttp.errors
import discord
import websockets.exceptions

from esst.core import CFG, CTX, MAIN_LOGGER
from .abstract import AbstractDiscordBot, AbstractDiscordCommandParser
from .catch_exc import catch_exc
from .chat_commands.parser import make_root_parser
from .events import DiscordEvents
from .logging_handler import register_logging_handler
from .tasks import DiscordTasks

LOGGER = MAIN_LOGGER.getChild(__name__)


class App(DiscordTasks,  # pylint: disable=too-many-instance-attributes
          DiscordEvents,
          AbstractDiscordBot):
    """
    ESST Discord bot.

    This class is self-contained in a thread that will auto-start.
    """

    @property
    def parser(self) -> AbstractDiscordCommandParser:
        """Chat command parser"""
        return self._parser

    @property
    def channel(self) -> discord.Channel:
        """Active channel"""
        return self._channel

    @property
    def user(self) -> discord.User:
        """User object owned by the bot"""
        return self._user

    @property
    def member(self) -> discord.Member:
        """Member object owned bu the bot"""
        return self._member

    @property
    def server(self) -> discord.Server:
        """Server object for the bot"""
        return self._server

    @property
    def client(self) -> discord.Client:
        """Client object for the bot"""
        return self._client

    @property
    def ready(self) -> bool:
        """True when the bot is initialized"""
        return bool(self._ready)

    def __init__(self):
        self._parser = make_root_parser()
        self._client = None
        self._server = None
        self._user = None
        self._member = None
        self._channel = None
        self._ready = False
        self.tasks = None

        if not CTX.start_discord_loop:
            LOGGER.debug('skipping Discord bot startup')
            return

        LOGGER.debug('starting Discord bot')
        CTX.discord_msg_queue.put(CFG.discord_motd)
        register_logging_handler()

    def _create_client(self):
        self._client = discord.Client(loop=CTX.loop)
        self.client.on_ready = self.on_ready
        self.client.on_message = self.on_message
        self.client.on_message_edit = self.on_message_edit

    async def get_channel(self):
        """
        Sets the channel for the bot.

        If the channel does not exist, it will be created on the server, provided the bot has the authorization.
        """
        for channel in self.server.channels:
            if channel.name == CFG.discord_channel:
                self._channel = channel
                break
        else:
            # noinspection PyUnresolvedReferences
            self._channel = await self.client.create_channel(
                server=self.server,
                name=CFG.discord_channel,
                type=discord.ChannelType.text,
            )

    async def _update_profile(self, user_name: str = None):
        user_name = user_name or CFG.discord_bot_name
        profile_update = {}
        if self.user.name != user_name:
            profile_update['username'] = user_name
        if os.path.exists('avatar.png'):
            with open('avatar.png', 'rb') as handle:
                profile_update['avatar'] = handle.read()
        if profile_update:
            try:
                await self.client.edit_profile(**profile_update)
            except discord.errors.HTTPException:
                pass
            except aiohttp.errors.ClientResponseError:
                pass
            except websockets.exceptions.ConnectionClosed:
                pass
            except RuntimeError:
                pass

    @catch_exc
    async def _update_presence(
            self,
            status: str = discord.Status.online,
            afk: bool = False,
    ):
        members = list(self.server.members)
        members.remove(self._member)
        random_member = random.choice(members)  # nosec
        await self.client.change_presence(
            game=discord.Game(
                name=f'with {random_member.display_name}',
                url=r'https://goo.gl/ZrxoaV',
                type=0,
            ),
            status=status,
            afk=afk,
        )

    @catch_exc
    async def on_ready(self):
        """
        Triggers when the bot is ready.
        """
        if not self.ready:
            self._user = self.client.user
            await self._update_profile()
            LOGGER.debug(f'Logged in as: {self.client.user.name}')
            try:
                self._server = set(self.client.servers).pop()
            except KeyError:
                LOGGER.error('Your discord bot has not server to connect to\n'
                             'Go to https://discordapp.com/developers/applications/me to create a bot, and note '
                             'the client ID.\n'
                             'Use the client ID in the following URL to join you bot to your Discord server:\n'
                             'https://discordapp.com/oauth2/authorize?client_id=CLIENT_ID&scope=bot')
            else:
                self._member = self.server.get_member(self.user.id)
                if self.user.display_name != CFG.discord_bot_name:
                    await self.client.change_nickname(self.member, CFG.discord_bot_name)
                await self._update_presence()

            await self.get_channel()

            self._ready = True

    @catch_exc
    async def _watch_for_exit_signals(self):
        if CTX.exit:
            while not self.ready:
                await asyncio.sleep(0.1)
            if self.ready:
                while not CTX.discord_msg_queue.empty():
                    await self._process_message_queue()
                await self.say('Bye bye !')
                await self.client.change_presence(status='offline')
            LOGGER.debug('closing Discord client')
            if self.client:
                while not self.client.is_logged_in:
                    await asyncio.sleep(0.1)
                if self.client.is_logged_in:
                    await self.client.logout()
                    await self.client.close()
                while not self.client.is_closed:
                    await asyncio.sleep(0.1)
            LOGGER.debug('Discord client is closed')
            return True

    async def watch_for_exit_signals(self):
        """
        Continuously runs and intercepts CTX.exit
        """
        while True:
            if await self._watch_for_exit_signals():
                break
            await asyncio.sleep(1)

    @catch_exc
    async def _run(self):
        if CTX.discord_can_start:
            LOGGER.debug('starting Discord client')
            self._create_client()
            await self.client.start(CFG.discord_token)
        else:
            await asyncio.sleep(1)

    @catch_exc
    async def run(self):
        """
        Main loop
        """

        if not CFG.discord_token:
            LOGGER.error('missing Discord token in config, cannot start bot')
            return

        if not CTX.start_discord_loop:
            LOGGER.debug('skipping Discord loop')
            return

        CTX.loop.create_task(self.watch_for_exit_signals())
        CTX.loop.create_task(self.monitor_queues())

        while not CTX.exit:
            await self._run()

        LOGGER.debug('end of Discord loop')
