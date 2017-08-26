# coding=utf-8
"""
Runs a Discord bot using the discord.py library
"""

import os
import random

import aiohttp.errors
import discord
import websockets.exceptions

from esst.core import CFG, CTX, MAIN_LOGGER
from .abstract import AbstractDiscordBot, AbstractDiscordCommandParser
from .commands import DiscordCommands
from .logging_handler import register_logging_handler
from .tasks import DiscordTasks

LOGGER = MAIN_LOGGER.getChild(__name__)


class DiscordBot(DiscordTasks,  # pylint: disable=too-many-instance-attributes
                 DiscordCommands,
                 AbstractDiscordBot):
    """
    ESST Discord bot.

    This class is self-contained in a thread that will auto-start.
    """

    @property
    def parser(self) -> AbstractDiscordCommandParser:
        return self._parser

    @property
    def channel(self) -> discord.Channel:
        return self._channel

    @property
    def user(self) -> discord.User:
        return self._user

    @property
    def member(self) -> discord.Member:
        return self._member

    @property
    def server(self) -> discord.Server:
        return self._server

    @property
    def client(self) -> discord.Client:
        return self._client

    @property
    def ready(self) -> bool:
        return bool(self._ready)

    @property
    def exiting(self) -> bool:
        return bool(self._exiting)

    def __init__(self):
        self._parser = make_root_parser()
        self._client = None
        self._server = None
        self._user = None
        self._member = None
        self._channel = None
        self._ready = False
        self._exiting = False
        self.tasks = None

        if not CTX.discord_start_bot:
            LOGGER.debug('skipping Discord bot startup')
            return
        self._exit = False

        LOGGER.debug('starting Discord bot')
        CTX.discord_msg_queue.put(CFG.discord_motd)
        register_logging_handler()

    def _create_client(self):
        self._client = discord.Client(loop=CTX.loop)
        # self.tasks = asyncio.gather(
        #     self.monitor_exit_signal(),
        #     self.monitor_queues(),
        #     loop=CTX.loop,
        # )
        CTX.loop.create_task(self.monitor_queues())
        # CTX.loop.create_task(self.monitor_exit_signal())
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

    async def _update_presence(
            self,
            status: str = discord.Status.online,
            afk: bool = False,
    ):
        members = list(self.server.members)
        members.remove(self._member)
        random_member = random.choice(members)
        await self.client.change_presence(
            game=discord.Game(
                name=f'with {random_member.display_name}',
                url=r'https://goo.gl/ZrxoaV',
                type=0,
            ),
            status=status,
            afk=afk,
        )

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

    async def run(self):
        if not CTX.discord_start_bot:
            LOGGER.debug('skipping Discord loop')
            return

        while not CTX.exit:
            LOGGER.debug('starting Discord client')
            self._create_client()
            try:
                await self.client.start(CFG.discord_token)
        except websockets.exceptions.InvalidHandshake:
            LOGGER.exception('invalid handshake')
        except websockets.exceptions.ConnectionClosed:
            LOGGER.exception('connection closed')
        except websockets.exceptions.InvalidState:
            LOGGER.exception('invalid state')
        except websockets.exceptions.PayloadTooBig:
            LOGGER.exception('payload too big')
        except websockets.exceptions.WebSocketProtocolError:
            LOGGER.exception('protocol error')
        except KeyboardInterrupt:
            pass

        if not self._exit:
            await self.run()
