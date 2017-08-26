# coding=utf-8
"""
Dummy abstract class to help split the Discord bot into multiple more manageable classes
"""

import abc
import sys

import discord

from esst.core.context import Context


class AbstractDiscordCommandParser:
    @abc.abstractmethod
    def dispatch(self,
                 argv=None,
                 add_help_command=True,
                 completion=True,
                 pre_call=None,
                 output_file=sys.stdout,
                 errors_file=sys.stderr,
                 raw_output=False,
                 namespace=None,
                 skip_unknown_args=False):
        pass

    @abc.abstractmethod
    def parse_args(self, args=None, namespace=None):
        pass

    @abc.abstractmethod
    def format_help(self):
        pass

    @abc.abstractmethod
    def parse_discord_message(self, message: str):
        pass


class AbstractDiscordBot:
    """
    Dummy abstract class to help split the Discord bot into multiple more manageable classes
    """

    @property
    @abc.abstractmethod
    def parser(self) -> AbstractDiscordCommandParser:
        pass

    @property
    @abc.abstractmethod
    def ready(self) -> bool:
        """
        Indicates if the bot is ready to process messages

        Returns: readiness as a boolean
        """
        pass

    @property
    @abc.abstractmethod
    def exiting(self) -> bool:
        """
        Indicates that the bot is trying to exit and that it should stop processing its message queue

        Returns: exit status as a boolean
        """
        pass

    @property
    @abc.abstractmethod
    def client(self) -> discord.Client:
        """
        Represents the bot :py:class:`discord.Client` object
        """
        pass

    @property
    @abc.abstractmethod
    def server(self) -> discord.Server:
        """
        Represents the bot :py:class:`discord.Server` object
        """
        pass

    @property
    @abc.abstractmethod
    def user(self) -> discord.User:
        """
        Represents the bot :py:class:`discord.User` object
        """
        pass

    @property
    @abc.abstractmethod
    def member(self) -> discord.Member:
        """
        Represents the bot :py:class:`discord.Member` object
        """
        pass

    @property
    @abc.abstractmethod
    def channel(self) -> discord.Channel:
        """
        Represents the bot :py:class:`discord.Channel` object

        This is the channel the bot will listen for commands in
        """
        pass

    @abc.abstractmethod
    def say(self, message: str):
        """
        Sends a message to the channel

        Args:
            message: message to send as string
        """
        pass

    @abc.abstractmethod
    def send(self, file_path: str):
        """
        Sends a message to the channel

        Args:
            message: message to send as string
        """
        pass
