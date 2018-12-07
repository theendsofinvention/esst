# coding=utf-8
"""
Dummy abstract class to help split the Discord bot into multiple more manageable classes
"""
import abc
import sys

import discord


class AbstractDiscordCommandParser:
    """
    Generic command parser for Discord bot
    """

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
        """
        Dispatch a command to an underlying function

        Args:
            argv: list of arguments
            add_help_command: whether or not to add help command
            completion: auto-completion of missing commands
            pre_call: function to call before
            output_file: redirect stdout
            errors_file: redirect stderr
            raw_output: outputs result as text
            namespace: command namespace
            skip_unknown_args: ignore unknown args
        """

    @abc.abstractmethod
    def parse_args(self, args=None, namespace=None):
        """
        Parse received args

        Args:
            args: arg list
            namespace: command namespace
        """

    @abc.abstractmethod
    def format_help(self):
        """
        Format and return help text

        """

    @abc.abstractmethod
    def parse_discord_message(self, message: str, is_admin: bool):
        """
        PArses message from Discord

        Args:
            message: message content
            is_admin: is sender an admin?

        """


class AbstractDiscordBot:
    """
    Dummy abstract class to help split the Discord bot into multiple more manageable classes
    """

    @property
    @abc.abstractmethod
    def parser(self) -> AbstractDiscordCommandParser:
        """
        Command parser
        """

    @property
    @abc.abstractmethod
    def ready(self) -> bool:
        """
        Indicates if the bot is ready to process messages

        Returns: readiness as a boolean
        """

    @property
    @abc.abstractmethod
    def client(self) -> discord.Client:
        """
        Represents the bot :py:class:`discord.Client` object
        """

    @property
    @abc.abstractmethod
    def server(self) -> discord.Server:
        """
        Represents the bot :py:class:`discord.Server` object
        """

    @property
    @abc.abstractmethod
    def user(self) -> discord.User:
        """
        Represents the bot :py:class:`discord.User` object
        """

    @property
    @abc.abstractmethod
    def member(self) -> discord.Member:
        """
        Represents the bot :py:class:`discord.Member` object
        """

    @property
    @abc.abstractmethod
    def channel(self) -> discord.Channel:
        """
        Represents the bot :py:class:`discord.Channel` object

        This is the channel the bot will listen for commands in
        """

    @abc.abstractmethod
    def say(self, message: str):
        """
        Sends a message to the channel

        Args:
            message: message to send as string
        """

    @abc.abstractmethod
    def send(self, file_path: str):
        """
        Sends a file to the channel

        Args:
            file_path: path to file to send
        """
