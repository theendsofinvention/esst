# coding=utf-8
"""
Manages Discord bot configuration
"""

import elib_config

from esst.sentry.sentry_context import SentryConfigContext


class DiscordBotConfig(SentryConfigContext):
    """
    Manages Discord bot configuration
    """
    DISCORD_START_BOT = elib_config.ConfigValueBool(
        'discord', 'enable',
        description='Enable the Discord bot',
        default=True,
    )

    DISCORD_BOT_NAME = elib_config.ConfigValueString(
        'discord', 'bot_name',
        description='Name of the discord bot',
        default='Mr Shiny'
    )

    DISCORD_MOTD = elib_config.ConfigValueString(
        'discord', 'motd',
        description='"Message of the day" that will be printed when the bot joins a Discord channel',
        default=''
    )

    DISCORD_CHANNEL = elib_config.ConfigValueString(
        'discord', 'channel',
        description='Name of the Discord channel the bot should join',
    )

    # FIXME: add documentation link
    DISCORD_TOKEN = elib_config.ConfigValueString(
        'discord', 'token',
        description='Discord bot token'
    )

    DISCORD_ADMIN_ROLES = elib_config.ConfigValueList(
        'discord', 'admin_roles',
        description='Roles on your server that have admin privileges over the server through the bot',
        element_type=str,
        default=[]
    )
