# coding=utf-8
"""
Manages config params for auto mission
"""

from elib.config import ConfigProp

from esst import __version__

NAMESPACE = 'DISCORD'


class DiscordConfig:
    """
    Manages config params for auto mission
    """
    discord_bot_name = ConfigProp(str, default='', namespace=NAMESPACE)
    discord_channel = ConfigProp(str, default='', namespace=NAMESPACE)
    discord_token = ConfigProp(str, default='', namespace=NAMESPACE)
    discord_admin_role = ConfigProp(list, default='', namespace=NAMESPACE)
    discord_motd = ConfigProp(str, namespace=NAMESPACE,
                default='Hello!\n'
                        f'This is ESST v{__version__}\n'
                        'Type "!help" for a list of available commands')
