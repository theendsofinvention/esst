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
    @ConfigProp(str, '', namespace=NAMESPACE)
    def discord_bot_name(self) -> str:
        """
        Name of the bot
        """
        pass

    @ConfigProp(str, '', namespace=NAMESPACE)
    def discord_channel(self) -> str:
        """
        Channel to join
        """
        pass

    @ConfigProp(str, '', namespace=NAMESPACE)
    def discord_token(self) -> str:
        """
        Discord bot token
        """
        pass

    @ConfigProp(list, default='', namespace=NAMESPACE)
    def discord_admin_role(self) -> list:
        """
        List of roles that are allowed to administrate the server
        """
        pass

    @ConfigProp(str, namespace=NAMESPACE,
                default='Hello!\n'
                        f'This is ESST v{__version__}\n'
                        'Type "!help" for a list of available commands')
    def discord_motd(self):
        """
        Message of the day (sent upon connection)
        """
        pass
