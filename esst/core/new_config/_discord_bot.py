# coding=utf-8

from elib.config import ConfigProp

from ..version import __version__

NAMESPACE = 'DISCORD'


class DiscordConfig:
    @ConfigProp(str, namespace=NAMESPACE)
    def discord_bot_name(self):
        pass

    @ConfigProp(str, namespace=NAMESPACE)
    def discord_channel(self):
        pass

    @ConfigProp(str, namespace=NAMESPACE)
    def discord_token(self):
        pass

    @ConfigProp(str, namespace=NAMESPACE,
                default='Hello!\n'
                        f'This is ESST v{__version__}\n'
                        'Type "!help" for a list of available commands')
    def discord_motd(self):
        pass
