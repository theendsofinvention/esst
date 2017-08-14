# coding=utf-8
"""
Manages Discord chat commands
"""
import blinker
import discord
import humanize

from esst.core.logger import MAIN_LOGGER
from esst.core.status import Status
from esst.core.version import __version__
from esst.dcs import missions_manager
from .abstract import AbstractDiscordBot

LOGGER = MAIN_LOGGER.getChild(__name__)


# noinspection PyAbstractClass
class DiscordCommands(AbstractDiscordBot):  # pylint: disable=abstract-method
    """
    Manages Discord chat commands
    """
    async def say(self, message: str):
        """
        Sends a message

        Args:
            message: message to send
        """
        content = f'```{message}```'
        # noinspection PyUnresolvedReferences
        await self.client.send_message(self.channel, content=content)

    async def print_help(self):
        """
        Prints help text in the Discord channel
        """
        await self.say(
            f'This is ESST v{__version__}\n'
            f'Available commands are:\n\n'
            f'!help:            prints this message\n\n'

            f'DCS commands:\n'
            f'!dcs status:          print current status of the server\n'
            f'!dcs version:         print the version of DCS running on the server\n'
            f'!dcs show missions:   show a list of the available mission on the server\n'
            f'!dcs show cpu:        show CPU usage of DCS.exe over the last 5 seconds\n'
            f'!dcs show cpu start:  start printing CPU usage of DCS.exe\n'
            f'!dcs show cpu stop:   stop printing CPU usage of DCS.exe\n'
            f'!dcs load [MISSION]:  restart DCS with the specified MISSION\n'
            f'!dcs restart:         restart DCS with the same mission\n\n'

            f'Upload a mission to the server:\n'
            f'Simply drag and drop the mission file to this channel on Discord, and type the options in '
            f'the "Add a comment" field of the upload window\n'
            f'\tAvailable options:\n'
            f'\t\t"overwrite": allow overwriting existing files\n'
            f'\t\t"load": immediately restart the server with the new mission\n'
            f'\t\t(note: options can be combined, for example: "load overwrite")\n'
        )

    # noinspection PyMethodMayBeStatic
    async def restart_dcs(self):
        """
        Sends restart command to the DCS application
        """
        blinker.signal('dcs command').send(__name__, cmd='restart')

    # noinspection PyMethodMayBeStatic
    async def show_cpu(self):
        """
        Show cpu usage of DCS once on Discord
        """
        blinker.signal('dcs command').send(__name__, cmd='show cpu')

    # noinspection PyMethodMayBeStatic
    async def show_cpu_start(self):
        """
        Starts showing CPU usage of DCS on Discord constantly (every 5 seconds)
        """
        blinker.signal('dcs command').send(__name__, cmd='show cpu start')

    # noinspection PyMethodMayBeStatic
    async def show_cpu_stop(self):
        """
        Stops showing CPU usage of DCS on Discord constantly
        """
        blinker.signal('dcs command').send(__name__, cmd='show cpu stop')

    async def print_dcs_status(self):
        """
        Prints the status of the DCS server
        """
        output = []
        for var in dir(Status):
            if var.startswith('_'):
                continue
            if var in ['mission_time', 'server_age']:
                output.append(f'{str.capitalize(var).replace("_", " ")}: '
                              f'{humanize.naturaltime(getattr(Status, var))}')
            else:
                output.append(f'{str.capitalize(var).replace("_", " ")}: {getattr(Status, var)}')
        output = '\n'.join(output)
        await self.say(f'{output}')

    async def show_missions(self):
        """
        Show available missions
        """
        mission_list = '\n\t'.join(missions_manager.list_available_missions())
        await self.say(''
                       'Available missions:\n'
                       f'\t{mission_list}\n\n'
                       'Use "!dcs load MISSION" where MISSION is one of the missions listed above to restart '
                       'the server with that mission file'
                       '')

    # noinspection PyMethodMayBeStatic
    async def load_mission(self, mission: str):
        """
        Loads specific mission

        Args:
            mission: mission to load
        """
        missions_manager.set_active_mission_from_name(mission, load=True)

    async def on_message_edit(self, _: discord.Message, after: discord.Message):
        """
        Dummy event catcher to re-transmit message when they're edited

        Messages are simply re-routed to the "on_message" event

        Args:
            _: message before edit
            after: message after edit
        """
        await self.on_message(after)

    async def on_message(self, message: discord.Message):  # pylint: disable=too-many-branches  # noqa: C901
        """
        Triggers on any message received from the Discord server

        Args:
            message: message received

        """
        if message.channel != self.channel:
            return
        if message.attachments:
            for attach in message.attachments:
                if attach['filename'].endswith('.miz'):
                    overwrite = 'overwrite' in message.content
                    load = 'load' in message.content
                    missions_manager.download_mission_from_discord(attach, overwrite, load)
        if message.content.startswith('!'):
            LOGGER.debug(f'received "{message.content}" command from: {message.author.display_name}')
            if message.content.startswith('!help'):
                await self.print_help()
            elif message.content.startswith('!dcs version'):
                await self.say(f'\nDCS version: {Status.dcs_version}')
            elif message.content.startswith('!dcs status'):
                await self.print_dcs_status()
            elif message.content.startswith('!dcs show missions'):
                await self.show_missions()
            elif message.content == '!dcs show cpu':
                await self.show_cpu()
            elif message.content == '!dcs show cpu start':
                await self.show_cpu_start()
            elif message.content == '!dcs show cpu stop':
                await self.show_cpu_stop()
            elif message.content.startswith('!dcs load '):
                await self.load_mission(message.content.replace('!dcs load ', ''))
            elif message.content.startswith('!dcs restart'):
                await self.restart_dcs()
            else:
                await self.say(f'Unknown command: {message.content}\n'
                               f'Type "!help" for a list of the available commands')
