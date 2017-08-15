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
            f'!help:                    prints this message\n\n'

            f'DCS commands:\n\n'
            f'!dcs status:              print current status of the server\n'
            f'!dcs version:             print the version of DCS running on the server\n'
            f'!dcs show missions:       show a list of the available mission on the server\n'
            f'!dcs show cpu:            show CPU usage of DCS.exe over the last 5 seconds\n'
            f'!dcs show cpu start:      start printing CPU usage of DCS.exe\n'
            f'!dcs show cpu stop:       stop printing CPU usage of DCS.exe\n'
            f'!dcs load [MISSION]:      restart DCS with the specified MISSION\n'
            f'!dcs restart:             restart DCS with the same mission\n\n'

            f'Upload a mission to the server:\n'
            f'Simply drag and drop the mission file to this channel on Discord, and type the options in '
            f'the "Add a comment" field of the upload window\n'
            f'\tAvailable options:\n'
            f'\t\t"overwrite": allow overwriting existing files\n'
            f'\t\t"load": immediately restart the server with the new mission\n'
            f'\t\t(note: options can be combined, for example: "load overwrite")\n\n'
            
            f'Environment:\n\n'
            f'!wx metar ICAO            updates the weather on the currently running mission\n' 
            f'!wx metar ICAO MISSION    updates the weather on any mission\n\n'
            f'Note: those two commands restart the DCS server with the latest mission'
        )

    async def print_dcs_status(self):
        """
        Prints the status of the DCS server
        """
        output = []
        for attr_name in dir(Status):
            if attr_name.startswith('_'):
                continue
            attr_nice_name = attr_name[:1].upper() + attr_name[1:]
            attr_nice_name = attr_nice_name.replace("_", " ")
            if attr_name in ['mission_time', 'server_age']:
                output.append(f'{attr_nice_name}: '
                              f'{humanize.naturaltime(getattr(Status, attr_name))}')
            else:
                output.append(f'{attr_nice_name}: {getattr(Status, attr_name)}')
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
        missions_manager.set_active_mission_from_name(self.ctx, mission, load=True)

    async def set_weather(self, cmd: str):
        cmd = cmd.split(' ')
        icao = cmd[0].upper()
        try:
            mission_name = cmd[1]
        except IndexError:
            mission_name = None
        # self.client.loop.create_task(missions_manager.set_weather(self.ctx, icao, mission_name))
        await missions_manager.set_weather(self.ctx, icao, mission_name)

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
                    missions_manager.download_mission_from_discord(self.ctx, attach, overwrite, load)
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
                self.ctx.obj['dcs_show_cpu_usage_once'] = True

            elif message.content == '!dcs show cpu start':
                self.ctx.obj['dcs_show_cpu_usage'] = True

            elif message.content == '!dcs show cpu stop':
                self.ctx.obj['dcs_show_cpu_usage'] = False

            elif message.content.startswith('!dcs load '):
                await self.load_mission(message.content.replace('!dcs load ', ''))

            elif message.content.startswith('!wx metar '):
                await self.set_weather(message.content.replace('!wx metar ', ''))

            elif message.content.startswith('!dcs restart'):
                self.ctx.obj['dcs_restart'] = True

            else:
                await self.say(f'Unknown command: {message.content}\n'
                               f'Type "!help" for a list of the available commands')
