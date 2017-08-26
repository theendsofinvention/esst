# coding=utf-8
"""
Manages a UDP socket and does two things:

1. Retrieve incoming messages from DCS and update :py:class:`esst.core.status.status`
2. Sends command to the DCS application via the socket
"""

import json
import socket
import time
import asyncio

from esst.core import MAIN_LOGGER, Status, CFG, CTX

LOGGER = MAIN_LOGGER.getChild(__name__)

KNOWN_COMMANDS = ['exit dcs']

PING_TIMEOUT = 30


class DCSListener:
    """
    This class is a self-starting thread that creates and manages a UDP socket as a two-way communication with DCS
    """

    def __init__(self):
        self.monitoring = False
        self.last_ping = None
        self.startup_age = None

        if not CTX.socket_start:
            LOGGER.debug('skipping startup of socket')
            return

        LOGGER.debug('starting socket thread')

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = ('localhost', 10333)

        self.cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cmd_address = ('localhost', 10334)

    def _parse_ping(self, data: dict):
        if Status.paused != data.get('paused'):
            if not data.get('paused'):
                LOGGER.info('DCS server is ready!')
        self.last_ping = time.time()
        Status.server_age = data.get('time')
        Status.mission_time = data.get('model_time')
        Status.paused = data.get('paused')
        Status.mission_file = data.get('mission_filename')
        Status.mission_name = data.get('mission_name')
        Status.players = data.get('players')

    def _parse_status(self, data: dict):
        LOGGER.debug(f'DCS server says: {data["message"]}')
        Status.server_status = data['message']
        if data['message'] in ['loaded mission']:
            LOGGER.debug('starting monitoring server pings')
            self.last_ping = time.time()
            self.monitoring = True
            CTX.socket_monitor_server_startup = False
        if data['message'] in ['stopping simulation']:
            LOGGER.debug('stopped monitoring server pings')
            self.monitoring = False

    async def _parse_commands(self):
        await asyncio.sleep(0.1)
        if not CTX.socket_cmd_q.empty():
            command = CTX.socket_cmd_q.get_nowait()
            if command not in KNOWN_COMMANDS:
                raise ValueError(f'unknown command: {command}')
            else:
                command = {'cmd': command}
                command = json.dumps(command) + '\n'
                LOGGER.debug(f'sending command via socket: {command}')
                self.cmd_sock.sendto(command.encode(), self.cmd_address)

    async def _monitor_server(self):
        await asyncio.sleep(0.1)
        if self.monitoring:
            if time.time() - self.last_ping > CFG.dcs_ping_interval:
                LOGGER.error('It has been 30 seconds since I heard from DCS. '
                             'It is likely that the server has crashed.')
                CTX.dcs_do_restart = True
                self.monitoring = False

    async def _monitor_server_startup(self):
        await asyncio.sleep(0.1)
        if CTX.socket_monitor_server_startup:
            if self.startup_age is None:
                self.startup_age = time.time()
            if time.time() - self.startup_age > CFG.dcs_server_startup_time:
                LOGGER.error('DCS is taking more than 2 minutes to start a multiplayer server.\n'
                             'Something is wrong ...')
                CTX.socket_monitor_server_startup = False

    async def _read_socket(self):
        await asyncio.sleep(0.1)
        try:
            data, _ = self.sock.recvfrom(4096)
            data = json.loads(data.decode().strip())
            if data['type'] == 'ping':
                self._parse_ping(data)
            if data['type'] == 'status':
                self._parse_status(data)
            else:
                pass
        except socket.timeout:
            pass

    async def run(self):
        """
        Infinite loop that manages a UDP socket and does two things:

        1. Retrieve incoming messages from DCS and update :py:class:`esst.core.status.status`
        2. Sends command to the DCS application via the socket
        """
        if not CTX.socket_start:
            LOGGER.debug('skipping startup of socket loop')
            return

        self.sock.bind(self.server_address)
        self.sock.settimeout(1)

        while not CTX.exit:
            await self._read_socket()
            await self._parse_commands()
            await self._monitor_server_startup()
            await self._monitor_server()
            await asyncio.sleep(0.1)

        self.sock.close()
        self.cmd_sock.close()
        LOGGER.debug('end of listener loop')

    async def exit(self):
        pass
