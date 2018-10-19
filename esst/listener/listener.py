# coding=utf-8
"""
Manages a UDP socket and does two things:

1. Retrieve incoming messages from DCS and update :py:class:`esst.core.status.status`
2. Sends command to the DCS application via the socket
"""
import asyncio
import json
import socket
import sys
import time

from esst import DCSConfig, LOGGER
from esst.core import CTX, Status
from esst.utils import now

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

        if not CTX.start_listener_loop:
            LOGGER.debug('skipping startup of socket')
            return

        LOGGER.debug('starting socket thread')

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = ('localhost', CTX.listener_server_port)

        self.cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cmd_address = ('localhost', CTX.listener_cmd_port)

    def _parse_ping(self, data: dict):
        if Status.paused != data.get('paused'):
            if not data.get('paused'):
                LOGGER.info('DCS server is ready!')
        players = data.get('players', set())
        if players != Status.players:
            players, old_players = set(players), set(Status.players)
            joined = players - old_players
            left = old_players - players
            if joined:
                LOGGER.info('player(s) joined: %s', ', '.join(joined))
            if left:
                LOGGER.info('player(s) left: %s', ', '.join(left))
        self.last_ping = time.time()
        Status.server_age = data.get('time', 'unknown')
        Status.mission_time = data.get('model_time', 'unknown')
        Status.paused = data.get('paused', 'unknown')
        Status.mission_file = data.get('mission_filename', 'unknown')
        Status.mission_name = data.get('mission_name', 'unknown')
        Status.players = data.get('players', set())

        CTX.players_history.append((now(), len(Status.players)))

    def _parse_status(self, data: dict):
        LOGGER.debug('DCS server says: %s', data["message"])
        if data['message'] in ['loaded mission']:
            LOGGER.debug('starting monitoring server pings')
            self.last_ping = time.time()
            self.monitoring = True
            CTX.listener_monitor_server_startup = False
        if data['message'] in ['stopping simulation']:
            LOGGER.debug('stopped monitoring server pings')
            self.monitoring = False
        Status.server_status = data['message']

    # def _parse_mission_load(self, data: dict):
    #     print(data)

    async def _parse_commands(self):
        await asyncio.sleep(0.1)
        if not CTX.listener_cmd_queue.empty():
            command = CTX.listener_cmd_queue.get_nowait()
            if command not in KNOWN_COMMANDS:
                raise ValueError(f'unknown command: {command}')
            else:
                command = {'cmd': command}
                command = json.dumps(command) + '\n'
                LOGGER.debug('sending command via socket: %s', command)
                self.cmd_sock.sendto(command.encode(), self.cmd_address)

    async def _monitor_server(self):
        await asyncio.sleep(0.1)
        if self.monitoring:
            if time.time() - self.last_ping > DCSConfig.DCS_PING_INTERVAL():
                LOGGER.error('It has been %s seconds since I heard from DCS. '
                             'It is likely that the server has crashed.',
                             DCSConfig.DCS_PING_INTERVAL())
                CTX.dcs_do_restart = True
                self.monitoring = False

    async def _monitor_server_startup(self):
        await asyncio.sleep(0.1)
        if CTX.listener_monitor_server_startup:
            if self.startup_age is None:
                self.startup_age = time.time()
            if time.time() - self.startup_age > DCSConfig.DCS_START_GRACE_PERIOD():
                LOGGER.error(f'DCS is taking more than %s seconds to start a '
                             'multiplayer server.\n'
                             'Something is wrong ...',
                             DCSConfig.DCS_START_GRACE_PERIOD())
                CTX.listener_monitor_server_startup = False

    async def _read_socket(self):
        await asyncio.sleep(0.1)
        try:
            data, _ = self.sock.recvfrom(4096)
            data = json.loads(data.decode().strip())
            if data['type'] == 'ping':
                self._parse_ping(data)
            elif data['type'] == 'status':
                self._parse_status(data)
            # elif data['type'] == 'mission_load':
            #     self._parse_mission_load(data)
            else:
                LOGGER.warning('unknown command received on DCS socket: "%s"', data['type'])
        except socket.timeout:
            pass

    async def run(self):
        """
        Infinite loop that manages a UDP socket and does two things:

        1. Retrieve incoming messages from DCS and update :py:class:`esst.core.status.status`
        2. Sends command to the DCS application via the socket
        """
        if not CTX.start_listener_loop:
            LOGGER.debug('skipping startup of socket loop')
            return

        try:
            self.sock.bind(self.server_address)
        except socket.error as exc:
            if exc.errno == 10048:
                LOGGER.error('cannot bind socket, maybe another instance of ESST is already running?')
                sys.exit(-1)

        self.sock.settimeout(1)

        while not CTX.exit:
            await self._read_socket()
            await self._parse_commands()
            await self._monitor_server_startup()
            await self._monitor_server()
            await asyncio.sleep(0.1)

        self.sock.close()
        LOGGER.debug('end of listener loop')

    async def run_until_dcs_is_closed(self):
        """
        Parse commands until DCS has closed itself (or was killed)
        """
        while Status.dcs_application != 'not running':
            await self._parse_commands()
            await asyncio.sleep(0.1)
        self.cmd_sock.close()
