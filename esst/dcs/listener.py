# coding=utf-8
"""
Manages a UDP socket and does two things:

1. Retrieve incoming messages from DCS and update :py:class:`esst.core.status.Status`
2. Sends command to the DCS application via the socket
"""

import json
import queue
import socket
import threading
import time

import blinker

from esst.core.logger import MAIN_LOGGER
from esst.core.status import Status

LOGGER = MAIN_LOGGER.getChild(__name__)

SOCKET_CMD_QUEUE = queue.Queue()
KNOWN_COMMANDS = ['exit dcs', 'exit']

PING_TIMEOUT = 30


def catch_command_signals(sender, **kwargs):
    """
    Listens for blinker.signal('socket command')

    Passes command to be executed in DCS

    Args:
        sender: name of the sender
        **kwargs: must contain "cmd" as a string
    """
    LOGGER.debug(f'got command signal from {sender}: {kwargs}')
    if 'cmd' not in kwargs:
        raise RuntimeError('missing command in signal')
    cmd = kwargs['cmd']
    if cmd not in KNOWN_COMMANDS:
        raise RuntimeError(f'unknown socket command: {cmd}')
    SOCKET_CMD_QUEUE.put(kwargs['cmd'])


blinker.signal('socket command').connect(catch_command_signals)


class DCSListener(threading.Thread):
    """
    This class is a self-starting thread that creates and manages a UDP socket as a two-way communication with DCS
    """

    def __init__(self, ctx):
        self.ctx = ctx
        threading.Thread.__init__(self, daemon=True)
        self.monitoring = False
        self.last_ping = None
        self.start()

    def run(self):
        """
        Starts the thread
        """
        self.listen()

    def start_monitoring(self):
        """
        Start measuring the intervals between pings received from the DCS server and triggers a DCS restarts if
        it gets too high
        """
        LOGGER.debug('starting monitoring server pings')
        self.last_ping = time.time()
        self.monitoring = True

    def stop_monitoring(self):
        """
        Stop measuring the intervals between pings received from the DCS server
        """
        LOGGER.debug('stopped monitoring server pings')
        self.monitoring = False

    def _parse_ping(self, data: dict):
        self.last_ping = time.time()
        Status.server_age = data.get('time')
        Status.mission_time = data.get('model_time')
        Status.paused = data.get('paused')
        Status.mission_file = data.get('mission_filename')
        Status.mission_name = data.get('mission_name')
        Status.players = data.get('players')

    def _parse_status(self, data: dict):
        if data['message'] in ['loaded mission']:
            self.start_monitoring()
        if data['message'] in ['stopping simulation']:
            self.stop_monitoring()
        LOGGER.info(f'DCS server says: {data["message"]}')

    def listen(self):
        """
        Infinite loop that manages a UDP socket and does two things:

        1. Retrieve incoming messages from DCS and update :py:class:`esst.core.status.Status`
        2. Sends command to the DCS application via the socket
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = ('localhost', 10333)
        sock.bind(server_address)
        sock.settimeout(1)

        cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cmd_address = ('localhost', 10334)

        while True:

            time.sleep(0.5)

            try:
                data, _ = sock.recvfrom(4096)
                data = json.loads(data.decode().strip())
                if data['type'] == 'ping':
                    self._parse_ping(data)
                if data['type'] == 'status':
                    self._parse_status(data)
                else:
                    pass
            except socket.timeout:
                pass

            if not SOCKET_CMD_QUEUE.empty():
                message = SOCKET_CMD_QUEUE.get_nowait()
                if message == 'exit':
                    sock.close()
                    blinker.signal('socket ready to exit').send(__name__)
                    break
                message = {'cmd': message}
                message = json.dumps(message) + '\n'
                LOGGER.debug(f'sending command via socket: {message}')
                cmd_sock.sendto(message.encode(), cmd_address)
            if self.monitoring:
                if time.time() - self.last_ping > 30:
                    LOGGER.error('It has been 30 seconds since I heard from DCS. '
                                 'It is likely that the server has crashed.')
                    blinker.signal('dcs command').send(__name__, cmd='restart')
                    self.stop_monitoring()
