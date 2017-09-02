# coding=utf-8

import websockets.exceptions
import socket
import aiohttp

from esst.core import CTX, MAIN_LOGGER
from esst.utils.conn import wan_available

LOGGER = MAIN_LOGGER.getChild(__name__)


def _pass_exception(exc):
    LOGGER.error(exc)
    # LOGGER.exception('Discord bot error')
    if CTX.sentry:
        CTX.sentry.captureException(True)

def catch_exc(func):

    async def wrapper(*args, **kwargs):

        try:
            return await func(*args, **kwargs)
        except websockets.exceptions.InvalidHandshake as exc:
            _pass_exception(exc)
        except websockets.exceptions.InvalidState as exc:
            _pass_exception(exc)
        except websockets.exceptions.PayloadTooBig as exc:
            _pass_exception(exc)
        except websockets.exceptions.WebSocketProtocolError as exc:
            _pass_exception(exc)
        except websockets.exceptions.InvalidURI as exc:
            _pass_exception(exc)
        except (aiohttp.ClientError, ConnectionError, OSError, aiohttp.ClientOSError) as exc:
            wan_available()
            _pass_exception(exc)

    return wrapper
