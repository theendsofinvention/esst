# coding=utf-8
"""
Manages Github requests
"""

import json
import typing

import requests

from esst import LOGGER

BASE_URL = 'https://api.github.com/'


def _make_request(endpoint):
    url = f'{BASE_URL}{endpoint}'
    LOGGER.debug(url)
    req = requests.get(url)
    if req.ok:
        return json.loads(req.text or req.content)
    if req.text or req.content:
        resp = json.loads(req.text or req.content)
        if resp['message']:
            raise ConnectionError(
                f'Request failed: {url}\nMessage: {resp["message"]}')

    raise ConnectionError(f'Request failed: {url}')


def get_latest_release(owner: str, repo: str) -> typing.Tuple[str, str, str]:
    """

    Args:
        owner: owner of the Github repo
        repo: name of the Github repo

    Returns: latest version, asset name, asset download URL

    """
    resp = _make_request(f'repos/{owner}/{repo}/releases/latest')
    return resp['tag_name'], resp['assets'][0]['name'], resp['assets'][0]['browser_download_url']
