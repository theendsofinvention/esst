# coding=utf-8


import json
import typing

import requests

from esst.core import MAIN_LOGGER

LOGGER = MAIN_LOGGER.getChild(__name__)

BASE_URL = 'https://api.github.com/'


def _make_request(endpoint):
    url = f'{BASE_URL}{endpoint}'
    LOGGER.debug(url)
    r = requests.get(url)
    if r.ok:
        return json.loads(r.text or r.content)
    if r.text or r.content:
        resp = json.loads(r.text or r.content)
        if resp['message']:
            raise ConnectionError(f'Request failed: {url}\nMessage: {resp["message"]}')

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


if __name__ == '__main__':
    tag, name, dlurl = get_latest_release('132nd-vWing', '132nd-Virtual-Wing-Training-Mission-Tblisi')
    print(tag, name, dlurl)
