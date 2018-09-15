# coding=utf-8
"""
Pytest config file
"""
import os
import sys
from pathlib import Path

import pytest


# from esst import core


def pytest_configure(config):
    """
    Runs at tests startup

    Args:
        config: pytest config args
    """
    print('pytest args: ', config.args)
    os.environ['DCS_PATH'] = 'test'
    os.environ['DCS_SERVER_NAME'] = 'test'
    os.environ['DCS_SERVER_PASSWORD'] = 'test'
    os.environ['DISCORD_BOT_NAME'] = 'test'
    os.environ['DISCORD_CHANNEL'] = 'test'
    os.environ['DISCORD_TOKEN'] = 'test'
    sys._called_from_test = True


# noinspection SpellCheckingInspection
def pytest_unconfigure(config):
    """Tear down"""
    print('pytest args: ', config.args)
    # noinspection PyUnresolvedReferences,PyProtectedMember
    del sys._called_from_test


# @pytest.fixture(autouse=True)
# def _reset_fs():
#     core.FS._reset()
#     yield
#     core.FS._reset()


@pytest.fixture(autouse=True)
def _dummy_config():
    Path('./esst_test.yml').write_text("""
dcs_path: './DCS'
dcs_server_name: 'server_name'
dcs_server_password: 'server_pwd'
discord_bot_name: 'bot_name'
discord_channel: 'channel'
discord_token: 'token'
    """)
    yield


@pytest.fixture(autouse=True)
def cleandir(request, tmpdir):
    """
    Creates a clean directory and cd into it for the duration of the test

    Args:
        request: Pytest request object
        tmpdir: Pytest tmpdir fixture

    """
    # from esst.core import FS
    # FS.saved_games_path = Path(str(tmpdir), 'Saved Games').absolute()
    # FS.ur_install_path = Path(str(tmpdir), 'UniversRadio').absolute()
    if 'nocleandir' in request.keywords:
        yield
    else:
        current_dir = os.getcwd()
        os.chdir(str(tmpdir))
        yield os.getcwd()
        os.chdir(current_dir)


def pytest_addoption(parser):
    """Adds options to Pytest command line"""
    parser.addoption("--long", action="store_true",
                     help="run long tests")


def pytest_runtest_setup(item):
    """Test suite setup"""

    # Skip tests that are marked with the "long" marker
    long_marker = item.get_marker("long")
    if long_marker is not None and not item.config.getoption('long'):
        pytest.skip('skipping long tests')
