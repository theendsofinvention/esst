# coding=utf-8
import os
import sys
from pathlib import Path

import pytest


@pytest.fixture(autouse=True, scope='function')
def _patch_config(tmpdir):
    from esst.core import FS
    FS.saved_games_path = Path(str(tmpdir), 'Saved Games').absolute()
    FS.ur_install_path = Path(str(tmpdir), 'UniversRadio').absolute()


def pytest_configure(config):
    print('pytest args: ', config.args)
    os.environ['DCS_PATH'] = 'test'
    os.environ['DCS_SERVER_NAME'] = 'test'
    os.environ['DCS_SERVER_PASSWORD'] = 'test'
    os.environ['DISCORD_BOT_NAME'] = 'test'
    os.environ['DISCORD_CHANNEL'] = 'test'
    os.environ['DISCORD_TOKEN'] = 'test'
    sys._called_from_test = True


def pytest_unconfigure(config):
    print('pytest args: ', config.args)
    # noinspection PyUnresolvedReferences,PyProtectedMember
    del sys._called_from_test


@pytest.fixture(autouse=True)
def cleandir(request, tmpdir):
    if 'nocleandir' in request.keywords:
        yield
    else:
        current_dir = os.getcwd()
        os.chdir(str(tmpdir))
        yield os.getcwd()
        os.chdir(current_dir)


def pytest_addoption(parser):
    parser.addoption("--long", action="store_true",
                     help="run long tests")


def pytest_runtest_setup(item):
    longmarker = item.get_marker("long")
    if longmarker is not None and not item.config.getoption('long'):
        pytest.skip('skipping long tests')
