# coding=utf-8
import os
import sys

import pytest


# noinspection PyUnusedLocal
def pytest_configure(config):
    sys._called_from_test = True


# noinspection PyUnusedLocal,SpellCheckingInspection
def pytest_unconfigure(config):
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
