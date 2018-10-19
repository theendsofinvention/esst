# coding=utf-8
"""
Tests from esst.autoexec_cfg
"""

import string
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

from esst import FS
from esst.dcs import autoexec_cfg


@pytest.fixture(autouse=True)
def _setup():
    FS.saved_games_path = '.'
    FS.dcs_autoexec_file = Path('./DCS/Config/autoexec.cfg')


def test_injection():
    Path('./DCS/Config').mkdir(parents=True)
    autoexec_file = Path('./DCS/Config/autoexec.cfg')
    assert not autoexec_file.exists()
    autoexec_cfg.inject_silent_crash_report()
    assert autoexec_file.exists()
    assert autoexec_file.read_text('utf8').endswith(autoexec_cfg._SILENT_CRASH_REPORT)


def test_no_dcs_saved_games_path():
    FS.saved_games_path = None
    FS.dcs_autoexec_file = './autoexec.cfg'
    with pytest.raises(RuntimeError) as exc_info:
        autoexec_cfg.inject_silent_crash_report()

    assert 'path uninitialized: saved games' in str(exc_info)


def test_no_config_path():
    Path('./DCS').mkdir(parents=True)
    with pytest.raises(FileNotFoundError) as exc_info:
        autoexec_cfg.inject_silent_crash_report()

    assert 'Config' in str(exc_info)


@given(text=st.text(alphabet=string.printable, min_size=0, max_size=100))
def test_existing_file(text):
    Path('./DCS/Config').mkdir(parents=True, exist_ok=True)

    autoexec_file = Path('./DCS/Config/autoexec.cfg')
    autoexec_file.write_text(text, encoding='utf8')
    assert autoexec_file.exists()
    assert autoexec_cfg.inject_silent_crash_report()
    assert autoexec_file.exists()
    content = autoexec_file.read_text('utf8')
    assert content.endswith(autoexec_cfg._SILENT_CRASH_REPORT)
    assert autoexec_cfg.inject_silent_crash_report()
    # Make sure the content does not change
    assert autoexec_file.read_text('utf8') == content
