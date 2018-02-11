# coding=utf-8
"""
Tests from esst.dcs.autoexec_cfg
"""

import string
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from esst import core, dcs


@pytest.fixture(autouse=True)
def _setup():
    core.FS.saved_games_path = '.'
    core.FS.dcs_autoexec_file = Path('./DCS/Config/autoexec.cfg')


def test_injection():
    Path('./DCS/Config').mkdir(parents=True)
    autoexec_file = Path('./DCS/Config/autoexec.cfg')
    assert not autoexec_file.exists()
    dcs.autoexec_cfg.inject_silent_crash_report()
    assert autoexec_file.exists()
    assert autoexec_file.read_text('utf8').endswith(dcs.autoexec_cfg._SILENT_CRASH_REPORT)


def test_no_dcs_saved_games_path():
    core.FS.saved_games_path = None
    core.FS.dcs_autoexec_file = './autoexec.cfg'
    with pytest.raises(RuntimeError) as exc_info:
        dcs.autoexec_cfg.inject_silent_crash_report()

    assert 'path uninitialized: saved games' in str(exc_info)


def test_no_config_path():
    Path('./DCS').mkdir(parents=True)
    with pytest.raises(FileNotFoundError) as exc_info:
        dcs.autoexec_cfg.inject_silent_crash_report()

    assert 'Config' in str(exc_info)


@given(text=st.text(alphabet=string.printable, min_size=0, max_size=100))
def test_existing_file(text):
    Path('./DCS/Config').mkdir(parents=True, exist_ok=True)

    autoexec_file = Path('./DCS/Config/autoexec.cfg')
    autoexec_file.write_text(text, encoding='utf8')
    assert autoexec_file.exists()
    assert dcs.autoexec_cfg.inject_silent_crash_report()
    assert autoexec_file.exists()
    content = autoexec_file.read_text('utf8')
    assert content.endswith(dcs.autoexec_cfg._SILENT_CRASH_REPORT)
    assert dcs.autoexec_cfg.inject_silent_crash_report()
    # Make sure the content does not change
    assert autoexec_file.read_text('utf8') == content
