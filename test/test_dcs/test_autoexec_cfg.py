# coding=utf-8

import pytest
import string
from hypothesis import strategies as st, given

from pathlib import Path

from esst.dcs import autoexec_cfg
from esst.core import FS


def test_injection():
    FS.saved_games_path = '.'
    Path('./DCS/Config').mkdir(parents=True)
    autoexec_file = Path('./DCS/Config/autoexec.cfg')
    assert not autoexec_file.exists()
    autoexec_cfg.inject_silent_crash_report('.')
    assert autoexec_file.exists()
    assert autoexec_file.read_text('utf8').endswith(autoexec_cfg._SILENT_CRASH_REPORT)


def test_no_dcs_saved_games_path():
    with pytest.raises(FileNotFoundError) as exc_info:
        autoexec_cfg.inject_silent_crash_report('./some/dir')

    assert 'Saved Games' in str(exc_info)


def test_no_config_path():
    FS.saved_games_path = '.'
    Path('./DCS').mkdir(parents=True)
    with pytest.raises(FileNotFoundError) as exc_info:
        autoexec_cfg.inject_silent_crash_report('.')

    assert 'Config' in str(exc_info)


@given(text=st.text(alphabet=string.printable, min_size=0, max_size=100))
def test_existing_file(text):
    FS.saved_games_path = '.'
    Path('./DCS/Config').mkdir(parents=True, exist_ok=True)

    autoexec_file = Path('./DCS/Config/autoexec.cfg')
    autoexec_file.write_text(text, encoding='utf8')
    assert autoexec_file.exists()
    assert autoexec_cfg.inject_silent_crash_report('.')
    assert autoexec_file.exists()
    content = autoexec_file.read_text('utf8')
    assert content.endswith(autoexec_cfg._SILENT_CRASH_REPORT)
    assert autoexec_cfg.inject_silent_crash_report('.')
    # Make sure the content does not change
    assert autoexec_file.read_text('utf8') == content

