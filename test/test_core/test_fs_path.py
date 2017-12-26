# coding=utf-8

import pytest
import string
from hypothesis import given, strategies as st, settings

from pathlib import Path

from esst.core import FS


def test_ensure_path():
    FS.saved_games_path = None

    with pytest.raises(RuntimeError):
        # noinspection PyTypeChecker
        FS._ensure_path(FS.saved_games_path)

    with pytest.raises(FileNotFoundError):
        FS._ensure_path('./test')

    assert isinstance(FS._ensure_path('./test', must_exist=False), Path)


def test_dcs_autoexec():
    assert isinstance(FS.get_dcs_autoexec_file(), Path)


@given(text=st.text(alphabet=string.printable, min_size=0, max_size=20))
def test_mission_editor_lua(text):
    with pytest.raises(FileNotFoundError):
        FS.get_mission_editor_lua_file('./test')
    Path('./MissionEditor').mkdir(exist_ok=True)
    Path('./MissionEditor/MissionEditor.lua').write_text(text)
    assert isinstance(FS.get_mission_editor_lua_file('.'), Path)


def test_dcs_exe_path():
    with pytest.raises(FileNotFoundError):
        FS.get_dcs_exe('.')
    Path('./bin').mkdir()
    with pytest.raises(FileNotFoundError):
        FS.get_dcs_exe('.')
    Path('./bin/dcs.exe').touch()
    assert isinstance(FS.get_dcs_exe('.'), Path)


def test_saved_games_no_variant():
    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant('.')
    assert 'Saved Games' in str(exc)

    saved_games = Path('./Saved Games')
    saved_games.mkdir()

    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant('./DCS')
    assert 'DCS' in str(exc)

    dcs = Path('./DCS')
    dcs.mkdir()

    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant('.')
    assert 'Saved Games\\DCS' in str(exc)

    Path(saved_games, 'DCS').mkdir()

    assert isinstance(FS.get_saved_games_variant('./DCS'), Path)

    variant = Path(dcs, 'dcs_variant.txt')
    variant.write_text('openbeta')

    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant('./DCS')
    assert 'Saved Games\\DCS.openbeta' in str(exc)

    Path(saved_games, 'DCS.openbeta').mkdir()
    assert isinstance(FS.get_saved_games_variant('./DCS'), Path)

    variant.write_text('openalpha')

    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant('./DCS')
    assert 'Saved Games\\DCS.openalpha' in str(exc)

    Path(saved_games, 'DCS.openalpha').mkdir()
    assert isinstance(FS.get_saved_games_variant('./DCS'), Path)




