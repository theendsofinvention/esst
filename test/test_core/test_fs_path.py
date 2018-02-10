# coding=utf-8
"""
Tests for esst.core.FS
"""
import string
from pathlib import Path

import pytest
from hypothesis import strategies as st
from hypothesis import given

from esst.core import FS


def test_ensure_path():
    FS.saved_games_path = None

    with pytest.raises(RuntimeError):
        # noinspection PyTypeChecker
        FS.ensure_path(FS.saved_games_path, 'test')

    with pytest.raises(FileNotFoundError):
        FS.ensure_path('./test', 'test')

    assert isinstance(FS.ensure_path('./test', 'test', must_exist=False), Path)


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
