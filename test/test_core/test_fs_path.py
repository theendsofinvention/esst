# coding=utf-8
"""
Tests for esst.core.FS
"""
import string
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from esst.core import FS


@pytest.fixture(autouse=True)
def _setup():
    FS.saved_games_path = './Saved Games'
    FS.dcs_path = './DCS'
    Path('./Saved Games').mkdir()
    Path('./DCS').mkdir()



def test_ensure_path():
    FS.saved_games_path = None

    with pytest.raises(RuntimeError):
        # noinspection PyTypeChecker
        FS.ensure_path(FS.saved_games_path, 'test')

    with pytest.raises(FileNotFoundError):
        FS.ensure_path('./test', 'test')



def test_saved_games_not_found():
    Path('./Saved Games').rmdir()
    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant()
    assert str(exc).endswith('FileNotFoundError: Saved Games')


def test_no_dcs_dir_in_saved_games():
    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant()
    assert str(exc).endswith('FileNotFoundError: Saved Games\\DCS')


def test_no_dcs_dir():
    pass




def test_saved_games_no_dcs():

    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant('./DCS')
    assert 'DCS' in str(exc)

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
