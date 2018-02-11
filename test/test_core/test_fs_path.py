# coding=utf-8
"""
Tests for esst.core.FS
"""
from pathlib import Path

import pytest

from esst.core import FS


@pytest.fixture(autouse=True)
def _setup():
    FS.saved_games_path = './Saved Games'
    FS.dcs_path = './DCS'
    Path('./Saved Games').mkdir()
    Path('./Saved Games/DCS').mkdir()
    Path('./DCS').mkdir()


def test_ensure_path():
    FS.saved_games_path = None

    with pytest.raises(RuntimeError):
        # noinspection PyTypeChecker
        FS.ensure_path(FS.saved_games_path, 'test')

    with pytest.raises(FileNotFoundError):
        FS.ensure_path('./test', 'test')


def test_saved_games_not_found():
    Path('./Saved Games/DCS').rmdir()
    Path('./Saved Games').rmdir()
    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant()
    assert str(exc).endswith('Saved Games')


def test_no_dcs_dir_in_saved_games():
    Path('./Saved Games/DCS').rmdir()
    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant()
    assert str(exc).endswith('Saved Games\\DCS')


def test_no_dcs_dir():
    Path('./DCS').rmdir()
    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant('./DCS')
    assert str(exc).endswith('\\DCS')


def test_base_variant():
    variant = FS.get_saved_games_variant()
    assert isinstance(variant, Path)
    expected = Path('Saved Games/DCS').absolute()
    assert variant.samefile(expected)


def test_variant_open_beta_missing():
    variant = Path('./DCS/dcs_variant.txt')
    variant.write_text('openbeta')

    with pytest.raises(FileNotFoundError) as exc:
        FS.get_saved_games_variant()
    assert str(exc).endswith('Saved Games\\DCS.openbeta')


def test_variant_open_beta():
    variant = Path('./DCS/dcs_variant.txt')
    variant.write_text('openbeta')
    Path('./Saved Games/DCS.openbeta').mkdir()
    assert isinstance(FS.get_saved_games_variant('./DCS'), Path)
