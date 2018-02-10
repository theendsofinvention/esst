# coding=utf-8
"""
Tests for esst.mission.store
"""
import random
import string
from pathlib import Path

import pytest

from esst import core
from esst.mission import store


@pytest.fixture(autouse=True)
def _setup():
    core.FS.dcs_mission_folder = Path('.')


def _random_file_name(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def test__get_mission_folder(tmpdir):
    path = store._get_mission_folder(str(tmpdir), 'ESST')
    assert isinstance(path, Path)
    assert path.exists()
    assert path.is_dir()


@pytest.mark.parametrize('path', [_random_file_name() for _ in range(10)])
def test__get_mission_folder_path_exists(tmpdir, path):
    Path(str(tmpdir), path).mkdir()
    path = store._get_mission_folder(str(tmpdir), path)
    assert isinstance(path, Path)
    assert path.exists()
    assert path.is_dir()


@pytest.mark.parametrize('path', [_random_file_name() for _ in range(10)])
def test__get_mission_folder_path_is_file(tmpdir, path):
    test_file = Path(str(tmpdir), path)
    with open(test_file, 'w') as stream:
        stream.write('test')
    with pytest.raises(RuntimeError):
        store._get_mission_folder(str(test_file))


def test_get_base_missions_folder():
    path = store.get_base_missions_folder()
    assert isinstance(path, Path)
    assert path.exists()
    assert path.is_dir()


def test_get_auto_missions_folder():
    path = store.get_auto_missions_folder()
    assert isinstance(path, Path)
    assert path.exists()
    assert path.is_dir()


@pytest.mark.parametrize('path', [_random_file_name() for _ in range(10)])
def test_get_random_auto_mission_name(path):
    orig_miz_file = Path(store.get_base_missions_folder(), f'{path}.miz')
    orig_miz_file.touch()
    random_miz = store.get_random_auto_mission_name(orig_miz_file)
    assert random_miz.parent == store.get_auto_missions_folder()


@pytest.mark.parametrize('path', [_random_file_name() for _ in range(10)])
def test_get_random_auto_mission_name_not_a_file(path):
    orig_miz_file = Path(store.get_base_missions_folder(), path)
    orig_miz_file.mkdir()
    with pytest.raises(RuntimeError):
        store.get_random_auto_mission_name(orig_miz_file)


@pytest.mark.parametrize('path', [_random_file_name() for _ in range(10)])
def test_get_random_auto_mission_name_not_a_miz_file(path):
    orig_miz_file = Path(store.get_base_missions_folder(), f'{path}.not_miz')
    orig_miz_file.touch()
    with pytest.raises(RuntimeError):
        store.get_random_auto_mission_name(orig_miz_file)


@pytest.mark.parametrize('path', [_random_file_name() for _ in range(10)])
def test_get_random_auto_mission_name_does_not_exist(path):
    orig_miz_file = Path(store.get_base_missions_folder(), f'{path}')
    with pytest.raises(RuntimeError):
        store.get_random_auto_mission_name(orig_miz_file)


@pytest.mark.parametrize('_', [_random_file_name() for _ in range(20)])
def test_clean_store(_):
    list_of_files = [f'{_random_file_name()}.miz' for _ in range(20)]
    for file in list_of_files:
        p = Path(store.get_auto_missions_folder(), file)
        p.touch()
        assert p.is_file()
    for x in store.clean():
        assert x.name in list_of_files
