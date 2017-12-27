# coding=utf-8
"""
Dummy test to make sure everything is importable
"""

import glob

import pytest


@pytest.mark.nocleandir
@pytest.mark.parametrize('module_', glob.glob('./esst/**/*.py', recursive=True))
def test_imports(module_):
    module_ = module_[2:-3].replace('\\', '.')
    __import__(module_)


@pytest.mark.nocleandir
@pytest.mark.parametrize('module_', list(glob.glob('./esst/**/*.py', recursive=True)))
def test_imports_tests(module_):
    module_ = module_[2:-3].replace('\\', '.')
    __import__(module_)
