# coding=utf-8

from setuptools import setup  # type: ignore

install_requires = [
    'discord.py',
    'everett',
    'pywinauto',
    'blinker',
    'certifi',
    'jinja2',
    'path.py',
    'pefile',
    'humanize',
]

test_requires = [
    'pytest',
    'pytest-pycharm',
    'flake8',
    'pylint',
    'mypy',
    'safety',
    'prospector',
]

dev_requires = [
    'pip-tools',
]

setup_requires = [
    'pytest-runner',
    'setuptools_scm',
]

entry_points = '''
[console_scripts]
esst=esst:main
'''


def main():
    setup(
        name='esst',
        use_scm_version=True,
        py_modules=['esst'],
        install_requires=install_requires,
        entry_points=entry_points,
        tests_require=test_requires,
        setup_requires=setup_requires,
        test_suite='pytest',
    )


if __name__ == '__main__':
    main()
