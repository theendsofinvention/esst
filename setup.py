# coding=utf-8

from setuptools import setup  # type: ignore

dependency_links = [r'git+https://github.com/132nd-etcher/EMFT.git#egg=emft-0.5.1']

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
    'click',
    'psutil',
    'github3.py==1.0.0a4',
    'emft==0.5.1',
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
        install_requires=install_requires,
        entry_points=entry_points,
        tests_require=test_requires,
        setup_requires=setup_requires,
        dependency_links=dependency_links,
        test_suite='pytest',
        packages=['esst', 'esst.core', 'esst.dcs', 'esst.discord_bot'],
    )


if __name__ == '__main__':
    main()
