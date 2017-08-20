# coding=utf-8

from setuptools import setup  # type: ignore

dependency_links = []

install_requires = [
    'discord.py',
    'everett',
    'certifi',
    'jinja2',
    'pefile',
    'humanize',
    'click',
    'psutil',
    'github3.py==1.0.0a4',
    'emiz',
]

test_requires = [
    'pytest',
    'pytest-pycharm',
    'flake8',
    'pylint',
    'safety',
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
        python_requires='>=3.6',
    )


if __name__ == '__main__':
    main()
