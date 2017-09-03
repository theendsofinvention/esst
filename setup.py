# coding=utf-8

import shutil
import os
from setuptools import find_packages, setup

dependency_links = []

install_requires = [
    'elib',
    'emiz',
    'discord.py',
    'certifi',
    'jinja2',
    'pefile',
    'humanize',
    'click',
    'psutil',
    'github3.py==1.0.0a4',
    'raven',
    'argh',
    'requests',
]

test_requires = [
    'pytest',
    'pytest-pycharm',
    'flake8',
    'pylint',
    'safety',
    'coverage',
    'pytest-pep8',
    'pytest-cache',
    'pytest-catchlog',
    'pytest-cov',
    'hypothesis',
]

dev_requires = [
    'pip-tools',
    'epab',
]

setup_requires = [
    'pytest-runner',
    'setuptools_scm',
]

entry_points = '''
[console_scripts]
esst=esst.__main__:main
'''


def main():
    try:
        shutil.copy2('./CHANGELOG.rst', './esst/CHANGELOG.rst')
        shutil.copy2('./README.md', './esst/README.md')
        setup(
            name='esst',
            use_scm_version=True,
            zip_safe=False,
            install_requires=install_requires,
            entry_points=entry_points,
            tests_require=test_requires,
            setup_requires=setup_requires,
            dependency_links=dependency_links,
            package_dir={'esst': 'esst'},
            package_data={
                'esst': [
                    'dcs/templates/*.lua',
                    'CHANGELOG.rst',
                    'README.md',
                ]
            },
            test_suite='pytest',
            packages=find_packages(),
            python_requires='>=3.6',
            extras_require={
                'dev': dev_requires,
                'test': test_requires,
            },
            license='MIT',
            classifiers=[
                'Development Status :: 3 - Alpha',
                'Environment :: Win32 (MS Windows)',
                'Intended Audience :: End Users/Desktop',
                'Natural Language :: English',
                'Operating System :: Microsoft :: Windows :: Windows 7',
                'Operating System :: Microsoft :: Windows :: Windows 8',
                'Operating System :: Microsoft :: Windows :: Windows 8.1',
                'Operating System :: Microsoft :: Windows :: Windows 10',
                'License :: OSI Approved :: MIT License',
                'Programming Language :: Python :: 3.6',
                'Programming Language :: Python :: 3.7',
                'Topic :: Games/Entertainment :: Simulation',
                'Topic :: System :: Systems Administration',
                'Topic :: Utilities',
            ],
        )
    finally:
        os.remove('./esst/CHANGELOG.rst')
        os.remove('./esst/README.md')


if __name__ == '__main__':
    main()
