# coding=utf-8

import os
import shutil

import versioneer
from setuptools import find_packages, setup

from pip.req import parse_requirements

requirements = [str(r.req) for r in
                parse_requirements('requirements.txt', session=False)]
test_requirements = [str(r.req) for r in
                     parse_requirements('requirements-dev.txt', session=False)]


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
            version=versioneer.get_version(),
            cmdclass=versioneer.get_cmdclass(),
            zip_safe=False,
            entry_points=entry_points,
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
            install_requires=requirements,
            tests_require=test_requirements,
            python_requires='>=3.6',
            extras_require={
                'callgraph': ['pycallgraph'],
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
