# coding=utf-8
"""
Etcher's Simple Server Tools
"""

from pip.req import parse_requirements
from setuptools import find_packages, setup

requirements = [str(r.req) for r in
                parse_requirements('requirements.txt', session=False)]
test_requirements = [str(r.req) for r in
                     parse_requirements('requirements-dev.txt', session=False)]

CLASSIFIERS = filter(None, map(str.strip,
                               """
Development Status :: 3 - Alpha
Environment :: Win32 (MS Windows)
Intended Audience :: End Users/Desktop
Natural Language :: English
Operating System :: Microsoft :: Windows :: Windows 7
Operating System :: Microsoft :: Windows :: Windows 8
Operating System :: Microsoft :: Windows :: Windows 8.1
Operating System :: Microsoft :: Windows :: Windows 10
License :: OSI Approved :: MIT License
Programming Language :: Python :: 3.6
Programming Language :: Python :: 3.7
Topic :: Games/Entertainment :: Simulation
Topic :: System :: Systems Administration
Topic :: Utilities
""".splitlines()))

entry_points = '''
[console_scripts]
esst=esst.__main__:main
'''

# noinspection SpellCheckingInspection
setup(
    name='esst',
    zip_safe=False,
    entry_points=entry_points,
    package_dir={'esst': 'esst'},
    package_data={
        'esst': [
            'dcs/templates/*.lua',
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
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    license='MIT',
    classifiers=CLASSIFIERS,
)
