#!/usr/bin/env python3

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

SHORT_TEXT = "A python 3 version of XTEA"


def safe_long_description(fn, fallback=SHORT_TEXT):
    """"Try to read fn, fallback to fallback test if impossible."""
    try:
        with open(fn) as desc_file:
            return desc_file.read()
    except FileNotFoundError:
        return fallback


LONG_TEXT = (
        safe_long_description("README.rst") +
        "\n"*4 +
        safe_long_description("changelog.rst")
)


setup(
    name='xtea3',
    version='1.0.0',
    description=SHORT_TEXT,
    long_description = LONG_TEXT,
    author="Simon Biewald",
    author_email="simon.biewald@hotmail.de",
    url="https://github.com/varbin/xtea3",
    keywords = "xtea tea encryption crypt python3 pypy3", 
    py_modules=['xtea3'],
    zip_safe=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: Public Domain",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Security :: Cryptography"],
    license="Public Domain",
    platform="Any",
    project_urls={
        'Source': 'https://github.com/Varbin/xtea3',
        'Say Thanks!': 'https://saythanks.io/to/Varbin',
        'Tracker': 'https://github.com/Varbin/xtea3/issues'
    },
    install_requires=["xtea>=0.6.0"],  # Dev version
)
