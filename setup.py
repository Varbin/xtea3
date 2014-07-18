try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


gf = lambda x: open(x).read()

long_text = gf("README.rst")+"\n"*4+gf("changelog.rst")

setup(
    name='xtea3',
    version='0.2',
    description="A python 3 version of XTEA",
    long_description = long_text,
    author="Simon Biewald",
    author_email="simon.biewald@hotmail.de",
    url="https://github.com/varbin/xtea3",
    download_url="https://github.com/Varbin/xtea",
    bugtrack_url="https://github.com/Varbin/xtea/issues",
    keywords = "xtea tea encryption crypt python3 pypy3", 
    py_modules=['xtea3'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: Public Domain",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.1",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Topic :: Security",
        "Topic :: Security :: Cryptography"]
    )
