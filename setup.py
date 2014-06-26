from distutils.core import setup

with open("README") as rm:
  long_text = rm.read()

setup(name='xtea3',
      version='0.1',
      description="A python 3 version of XTEA",
      long_description = long_text,
      author="Simon Biewald",
      author_email="simon.biewald@hotmail.de",
      py_modules=['xtea3'],
      classifiers=[
	"Development Status :: 4 - Beta",
	"Operating System :: OS Independent",
	"Programming Language :: Python :: 3",
  "Programming Language :: Python :: 3.2",
  "Programming Language :: Python :: 3.3",
  "Programming Language :: Python :: 3.4",
	"Topic :: Security :: Cryptography"]
      )
