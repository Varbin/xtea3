r"""
XTEA-Cipher in Python (eXtended Tiny Encryption Algorithm)

XTEA is a block cipher with 8 bytes block size and 16 bytes key size (128-Bit).
The algorithm is secure at 2014 with the recommended 64 rounds (32 cycles). This
implementation supports following modes of operation:
ECB, CBC, CFB OFB, CTR

It also supports CBC-MAC


Example:

    >>> import xtea3  # PEP272-usage
    >>> key = b"keep that secret"  # Use a better key & keep secret!
    >>> plain_text = b"Attack at dawn."  # The 'secret' message.
    >>> encrypter = xtea3.new(key, mode=xtea3.MODE_OFB, IV=b"12345678")  # Use random IV
    >>> cipher_text = encrypter.encrypt(plain_text)
    >>> cipher_text
    b'\xa3T\xfa\xda#U/X$\x96\xc9Xt\x00\x19'
    >>> decrypter = xtea3.new(key, mode=xtea3.MODE_OFB, IV=b"12345678")
    >>> decrypter.decrypt(cipher_text) == plain_text
    True


The module defines following modes of operation::

    MODE_ECB = 1
    MODE_CBC = 2
    MODE_CFB = 3
    MODE_PGP = 4
    MODE_OFB = 5
    MODE_CTR = 6

Other constants::

    block_size = 8
    key_size = 16


"""

import array

from xtea import MODE_ECB, MODE_CBC, MODE_CFB, MODE_CTR, MODE_OFB, MODE_PGP
from xtea import new, XTEACipher
from xtea import key_size, block_size
from xtea.counter import Counter

__all__ = ["MODE_PGP", "MODE_OFB", "MODE_CTR", "MODE_CFB", "MODE_CBC", "MODE_ECB",
           "new", "XTEACipher", "Counter", "key_size", "block_size"]


if __name__ == "__main__":
    import doctest
    doctest.testmod()