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

__all__ = ["MODE_PGP", "MODE_OFB", "MODE_CTR", "MODE_CFB", "MODE_CBC", "MODE_ECB",
           "new", "XTEACipher", "Counter", "key_size", "block_size"]


class Counter:
    """Small counter for CTR mode, based on arrays

    Example:
    
        >>> from xtea3 import Counter
        >>> nonce = b"$2dUI84e" # This should be random
        >>> c = Counter(nonce)
        >>> c()
        b'%2dUI84e'
        >>> c()
        b'&2dUI84e'
        >>> c()
        b"'2dUI84e"
        >>> c.reset()
        >>> c()
        b'%2dUI84e'
    """
    
    def __init__(self, nonce):
        """Constructor for a counter which is suitable for CTR mode.

        Args:
            nonce (bytes): The start value;
                it MUST be unique to be secure.
                The secrets module or os.urandom(n) are solid
                choices for generating random bytes.

        """
        self.__nonce = nonce
        self.__current = array.array("B", self.__nonce)

    def __call__(self):
        """Increase the counter by one.

        Returns:
            bytes
        """
        for i in range(len(self.__current)):
            try:
                self.__current[i] += 1
                break
            except IndexError:
                self.__current[i] = 0
        return self.__current.tostring()
    
    def reset(self):
        """Reset the counter to the nonce."""
        self.__current = array.array("B", self.__nonce)



if __name__ == "__main__":
    import doctest
    doctest.testmod()