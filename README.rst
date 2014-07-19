===========
Python XTEA
===========

    This is an XTEA-Cipher implementation in Python 3 (eXtended Tiny Encryption Algorithm).

    XTEA is a very fast and small blockcipher with 8 bytes blocksize and 16 bytes Keysize (128-Bit).
    The algorithm is secure at 2014 with the recommend 64 rounds (32 cycles). The minimum for rounds is  38 (19 cycles).
    This implementation supports following modes of operation:
    ECB, OFB
    More modes will be added.


Example:

    >>> from xtea3 import *
    >>> key = b" "*16  # Never use this key
    >>> text = b"This is a text. "*8
    >>> x = new(key, mode=MODE_OFB, IV=b"12345678")  # Never reuse the IV!
    >>> c = x.encrypt(text)
    >>> text == x.decrypt(c)
    True
    
Note
====
   
    I does NOT guarantee that this implementation is secure. If there are bugs, tell me them. 
    The old version for Python 2 still will be updated.
    My GPG/PGP key: 0CB97138 (full fingerprint: 8F93 4984 3BA7 4A1C E5F2  A1BA 1338 DFDE 0CB9 7138)
