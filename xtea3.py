"""
XTEA-Cipher in Python (eXtended Tiny Encryption Algorithm)

XTEA is a blockcipher with 8 bytes blocksize and 16 bytes Keysize (128-Bit).
The algorithm is secure at 2014 with the recommend 64 rounds (32 cycles). This
implementation supports following modes of operation:
ECB, CBC, CFB OFB, CTR

It also supports CBC-MAC


Example:

    >>> from xtea import *
    >>> key = b" "*16  # Never use this
    >>> text = b"This is a text. "*8
    >>> x = new(key, mode=MODE_OFB, IV="12345678")
    >>> c = x.encrypt(text)
    >>> c
    b'\x8e.\xa5B\xb8gk\xbc'
    >>> text == x.decrypt(c)
    True


The module defines folowing modes of operation::

    MODE_ECB = 1
    MODE_CBC = 2
    MODE_CFB = 3
    MODE_PGP = 4
    MODE_OFB = 5
    MODE_CTR = 6

Other constants::

    #Supported modes
    supported = (
        MODE_ECB,
        MODE_CBC,
        MODE_CFB,
        MODE_OFB,
        MODE_CTR)

    # Internal blocksize
    block_size = 64
    #Key size
    key_size = 128


"""


import struct
import binascii
import sys
import warnings
import array

MODE_ECB = 1
MODE_CBC = 2
MODE_CFB = 3
MODE_PGP = 4
MODE_OFB = 5
MODE_CTR = 6

supported = (
    MODE_ECB,
    MODE_CBC,
    MODE_CFB,
    MODE_OFB,
    MODE_CTR)


block_size = 64
key_size = 128


def new(key, **kwargs):
    """Create an "XTEACipher" object.
    It fully PEP-272 comliant, default mode is ECB.

    Args:
        key (bytes): The key for encrytion/decryption. Must be 16 in length

    Kwargs:
        mode (int): Mode of operation, must be one of this::

            1 = ECB
            2 = CBC
            3 = CFB
            5 = OFB
            6 = CTR
        
        IV (bytes): Initialisation vector (needed with CBC/CFB).
        Must be 8 in length.
        
        counter (callable object): a callable counter wich returns bytes or int (needed with CTR)
        
            .. deprecated:: 0.2
               **Use bytes only.**
        
        endian (char / string): how data is beeing extracted (default "!")

        rounds (int / float): How many rounds are going to be used, one round are two cycles, there are no *half* cycles. The minimum rounds are 37 (default 64)

    Raises:
        ValueError if invalid/not all data is give,
        NotImplementedError on MODE_PGP

    Returns:
       XTEACipher object

    """
    return XTEACipher(key, **kwargs)


class XTEACipher(object):
    """The main cipher class."""
    
    block_size = 64
    IV = None
    counter = None
    
    def __init__(self, key, **kwargs):
        """Alternative constructor.
        Create an cipher object.

        Args:
            key (bytes): The key for encrytion/decryption. Must be 16 in length

        Kwargs:
            mode (int): Mode of operation, must be one of this::

                1 = ECB
                2 = CBC
                3 = CFB
                5 = OFB
                6 = CTR

            IV (bytes): Initialisation vector (needed with CBC/CFB). Must be 8 in length.

            counter (callable object): a callable counter wich returns bytes or int (needed with CTR)
      
            endian (char / string): how data is beeing extracted (default "!")

    Raises:
        ValueError if invalid/not all data is give, NotImplementedError on MODE_PGP

    Creates:
        XTEACipher object

    """
        self.__key = key
        
        if len(key) != key_size/8:
            raise ValueError("Key must be 128 bits long")
        
        keys = kwargs.keys()
        if "mode" in keys:
            self.mode = kwargs["mode"]
            if self.mode not in supported:
                raise NotImplementedError("This mode is not supported!")
        else:
            self.mode = MODE_ECB
            
        if "IV" in keys:
            self.__IV = kwargs["IV"]
            if len(self.__IV) != self.block_size/8:
                raise ValueError("IV must be 8 bytes long")
        elif self.mode == MODE_OFB:
            self.__IV = b'\00\00\00\00\00\00\00\00'

        if "counter" in keys:
            self.__counter = kwargs["counter"]
        elif self.mode == MODE_CTR:
            raise ValueError("CTR needs a counter!")
        if "rounds" in keys:
            self.rounds = kwargs["rounds"]
        else:
            self.rounds = 64
            
        if "endian" in keys:
            self.endian = kwargs["endian"]
            if isinstance(self.endian, bytes):
                self.endian = self.endian.decode()
        else:
            self.endian = "!"

    def encrypt(self, data):
        """Encrypt data, it must be a multiple of 8 in length.
        When using the OFB-mode, the function for encryption and decryption
        is the same.

        Args:
            data (bytes): The data to encrypt.

        Returns:
            bytes

        Raises:
            ValueError if data is not padded

        """

        #ECB
        if self.mode == MODE_ECB:
            if not len(data) % (self.block_size/8):
                out = []
                blocks=self._block(data)
                for block in blocks:
                    out.append(_encrypt(self.__key, block, self.rounds/2, self.endian))
                return b"".join(out)
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")

        #CBC
        elif self.mode == MODE_CBC:
            if not len(data) % (self.block_size/8):
                out = [self.__IV]
                blocks=self._block(data)
                for i in range(0, len(blocks)):
                    xored = xor_bytes(blocks[i], out[i])
                    out.append(_encrypt(self.__key,xored,self.rounds/2,self.endian))
                return b"".join(out[1:])
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")
                
        #OFB
        elif self.mode == MODE_OFB:
            return _crypt_ofb(self.__key, data, self.__IV, self.rounds/2)

        #CFB
        elif self.mode == MODE_CFB:
            if not len(data) % (self.block_size/8):
                blocks = self._block(data)
                out = []
                fb = self.__IV
                for bn in blocks:
                    tx = _encrypt(self.__key, fb, self.rounds/2, self.endian)
                    fb = xor_bytes(bn, tx)
                    out.append(fb)
                return b"".join(out)
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")

        #CTR
        elif self.mode == MODE_CTR:
            l = (type(1),type(.1)) # Typelist
            
            blocks = self._block(data)
            out = []
            c  = self.__counter()
            if type(c) in l:
                warnings.warn(
                    "Numbers as counter-value are buggy!",
                    DeprecationWarning)
                for block in blocks:
                    n = stringToLong(block)
                    out.append(
                        _encrypt(
                            self.__key,struct.pack(self.endian+b'Q', n^c),
                            self.rounds/2, self.endian))
                    c = self.__counter()

            else:
                for block in blocks:
                    n = block
                    out.append(
                        _encrypt(
                            self.__key,
                            xor_bytes(n, c),
                            self.rounds/2,
                            self.endian)
                        )
                    c = self.__counter()
            return b"".join(out)



    def decrypt(self, data):
        """Decrypt data, it must be a multiple of 8 in length. When using the OFB-mode,
        the function for encryption and decryption is the same.

        Args:
            data (bytes): The data to decrypt.

        Returns:
            bytes.

        Raises:
            ValueError

        """
        #ECB
        if self.mode == MODE_ECB:
            if not len(data) % (self.block_size/8):
                out = []
                blocks=self._block(data)
                for block in blocks:
                    out.append(_decrypt(self.__key, block, self.rounds/2, self.endian))
                return b"".join(out)
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")

        #CBC
        elif self.mode == MODE_CBC:
            if not (len(data) % self.block_size):
                out = []
                blocks = self._block(data)
                blocks = [self.__IV]+blocks
                for i in range(1, len(blocks)):
                    out.append(
                        xor_bytes(
                            _decrypt(
                                self.__key,blocks[i]
                                ,self.rounds/2,
                                self.endian),
                            blocks[i-1])
                        )
                return b"".join(out)
            
        #OFB
        elif self.mode == MODE_OFB:
            return _crypt_ofb(self.__key, data, self.__IV, self.rounds/2)

        #CFB
        elif self.mode == MODE_CFB:
            if not len(data) % (self.block_size/8):
                blocks = self._block(data)
                out = []
                fb = self.__IV
                for block in blocks:
                    tx = _encrypt(self.__key, fb, self.rounds/2, self.endian)
                    fb = block[:]
                    out.append(xor_bytes(block,tx))
                return b"".join(out)
            else:
                raise ValueError("Input string must be a multiple of blocksize in length")

        #CTR
        elif self.mode == MODE_CTR:
            l = (type(1), type(.1))
            blocks = self._block(data)
            out = []
            c = self.__counter()
            if type(c) in l:
                warnings.warn(
                    "Numbers as counter-value are buggy!",
                    DeprecationWarning)
                for block in blocks:
                    nc = struct.unpack(
                        self.endian+b"Q",
                        _decrypt(
                            self.__key,
                            block,
                            self.rounds//2,
                            self.endian)
                        )
                    try:
                        out.append(longToString(nc[0]^c))
                    except:
                        warnings.warn(
                            "Unable to decrypt this block, block is lost",
                            RuntimeWarning)
                        out.append(b"\00"*8)
                    c = self.__counter()
            else:
                for block in blocks:
                    nc = _decrypt(self.__key, block, self.rounds//2, self.endian)
                    out.append(xor_bytes(nc, c))
                    c = self.__counter()
            return b"".join(out)
        

    def _block(self, s):
        l = []
        rest_size = len(s) % (self.block_size/8)
        for i in range(int(len(s)/(self.block_size/8))):
            l.append(s[i*(self.block_size//8):((i+1)*(self.block_size//8))])
        if rest_size:
            raise ValueError()
        return l
        

class CBCMAC(object):
    """Generates a CBCMAC based on XTEA.
    CBC-MAC is a technique for constructing a MACs from a block cipher.
    The message is encrypted with a blockcipher, XTEA in this case, 
    in Cipher-Block-Chaining mode with constant initialisation vector.
    The last block is beeing returned, this is the MAC-tag for a message.

    Example:
    
        >>> from xtea3 import CBCMAC
        >>> key = b"Df/45SD41§y|&0=K"
        >>> data = b"Lorem ipsum, dolorem set it amet!"*16
        >>> c = CBCMAC.new(key, data)
        >>> old = c.digest()
        >>> old
        ...
        >>> c.update(b"Random data..."*8)
        >>> new = c.digest()
        >>> new
        ...
        >>> new != old
        True

    NEVER do following:

        >>> from xtea3 import CBCMAC
        >>> key = b"Df/45SD41§y|&0=K"
        >>> data = b"Lorem ipsum, dolorem set it amet!"*16
        >>> c = CBCMAC.new(key)
        >>> c.update(data)
        >>> c.update(b"Random data..."*8)
    
    """

    #: Canoncial name for functions like hashlib
    name = "xtea-cbcmac"

    #: Internal blocksize in bits (of XTEA; 8 bytes)
    block_size = 64

    #: Out size in bytes (length)
    digest_size = 8
    
    def __init__(self, key, string=b"", endian="!"):
        warnings.warn("This is experimental!")
        self.__cipher = new(key, mode=MODE_CBC, IV=b"\00"*8, endian=endian)

        #: The text to authenticated. Obviously, while updating, var "string" will added, but it is type "bytes"
        self.text = bytes(
            str(
                len(
                    string
                    )
                ), "utf-8")+string
        
        self.__key = key

    @staticmethod
    def new(key, string=b"", endian="!"):
        """Constructor for an CBCMAC object, provides a *fake module* xtea.CBCMAC.

        Look in PEP-452 for details of this function.

        Args:
            key (bytes): The MAC key

        Kwargs:
            string (bytes): The data, sorry for the name
            
            endian (char, string): How to extract data and key, see in struct documentation for detail
            

        """
        return CBCMAC(key, string, endian)

    def update(self, string):
        """\            
        Update the hash object with the object string,
        which must be interpretable as a buffer of bytes.    
        Repeated calls are equivalent to a single call
        with the concatenation of all the arguments.

        .. warning:
            You *should* add the first message to __init__/new function for security reasons!

        Args:
            string (bytes): Text to add

        """
        
        self.text += string

    def copy(self):
        """Return a copy (*clone*) of the CBCMAC object with the same key, text and endian

        Returns:
            CBCMAC

        """
        
        return CBCMAC.new(self.__key, self.text, self.__cipher.endian)

    def digest(self):
        """Return the digest of the data passed to the update() method so far.
        This is a bytes object of size digest_size which may contain bytes
        in the whole range from 0 to 255.

        Returns:
            bytes - the mac

        """
        return self.__cipher.encrypt(
            self.text +
            b"\00"*(
                8 - (
                    len(
                        self.text
                        ) % 8)
                )
            )[-8:]

    def hexdigest(self):
        """Like digest() except the digest is returned as a string object
        of double length, containing only hexadecimal digits.
        This may be used to exchange the value safely in email or other
        non-binary environments.

        Returns:
            string - the mac

        """
        
        return binascii.hexlify(self.digest()).decode()


################ Basic counter

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
            nonce (bytes): The start value, \
            it MUST be random if it should be secure, for example, use *os.urandom* for it.

        """
        self.__nonce = nonce
        self.reset()

    def __call__(self):
        """The method that makes it callable.

        Returns:
            bytes
        """
        for i in range(len(self.__current)):
            try:
                self.__current[i] += 1
                break
            except:
                self.__current[i] = 0
        return self.__current.tostring()
    
    def reset(self):
        """Reset the counter to the nonce
        """
        self.__current = array.array("B", self.__nonce)

################ Util functions: basic encrypt/decrypt, OFB
"""
This are utilities only, use them only if you know what you do.

Functions:
_crypt_ofb -- Encrypt or decrypt data in OFB mode.
_encrypt -- Encrypt one single block of data.
_decrypt -- Decrypt one single block of data.
xor_strings -- xor to strings together.
stringToLong -- Convert any string to a number.
longToString --Convert some longs to string.
"""

def _crypt_ofb(key,data,iv=b'\00\00\00\00\00\00\00\00',n=32):
    """Encrypt or decrypt data in OFB mode.

    Only use if you know what you do.

    Keyword arguments:
    key -- the key for encrypting (and decrypting)
    data -- plain / ciphertext
    iv -- initialisation vector (default "\x00"*8)
    n -- cycles, more cycles -> more security (default 32)
    """
    def keygen(key,iv,n):
        while True:
            iv = _encrypt(key,iv,n)
            for k in iv:
                yield k
    xor = [ bytes([x^y]) for (x,y) in zip(data,keygen(key,iv,n)) ]
    return b"".join(xor)

def _encrypt(key,block,n=32,endian="!"):
    """Encrypt one single block of data.

    Only use if you know what to do.

    Keyword arguments:
    key -- the key for encrypting (and decrypting)
    block  -- one block plaintext
    n -- cycles, one cycle is two rounds, more cycles
          -> more security and slowness (default 32)
    endian -- how struct will handle data (default "!" (big endian/network))
    """
    v0,v1 = struct.unpack(endian+"2L",block)
    k = struct.unpack(endian+"4L",key)
    sum,delta,mask = 0,0x9e3779b9,0xffffffff
    for round in range(int(n)):
        v0 = (v0 + (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & mask
        sum = (sum + delta) & mask
        v1 = (v1 + (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & mask
    return struct.pack(endian+"2L",v0,v1)

def _decrypt(key,block,n=32,endian="!"):
    """Decrypt one single block of data.

    Only use if you know what to do.

    Keyword arguments:
    key -- the key for encrypting (and decrypting)
    block  -- one block ciphertext
    n -- cycles, one cycle is two rounds, more cycles
          -> more security and slowness (default 32)
    endian -- how struct will handle data (default "!" (big endian/network))
    """
    v0,v1 = struct.unpack(endian+"2L",block)
    k = struct.unpack(endian+"4L",key)
    delta,mask = 0x9e3779b9,0xffffffff
    sum = (delta * int(n)) & mask
    for round in range(int(n)):
        v1 = (v1 - (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & mask
        sum = (sum - delta) & mask
        v0 = (v0 - (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & mask
    return struct.pack(endian+"2L",v0,v1)

def xor_bytes(a, b):
    return bytes([c^d for c,d in zip(a,b)])

def stringToLong(s):
    """Convert any string to a number."""
    return int(binascii.hexlify(s),16)

def longToString(n):
    """Convert some longs to string."""
    return binascii.unhexlify("%x" % n)


################ Test function


def test(n=100):
    """A test function, it justs tests for bugfree and symetric encryption/decryption.

    The results will be printed out.
    The encryption/decryption will run *n* times.
    The test will be finished in 5 to 40 seconds.

    Args:
        n (int): Rounds per mode


    Example::

        >>> test(250)
        Starting test...
        ...
        
        Results
        ===============

        Fails:

        |ECB|CBC|CFB|OFB|CTR|
        |---|---|---|---|---|
        |000|000|000|000|000|

        Success rate:
        100.0 %


        Time:

        ECB: 1.6845053874546017
        CBC: 1.8182448889277514
        CFB: 1.7761231099162256
        OFB: 1.880623759974088
        CTR: 1.9194539924472593
        Total: 10.855074248636152
        """
    
    import os
    from time import clock
    
    print ("Starting test...")
    print ()
    print ("Testing ECB")
    fails_ecb = 0
    start = clock()
    for i in range(n):
        try:
            plain = os.urandom(56)*8
            e = new(os.urandom(16))
            encrypted = e.encrypt(plain)
            decrypted = e.decrypt(encrypted)
            if decrypted != plain: fails_ecb += 1
        except:
            raise Exception("ECB failed...")
    end = clock()
    time_ecb = end - start

    print ("Testing CBC")
    fails_cbc = 0
    start = clock()
    for i in range(n):
        try:
            key = os.urandom(16)
            iv = os.urandom(8)
            c1 = new(key, mode=MODE_CBC, IV=iv)
            c2 = new(key, mode=MODE_CBC, IV=iv)
            plain = os.urandom(56)*8
            encrypted = c1.encrypt(plain)
            decrypted = c2.decrypt(encrypted)
            if decrypted != plain: fails_cbc+=1
            
        except:
            raise Exception("CBC failed...")
    end = clock()
    time_cbc = end - start

    print ("Testing CFB")
    fails_cfb = 0
    start = clock()
    for i in range(n):
        try:
            key = os.urandom(16)
            iv = os.urandom(8)
            c1 = new(key, mode=MODE_CFB, IV=iv)
            c2 = new(key, mode=MODE_CFB, IV=iv)
            plain = os.urandom(56)*8
            encrypted = c1.encrypt(plain)
            decrypted = c2.decrypt(encrypted)
            if decrypted != plain: fails_cfb+=1
            
        except:
            raise Exception("CFB failed...")
    end = clock()
    time_cfb = end - start

    print ("Testing OFB")
    fails_ofb = 0
    start = clock()
    for i in range(n):
        try:
            key = os.urandom(16)
            iv = os.urandom(8)
            c1 = new(key, mode=MODE_OFB, IV=iv)
            c2 = new(key, mode=MODE_OFB, IV=iv)
            plain = os.urandom(56)*8
            encrypted = c1.encrypt(plain)
            decrypted = c2.decrypt(encrypted)
            if decrypted != plain: fails_ofb+=1
            
        except:
            raise Exception("CFB failed...")
    end = clock()
    time_ofb = end - start
            
    print ("Testing OFB (function)")
    start = clock()
    for i in range(n):
        try:
            key = os.urandom(16)
            plain = os.urandom(56)*8
            encrypted = _crypt_ofb(key, plain)
            decrypted = _crypt_ofb(key, encrypted)
            if decrypted != plain:
                fails_ofb+=1
        except:
            raise Exception("OFB failed...")
    end = clock()
    time_ofb += end - start
    
    print ("Testing CTR")
    fails_ctr = 0
    start = clock()
    for i in range(n):
        try:
            key = os.urandom(16)
            nonce = os.urandom(8)
            c = Counter(nonce)
            cf = new(key, mode=MODE_CTR, counter=c)
            plain = os.urandom(56)*8
            encrypted = cf.encrypt(plain)
            c=Counter(nonce)
            cf = new(key, mode=MODE_CTR, counter=c)
            decrypted = cf.decrypt(encrypted)
            if decrypted != plain:
                fails_ctr+=1
        except Exception as e:
            raise Exception("CTR failed...")
    end = clock()
    time_ctr = end - start
    success = (n*5) - sum((fails_ecb, fails_cbc, fails_cfb, fails_ofb, fails_ctr))
    percent = ((success*1.0) / (n*5)) * 100

    print ()
    print ()
    print ("Results")
    print ("="*15)
    print ()
    print ("Fails:")
    print ()
    print ("|ECB|CBC|CFB|OFB|CTR|")
    print ("|---|---|---|---|---|")
    print ("|%s|%s|%s|%s|%s|" % (
        str(fails_ecb).rjust(3,"0"),
        str(fails_cbc).rjust(3,"0"),
        str(fails_cfb).rjust(3,"0"),
        str(fails_ofb).rjust(3,"0"),
        str(fails_ctr).rjust(3,"0")))
    print ()
    print ("Succes rate:")
    print (percent,"%")
    print ()
    print ()
    print ("Time:")
    print ()
    print ("ECB: %s\nCBC: %s\nCFB: %s\nOFB: %s\nCTR: %s\nTotal: %s\n" % (
        str(time_ecb),
        str(time_cbc),
        str(time_cfb),
        str(time_ofb),
        str(time_ctr),
        str(sum((time_ecb,
                time_cbc,
                time_cfb,
                time_cfb,
                time_ofb,
                time_ctr)
                )
            )
        )
           )

if __name__ == "__main__":
    test()
