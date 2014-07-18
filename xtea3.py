"""
XTEA-Cipher in Python (eXtended Tiny Encryption Algorithm)

XTEA is a blockcipher with 8 bytes blocksize and 16 bytes Keysize (128-Bit).
The algorithm is secure at 2014 with the recommend 64 rounds (32 cycles). This
implementation supports following modes of operation:
ECB, OFB

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
"""


import struct
import binascii
import sys
import warnings

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
    """Create an cipher object.

    Keyword arguments
    key -- the key for encrypting (and decrypting)

    Other arguments:
    mode -- Block cipher mode of operation (default MODE_ECB)
    IV -- Initialisation vector (needed with CBC/CFB)
    counter -- a callable counter (needed with CTR)
    endian -- how to use struct (default "!" (big endian/network))    """
    return XTEACipher(key, **kwargs)


class XTEACipher(object):
    """The cipher class

    Functions:
    encrypt -- encrypt data
    decrypt -- decrypt data

    _block -- splits the data in blocks (you may need padding)

    Constants:
    bloc_size = 8

    Variables:
    IV -- the initialisation vector (default None or "\00"*8)
    conuter -- counter for CTR (default None)
    
    """
    
    block_size = 64
    IV = None
    counter = None
    
    def __init__(self, key, **kwargs):
        """Initiate the cipher
        same arguments as for new."""
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
            self.IV = b'\00\00\00\00\00\00\00\00'

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
        else:
            self.endian = b"!"

    def encrypt(self, data):
        """Encrypt data.

        Keyword arguments:
        data -- the data (plaintext) to encrypt

        On OFB, encrypt and decrypt is the same.
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
            return _crypt_ofb(self.__key, data, self.IV, self.rounds/2)

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
            for block in blocks:
                c = self.__counter()
                if type(c) in l:
                    warnings.warn(
                        "Numbers as counter-value are buggy!",
                        DeprecationWarning)
                    n = stringToLong(block)
                    out.append(
                        _encrypt(
                            self.__key,struct.pack(self.endian+b'Q', n^c),
                            self.rounds/2, self.endian))
                else:
                    n = block
                    out.append(
                        _encrypt(
                            self.__key,
                            xor_bytes(n, c),
                            self.rounds/2,
                            self.endian)
                        )
            return b"".join(out)



    def decrypt(self, data):
        """Decrypt data.

        Keyword arguments:
        data -- the data (ciphertext) to decrypt.

        On OFB, encrypt and decrypt is the same.
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
            return _crypt_ofb(self.__key, data, self.IV, self.rounds/2)

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
            for block in blocks:
                c = self.__counter()
                if type(c) in l:
                    warnings.warn(
                        "Numbers as counter-value are buggy!",
                        DeprecationWarning)
                    nc = struct.unpack(self.endian+b"Q",_decrypt(self.__key, block, self.rounds//2, self.endian))
                    try:
                        out.append(longToString(nc[0]^c))
                    except:
                        warnings.warn(
                            "Unable to decrypt this block, block is lost",
                            RuntimeWarning)
                        out.append(b"\00"*8)
                else:
                    nc = _decrypt(self.__key, block, self.rounds//2, self.endian)
                    out.append(xor_bytes(nc, c))
            return b"".join(out)
        

    def _block(self, s):
        l = []
        rest_size = len(s) % (self.block_size/8)
        for i in range(int(len(s)/(self.block_size/8))):
            l.append(s[i*(self.block_size//8):((i+1)*(self.block_size//8))])
        if rest_size:
            raise ValueError()
        return l

################ CBCMAC

class CBCMAC(object):
    name = "xtea-cbcmac"
    block_size = 64
    digest_size = 8
    
    """Just a small implementation of the CBCMAC algorithm, based on XTEA."""
    def __init__(self, key, string=b"", endian=b"!"):
        warnings.warn("This is experimental!")
        self.cipher = new(key, mode=MODE_CBC, IV=b"\00"*8, endian=endian)
        self.text = string
        self.key = key

    @staticmethod
    def new(key, string=b"", endian=b"!"):
        return CBCMAC(key, string, endian)

    def update(self, string):
        self.text += string

    def copy(self):
        return CBCMAC.new(self.key, self.text, self.cipher.endian)

    def digest(self):
        return self.cipher.encrypt(self.text)[-8:]

    def hexdigest(self):
        return binascii.hexlify(self.digest())


################ Util functions: basic encrypt/decrypt, OFB
"""
This a utilities only, use them only if you know what you do.

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

def _encrypt(key,block,n=32,endian=b"!"):
    """Encrypt one single block of data.

    Only use if you know what to do.

    Keyword arguments:
    key -- the key for encrypting (and decrypting)
    block  -- one block plaintext
    n -- cycles, one cycle is two rounds, more cycles
          -> more security and slowness (default 32)
    endian -- how struct will handle data (default "!" (big endian/network))
    """
    v0,v1 = struct.unpack(endian+b"2L",block)
    k = struct.unpack(endian+b"4L",key)
    sum,delta,mask = 0,0x9e3779b9,0xffffffff
    for round in range(int(n)):
        v0 = (v0 + (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & mask
        sum = (sum + delta) & mask
        v1 = (v1 + (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & mask
    return struct.pack(endian+b"2L",v0,v1)

def _decrypt(key,block,n=32,endian=b"!"):
    """Decrypt one single block of data.

    Only use if you know what to do.

    Keyword arguments:
    key -- the key for encrypting (and decrypting)
    block  -- one block ciphertext
    n -- cycles, one cycle is two rounds, more cycles
          -> more security and slowness (default 32)
    endian -- how struct will handle data (default "!" (big endian/network))
    """
    v0,v1 = struct.unpack(endian+b"2L",block)
    k = struct.unpack(endian+b"4L",key)
    delta,mask = 0x9e3779b9,0xffffffff
    sum = (delta * int(n)) & mask
    for round in range(int(n)):
        v1 = (v1 - (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & mask
        sum = (sum - delta) & mask
        v0 = (v0 - (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & mask
    return struct.pack(endian+b"2L",v0,v1)

def xor_bytes(a, b):
    return bytes([c^d for c,d in zip(a,b)])

def stringToLong(s):
    """Convert any string to a number."""
    return int(binascii.hexlify(s),16)

def longToString(n):
    """Convert some longs to string."""
    return binascii.unhexlify("%x" % n)


################ Test function

c = 0 # Test

def _test():
    
    global c
    import os
    from time import clock
    import array
    
    class Counter:
        def __init__(self, nonce):
            self.__nonce = nonce
            self.reset()

        def __call__(self):
            for i in range(len(self.__current)):
                try:
                    self.__current[i] += 1
                    break
                except:
                    self.__current[i] = 0
            return self.__current.tostring()
        def reset(self):
            self.__current = array.array("B", self.__nonce)
    print ("Starting test...")
    print ("Testing ECB")
    fails_ecb = 0
    start = clock()
    for i in range(250):
        try:
            plain = os.urandom(56)*8
            e = new(os.urandom(16))
            encrypted = e.encrypt(plain)
            decrypted = e.decrypt(encrypted)
            if decrypted != plain: fails_ecb += 1
        except:
            print ("Fail with Error...", file=sys.stderr)
            fails_ecb+=1
    end = clock()
    time_ecb = end - start

    print ("Testing CBC")
    fails_cbc = 0
    start = clock()
    for i in range(250):
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
            print ("Fail with Error...", file=sys.stderr)
            fails_cbc+=1
    end = clock()
    time_cbc = end - start

    print ("Testing CFB")
    fails_cfb = 0
    start = clock()
    for i in range(250):
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
            print ("Fail with Error...", file=sys.stderr)
            fails_cfb+=1
    end = clock()
    time_cfb = end - start
            
    print ("Testing OFB (function)")
    fails_ofb = 0
    start = clock()
    for i in range(250):
        try:
            key = os.urandom(16)
            plain = os.urandom(56)*8
            encrypted = _crypt_ofb(key, plain)
            decrypted = _crypt_ofb(key, encrypted)
            if decrypted != plain:
                fails_ofb+=1
        except:
            print ("Fail with Error...", file=sys.stderr)
            fails_ofb+=1
    end = clock()
    time_ofb = end - start
    
    print ("Testing CTR")
    fails_ctr = 0
    start = clock()
    for i in range(250):
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
            print ("Fail with Error...", file=sys.stderr)
            fails_ctr += 1
    end = clock()
    time_ctr = end - start

    print ()
    print ()
    print ("Result")
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
    print ("Time:")
    print ()
    print ("ECB: %s\nCBC: %s\nCFB: %s\nOFB: %s\nCTR: %s\n" % (
        str(time_ecb),
        str(time_cbc),
        str(time_cfb),
        str(time_ofb),
        str(time_ctr)
        )
           )

if __name__ == "__main__":
    _test()
