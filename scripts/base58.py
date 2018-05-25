'''Base58 encoding

Implementations of Base58 and Base58Check endcodings that are compatible
with the bitcoin network.
'''

# This module is based upon base58 snippets found scattered over many bitcoin
# tools written in python. From what I gather the original source is from a
# forum post by Gavin Andresen, so direct your praise to him.
# This module adds shiny packaging and support for python3.

from hashlib import sha256

__version__ = '0.2.5'

# 58 character alphabet used
__alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__base = len(__alphabet)

if bytes == str:  # python2
    iseq, bseq, buffer = (
        lambda s: map(ord, s),
        lambda s: ''.join(map(chr, s)),
        lambda s: s,
    )
else:  # python3
    iseq, bseq, buffer = (
        lambda s: s,
        bytes,
        lambda s: s.buffer,
    )


def scrub_input(v):
    if isinstance(v, str) and not isinstance(v, bytes):
        v = v.encode('ascii')

    if not isinstance(v, bytes):
        raise TypeError(
            "a bytes-like object is required (also str), not '%s'" %
            type(v).__name__)

    return v


def b58encode_int(i, default_one=True):
    '''Encode an integer using Base58'''
    if not i and default_one:
        return __alphabet[0:1]
    string = b""
    while i >= __base:
        i, idx = divmod(i, __base)
        string = __alphabet[idx:idx+1] + string
    string = __alphabet[i:i+1] + string
    return string


def b58encode(v):
    '''Encode a string using Base58'''

    v = scrub_input(v)

    # leading-0s will become leading-1s
    nPad = len(v)
    v = v.lstrip(b'\0')
    nPad -= len(v)

    p, acc = 1, 0
    for c in iseq(reversed(v)):
        acc += p * c
        p = p << 8

    result = b58encode_int(acc, default_one=False)

    # adding leading-1s
    return (__alphabet[0:1] * nPad + result)


def b58decode_int(v):
    '''Decode a Base58 encoded string as an integer'''

    v = scrub_input(v)

    decimal = 0
    for char in v:
        decimal = decimal * __base + __alphabet.index(char)
    return decimal


def b58decode(v):
    '''Decode a Base58 encoded string'''

    v = scrub_input(v)

    # leading-1s will become leading-0s
    nPad = len(v)
    v = v.lstrip(__alphabet[0:1])
    nPad -= len(v)

    acc = b58decode_int(v)

    result = []
    while acc >= 256:
        acc, mod = divmod(acc, 256)
        result.append(mod)
    result.append(acc)

    # adding leading-0s
    return (b'\0' * nPad + bseq(reversed(result)))


def b58encode_check(v):
    '''Encode a string using Base58 with a 4 character checksum'''

    digest = sha256(sha256(v).digest()).digest()
    return b58encode(v + digest[:4])


def b58decode_check(v):
    '''Decode and verify the checksum of a Base58 encoded string'''

    result = b58decode(v)
    result, check = result[:-4], result[-4:]
    digest = sha256(sha256(result).digest()).digest()

    if check != digest[:4]:
        raise ValueError("Invalid checksum")

    return result


# https://en.bitcoin.it/wiki/Wallet_import_format
privKey = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
uncompressedExtKey = b'\x80' + privKey.to_bytes(32, byteorder='big')
uncompressedWIF = b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
compressedExtKey = b'\x80' + privKey.to_bytes(32, byteorder='big') + b'\x01'
compressedWIF = b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'

def test_privKey_to_wif():
    wif = b58encode_check(uncompressedExtKey)
    print(wif==uncompressedWIF)
    #assert_that(wif, equal_to(uncompressedWIF))
    wif = b58encode_check(compressedExtKey)
    print(wif==compressedWIF)
    #assert_that(wif, equal_to(compressedWIF))
    

def test_wif_to_privKey():
    extKey = b58decode_check(uncompressedWIF)
    print(extKey==uncompressedExtKey)
    #assert_that(extKey, equal_to(uncompressedExtKey))
    extKey = b58decode_check(compressedWIF)
    print(extKey==compressedExtKey)
    #assert_that(extKey, equal_to(compressedExtKey))
    

if __name__ == "__main__":
  print("### 1")
  print(b58encode(b'hello world'))
  print(b58decode(b'StV1DL6CwTryKyV').decode('ascii'))
  print(b58decode(b58encode(b'hello world'))==b'hello world')
  print(b58encode(b58decode(b'StV1DL6CwTryKyV'))==b'StV1DL6CwTryKyV')

  print("### 2")
  print(b58encode("hello world"))
  print(b58decode("StV1DL6CwTryKyV").decode('ascii'))
  print(b58decode(b58encode("hello world"))==b'hello world')
  print(b58encode(b58decode("StV1DL6CwTryKyV"))==b'StV1DL6CwTryKyV')

  print("### 3")
  print(b58encode(b'\x00\x00hello world'))
  print(b58decode(b'11StV1DL6CwTryKyV').decode('ascii'))
  print(b58decode(b58encode(b'\0\0hello world'))==b'\0\0hello world')
  print(b58encode(b58decode(b'11StV1DL6CwTryKyV'))==b'11StV1DL6CwTryKyV')

  print("### 4")
  print(b58encode("  hello world"))
  print(b58decode("11StV1DL6CwTryKyV").decode('ascii'))
  print(b58decode(b58encode("  hello world"))==b'\x00\x00hello world')
  print(b58encode(b58decode("11StV1DL6CwTryKyV"))==b'11StV1DL6CwTryKyV')

  print("### 5")
  print(b58encode(b'')=='')
  print(b58encode('')=='')
  print(b58decode('1')==b'\0')
  print(b58decode(b'1')==b'\0')

  print("### tests")
  test_privKey_to_wif()
  test_wif_to_privKey()

  print("### spaces")
  print("  hello world"==b'\0\0hello world'.decode('ascii'))
  print("  hello world"==b'\00\00hello world'.decode('ascii'))
  print("  hello world"==b'\x00\x00hello world'.decode('ascii'))

  print(__base)
