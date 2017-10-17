#!/usr/bin/python3

# adapted from https://github.com/keis/base58

"""encode/decode base58 in the same way that Bitcoin does"""

__chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__base = len(__chars)

def b58encode(bytes_address):
  """ convert an input bytes address (or string address) to encoded string    
  """

  if isinstance(bytes_address, str):
    bytes_address = bytes_address.encode()

  if not isinstance(bytes_address, bytes):
    raise TypeError("a bytes-like object is required (even str), not '%s'" %
                    type(bytes_address).__name__)

  string = ''
  value = int.from_bytes(bytes_address, byteorder='big')
  while value >= __base:
    value, mod = divmod(value, __base)
    string = __chars[mod] + string
  string = __chars[value] + string

  # Bitcoin does a little leading-zero-compression:
  # leading 0-bytes in the input become leading-1s
  for c in bytes_address:
    if c == 0:
      string = __chars[0] + string
    else: break

  return string

def b58decode(v):
  """ decode an encoded input string (or input bytes) into bytes
  """

  if isinstance(v, bytes):
    v = v.decode('ascii')

  if not isinstance(v, str):
    raise TypeError("a string-like object is required (even bytes), not '%s'" %
                    type(v).__name__)
  
  nPad = len(v)
  v = v.lstrip(__chars[0])
  nPad -= len(v)

  acc = 0
  for char in v:
    acc = acc * __base + __chars.index(char)
  
  result = []
  while acc >= 256:
    acc, mod = divmod(acc, 256)
    result.append(mod)
  result.append(acc)

  return (b'\0' * nPad + bytes(reversed(result)))

from hashlib import sha256

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
uncompressedWIF = '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
compressedExtKey = b'\x80' + privKey.to_bytes(32, byteorder='big') + b'\x01'
compressedWIF = 'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'

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
  print(b58encode(b'hello world'))
  print(b58decode("StV1DL6CwTryKyV").decode('ascii'))
  print(b58decode(b58encode(b'hello world'))==b'hello world')
  print(b58encode(b58decode("StV1DL6CwTryKyV"))=="StV1DL6CwTryKyV")

  print(b58decode(b'StV1DL6CwTryKyV').decode('ascii'))
  print(b58encode("hello world"))
  print(b58decode(b58encode("hello world"))==b'hello world')
  print(b58encode(b58decode(b'StV1DL6CwTryKyV'))=="StV1DL6CwTryKyV")

  print(b58encode(b'\0\0hello world'))
  print(b58decode("11StV1DL6CwTryKyV").decode('ascii'))
  print(b58decode(b58encode(b'\0\0hello world'))==b'\0\0hello world')
  print(b58encode(b58decode("11StV1DL6CwTryKyV"))=="11StV1DL6CwTryKyV")

  print(b58decode(b'11StV1DL6CwTryKyV').decode('ascii'))
  print(b58encode("\0\0hello world"))
  print(b58decode(b58encode("\0\0hello world"))==b'\0\0hello world')
  print(b58encode(b58decode(b'11StV1DL6CwTryKyV'))=="11StV1DL6CwTryKyV")

  print("###")
  print(b58encode(b'')=='')
  print(b58encode('')=='')
  print(b58decode('1')==b'\0')
  print(b58decode(b'1')==b'\0')

  print("### tests")
  test_privKey_to_wif()
  test_wif_to_privKey()
