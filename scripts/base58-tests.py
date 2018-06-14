from base58 import b58encode, b58encode_check, b58decode, b58decode_check

# https://en.bitcoin.it/wiki/Wallet_import_format
prvkey = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
uncompressedExtKey = b'\x80' + prvkey.to_bytes(32, byteorder='big')
uncompressedWIF = b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
compressedExtKey = b'\x80' + prvkey.to_bytes(32, byteorder='big') + b'\x01'
compressedWIF = b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'

def test_prvkey_to_wif():
    wif = b58encode_check(uncompressedExtKey)
    print(wif==uncompressedWIF)
    #assert_that(wif, equal_to(uncompressedWIF))
    wif = b58encode_check(compressedExtKey)
    print(wif==compressedWIF)
    #assert_that(wif, equal_to(compressedWIF))
    

def test_wif_to_prvkey():
    extKey = b58decode_check(uncompressedWIF)
    print(extKey==uncompressedExtKey)
    #assert_that(extKey, equal_to(uncompressedExtKey))
    extKey = b58decode_check(compressedWIF)
    print(extKey==compressedExtKey)
    #assert_that(extKey, equal_to(compressedExtKey))
    

if __name__ == "__main__":
  print("\n### 1")
  print(b58encode(b'hello world'))
  print(b58decode(b'StV1DL6CwTryKyV'))
  print(b58decode(b58encode(b'hello world'))==b'hello world')
  print(b58encode(b58decode(b'StV1DL6CwTryKyV'))==b'StV1DL6CwTryKyV')

  print("\n### 2")
  print(b58encode("hello world"))
  print(b58decode("StV1DL6CwTryKyV"))
  print(b58decode(b58encode("hello world"))==b'hello world')
  print(b58encode(b58decode("StV1DL6CwTryKyV"))==b'StV1DL6CwTryKyV')

  print("\n### 3")
  print(b58encode(b'\x00\x00hello world'))
  print(b58decode(b'11StV1DL6CwTryKyV'))
  print(b58decode(b58encode(b'\0\0hello world'))==b'\x00\x00hello world')
  print(b58encode(b58decode(b'11StV1DL6CwTryKyV'))==b'11StV1DL6CwTryKyV')

  print("\n### 4")
  print(b58encode("\x00\x00hello world"))
  print(b58decode("11StV1DL6CwTryKyV"))
  print(b58decode(b58encode("\x00\x00hello world"))==b'\x00\x00hello world')
  print(b58encode(b58decode("11StV1DL6CwTryKyV"))==b'11StV1DL6CwTryKyV')

  print("\n### wif tests")
  test_prvkey_to_wif()
  test_wif_to_prvkey()
