#!/usr/bin/python3

from ECsecp256k1 import order
from hashlib import sha256
from base58 import b58encode, b58encode_check, b58decode, b58decode_check

# https://en.bitcoin.it/wiki/Wallet_import_format
print("\n****** Private ECDSA Key to WIF ******")

print("\n*** [1] Private ECDSA Key:")
p = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
# 0 < p < order
assert 0 < p        , "Invalid Private Key"
assert     p < order, "Invalid Private Key"
print(hex(p))

print("\n*** [2] 0x80 Extended Key (Compressed):")
ExtKey = b'\x80' + p.to_bytes(32, byteorder='big') + b'\x01'
print(ExtKey.hex())

print("\n*** [3] SHA-256 hashing of the Extended Key:")
h1 = sha256(ExtKey).digest()
print(h1.hex())

print("\n*** [4] SHA-256 hashing of the SHA-256:")
h2 = sha256(h1).digest()
print(h2.hex())

print("\n*** [5] First 4 bytes of the second SHA-256 hash used as address checksum:")
print(h2[:4].hex())

print("\n*** [6] checksum added at the end of extended key:")
addr = ExtKey + h2[:4]
print(addr.hex())

print("\n*** [7] Base58 encoding")
wif = b58encode(addr)
assert wif == 'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617', "failure"
print(wif)
assert b58encode_check(ExtKey) == 'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617', "failure"

print("\n****** WIF to private key ******")

print("\n*** [1] Base58 WIF")
print(wif)
compressed = len(wif)-51
print ("compressed" if (compressed==1) else "uncompressed")

print("\n*** [2] Base58 decoding")
addr = b58decode(wif)
print(addr.hex())

print("\n*** [3] Extended key (checksum verified)")
ExtKey, checksum = addr[:-4], addr[-4:]
verified = sha256(sha256(ExtKey).digest()).digest()[:4]==checksum
print(ExtKey.hex() + " (" + ("true" if verified else "false") + ")")
print(b58decode_check(wif).hex())

print("\n*** [4] Private key")
p2 = ExtKey[1:-1].hex() if compressed else ExtKey[1:].hex()
assert int(p2, 16) == p, "failure"
print(p2)
