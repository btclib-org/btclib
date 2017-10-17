#!/usr/bin/python3

from secp256k1 import order
from hashlib import sha256
from base58 import b58encode, b58encode_check, b58decode, b58decode_check

# https://en.bitcoin.it/wiki/Wallet_import_format
print("\n****** Private ECDSA Key to WIF ******")

print("\n*** [1] Private ECDSA Key:")
privKey = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
# 0 < k < order
assert 0 < privKey        , "Invalid Private Key"
assert     privKey < order, "Invalid Private Key"
print(hex(privKey).upper())

print("\n*** [2] 0x80 Extended Key (Compressed):")
extKey = b'\x80' + privKey.to_bytes(32, byteorder='big') + b'\x01'
print(extKey.hex().upper())

print("\n*** [3] SHA-256 hashing of the Extended Key:")
h1 = sha256(extKey).digest()
print(h1.hex().upper())

print("\n*** [4] SHA-256 hashing of the SHA-256:")
h2 = sha256(h1).digest()
print(h2.hex().upper())

print("\n*** [5] First 4 bytes of the second SHA-256 hash used as address checksum:")
print(h2[:4].hex().upper())

print("\n*** [6] checksum added at the end of extended key:")
addr = extKey + h2[:4]
print(addr.hex().upper())

print("\n*** [7] Base58 encoding")
wif = b58encode(addr)
print(wif)
print(b58encode_check(extKey))

print("\n****** WIF to private key ******")

print("\n*** [1] Base58 WIF")
print(wif)
compressed = len(wif)-51
print ("compressed" if (compressed==1) else "uncompressed")

print("\n*** [2] Base58 decoding")
addr = b58decode(wif)
print(addr.hex().upper())

print("\n*** [3] Extended key (checksum verified)")
extKey, checksum = addr[:-4], addr[-4:]
verified = sha256(sha256(extKey).digest()).digest()[:4]==checksum
print(extKey.hex().upper() + " (" + ("true" if verified else "false") + ")")
print(b58decode_check(wif).hex().upper())

print("\n*** [4] Private key")
print(extKey[1:-4-compressed].hex().upper())
