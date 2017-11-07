# -*- coding: utf-8 -*-
"""
Created on Mon Oct 16 11:16:55 2017

@author: dfornaro, fametrano
"""
from secp256k1 import order, G, pointMultiply
from hmac import HMAC
from hashlib import sha512, sha256
from hashlib import new as hnew
from base58 import b58encode_check

def h160(inp):
  h1 = sha256(inp).digest()
  return hnew('ripemd160', h1).digest()

## https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

# version bytes
# mainnet: 0x0488B21E public  -> xpub; 0x0488ADE4 private -> xprv
# testnet: 0x043587CF public         ; 0x04358394 private
xprv = 0x0488ADE4
xprv = xprv.to_bytes(4, byteorder='big')
xpub = 0x0488B21E
xpub = xpub.to_bytes(4, byteorder='big')

seed = 0x000102030405060708090a0b0c0d0e0f
seed_bytes = 16
print("Seed:", hex(seed), "\nbytes:", seed_bytes)

# ==master ext private key==
# depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ...
depth = b'\x00'
# This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
child_number = b'\x00\x00\x00\x00'
# the fingerprint of the parent's public key (0x00000000 if master key)
fingerprint  = b'\x00\x00\x00\x00'
idf = depth + fingerprint + child_number

# master private key, master public key, chain code
hashValue = HMAC(b"Bitcoin seed", seed.to_bytes(seed_bytes, byteorder='big'), sha512).digest()
p_bytes = hashValue[:32]
p = int(p_bytes.hex(), 16) % order
p_bytes = b'\x00' + p.to_bytes(32, byteorder='big')
P = pointMultiply(p, G)
P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
chain_code = hashValue[32:]

#extended keys
ext_prv = b58encode_check(xprv + idf + chain_code + p_bytes)
print("\nm")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + P_bytes)
print("M")
print(ext_pub)
assert ext_prv == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", "failure"
assert ext_pub == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", "failure"

# ==first (0) hardened child==
depth = b'\x01'
child_number = 0 + 0x80000000 #hardened
child_number = child_number.to_bytes(4, byteorder='big')
fingerprint = h160(P_bytes)[:4]
idf = depth + fingerprint + child_number

key = p_bytes if child_number[0]>127 else P_bytes
hashValue = HMAC(chain_code, key + child_number, sha512).digest()
p = (p + int(hashValue[:32].hex(), 16)) % order
p_bytes = b'\x00' + p.to_bytes(32, byteorder='big')
P = pointMultiply(p, G)
P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
chain_code = hashValue[32:]

ext_prv = b58encode_check(xprv + idf + chain_code + p_bytes)
print("\nm/0'")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + P_bytes)
print("M/0'")
print(ext_pub)
assert ext_prv == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "failure"
assert ext_pub == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "failure"

# ==second (1) normal grandchild==
depth = b'\x02'
child_number = 1 + 0x00000000 #normal
child_number = child_number.to_bytes(4, byteorder='big')
fingerprint = h160(P_bytes)[:4]
idf = depth + fingerprint + child_number

key = p_bytes if child_number[0]>127 else P_bytes
hashValue = HMAC(chain_code, key + child_number, sha512).digest()
p = (p + int(hashValue[:32].hex(), 16)) % order
p_bytes = b'\x00' + p.to_bytes(32, byteorder='big')
P = pointMultiply(p, G)
P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
chain_code = hashValue[32:]

ext_prv = b58encode_check(xprv + idf + chain_code + p_bytes)
print("\nm/0'/1")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + P_bytes)
print("M/0'/1")
print(ext_pub)
assert ext_prv == "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "failure"
assert ext_pub == "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", "failure"

# ==third (2) hardened grand-grandchild==
depth = b'\x03'
child_number = 2 + 0x80000000 #hardened
child_number = child_number.to_bytes(4, byteorder='big')
fingerprint = h160(P_bytes)[:4]
idf = depth + fingerprint + child_number

key = p_bytes if child_number[0]>127 else P_bytes
hashValue = HMAC(chain_code, key + child_number, sha512).digest()
p = (p + int(hashValue[:32].hex(), 16)) % order
p_bytes = b'\x00' + p.to_bytes(32, byteorder='big')
P = pointMultiply(p, G)
P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
chain_code = hashValue[32:]

ext_prv = b58encode_check(xprv + idf + chain_code + p_bytes)
print("\nm/0'/1/2'")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + P_bytes)
print("M/0'/1/2'")
print(ext_pub)
assert ext_prv == "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", "failure"
assert ext_pub == "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", "failure"

# ==third (2) normal grand-grand-grandchild==
depth = b'\x04'
child_number = 2 + 0x00000000 #normal
child_number = child_number.to_bytes(4, byteorder='big')
fingerprint = h160(P_bytes)[:4]
idf = depth + fingerprint + child_number

key = p_bytes if child_number[0]>127 else P_bytes
hashValue = HMAC(chain_code, key + child_number, sha512).digest()
p = (p + int(hashValue[:32].hex(), 16)) % order
p_bytes = b'\x00' + p.to_bytes(32, byteorder='big')
P = pointMultiply(p, G)
P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
chain_code = hashValue[32:]

ext_prv = b58encode_check(xprv + idf + chain_code + p_bytes)
print("\nm/0'/1/2'/2")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + P_bytes)
print("M/0'/1/2'/2")
print(ext_pub)
assert ext_prv == "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334", "failure"
assert ext_pub == "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV", "failure"

# ==1000000001th (1000000000) normal grand-grand-grand-grandchild==
depth = b'\x05'
child_number = 1000000000 + 0x00000000 #normal
child_number = child_number.to_bytes(4, byteorder='big')
fingerprint = h160(P_bytes)[:4]
idf = depth + fingerprint + child_number

key = p_bytes if child_number[0]>127 else P_bytes
hashValue = HMAC(chain_code, key + child_number, sha512).digest()
p = (p + int(hashValue[:32].hex(), 16)) % order
p_bytes = b'\x00' + p.to_bytes(32, byteorder='big')
P = pointMultiply(p, G)
P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
chain_code = hashValue[32:]

ext_prv = b58encode_check(xprv + idf + chain_code + p_bytes)
print("\nm/0'/1/2'/2/1000000000")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + P_bytes)
print("M/0'/1/2'/2/1000000000")
print(ext_pub)
assert ext_prv == "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", "failure"
assert ext_pub == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", "failure"
