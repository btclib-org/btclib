# -*- coding: utf-8 -*-
"""
Created on Mon Oct 16 11:16:55 2017

@author: dfornaro, fametrano
"""
from ECsecp256k1 import order, G, pointMultiply
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

seed = 0x4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
seed_bytes = 64
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
assert ext_prv == "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6", "failure"
assert ext_pub == "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13", "failure"

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
assert ext_prv == "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L", "failure"
assert ext_pub == "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y", "failure"

