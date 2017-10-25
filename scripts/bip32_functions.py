# -*- coding: utf-8 -*-
"""
Created on Mon Oct 23 09:41:51 2017

@author: dfornaro, fametrano
"""

from secp256k1 import order, G, pointMultiply, pointAdd, a, b, prime
from hmac import HMAC
from hashlib import new as hnew
from hashlib import sha512, sha256
from base58 import b58encode_check, b58decode_check
from FiniteFields import modular_sqrt

BITCOIN_PRIVATE = b'\x04\x88\xAD\xE4'
BITCOIN_PUBLIC = b'\x04\x88\xB2\x1E'
TESTNET_PRIVATE = b'\x04\x35\x83\x94'
TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
PRIVATE = [BITCOIN_PRIVATE, TESTNET_PRIVATE]
PUBLIC = [BITCOIN_PUBLIC, TESTNET_PUBLIC]

def h160(inp):
  h1 = sha256(inp).digest()
  return hnew('ripemd160', h1).digest()

def from_compressed_to_point(P_compr):
  X = int.from_bytes(P_compr[1:], byteorder='big')
  Y_2 = X**3 + a*X + b
  Y = modular_sqrt(Y_2, prime)
  if (Y % 2 == 0):
    if (P_compr[0] != 2):
      Y = prime - Y
  else:
    if (P_compr[0] == 2):
      Y = prime - Y
  P = (X, Y)
  return P

def parse_extkey(extKey):
  decoded = b58decode_check(extKey)
  info = {"private": (decoded[:4] in PRIVATE),
          "depth": decoded[4],
          "fingerprint" : decoded[5:9],
          "index" : int.from_bytes(decoded[9:13], byteorder='big'),
          "chain_code" : decoded[13:45],
          "key" : decoded[45:]
          }
  return info
    
def bip32_master_key(seed, seed_bytes):
  depth = b'\x00'
  child_number = b'\x00\x00\x00\x00'
  fingerprint  = b'\x00\x00\x00\x00'
  idf = depth + fingerprint + child_number
  hashValue = HMAC(b"Bitcoin seed", seed.to_bytes(seed_bytes, byteorder='big'), sha512).digest()
  p_bytes = hashValue[:32]
  p = int(p_bytes.hex(), 16) % order
  p_bytes = b'\x00' + p.to_bytes(32, byteorder='big')
  P = pointMultiply(p, G)
  P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
  chain_code = hashValue[32:]
  ext_prv = b58encode_check(BITCOIN_PRIVATE + idf + chain_code + p_bytes)
  ext_pub = b58encode_check(BITCOIN_PUBLIC  + idf + chain_code + P_bytes)
  return ext_prv, ext_pub

# Child Key Derivation
def bip32_ckd(extKey, child):
  parent = parse_extkey(extKey)
  
  if parent["private"] == True:
    p = int.from_bytes(parent["key"][1:], byteorder='big')
    P = pointMultiply(p, G)
    key = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
  else:
    key = parent["key"]
  fingerprint = h160(key)[:4]
  depth_child = (parent["depth"] + 1).to_bytes(1, byteorder='big')
  child_number = child.to_bytes(4, byteorder='big')
  idf = depth_child + fingerprint + child_number

  if (child >= 0x80000000): #private (hardened) derivation
    assert parent["private"] == True, "Cannot do private (hardened) derivation from Pubkey"
    key = parent["key"]
  data = key + child_number
  hashValue = HMAC(parent["chain_code"], data, sha512).digest()
  chain_code = hashValue[32:]

  if parent["private"] == True:
    p = (int.from_bytes(parent["key"][1:], byteorder='big') + int(hashValue[:32].hex(), 16)) % order
    p_bytes = b'\x00' + p.to_bytes(32, byteorder='big')
    P = pointMultiply(p, G)
    P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
    ext_prv = b58encode_check(BITCOIN_PRIVATE + idf + chain_code + p_bytes)
    ext_pub = b58encode_check(BITCOIN_PUBLIC  + idf + chain_code + P_bytes)    
    return ext_prv, ext_pub
  else:
    p = int(hashValue[:32].hex(), 16) % order
    P = pointMultiply(p, G)
    P_parent = from_compressed_to_point(parent["key"])
    P = pointAdd(P, P_parent)
    P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
    return b58encode_check(BITCOIN_PUBLIC + idf + chain_code + P_bytes)       



# == Test vector 1 ==
  
seed = 0x000102030405060708090a0b0c0d0e0f
seed_bytes = 16
(ext_prv, ext_pub) = bip32_master_key(seed, seed_bytes)
assert ext_prv == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
assert ext_pub == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"


(ext_prv, ext_pub) = bip32_ckd(ext_prv, 0x80000000+0)
assert ext_prv == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "failure"
assert ext_pub == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "failure"

(ext_prv, ext_pub) = bip32_ckd(ext_prv, 1)
assert ext_prv == "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "failure"
assert ext_pub == "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", "failure"

# == Test vector 3 ==

seed = 0x4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
seed_bytes = 64
(ext_prv,ext_pub) = bip32_master_key(seed, seed_bytes)
assert ext_prv == "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
assert ext_pub == "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"

(ext_prv,ext_pub) = bip32_ckd(ext_prv, 0x80000000+0)
assert ext_prv == "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L", "failure"
assert ext_pub == "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y", "failure"
