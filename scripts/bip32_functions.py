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

def xprvtoxpub(xprv):
  decoded = b58decode_check(xprv)
  assert decoded[45] == 0x00, "not a private key"
  p = int.from_bytes(decoded[46:], byteorder='big')
  P = pointMultiply(p, G)
  P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
  xpub = BITCOIN_PUBLIC + decoded[4:45] + P_bytes
  return b58encode_check(xpub)

def parse_xkey(xkey):
  decoded = b58decode_check(xkey)
  info = {"vbytes": decoded[:4],
          "depth": decoded[4],
          "fingerprint" : decoded[5:9],
          "child_number" : decoded[9:13],
          "chain_code" : decoded[13:45],
          "key" : decoded[45:]
          }
  return info
    
def compose_xkey(vbytes, depth, fingerprint, child_number, chain_code, key):
  extKey = vbytes + \
           depth + \
           fingerprint + \
           child_number + \
           chain_code + \
           key
  return b58encode_check(extKey)
    
def bip32_master_key(seed, seed_bytes, vbytes=BITCOIN_PRIVATE):
  hashValue = HMAC(b"Bitcoin seed", seed.to_bytes(seed_bytes, byteorder='big'), sha512).digest()
  p_bytes = hashValue[:32]
  p = int(p_bytes.hex(), 16) % order
  p_bytes = b'\x00' + p.to_bytes(32, byteorder='big')
  chain_code = hashValue[32:]
  xprv = compose_xkey(vbytes, b'\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', chain_code, p_bytes)
  return xprv

# Child Key Derivation
def bip32_ckd(extKey, child_index):
  parent = parse_xkey(extKey)
  
  depth = (parent["depth"] + 1).to_bytes(1, byteorder='big')

  if parent["vbytes"] in PRIVATE:
    parent_prvkey = int.from_bytes(parent["key"][1:], byteorder='big')
    P = pointMultiply(parent_prvkey, G)
    parent_pubkey = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
  else:
    parent_pubkey = parent["key"]
  fingerprint = h160(parent_pubkey)[:4]
  child_number = child_index.to_bytes(4, byteorder='big')

  if (child_number[0] >= 0x80): #private (hardened) derivation
    assert parent["vbytes"] in PRIVATE, "Cannot do private (hardened) derivation from Pubkey"
    parent_key = parent["key"]
  else:
    parent_key = parent_pubkey
  hashValue = HMAC(parent["chain_code"], parent_key + child_number, sha512).digest()
  chain_code = hashValue[32:]
  p = int(hashValue[:32].hex(), 16)

  if parent["vbytes"] in PRIVATE:
    p = (p + parent_prvkey) % order
    p_bytes = b'\x00' + p.to_bytes(32, byteorder='big')
    xprv = compose_xkey(BITCOIN_PRIVATE, depth, fingerprint, child_number, chain_code, p_bytes)
    return xprv
  else:
    P = pointMultiply(p, G)
    X = int.from_bytes(parent_pubkey[1:], byteorder='big')
    Y_2 = X**3 + a*X + b
    Y = modular_sqrt(Y_2, prime)
    if (Y % 2 == 0):
      if (parent_pubkey[0] == 3):
        Y = prime - Y
    else:
      if (parent_pubkey[0] == 2):
        Y = prime - Y
    parentPoint = (X, Y)
    P = pointAdd(P, parentPoint)
    P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, byteorder='big')
    xpub = compose_xkey(BITCOIN_PUBLIC, depth, fingerprint, child_number, chain_code, P_bytes)
    return xpub


# == Test vector 1 ==
  
seed = 0x000102030405060708090a0b0c0d0e0f
seed_bytes = 16
xprv = bip32_master_key(seed, seed_bytes)
assert xprv == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
xpub = xprvtoxpub(xprv)
assert xpub == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"


xprv = bip32_ckd(xprv, 0x80000000+0)
assert xprv == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "failure"
xpub = xprvtoxpub(xprv)
assert xpub == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "failure"

xprv = bip32_ckd(xprv, 1)
assert xprv == "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "failure"
xpub = xprvtoxpub(xprv)
assert xpub == "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", "failure"

# == Test vector 3 ==

seed = 0x4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
seed_bytes = 64
xprv = bip32_master_key(seed, seed_bytes)
assert xprv == "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
xpub = xprvtoxpub(xprv)
assert xpub == "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"

xprv = bip32_ckd(xprv, 0x80000000+0)
assert xprv == "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L", "failure"
xpub = xprvtoxpub(xprv)
assert xpub == "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y", "failure"
