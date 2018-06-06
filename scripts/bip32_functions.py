# -*- coding: utf-8 -*-
"""
Created on Mon Oct 27 09:41:51 2017

@author: dfornaro, fametrano
"""

# This script gives you the basic functions used in the Hierarchical Deterministic Wallet defined in BIP32

from ECsecp256k1 import order, G, pointMultiply, pointAdd, a, b, prime
from hmac import HMAC
from hashlib import new as hnew
from hashlib import sha512, sha256
from base58 import b58encode_check, b58decode_check
from FiniteFields import modular_sqrt

BITCOIN_PRIVATE = b'\x04\x88\xAD\xE4'
BITCOIN_PUBLIC = b'\x04\x88\xB2\x1E'
TESTNET_PRIVATE = b'\x04\x35\x83\x94'
TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
BITCOIN_SEGWIT_PRIVATE = b'\x04\xb2\x43\x0c'
BITCOIN_SEGWIT_PUBLIC = b'\x04\xb2\x47\x46'
PRIVATE = [BITCOIN_PRIVATE, TESTNET_PRIVATE, BITCOIN_SEGWIT_PRIVATE]
PUBLIC  = [BITCOIN_PUBLIC,  TESTNET_PUBLIC, BITCOIN_SEGWIT_PUBLIC]

def h160(inp):
  # Funcion that computes the HASH160
  h1 = sha256(inp).digest()
  return hnew('ripemd160', h1).digest()

def public_key_to_bc_address(inp, version=b'\x00'):
  # Function that computes the address from a public key
  vh160 = version + h160(inp)
  return b58encode_check(vh160)

def bip32_isvalid_xkey(vbytes, depth, fingerprint, index, chain_code, key):
  # Function that checks for the validity of the component of an extended key
  # INPUT:
  #   vbytes: 4 bytes for the version
  #   depth: 1 byte for the depth
  #   fingerprint: 4 bytes for the fingerprint
  #   index: 4 bytes for the child index
  #   chain_code: 32 bytes for the chain code
  #   key: 33 bytes for the private or public key
  # OUTPUT:
  #   none
  assert len(key) == 33, "wrong length for key"
  if (vbytes in PUBLIC):
    assert key[0] in (2, 3)
  elif (vbytes in PRIVATE):
    assert key[0] == 0
  else:
    raise Exception("invalix key[0] prefix '%s'" % type(key[0]).__name__)
  assert int.from_bytes(key[1:33], 'big') < order, "invalid key"
  assert len(depth) == 1, "wrong length for depth"
  assert len(fingerprint) == 4, "wrong length for fingerprint"
  assert len(index) == 4, "wrong length for index"
  assert len(chain_code) == 32, "wrong length for chain_code"

def bip32_parse_xkey(xkey):
  # Function that parses an extended key
  # INPUT:
  #   xkey: extended key
  # OUTPUT:
  #   info: dictionary with all the informations extractable from the extended key 
  decoded = b58decode_check(xkey)
  assert len(decoded) == 78, "wrong length for decoded xkey"
  info = {"vbytes": decoded[:4],
          "depth": decoded[4:5],
          "fingerprint" : decoded[5:9],
          "index" : decoded[9:13],
          "chain_code" : decoded[13:45],
          "key" : decoded[45:]
          }
  bip32_isvalid_xkey(info["vbytes"], info["depth"], info["fingerprint"], \
                     info["index"], info["chain_code"], info["key"])
  return info

def bip32_compose_xkey(vbytes, depth, fingerprint, index, chain_code, key):
  # Function that composes an extended key
  # INPUT:
  #   vbytes: 4 bytes for the version
  #   depth: 1 byte for the depth
  #   fingerprint: 4 bytes for the fingerprint
  #   index: 4 bytes for the child index
  #   chain_code: 32 bytes for the chain code
  #   key: 33 bytes for the private or public key
  # OUTPUT:
  #   xkey: extended key
  bip32_isvalid_xkey(vbytes, depth, fingerprint, index, chain_code, key)
  xkey = vbytes + \
         depth + \
         fingerprint + \
         index + \
         chain_code + \
         key
  return b58encode_check(xkey)

def bip32_xprvtoxpub(xprv):
  # Function that derives the extended public key from the extended private key
  # INPUT:
  #   xprv: extended private key
  # OUTPUT:
  #   xpub: extended public key
  decoded = b58decode_check(xprv)
  assert decoded[45] == 0, "not a private key"
  p = int.from_bytes(decoded[46:], 'big')
  P = pointMultiply(p, G)
  P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, 'big')
  network = PRIVATE.index(decoded[:4])
  xpub = PUBLIC[network] + decoded[4:45] + P_bytes
  return b58encode_check(xpub)

def bip32_master_key(seed, seed_bytes, vbytes = PRIVATE[0]):
  # Function that derives the master extended private key from the seed
  # INPUT:
  #   seed: BIP 32 seed
  #   seed_bytes: number of the bytes of the seed
  #   vbytes: version of the master extended private key
  # OUTPUT:
  #   xprv: master extended private key
  hashValue = HMAC(b"Bitcoin seed", seed.to_bytes(seed_bytes, 'big'), sha512).digest()
  p_bytes = hashValue[:32]
  p = int(p_bytes.hex(), 16) % order
  p_bytes = b'\x00' + p.to_bytes(32, 'big')
  chain_code = hashValue[32:]
  xprv = bip32_compose_xkey(vbytes, b'\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', chain_code, p_bytes)
  return xprv

# Child Key Derivation
def bip32_ckd(extKey, child_index):
  # Function that computes the child key derivation. 
  # Normal or hardened derivation depends on the child index.
  # If the parent key is a public key, this function gives you the public child key. (normal derivation)
  # INPUT:
  #   extKey: extended parent key, it could be public or private
  #   child_index: index of the child, if less than 0x80000000 we will have a normal derivation, hardened otherwise
  # OUTPUT:
  #   extKey: extended child key, it could be public or private
  parent = bip32_parse_xkey(extKey)
  depth = (int.from_bytes(parent["depth"], 'big') + 1).to_bytes(1, 'big')
  if parent["vbytes"] in PRIVATE:
    network = PRIVATE.index(parent["vbytes"])
    parent_prvkey = int.from_bytes(parent["key"][1:], 'big')
    P = pointMultiply(parent_prvkey, G)
    parent_pubkey = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, 'big')
  else:
    network = PUBLIC.index(parent["vbytes"])
    parent_pubkey = parent["key"]
  fingerprint = h160(parent_pubkey)[:4]
  index = child_index.to_bytes(4, 'big')

  if (index[0] >= 0x80): #private (hardened) derivation
    assert parent["vbytes"] in PRIVATE, "Cannot do private (hardened) derivation from Pubkey"
    parent_key = parent["key"]
  else:
    parent_key = parent_pubkey
  hashValue = HMAC(parent["chain_code"], parent_key + index, sha512).digest()
  chain_code = hashValue[32:]
  p = int(hashValue[:32].hex(), 16)

  if parent["vbytes"] in PRIVATE:
    p = (p + parent_prvkey) % order
    p_bytes = b'\x00' + p.to_bytes(32, 'big')
    return bip32_compose_xkey(PRIVATE[network], depth, fingerprint, index, chain_code, p_bytes)
  else:
    P = pointMultiply(p, G)
    X = int.from_bytes(parent_pubkey[1:], 'big')
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
    P_bytes = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, 'big')
    return bip32_compose_xkey(PUBLIC[network], depth, fingerprint, index, chain_code, P_bytes)

# hdkeypath
def path(extKey, index_child, version=b'\x00'):
  # Recursive function that calculates the child key, following a "path". 
  # INPUT:
  #   extKey: extended key from which you want to start the path, it could be public or private
  #   index_child: vector of indeces of the path: [0,1,2] should be third child of the second child of the first child.
  # OUTPUT:
  #   extKey: extended child key, it could be public or private
  extKey = bip32_ckd(extKey, index_child[0])
  info_xprv = bip32_parse_xkey(extKey)
  if index_child[1:] == []:
    if (info_xprv["vbytes"] in PRIVATE):
      xpub = bip32_xprvtoxpub(extKey)
    elif (info_xprv["vbytes"] in PUBLIC):
      xpub = extKey
    else:
      assert False
    info_xpub = bip32_parse_xkey(xpub)
    return public_key_to_bc_address(info_xpub['key'], version)
  else:
    return path(extKey, index_child[1:], version)

def bip32_test():
  # == Test vector 1 ==
  
  seed = 0x000102030405060708090a0b0c0d0e0f
  seed_bytes = 16
  xprv = bip32_master_key(seed, seed_bytes)
  assert xprv == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
  xpub = bip32_xprvtoxpub(xprv)
  assert xpub == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"


  xprv = bip32_ckd(xprv, 0x80000000+0)
  assert xprv == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "failure"
  xpub = bip32_xprvtoxpub(xprv)
  assert xpub == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "failure"

  xprv = bip32_ckd(xprv, 1)
  assert xprv == "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "failure"
  xpub = bip32_xprvtoxpub(xprv)
  assert xpub == "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", "failure"

  # == Test vector 3 ==

  seed = 0x4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
  seed_bytes = 64
  xprv = bip32_master_key(seed, seed_bytes)
  assert xprv == "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
  xpub = bip32_xprvtoxpub(xprv)
  assert xpub == "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"

  xprv = bip32_ckd(xprv, 0x80000000+0)
  assert xprv == "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L", "failure"
  xpub = bip32_xprvtoxpub(xprv)
  assert xpub == "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y", "failure"

if __name__ == "__main__":
  bip32_test()
