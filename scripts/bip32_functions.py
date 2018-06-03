# -*- coding: utf-8 -*-
"""
Created on Mon Oct 27 09:41:51 2017

@author: dfornaro, fametrano
"""

# This script gives you the basic functions used in the Hierarchical Deterministic Wallet defined in BIP32

from ECsecp256k1 import ec
from WIF_address import h160, address_from_pubkey
from hmac import HMAC
from hashlib import sha512
from base58 import b58encode_check, b58decode_check

MAINNET_PRIVATE = b'\x04\x88\xAD\xE4'
MAINNET_PUBLIC  = b'\x04\x88\xB2\x1E'
TESTNET_PRIVATE = b'\x04\x35\x83\x94'
TESTNET_PUBLIC  = b'\x04\x35\x87\xCF'
SEGWIT_PRIVATE  = b'\x04\xb2\x43\x0c'
SEGWIT_PUBLIC   = b'\x04\xb2\x47\x46'
PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE, SEGWIT_PRIVATE]
PUBLIC  = [MAINNET_PUBLIC,  TESTNET_PUBLIC,  SEGWIT_PUBLIC]

# version    : [  : 4]  4 bytes
# depth      : [ 4: 5]  1 byte
# fingerprint: [ 5: 9]  4 bytes
# child_index: [ 9:13]  4 bytes
# chain_code : [13:45] 32 bytes
# key        : [45:78] 33 bytes (private/public)

def bip32_isvalid_xkey(version, key):
  """check validity of the xkey components"""
  if (version in PUBLIC):
    assert key[0] in (2, 3)
  elif (version in PRIVATE):
    assert key[0] == 0
  else:
    raise Exception("invalix key[0] prefix '%s'" % type(key[0]).__name__)
  assert int.from_bytes(key[1:33], 'big') < ec.order, "invalid key"

def bip32_parse_xkey(xkey):
  """parse an extended key"""
  decoded = b58decode_check(xkey)
  assert len(decoded) == 78, "wrong length for decoded xkey"
  info = {"version"     : decoded[  : 4],
          "depth"       : decoded[ 4: 5],
          "fingerprint" : decoded[ 5: 9],
          "child_index" : decoded[ 9:13],
          "chain_code"  : decoded[13:45],
          "key"         : decoded[45:]
         }
  bip32_isvalid_xkey(info["version"], info["key"])
  return info

def bip32_compose_xkey(version, depth, fingerprint, child_index, chain_code, key):
  assert len(version)     ==  4, "wrong length (%s) for version" % len(version)
  assert len(depth)       ==  1, "wrong length (%s) for depth" % len(depth)
  assert len(fingerprint) ==  4, "wrong length (%s) for fingerprint" % len(fingerprint)
  assert len(child_index) ==  4, "wrong length (%s) for child_index" % len(child_index)
  assert len(chain_code)  == 32, "wrong length (%s) for chain_code" % len(chain_code)
  assert len(key)         == 33, "wrong length (%s) for key" % len(key)
  bip32_isvalid_xkey(version, key)
  xkey = version + depth + fingerprint + child_index + chain_code + key
  return b58encode_check(xkey)

def bip32_master_key(bip32_seed, seed_bytes, version = PRIVATE[0]):
  """derive the master extended private key from the seed"""
  hashValue = HMAC(b"Bitcoin seed", bip32_seed.to_bytes(seed_bytes, 'big'), sha512).digest()
  p_bytes = hashValue[:32]
  p = int(p_bytes.hex(), 16) % ec.order
  p_bytes = b'\x00' + p.to_bytes(32, 'big')
  chain_code = hashValue[32:]
  xprv = bip32_compose_xkey(version, b'\x00', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', chain_code, p_bytes)
  return xprv

def bip32_xpub_from_xprv(xprv):
  """derive the extended public key from the extended private key"""
  info = bip32_parse_xkey(xprv)
  assert info["key"][0] == 0, "not an extended private key"
  p = int.from_bytes(info["key"][1:], 'big')
  P = ec.pointMultiply(p)
  info["key"] = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, 'big')
  info["version"] = PUBLIC[PRIVATE.index(info["version"])]
  return bip32_compose_xkey(info["version"], info["depth"], info["fingerprint"], \
                            info["child_index"], info["chain_code"], info["key"])

def bip32_ckd(xparentkey, child_index):
  """Child Key Derivation"""
  # public key normal derivation if the extended parent key is a public key
  #
  # private key derivation if the extended parent key is a private key
  # normal or hardened derivation according to child_index:
  # normal if less than 0x80000000, else hardened

  parent = bip32_parse_xkey(xparentkey)
  # increase depth
  depth = (int.from_bytes(parent["depth"], 'big') + 1).to_bytes(1, 'big')
  child_index = child_index.to_bytes(4, 'big')

  if parent["version"] in PRIVATE:
    network = PRIVATE.index(parent["version"])
    parent_prvkey = int.from_bytes(parent["key"][1:], 'big')
    P = ec.pointMultiply(parent_prvkey)
    parent_pubkey = (b'\x02' if (P[1] % 2 == 0) else b'\x03') + P[0].to_bytes(32, 'big')
    if (child_index[0] >= 0x80): #hardened derivation
      parent_key = parent["key"]
    else:
      parent_key = parent_pubkey
  else:
    network = PUBLIC.index(parent["version"])
    parent_pubkey = parent["key"]
    assert child_index[0] < 0x80, "Cannot do private (hardened) derivation from Pubkey"
    parent_key = parent_pubkey

  fingerprint = h160(parent_pubkey)[:4]
  hashValue = HMAC(parent["chain_code"], parent_key + child_index, sha512).digest()
  chain_code = hashValue[32:]
  p = int(hashValue[:32].hex(), 16)

  if parent["version"] in PRIVATE:
    p = (p + parent_prvkey) % ec.order
    p_bytes = b'\x00' + p.to_bytes(32, 'big')
    return bip32_compose_xkey(PRIVATE[network], depth, fingerprint, child_index, chain_code, p_bytes)
  else:
    P = ec.pointMultiply(p)
    parentPoint = ec.scrubPoint(parent_pubkey)
    P = pointAdd(P, parentPoint)
    P_bytes = bytes_from_point(P, True)
    return bip32_compose_xkey(PUBLIC[network], depth, fingerprint, child_index, chain_code, P_bytes)

# hdkeypath
def bip32_path(extKey, index_child, version=b'\x00'):
  # Recursive function that calculates the child key, following a "path". 
  # INPUT:
  #   extKey: extended key from which you want to start the path, it could be public or private
  #   index_child: vector of indexes of the path,
  #                e.g. [0,1,2] means be third child of the second child of the first child.
  # OUTPUT:
  #   extKey: extended child key, it could be public or private
  extKey = bip32_ckd(extKey, index_child[0])
  info_xprv = bip32_parse_xkey(extKey)
  if index_child[1:] == []:
    if (info_xprv["version"] in PRIVATE):
      xpub = bip32_xpub_from_xprv(extKey)
    elif (info_xprv["version"] in PUBLIC):
      xpub = extKey
    else:
      assert False
    info_xpub = bip32_parse_xkey(xpub)
    return address_from_pubkey(info_xpub['key'], version)
  else:
    return bip32_path(extKey, index_child[1:], version)

def bip32_test():
  # == Test vector 1 ==
  
  seed = 0x000102030405060708090a0b0c0d0e0f
  seed_bytes = 16
  xprv = bip32_master_key(seed, seed_bytes)
  assert xprv == b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub == b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"


  xprv = bip32_ckd(xprv, 0x80000000+0)
  assert xprv == b"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "failure"
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub == b"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "failure"

  xprv = bip32_ckd(xprv, 1)
  assert xprv == b"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "failure"
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub == b"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", "failure"

  # == Test vector 3 ==

  seed = 0x4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
  seed_bytes = 64
  xprv = bip32_master_key(seed, seed_bytes)
  assert xprv == b"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub == b"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"

  xprv = bip32_ckd(xprv, 0x80000000+0)
  assert xprv == b"xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L", "failure"
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub == b"xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y", "failure"

if __name__ == "__main__":
  bip32_test()
