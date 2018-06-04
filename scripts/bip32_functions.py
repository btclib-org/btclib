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

# VERSION BYTES =      4 bytes        Base58 encode starts with
MAINNET_PRIVATE = b'\x04\x88\xAD\xE4' # xprv
TESTNET_PRIVATE = b'\x04\x35\x83\x94' # tprv
SEGWIT_PRIVATE  = b'\x04\xb2\x43\x0c'
PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE, SEGWIT_PRIVATE]

MAINNET_PUBLIC  = b'\x04\x88\xB2\x1E' # xpub
TESTNET_PUBLIC  = b'\x04\x35\x87\xCF' # tpub
SEGWIT_PUBLIC   = b'\x04\xb2\x47\x46'
PUBLIC  = [MAINNET_PUBLIC,  TESTNET_PUBLIC,  SEGWIT_PUBLIC]

MAINNET_ADDRESS  = b'\x00'             # 1
TESTNET_ADDRESS  = b'\x6F'             # m or n
ADDRESS  = [MAINNET_ADDRESS,  TESTNET_ADDRESS]

# version    : [  : 4]  4 bytes
# depth      : [ 4: 5]  1 byte
# fingerprint: [ 5: 9]  4 bytes
# child_index: [ 9:13]  4 bytes
# chain_code : [13:45] 32 bytes
# key        : [45:78] 33 bytes (private/public)

def bip32_master_prvkey_from_seed(bip32_seed, version = PRIVATE[0]):
  """derive the master extended private key from the seed"""
  assert version in PRIVATE, "wrong version, master key must be private"
  xprv = version
  xprv += b'\x00'                         # depth
  xprv += b'\x00\x00\x00\x00'             # fingerprint
  xprv += b'\x00\x00\x00\x00'             # child_index
  hashValue = HMAC(b"Bitcoin seed", bip32_seed, sha512).digest()
  xprv += hashValue[32:]                  # chain_code
  p = int.from_bytes(hashValue[:32], 'big') % ec.order
  xprv += b'\x00' + p.to_bytes(32, 'big') # key
  return b58encode_check(xprv)


def bip32_xpub_from_xprv(xprv):
  """derive the extended public key from the extended private key"""
  xprv = b58decode_check(xprv)
  assert len(xprv) == 78, "wrong length for decoded extended private key"
  assert xprv[45] == 0, "the extended key is not a private one"
  # version
  i = PRIVATE.index(xprv[:4])
  xpub = PUBLIC[i]
  # depth, fingerprint, child_index, and chain_code are left unchanged
  xpub += xprv[4:45]
  # public key derivation
  P = ec.pointMultiply(xprv[46:])
  xpub += ec.bytes_from_point(P, True)
  return b58encode_check(xpub)


def bip32_ckd(xparentkey, child_index):
  """Child Key Derivation"""
  # key derivation is normal if the extended parent key is public or
  # child_index is less than 0x80000000
  #
  # key derivation is hardened if the extended parent key is private and
  # child_index is not less than 0x80000000

  if isinstance(child_index, int):
    child_index = child_index.to_bytes(4, 'big')

  xparent = b58decode_check(xparentkey)
  assert len(xparent) == 78, "wrong length for extended parent key"

  version = xparent[:4]

  xkey = version                                # version
  xkey += (xparent[4] + 1).to_bytes(1, 'big')   # (increased) depth

  if (version in PRIVATE):
    assert xparent[45] == 0, "version/key mismatch in extended parent key"
    parent_prvkey = xparent[46:]
    parent_pubkey = ec.bytes_from_point(ec.pointMultiply(parent_prvkey), True)
    xkey += h160(parent_pubkey)[:4]             # fingerprint of parent pubkey
    xkey += child_index                         # child_index
    if (child_index[0] < 0x80): # normal derivation
      h = HMAC(xparent[13:45], parent_pubkey + child_index, sha512).digest()
    else:                       # hardened derivation
      h = HMAC(xparent[13:45], xparent[45:] + child_index, sha512).digest()
    xkey += h[32:]                              # chain_code
    p = int.from_bytes(h[:32], 'big')
    p = (p + int.from_bytes(parent_prvkey, 'big')) % ec.order
    xkey += b'\x00' + p.to_bytes(32, 'big')     # key
  elif (version in PUBLIC):
    assert xparent[45] in (2, 3), "version/key mismatch in extended parent key"
    xkey += h160(xparent[45:])[:4]              # fingerprint of parent pubkey
    assert child_index[0] < 0x80, "No private/hardened derivation from pubkey"
    xkey += child_index                         # child_index
    # normal derivation
    h = HMAC(xparent[13:45], xparent[45:] + child_index, sha512).digest()
    xkey += h[32:]                              # chain_code
    P = ec.pointMultiply(h[:32])
    parentPoint = ec.scrub_point(xparent[45:])
    P = ec.pointAdd(P, parentPoint)
    xkey += ec.bytes_from_point(P, True)        # key
  else:
    raise ValueError("invalid extended key version")

  return b58encode_check(xkey)


# hdkeypath
def bip32_derive(xkey, path, version=b'\x00'):
  """derive an extended key according to path like "m/44'/0'/1'/0/10" (absolute) or "./0/10" (relative) """

  steps = path.split('/')
  if steps[0] not in {'m', '.'}:
    raise ValueError('Invalid derivation path: {}'.format(path))  
  if steps[0] == 'm':
    decoded = b58decode_check(xkey)
    t = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    assert decoded[4:13] == t, "Trying to derive absolute path from non-master key"

  for step in steps[1:]:
    hardened = False
    if step[-1] == "'" or step[-1] == "H":
      hardened = True
      step = step[:-1]
    index = int(step)
    index += 0x80000000 if hardened else 0
    xkey = bip32_ckd(xkey, index)

  return xkey


def address_from_extpubkey(xpub):
  xpub = b58decode_check(xpub)
  assert len(xpub) == 78, "wrong length for decoded extended public key"
  assert xpub[45] in (2, 3), "the extended key is not a public one"
  version = xpub[:4]
  i = PUBLIC.index(version)
  return address_from_pubkey(xpub[45:], ADDRESS[i])



def bip32_test():
  # == Test vector 1 ==
  
  seed = 0x000102030405060708090a0b0c0d0e0f
  seed = seed.to_bytes(16, 'big')
  
  mprv = bip32_master_prvkey_from_seed(seed)
  assert mprv == b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
  mpub = bip32_xpub_from_xprv(mprv)
  assert mpub == b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
  address_from_extpubkey(mpub)

  mprv = bip32_derive(mprv, "m")
  assert mprv == b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
  mpub = bip32_derive(mpub, "m")
  assert mpub == b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

  xprv = bip32_derive(mprv, "m/0'")
  assert xprv == b"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub == b"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

  xprv = bip32_derive(mprv, "m/0'/1")
  assert xprv == b"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
  xpub = bip32_derive(xpub, "./1")
  assert xpub == b"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub == b"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"

  xprv = bip32_derive(xprv, "./2H")
  assert xprv == b"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub == b"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"

  xprv = bip32_derive(xprv, "./2")
  assert xprv == b"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
  xpub = bip32_derive(xpub, "./2")
  assert xpub == b"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub == b"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"

  xprv = bip32_derive(mprv, "m/0'/1/2'/2/1000000000")
  assert xprv == b"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
  xpub = bip32_derive(xpub, "./1000000000")
  assert xpub == b"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub == b"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
  address_from_extpubkey(xpub)


  # == Test vector 3 ==

  seed = 0x4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
  seed = seed.to_bytes(64, 'big')

  mprv = bip32_master_prvkey_from_seed(seed)
  assert mprv == b"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
  mpub = bip32_xpub_from_xprv(mprv)
  assert mpub == b"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"

  mprv = bip32_derive(mprv, "m")
  assert mprv == b"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
  mpub = bip32_derive(mpub, "m")
  assert mpub == b"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"

  xprv = bip32_derive(mprv, "m/0'")
  assert xprv == b"xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub == b"xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"


if __name__ == "__main__":
  bip32_test()
