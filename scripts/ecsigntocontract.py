# -*- coding: utf-8 -*-
"""
Created on Sat Oct 28 01:03:03 2017

@author: Leonardo, fametrano
"""

# import - check - decode - from/to ec_point - from/to int
# ecdsa - ecssa - sign-to-contract - test


# %% import

from hashlib import sha256
from base58 import b58decode_check, __chars as b58digits
from ECsecp256k1 import pointAdd, pointMultiply, \
                        order as ec_order, prime as ec_prime, G as ec_G, \
                        a as ec_a, b as ec_b
from FiniteFields import modInv, modular_sqrt
from string import hexdigits
from rfc6979 import rfc6979
from ecutils import default_hasher, str_to_hash, check_hash_digest, decode_prv, hash_to_int, int_to_bytes, check_ec_point
from ecdsa import ecdsa_sign, ecdsa_verify, check_dsasig, ecdsa_recover, ecdsa_sign_raw
from ecssa import ecssa_sign, ecssa_verify, check_ssasig, ecssa_recover, ecssa_sign_raw

# %% sign to contract
# IDEA:
#    insert a commitment in a signature (singing something else!)
#    using this valid commitment operation:
#    R -> hash(R||c)G + R  (R ec point, G generator, c commit)
# HOW:
#    when you sign you generate a nonce (k) and compute a ec point (R = kG)
#    instead of proceeding using (k,R) you compute a value (e) that embed the
#    commitment: e = hash(R.x||commit)
#    you substitute the nonce with k+e and R with R+eG, and proceed signing
#    in the standard way using instead (k+e,R+eG)
# VERIFICATION:
#    the verifier can see W.x (W = R+eG) on the signature
#    the signer (and committer) provides R and commit
#    the verifier checks that:   W.x = (R+eG).x
#                               (with e = hash(R.x||commit))

def check_receipt(receipt):
  """check receipt format
  """
  assert type(receipt[0]) == int and \
         0 < receipt[0] and receipt[0] < ec_prime, \
         "1st part of the receipt must be an int in (0, ec_prime)"
  check_ec_point(receipt[1])

def insert_commit(k, c, hasher=default_hasher):
  """insert a commit in a ec point
  """
  R = pointMultiply(k, ec_G)
  e = hash_to_int(hasher(int_to_bytes(R[0], 32) + c).digest())
  return R, (e + k) % ec_order

def ecdsa_sign_and_commit(m, prv, c, eph_prv=None, hasher=default_hasher):
  check_hash_digest(m)
  prv = decode_prv(prv)
  eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else decode_prv(eph_prv)
  h = hash_to_int(m)
  check_hash_digest(c)
  R, eph_prv = insert_commit(eph_prv, c, hasher)
  sig = ecdsa_sign_raw(h, prv, eph_prv)
  receipt = (sig[0], R)
  return sig, receipt

def ecssa_sign_and_commit(m, prv, c, eph_prv=None, hasher=default_hasher):
  check_hash_digest(m)
  prv = decode_prv(prv)
  eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else decode_prv(eph_prv)
  check_hash_digest(c)
  R, eph_prv = insert_commit(eph_prv, c, hasher)
  sig = ecssa_sign_raw(m, prv, eph_prv, hasher)
  receipt = (sig[0], R)
  return sig, receipt

def ec_verify_commit(receipt, c, hasher=default_hasher):
  check_receipt(receipt)
  check_hash_digest(c)
  w, R = receipt
  e = hash_to_int(hasher(int_to_bytes(R[0], 32) + c).digest())
  W = pointAdd(R, pointMultiply(e, ec_G))
  return w % ec_order == W[0] % ec_order
  # weaker verfication! w in [1..ec_order-1] dsa
  #                     w in [1..ec_prime-1] ssa
  # choice to manage with the same function


# %% tests

def test_ecdsa(param, verify=True, recover=True, verify_commit=True):
  print("*** testing ecdsa2")
  m, prv, c = param
  sig = ecdsa_sign(m, prv)
  pub = pointMultiply(prv, ec_G)
  if verify:
    assert ecdsa_verify(m, sig, pub), "invalid sig"
  if recover:
    assert pub in (ecdsa_recover(m, sig, 0), ecdsa_recover(m, sig, 1)),\
    "the recovered pubkey is not correct"
  if verify_commit:
    sig_commit, receipt = ecdsa_sign_and_commit(m, prv, c)
    assert ecdsa_verify(m, sig_commit, pub), "sig verification failed"
    assert ec_verify_commit(receipt, c), "commit verification failed"
  print("ecdsa tests passed")

def test_ecssa(param, verify=True, recover=True, verify_commit=True):
  print("*** testing ecssa2")
  m, prv, c = param
  sig = ecssa_sign(m, prv)
  pub = pointMultiply(prv, ec_G)
  if verify:
    assert ecssa_verify(m, sig, pub), "invalid sig"
  if recover:
    assert pub == ecssa_recover(m, sig), \
    "the recovered pubkey is not correct"
  if verify_commit:
    sig_commit, receipt = ecssa_sign_and_commit(m, prv, c)
    assert ecssa_verify(m, sig_commit, pub), "sig verification failed"
    assert ec_verify_commit(receipt, c), "commit verification failed"
  print("ecssa tests passed")

def main(ecdsa=True, ecssa=True, \
         verify=True, recover=True, verify_commit=True):
  m = str_to_hash("hello world")
  prv = 1
  c = str_to_hash("sign to contract")
  param = m, prv, c
  if ecdsa:
    test_ecdsa(param, verify, recover, verify_commit)
  if ecssa:
    test_ecssa(param, verify, recover, verify_commit)

if __name__ == "__main__":
  # execute only if run as a script
  main()
