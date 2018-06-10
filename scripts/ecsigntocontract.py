# -*- coding: utf-8 -*-
"""
Created on Sat Oct 28 01:03:03 2017

@author: Leonardo, fametrano
"""

# import - check - decode - from/to ec_point - from/to int
# ecdsa - ecssa - sign-to-contract - test


# %% import

from hashlib import sha256
from base58 import b58decode_check, base58digits as b58digits
from ECsecp256k1 import ec
from FiniteFields import mod_inv, mod_sqrt
from string import hexdigits
from rfc6979 import rfc6979
from ecutils import str_to_hash, int_from_hash
from WIF_address import int_from_prvkey
from ecdsa import ecdsa_sign, ecdsa_verify, check_dsasig, ecdsa_recover, ecdsa_sign_raw
from ecssa import ecssa_sign, ecssa_verify, check_ssasig, ecssa_recover, ecssa_sign_raw

# %% sign to contract
# IDEA:
#    insert a commitment in a signature (signing something else!)
#    using this valid commitment operation:
#    R -> hash(R||c)G + R  (R ec point, G generator, c commit)
# HOW:
#    when you sign you generate a nonce (k) and compute a ec point (R = kG)
#    instead of proceeding using (k,R) you compute a value (e) that embed the
#    commitment: e = hash(R.x||c)
#    you substitute the nonce with k+e and R with R+eG, and proceed signing
#    in the standard way using instead (k+e,R+eG)
# VERIFICATION:
#    the verifier can see W.x (W = R+eG) on the signature
#    the signer (and committer) provides R and c
#    the verifier checks that:   W.x = (R+eG).x
#                               (with e = hash(R.x||c))

def check_receipt(receipt):
  """check receipt format
  """
  # FIXME
  # assert type(receipt[0]) == int and \
  #       0 < receipt[0] and receipt[0] < ec_prime, \
  #       "1st part of the receipt must be an int in (0, ec_prime)"
  ec.tuple_from_point(receipt[1])

def ec_insert_commit(k, c, hasher=sha256):
  """insert a commit in a ec point
  """
  R = ec.pointMultiply(k)
  e = int_from_hash(hasher(R[0].to_bytes(32, 'big') + c).digest())
  return R, (e + k) % ec.order

def ecdsa_sign_and_commit(m, prv, c, eph_prv=None, hasher=sha256):
  prv = int_from_prvkey(prv)
  eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else int_from_prvkey(eph_prv)
  R, eph_prv = ec_insert_commit(eph_prv, c, hasher)
  sig = ecdsa_sign_raw(m, prv, eph_prv)
  receipt = (sig[0], R)
  return sig, receipt

def ecssa_sign_and_commit(m, prv, c, eph_prv=None, hasher=sha256):
  prv = int_from_prvkey(prv)
  eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else int_from_prvkey(eph_prv)
  R, eph_prv = ec_insert_commit(eph_prv, c, hasher)
  sig = ecssa_sign_raw(m, prv, eph_prv, hasher)
  receipt = (sig[0], R)
  return sig, receipt

def ec_verify_commit(receipt, c, hasher=sha256):
  check_receipt(receipt)
  w, R = receipt
  e = int_from_hash(hasher(R[0].to_bytes(32, 'big') + c).digest())
  W = ec.pointAdd(R, ec.pointMultiply(e))
  return w % ec.order == W[0] % ec.order
  # weaker verfication! w in [1..ec.order-1] dsa
  #                     w in [1..ec_prime-1] ssa
  # choice to manage with the same function


# %% tests

def test_ecdsa(param, verify_sig=True, recover=True, verify_commit=True):
  print("*** testing ecdsa2")
  m, prv, c = param
  sig = ecdsa_sign(m, prv)
  pub = ec.pointMultiply(prv)
  if verify_sig:
    assert ecdsa_verify(m, sig, pub), "invalid sig"
  if recover:
    assert pub in (ecdsa_recover(m, sig, 0), ecdsa_recover(m, sig, 1)),\
    "the recovered pubkey is not correct"
  if verify_commit:
    sig_commit, receipt = ecdsa_sign_and_commit(m, prv, c)
    assert ecdsa_verify(m, sig_commit, pub), "sig verification failed"
    assert ec_verify_commit(receipt, c), "commit verification failed"
  print("ecdsa tests passed")

def test_ecssa(param, verify_sig=True, recover=True, verify_commit=True):
  print("*** testing ecssa2")
  m, prv, c = param
  sig = ecssa_sign(m, prv)
  pub = ec.pointMultiply(prv)
  if verify_sig:
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
         verify_sig=True, recover=True, verify_commit=True):
  m = str_to_hash("hello world")
  prv = 1
  c = str_to_hash("sign to contract")
  param = m, prv, c
  if ecdsa:
    test_ecdsa(param, verify_sig, recover, verify_commit)
  if ecssa:
    test_ecssa(param, verify_sig, recover, verify_commit)

if __name__ == "__main__":
  # execute only if run as a script
  main()
