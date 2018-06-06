# -*- coding: utf-8 -*-
"""
Created on Sat Oct 28 01:03:03 2017

@author: Leonardo, fametrano
"""

# import - check - decode - from/to ec_point - from/to int
# ecdsa - ecssa - sign-to-contract - test


# %% import

from hashlib import sha256
from base58 import b58decode_check, __alphabet as b58digits
from ECsecp256k1 import ec
from FiniteFields import mod_inv, mod_sqrt
from string import hexdigits
from rfc6979 import rfc6979
from ecutils import default_hasher, check_hash_digest, decode_prv, hash_to_int, decode_pub

# %% ecdsa sign
# Design choice: what is signed is `m`, a 32 bytes message.

def ecdsa_sign(m, prv, eph_prv=None, hasher=default_hasher):
  check_hash_digest(m)
  prv = decode_prv(prv)
  eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else decode_prv(eph_prv)
  h = hash_to_int(m)
  r, s = ecdsa_sign_raw(h, prv, eph_prv)
  assert r != 0 and s != 0, "failed to sign"  # this should be checked inside deterministic_k
  return r, s

def ecdsa_sign_raw(h, prv, eph_prv):
  R = ec.pointMultiply(eph_prv)
  r = R[0] % ec.order
  s = mod_inv(eph_prv, ec.order) * (h + prv * r) % ec.order
  return r, s

def ecdsa_verify(m, dsasig, pub):
  check_hash_digest(m)
  check_dsasig(dsasig)
  pub = decode_pub(pub)
  h = hash_to_int(m)
  return ecdsa_verify_raw(h, dsasig, pub)

def ecdsa_verify_raw(h, dsasig, pub):
  r, s = dsasig
  s1 = mod_inv(s, ec.order)
  # by choice at this level do not manage point at infinity (h = 0, R = 0G)
  R = ec.pointAdd(ec.pointMultiply(r * s1 % ec.order, pub),
                  ec.pointMultiply(h * s1 % ec.order))
  return R[0] % ec.order == r

def ecdsa_recover(m, dsasig, y_mod_2):
  check_hash_digest(m)
  check_dsasig(dsasig)
  assert y_mod_2 in (0, 1)
  h = hash_to_int(m)
  return ecdsa_recover_raw(h, dsasig, y_mod_2)

def ecdsa_recover_raw(h, dsasig, y_mod_2):
  r, s = dsasig
  r1 = mod_inv(r, ec.order)
  R = (r, ec.y(r, y_mod_2))
  # by choice at this level do not manage point at infinity (h = 0, R = 0G)
  return ec.pointAdd(ec.pointMultiply(dsasig[1] * r1 % ec.order, R),
                    ec.pointMultiply(-h * r1 % ec.order))

def check_dsasig(dsasig):
  """check sig has correct dsa format
  """
  assert type(dsasig) == tuple and \
         len(dsasig) == 2 and \
         type(dsasig[0]) == int and type(dsasig[1]) == int, \
         "dsasig must be a tuple of 2 int"
  assert 0 < dsasig[0] and dsasig[0] < ec.order and \
         0 < dsasig[1] and dsasig[1] < ec.order, \
         "r and s must be in [1..order]"
