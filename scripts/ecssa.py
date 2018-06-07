# -*- coding: utf-8 -*-
"""
Created on Sat Oct 28 01:03:03 2017

@author: Leonardo, fametrano
"""

# %% import

from hashlib import sha256
from ECsecp256k1 import ec
from FiniteFields import mod_inv
from rfc6979 import rfc6979
from ecutils import decode_prv, int_from_hash

# %% ecssa sign
# https://github.com/sipa/secp256k1/blob/968e2f415a5e764d159ee03e95815ea11460854e/src/modules/schnorr/schnorr.md

# different structure, cannot compute e (int) before ecssa_sign_raw

def ecssa_sign(m, prv, eph_prv=None, hasher=sha256):
  prv = decode_prv(prv)
  eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else decode_prv(eph_prv)
  return ecssa_sign_raw(m, prv, eph_prv, hasher)

def ecssa_sign_raw(m, prv, eph_prv, hasher=sha256):
  R = ec.pointMultiply(eph_prv)
  if R[1] % 2 == 1:
      eph_prv = ec.order - eph_prv  # <=> R_y = ec_prime - R_y
  R_x = R[0].to_bytes(32, 'big')
  e = int_from_hash(hasher(R_x + m).digest())
  assert e != 0 and e < ec.order, "sign fail"
  s = (eph_prv - e * prv) % ec.order
  return R[0], s

def ecssa_verify(m, ssasig, pub, hasher=sha256):
  check_ssasig(ssasig)
  pub =  ec.tuple_from_point(pub)
  return ecssa_verify_raw(m, ssasig, pub, hasher)

def ecssa_verify_raw(m, ssasig, pub, hasher):
  R_x, s = ssasig[0].to_bytes(32, 'big'), ssasig[1]
  e = int_from_hash(hasher(R_x + m).digest())
  if e == 0 or e >= ec.order:  # invalid e value
    return False
  # by choice at this level do not manage point at infinity (h = 0, R = 0G)
  R = ec.pointAdd(ec.pointMultiply(e, pub), ec.pointMultiply(s))
  if R[1] % 2 == 1:  # R.y odd
    return False
  return R[0] == ssasig[0]

def ecssa_recover(m, ssasig, hasher=sha256):
  check_ssasig(ssasig)
  return ecssa_recover_raw(m, ssasig, hasher)


def ecssa_recover_raw(m, ssasig, hasher=sha256):
  R_x, s = ssasig
  R = (R_x, ec.y(R_x, 0))
  R_x = R_x.to_bytes(32, 'big')
  e = int_from_hash(hasher(R_x + m).digest())
  assert e != 0 and e < ec.order, "invalid e value"
  e1 = mod_inv(e, ec.order)
  # by choice at this level do not manage point at infinity (h = 0, R = 0G)
  return ec.pointAdd(ec.pointMultiply(e1, R), ec.pointMultiply(-e1 * s % ec.order))

def check_ssasig(ssasig):
  """check sig has correct ssa format
  """
  assert type(ssasig) == tuple and len(ssasig) == 2 and \
         type(ssasig[0]) == int and type(ssasig[1]) == int, \
         "ssasig must be a tuple of 2 int"
  # R.x is valid iif R.y does exist
  ec.y(ssasig[0])
  assert 0 < ssasig[1] and ssasig[1] < ec.order, "s must be in [1..order]"
