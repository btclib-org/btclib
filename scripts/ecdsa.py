#!/usr/bin/env python3

""" Elliptic Curve Digital Signature Algorithm
"""

from hashlib import sha256
from ECsecp256k1 import ec
from FiniteFields import mod_inv
from rfc6979 import rfc6979
from ecutils import int_from_hash
from WIF_address import int_from_prvkey

# %% ecdsa sign
# Design choice: what is signed is `m`, a 32 bytes message.



def ecdsa_sign(m, prv, eph_prv=None, hasher=sha256):
  prv = int_from_prvkey(prv)
  eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else int_from_prvkey(eph_prv)
  return ecdsa_sign_raw(m, prv, eph_prv)

def ecdsa_sign_raw(m, prv, eph_prv):
  h = int_from_hash(m)
  R = ec.pointMultiply(eph_prv)
  r = R[0] % ec.order
  s = mod_inv(eph_prv, ec.order) * (h + prv * r) % ec.order
  assert r != 0 and s != 0, "failed to sign"
  return r, s



def ecdsa_verify(m, dsasig, pub):
  check_dsasig(dsasig)
  pub =  ec.tuple_from_point(pub)
  return ecdsa_verify_raw(m, dsasig, pub)

def ecdsa_verify_raw(m, dsasig, pub):
  h = int_from_hash(m)
  r, s = dsasig
  s1 = mod_inv(s, ec.order)
  # by choice at this level do not manage point at infinity (h = 0, R = 0G)
  R = ec.pointAdd(ec.pointMultiply(r * s1 % ec.order, pub),
                  ec.pointMultiply(h * s1 % ec.order))
  return R[0] % ec.order == r



def ecdsa_recover(m, dsasig, y_mod_2):
  check_dsasig(dsasig)
  assert y_mod_2 in (0, 1)
  return ecdsa_recover_raw(m, dsasig, y_mod_2)

def ecdsa_recover_raw(m, dsasig, y_mod_2):
  h = int_from_hash(m)
  r, s = dsasig # FIXME: why is s not used?
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
         0 < dsasig[1] and dsasig[1] < ec.order, "r and s must be in [1..order]"


if __name__ == "__main__":
  prv = 0x1
  pub = ec.pointMultiply(prv)
  msg = sha256(b'Satoshi Nakamoto').digest()
  expected_signature = (0x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8,
                        0x2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5)
  r, s = ecdsa_sign(msg, prv)
  assert r == expected_signature[0] and \
         s in (expected_signature[1], ec.order - expected_signature[1])

  assert ecdsa_verify(msg, (r, s), pub)

  assert pub in (ecdsa_recover(msg, (r, s), 0), ecdsa_recover(msg, (r, s), 1))
