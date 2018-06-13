#!/usr/bin/env python3

"""sign-to-contract

IDEA:
  Let c be a value (bytes) and P an EC point, then
    c, P -> h(P||c)G + P
  is a commitment operation. (G generator, || concatenation)
  The signature contains an EC point, thus it can become a
  commitment to c.
HOW:
  when signing, generate a nonce (k) and compute a EC point (R = kG)
  instead of proceeding using (k,R), compute a value (e) that is a
  commitment to c:
    e = hash(R.x||c)
  substitute the nonce k with k+e and R with R+eG, and proceed signing
  in the standard way, using (k+e,R+eG).
COMMITMENT VERIFICATION:
  the verifier can see W.x (W = R+eG) on the signature
  the signer (and committer) provides R and c
  the verifier checks that:   W.x = (R+eG).x
                              (with e = hash(R.x||c))
"""

from ECsecp256k1 import pointAdd, pointMultiply, \
                        order as ec_order, prime as ec_prime, G as ec_G
from rfc6979 import rfc6979
from ecutils import default_hasher, str_to_hash, check_hash_digest, decode_prv, hash_to_int, int_to_bytes, check_ec_point
from ecdsa import ecdsa_sign, ecdsa_verify, check_dsasig, ecdsa_recover, ecdsa_sign_raw
from ecssa import ecssa_sign, ecssa_verify, check_ssasig, ecssa_recover, ecssa_sign_raw


def check_receipt(receipt):
  """check receipt format
  """
  assert type(receipt[0]) == int and \
         0 < receipt[0] and receipt[0] < ec_prime, \
         "1st part of the receipt must be an int in (0, ec_prime)"
  check_ec_point(receipt[1])

def tweak(k, c, hasher=default_hasher):
  """tweak kG

  returns:
  - point kG to tweak
  - tweaked private key k + h(kG||c), the corresponding pubkey is a commitment to kG, c
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
  R, eph_prv = tweak(eph_prv, c, hasher)
  sig = ecdsa_sign_raw(h, prv, eph_prv)
  receipt = (sig[0], R)
  return sig, receipt

def ecssa_sign_and_commit(m, prv, c, eph_prv=None, hasher=default_hasher):
  check_hash_digest(m)
  prv = decode_prv(prv)
  eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else decode_prv(eph_prv)
  check_hash_digest(c)
  R, eph_prv = tweak(eph_prv, c, hasher)
  sig = ecssa_sign_raw(m, prv, eph_prv, hasher)
  receipt = (sig[0], R)
  return sig, receipt

def verify_ec_commit(receipt, c, hasher=default_hasher):
  check_receipt(receipt)
  check_hash_digest(c)
  w, R = receipt
  e = hash_to_int(hasher(int_to_bytes(R[0], 32) + c).digest())
  W = pointAdd(R, pointMultiply(e, ec_G))
  return w % ec_order == W[0] % ec_order
  # weaker verfication! dsa: w in [1..ec_order-1]
  #                     ssa: w in [1..ec_prime-1]
  # design choice: manage them with the same function


if __name__ == "__main__":
  prv = 0x1
  pub = pointMultiply(prv, ec_G)
  m = str_to_hash("hello world")
  c = str_to_hash("sign to contract")

  sig_ecdsa, receipt_ecdsa = ecdsa_sign_and_commit(m, prv, c)
  assert ecdsa_verify(m, sig_ecdsa, pub)
  assert pub in (ecdsa_recover(m, sig_ecdsa, 0), ecdsa_recover(m, sig_ecdsa, 1))
  assert verify_ec_commit(receipt_ecdsa, c)

  sig_ecssa, receipt_ecssa = ecssa_sign_and_commit(m, prv, c)
  assert ecssa_verify(m, sig_ecssa, pub)
  assert pub in (ecssa_recover(m, sig_ecssa), ecssa_recover(m, sig_ecssa))
  assert verify_ec_commit(receipt_ecssa, c)
