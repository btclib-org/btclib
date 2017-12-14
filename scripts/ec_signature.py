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
from secp256k1 import pointAdd, pointMultiply, \
                      order as ec_order, prime as ec_prime, G as ec_G, \
                      a as ec_a, b as ec_b
from FiniteFields import modInv, modular_sqrt
from string import hexdigits
from rfc6979 import deterministic_k


# %% default setting
default_hasher = sha256
default_hash_digest_size = 32


# %% check

def check_ec_str(ec_str):
  """check ec point in str has a correct format
  """
  assert len(ec_str) >= 4, "pubkey string must be at least 4 characters"
  assert ec_str[:2] in ("02","03","04"), \
         "an EC point in string must start with 02, 03 or 04"
  assert all(c in hexdigits for c in ec_str), \
         "an EC point in string must have only hex digits"
  assert (len(ec_str) % 2 == 0 and len(ec_str) <= 66) \
         or len(ec_str) == 130, \
         "an EC point in string must have 2, 4, 6, ..., 66, or 130 hex digits"

def check_ec_point(ec_point):
  """check ec point has correct format and is on the curve
  """
  assert type(ec_point) == tuple and \
         len(ec_point) == 2 and \
         type(ec_point[0]) == int and type(ec_point[1]) == int, \
         "ec_point must be a tuple of 2 int"
  assert 0 <= ec_point[0] and ec_point[0] < ec_prime and \
         0 <= ec_point[1] and ec_point[1] < ec_prime, \
         "ec_point must have integer coordinates in [0, ec_prime)"
  assert (ec_point[1]**2 % ec_prime) == \
         (ec_point[0]**3 + ec_a * ec_point[0] + ec_b) % ec_prime, \
         "ec_point must satisfy the curve equation"

def check_hash_digest(m, hash_digest_size=default_hash_digest_size):
  """check that m is a bytes message with correct length
  """
  assert type(m) == bytes and len(m) == hash_digest_size, "m must be bytes with correct bytes length"

def check_dsasig(dsasig):
  """check sig has correct dsa format
  """
  assert type(dsasig) == tuple and \
         len(dsasig) == 2 and \
         type(dsasig[0]) == int and type(dsasig[1]) == int, \
         "dsasig must be a tuple of 2 int"
  assert 0 < dsasig[0] and dsasig[0] < ec_order and \
         0 < dsasig[1] and dsasig[1] < ec_order, \
         "r and s must be in [1..order]"

def check_ssasig(ssasig):
  """check sig has correct ssa format
  """
  assert type(ssasig) == tuple and len(ssasig) == 2 and \
         type(ssasig[0]) == int and type(ssasig[1]) == int, \
         "ssasig must be a tuple of 2 int"
  assert 0 < ssasig[0] and ssasig[0] < ec_prime, "R.x must be in [1..prime]"
  assert 0 < ssasig[1] and ssasig[1] < ec_order, "s must be in [1..order]"


# %% decode

def decode_prv(prv):
  """from prv in various formats to int
  """
  assert type(prv) in (str, bytes, int), "private key should be a hex string, bytes or int"
  if type(prv) == str:
    if prv[:2] == "0x": prv = prv[2:]
    if all(c in hexdigits for c in prv) and len(prv) == 64: prv = int(prv, 16) # hex
    elif all(c in b58digits for c in prv): prv = b58decode_check(prv)[2:] # Wif
    # may it happen that a str may represent both a wif and a hex?
    # should check in a better way, e.g. wif starts with a digit
    else: assert 0, "if private key is a string, it must be hex or Wif"
  if type(prv) == bytes: prv = int.from_bytes(prv, "big")
  assert 0 < prv and prv < ec_order, "private key must be between 1 and "+ str(ec_order - 1)
  return prv

def decode_eph_prv(eph_prv, prv=None, msg=None, hasher=None):
  """from eph_prv in various formats to int, use rfc6979 if eph_prv is missing
  """
  if eph_prv != None:
    return decode_prv(eph_prv)
  else:
    # add checks for prv, msg, hasher?
    return deterministic_k(prv, msg, hasher)

def decode_pub(pub):
  """from pub in various formats to ec point
  """
  assert type(pub) in (str, bytes, tuple), "invalid format for ec_point"
  if type(pub) == str: pub = str_to_ec_point(pub)
  if type(pub) == bytes: pub = bytes_to_ec_point(pub)
  check_ec_point(pub)
  return pub

def decode_msg(msg):
  """from msg in various formats to bytes
  """
  assert type(msg) in (str, bytes), "msg must be string or bytes"
  if type(msg) == str: msg = msg.encode()
  return msg


# %% from/to ec_point

def ec_x_to_y(x, y_mod_2):
  """from (x, parity_of_y) to (x, y) ec point
  """
  assert type(x) == int, "x must be an int"
  assert 0 < x and x < ec_prime, "ec_point must have integer coordinates in [0, ec_prime)"
  y = modular_sqrt((x**3 + ec_a * x + ec_b) % ec_prime, ec_prime)
  check_ec_point((x, y)) # <=> y!=0
  change_parity = ((y % 2) + y_mod_2) == 1
  return (ec_prime - y) if change_parity else y

def str_to_ec_point(ec_str):
  """ec point in str to ec point
  """
  check_ec_str(ec_str)
  if ec_str[:2] == "04":
    return (int(ec_str[2:66], 16), int(ec_str[66:], 16))
  else:
    x = int(ec_str[2:], 16)
    y = ec_x_to_y(x, 0 if ec_str[:2] == "02" else 1)
    return x, y

def bytes_to_ec_point(b):
  """ec point in bytes to ec point
  """
  assert type(b) == bytes and len(b) > 0
  assert b[0] in (2, 3, 4), "pubkey must start with 02, 03 or 04"
  if b[0] == 4:
    assert len(b) == 65, "ext pubkey has 65 bytes"
    # otherwise it is impossible to understand when the second coord starts
    return (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))
  else:
    x = int.from_bytes(b[1:], "big")
    return (x, ec_x_to_y(x, 0 if b[0] == 2 else 1))

def ec_point_to_bytes(ec_point, compressed=True):
  """ec point to bytes
  """
  check_ec_point(ec_point)
  if compressed:
    return (b'\x02' if ec_point[1] % 2 == 0 else b'\x03') + \
           int_to_bytes(ec_point[0])
  else:
    return b'\x04' + int_to_bytes(ec_point[0], 32) + int_to_bytes(ec_point[0], 32)


# %% from/to int

def hash_to_int(h):
  """from hash digest to int
  """
  h_len = len(h) * 8
  L_n = ec_order.bit_length() # use the L_n leftmost bits of the hash
  n = (h_len - L_n) if h_len >= L_n else 0
  return int.from_bytes(h, "big") >> n

def int_to_bytes(n, byte_len=None):
  """int to bytes, if byte_len is missing minimum length
  """
  if byte_len == None: byte_len = (n.bit_length() + 7) // 8
  return n.to_bytes(byte_len, "big")

def str_to_hash(msg, hasher=default_hasher):
  """from a message in string to its hash digest
  """
  assert type(msg) == str, "message must be a string"
  return hasher(msg.encode()).digest()


# %% ecdsa sign
# Design choice: what is signed is `m`, a 32 bytes message.

def ecdsa_sign(m, prv, eph_prv=None, hasher=default_hasher):
  check_hash_digest(m)
  prv = decode_prv(prv)
  eph_prv = deterministic_k(prv, m, hasher) if eph_prv is None else decode_prv(eph_prv)
  h = hash_to_int(m)
  r, s = ecdsa_sign_raw(h, prv, eph_prv)
  assert r != 0 and s != 0, "failed to sign"  # this should be checked inside deterministic_k
  return r, s

def ecdsa_sign_raw(h, prv, eph_prv):
  R = pointMultiply(eph_prv, ec_G)
  r = R[0] % ec_order
  s = modInv(eph_prv, ec_order) * (h + prv * r) % ec_order
  return r, s

def ecdsa_verify(m, dsasig, pub):
  check_hash_digest(m)
  check_dsasig(dsasig)
  pub = decode_pub(pub)
  h = hash_to_int(m)
  return ecdsa_verify_raw(h, dsasig, pub)

def ecdsa_verify_raw(h, dsasig, pub):
  r, s = dsasig
  s1 = modInv(s, ec_order)
  # by choice at this level do not manage point at infinity (h = 0, R = 0G)
  R = pointAdd(pointMultiply(r * s1 % ec_order, pub),
               pointMultiply(h * s1 % ec_order, ec_G))
  return R[0] % ec_order == r

def ecdsa_recover(m, dsasig, y_mod_2):
  check_hash_digest(m)
  check_ssasig(dsasig)
  assert y_mod_2 in (0, 1)
  h = hash_to_int(m)
  return ecdsa_recover_raw(h, dsasig, y_mod_2)

def ecdsa_recover_raw(h, dsasig, y_mod_2):
  r, s = dsasig
  r1 = modInv(r, ec_order)
  R = (r, ec_x_to_y(r, y_mod_2))
  # by choice at this level do not manage point at infinity (h = 0, R = 0G)
  return pointAdd(pointMultiply(dsasig[1] * r1 % ec_order, R),
                  pointMultiply(-h * r1 % ec_order, ec_G))


# %% ecssa sign
# source:
# https://github.com/sipa/secp256k1/blob/968e2f415a5e764d159ee03e95815ea11460854e/src/modules/schnorr/schnorr.md

# different structure, cannot compute e (int) before ecssa_sign_raw

def ecssa_sign(m, prv, eph_prv=None, hasher=default_hasher):
  check_hash_digest(m)
  prv = decode_prv(prv)
  eph_prv = deterministic_k(prv, m, hasher) if eph_prv is None else decode_prv(eph_prv)
  return ecssa_sign_raw(m, prv, eph_prv, hasher)

def ecssa_sign_raw(m, prv, eph_prv, hasher=default_hasher):
  R = pointMultiply(eph_prv, ec_G)
  if R[1] % 2 == 1:
      eph_prv = ec_order - eph_prv  # <=> R_y = ec_prime - R_y
  R_x = int_to_bytes(R[0], 32)
  e = hash_to_int(hasher(R_x + m).digest())
  assert e != 0 and e < ec_order, "sign fail"
  s = (eph_prv - e * prv) % ec_order
  return R[0], s

def ecssa_verify(m, ssasig, pub, hasher=default_hasher):
  check_hash_digest(m)
  check_ssasig(ssasig)
  pub = decode_pub(pub)
  return ecssa_verify_raw(m, ssasig, pub, hasher)

def ecssa_verify_raw(m, ssasig, pub, hasher):
  R_x, s = int_to_bytes(ssasig[0], 32), ssasig[1]
  e = hash_to_int(hasher(R_x + m).digest())
  if e == 0 or e >= ec_order:  # invalid e value
    return False
  # by choice at this level do not manage point at infinity (h = 0, R = 0G)
  R = pointAdd(pointMultiply(e, pub), pointMultiply(s, ec_G))
  if R[1] % 2 == 1:  # R.y odd
    return False
  return R[0] == ssasig[0]

def ecssa_recover(m, ssasig, hasher=default_hasher):
  check_hash_digest(m)
  check_ssasig(ssasig)
  return ecssa_recover_raw(m, ssasig, hasher)

def ecssa_recover_raw(m, ssasig, hasher=default_hasher):
  R_x, s = ssasig
  R = (R_x, ec_x_to_y(R_x, 0))
  R_x = int_to_bytes(R_x, 32)
  e = hash_to_int(hasher(R_x + m).digest())
  assert e != 0 and e < ec_order, "invalid e value"
  e1 = modInv(e, ec_order)
  # by choice at this level do not manage point at infinity (h = 0, R = 0G)
  return pointAdd(pointMultiply(e1, R), pointMultiply(-e1 * s % ec_order, ec_G))


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
  eph_prv = deterministic_k(prv, m, hasher) if eph_prv is None else decode_prv(eph_prv)
  h = hash_to_int(m)
  check_hash_digest(c)
  R, eph_prv = insert_commit(eph_prv, c, hasher)
  sig = ecdsa_sign_raw(h, prv, eph_prv)
  receipt = (sig[0], R)
  return sig, receipt

def ecssa_sign_and_commit(m, prv, c, eph_prv=None, hasher=default_hasher):
  check_hash_digest(m)
  prv = decode_prv(prv)
  eph_prv = deterministic_k(prv, m, hasher) if eph_prv is None else decode_prv(eph_prv)
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

def test_all(ecdsa=True, ecssa=True, \
             verify=True, recover=True, verify_commit=True):
  m = str_to_hash("hello world")
  prv = 1
  c = str_to_hash("sign to contract")
  param = m, prv, c
  if ecdsa:
    test_ecdsa(param, verify, recover, verify_commit)
  if ecssa:
    test_ecssa(param, verify, recover, verify_commit)

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
