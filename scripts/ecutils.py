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

def check_hash_digest(m, hash_digest_size=default_hash_digest_size):
  """check that m is a bytes message with correct length
  """
  assert type(m) == bytes and len(m) == hash_digest_size, "m must be bytes with correct bytes length"

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
  assert 0 < prv and prv < ec.order, "private key must be between 1 and "+ str(ec.order - 1)
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
  return ec.tuple_from_point(pub)

def decode_msg(msg):
  """from msg in various formats to bytes
  """
  assert type(msg) in (str, bytes), "msg must be string or bytes"
  if type(msg) == str: msg = msg.encode()
  return msg


# %% from/to ec_point

def str_to_ec_point(ec_str):
  """ec point in str to ec point
  """
  check_ec_str(ec_str)
  if ec_str[:2] == "04":
    return (int(ec_str[2:66], 16), int(ec_str[66:], 16))
  else:
    x = int(ec_str[2:], 16)
    y = ec.y(x, 0 if ec_str[:2] == "02" else 1)
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
    return (x, ec.y(x, 0 if b[0] == 2 else 1))


# %% from/to int

def hash_to_int(h):
  """from hash digest to int
  """
  h_len = len(h) * 8
  L_n = ec.order.bit_length() # use the L_n leftmost bits of the hash
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
