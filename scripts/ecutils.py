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
from string import hexdigits

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


# %% from/to int

def int_from_hash(hash_digest, size=32):
  """from hash digest to int
  """
  assert type(hash_digest) == bytes and len(hash_digest) == size, "hash_digest must be bytes with correct bytes length"
  h_len = len(hash_digest) * 8
  L_n = ec.order.bit_length() # use the L_n leftmost bits of the hash
  n = (h_len - L_n) if h_len >= L_n else 0
  return int.from_bytes(hash_digest, "big") >> n

def str_to_hash(msg, hasher=sha256):
  """from a message in string to its hash digest
  """
  assert type(msg) == str, "message must be a string"
  return hasher(msg.encode()).digest()
