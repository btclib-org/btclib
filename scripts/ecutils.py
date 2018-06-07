# -*- coding: utf-8 -*-
"""
Created on Sat Oct 28 01:03:03 2017

@author: Leonardo, fametrano
"""

# import - check - decode - from/to ec_point - from/to int
# ecdsa - ecssa - sign-to-contract - test


# %% import

from hashlib import sha256
from ECsecp256k1 import ec
from string import hexdigits

def decode_msg(msg):
  """from msg in various formats to bytes
  """
  assert type(msg) in (str, bytes), "msg must be string or bytes"
  if type(msg) == str: msg = msg.encode()
  return msg

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
