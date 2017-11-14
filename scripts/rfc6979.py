# -*- coding: utf-8 -*-
"""
Created on Thu Nov  9 11:00:55 2017

@author: Leonardo
"""

# deterministic generation of k following rfc6979
# https://tools.ietf.org/html/rfc6979#section-3.2
# code addapted from:
# https://github.com/AntonKueltz/fastecdsa/blob/master/fastecdsa/util.py

from hashlib import sha256
from secp256k1 import order as ec_order
from struct import pack
from binascii import hexlify
from hmac import new as hmac_new

qlen = len(bin(ec_order)) - 2  # -2 for the leading '0b'
rlen = ((qlen + 7) // 8) * 8

def bits2int(b):
  i = int(hexlify(b), 16)
  blen = len(b) * 8
  if blen > qlen:
    i >>= (blen - qlen)
  return i

def int2octets(x):
  octets = b''
  while x > 0:
    octets = pack('=B', (0xff & x)) + octets
    x >>= 8
  padding = b'\x00' * (rlen // 8 - len(octets))
  return padding + octets

def bits2octets(b):
  z1 = bits2int(b)  # -2 for the leading '0b'
  z2 = z1 % ec_order
  return int2octets(z2)

def deterministic_k(prv, msg, hasher = sha256):
  assert type(prv) == int and 0 < prv and prv < ec_order, "invalid prv"
  if type(msg) == str: msg = msg.encode()
  assert type(msg) == bytes
  hashmsg = hasher(msg)
  return deterministic_k_raw(prv, hashmsg, hasher)

def deterministic_k_raw(prv, hashmsg, hasher = sha256):
  hash_size = hashmsg.digest_size
  hashmsg = hashmsg.digest()
  prv_and_msg = int2octets(prv) + bits2octets(hashmsg)
  v = b'\x01' * hash_size
  k = b'\x00' * hash_size
  k = hmac_new(k, v + b'\x00' + prv_and_msg, hasher).digest()
  v = hmac_new(k, v, hasher).digest()
  k = hmac_new(k, v + b'\x01' + prv_and_msg, hasher).digest()
  v = hmac_new(k, v, hasher).digest()
  while True:
    t = b''
    while len(t) * 8 < qlen:
      v = hmac_new(k, v, hasher).digest()
      t = t + v
    nonce = bits2int(t)
    if nonce >= 1 and nonce < ec_order:
      # here it should be checked that nonce do not yields a invalid signature
      # but then I should put the signature generation here
      return nonce
    k = hmac_new(k, v + b'\x00', hasher).digest()
    v = hmac_new(k, v, hasher).digest()