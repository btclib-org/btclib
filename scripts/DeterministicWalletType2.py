#!/usr/bin/env python3

"""
Deterministic Wallet (Type-2)
"""

from hashlib import sha256
from random import randint
from ellipticcurves import secp256k1 as ec
from WIF_address import int_from_prvkey

# master prvkey
mprvkey = randint(0, ec.order-1)
print('\nmaster private key:', format(mprvkey, '#064x'))

# Master Pubkey:
mpubkey = ec.pointMultiply(mprvkey)
print('Master Public Key:', format(mpubkey[0], '#064x'))
print('                  ', format(mpubkey[1], '#064x'))

# public random number
r = randint(0, 2**256-1)
print('public ephemeral key:', format(r, '#064x'))

p = []
h_int = []
nKeys = 3
r_bytes = r.to_bytes(32, 'big')
for i in range(0, nKeys):
  i_bytes = i.to_bytes(32, 'big')
  h_hex = sha256(i_bytes+r_bytes).hexdigest()
  h_int.append(int(h_hex, 16))
  p.append((mprvkey + h_int[i]) % ec.order)
  P = ec.pointMultiply(p[i])
  print('prvkey#', i, ':', format(p[i], '#064x'))
  print('Pubkey#', i, ':', format(P[0], '#064x'))
  print('           ',     format(P[1], '#064x'))

# Pubkeys could be calculated without using prvkeys
for i in range(0, nKeys):
  P = ec.pointAdd(mpubkey, ec.pointMultiply(h_int[i]))
  assert P == ec.pointMultiply(p[i])

def det_wallet2(key, r, i):
  r_bytes = r.to_bytes(32, 'big')
  i_bytes = i.to_bytes(32, 'big')
  h_hex = sha256(i_bytes+r_bytes).hexdigest()
  h_int = int(h_hex, 16)

  try:
    prvkey = int_from_prvkey(key)
    return (prvkey + h_int) % ec.order
  except:
    pubkey = ec.tuple_from_point(key)
    return ec.pointAdd(pubkey, ec.pointMultiply(h_int))
  raise ValueError("Invalid key")

print()
print('prvkey#', 2, ':', format(det_wallet2(mprvkey, r, 2), '#064x'))
P = det_wallet2(mpubkey, r, 2)
print('Pubkey#', i, ':', format(P[0], '#064x'))
print('           ',     format(P[1], '#064x'))
