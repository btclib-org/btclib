#!/usr/bin/env python3

"""
Deterministic Wallet (Type-2)
"""

from hashlib import sha256
from random import randint
from ellipticcurves import secp256k1 as ec
from wifaddress import int_from_prvkey

# master prvkey
mprvkey = randint(0, ec.n-1)
print('\nmaster private key:', format(mprvkey, '#064x'))

# Master Pubkey:
mpubkey = pointMultiply(ec, mprvkey, ec.G)
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
  p.append((mprvkey + h_int[i]) % ec.n)
  P = pointMultiply(ec, p[i])
  print('prvkey#', i, ':', format(p[i], '#064x'))
  print('Pubkey#', i, ':', format(P[0], '#064x'))
  print('           ',     format(P[1], '#064x'))

# Pubkeys could be calculated without using prvkeys
for i in range(0, nKeys):
  P = ec.pointAdd(mpubkey, pointMultiply(ec, h_int[i], ec.G))
  assert P == pointMultiply(ec, p[i], ec.G)

def det_wallet2(key, r, i):
  r_bytes = r.to_bytes(32, 'big')
  i_bytes = i.to_bytes(32, 'big')
  h_hex = sha256(i_bytes+r_bytes).hexdigest()
  h_int = int(h_hex, 16)

  try:
    prvkey = int_from_prvkey(key)
    return (prvkey + h_int) % ec.n
  except:
    pubkey = ec.to_Point(key)
    return ec.pointAdd(pubkey, pointMultiply(ec, h_int, ec.G))
  raise ValueError("Invalid key")

print()
print('prvkey#', 2, ':', format(det_wallet2(mprvkey, r, 2), '#064x'))
P = det_wallet2(mpubkey, r, 2)
print('Pubkey#', i, ':', format(P[0], '#064x'))
print('           ',     format(P[1], '#064x'))
