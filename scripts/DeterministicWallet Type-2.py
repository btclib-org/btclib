#!/usr/bin/python3

"""
Deterministic Wallet (Type-2)
"""

from ECsecp256k1 import order, G, modInv, pointAdd, pointMultiply
from hashlib import sha256
import random

# master prvkey
mprvkey = random.randint(0, order-1)
print('\nmaster private key:', hex(mprvkey))

# Master Pubkey:
MP = pointMultiply(mprvkey, G)
print('Master Public Key:', hex(MP[0]))
print('                  ', hex(MP[1]))

# public random number
r = random.randint(0, order-1)
print('public ephemeral key:', hex(r))

p = []
h_int = []
nKeys = 3
r_bytes = r.to_bytes(32, 'big')
for i in range(0, nKeys):
  i_bytes = i.to_bytes(32, 'big')
  h_hex = sha256(i_bytes+r_bytes).hexdigest()
  h_int.append(int(h_hex, 16))
  p.append((mprvkey + h_int[i]) %order)
  P = pointMultiply(p[i], G)
  print('prvkey#', i, ':', hex(p[i]))
  print('Pubkey#', i, ':', hex(P[0]))
  print('           ',     hex(P[1]))

# Pubkeys could be calculated without using prvkeys
for i in range(0, nKeys):
  P = pointAdd(MP, pointMultiply(h_int[i], G))                 
  assert P == pointMultiply(p[i], G)

