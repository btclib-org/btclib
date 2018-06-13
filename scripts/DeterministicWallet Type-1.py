#!/usr/bin/python3

"""
Deterministic Wallet (Type-1)
"""

from ECsecp256k1 import order, G, modInv, pointAdd, pointMultiply
from hashlib import sha256
import random

# master prvkey
mprvkey = random.randint(0, order-1)
print('\nmaster private key =', hex(mprvkey))











nKeys = 3
mprvkey_bytes = mprvkey.to_bytes(32, 'big')
for i in range(0, nKeys):
  i_bytes = i.to_bytes(32, 'big')
  h_hex = sha256(i_bytes+mprvkey_bytes).hexdigest()
  p = int(h_hex, 16) %order
  P = pointMultiply(p, G)
  print('prvkey#', i, ':', hex(p))
  print('Pubkey#', i, ':', hex(P[0]))
  print('           ',     hex(P[1]))
