#!/usr/bin/env python3

"""
Deterministic Wallet (Type-1)
"""

from ECsecp256k1 import ec
from hashlib import sha256
from random import randint

# master prvkey
mprvkey = randint(0, ec.order-1)
print('\nmaster private key =', hex(mprvkey))

nKeys = 3
mprvkey_bytes = mprvkey.to_bytes(32, 'big')
for i in range(0, nKeys):
  i_bytes = i.to_bytes(32, 'big')
  h_hex = sha256(i_bytes+mprvkey_bytes).hexdigest()
  p = int(h_hex, 16) % ec.order
  P = ec.pointMultiply(p)
  print('prvkey#', i, ':', format(p, '#064x'))
  print('Pubkey#', i, ':', format(P[0], '#064x'))
  print('           ',     format(P[1], '#064x'))
