#!/usr/bin/env python3

"""
Deterministic Wallet (Type-1)
"""

from hashlib import sha256
from random import randint
from ellipticcurves import secp256k1 as ec
from wifaddress import bytes_from_prvkey

# master prvkey
mprvkey = randint(0, ec.n-1)
print('\nmaster private key =', hex(mprvkey))

nKeys = 3
mprvkey_bytes = mprvkey.to_bytes(32, 'big')
for i in range(0, nKeys):
  i_bytes = i.to_bytes(32, 'big')
  h_hex = sha256(i_bytes+mprvkey_bytes).hexdigest()
  p = int(h_hex, 16) % ec.n
  P = pointMultiply(ec, p, ec.G)
  print('prvkey#', i, ':', format(p, '#064x'))
  print('Pubkey#', i, ':', format(P[0], '#064x'))
  print('           ',     format(P[1], '#064x'))

def det_wallet1(mprvkey, i):
  mprvkey = bytes_from_prvkey(mprvkey)
  i_bytes = i.to_bytes(32, 'big')
  h_hex = sha256(i_bytes+mprvkey_bytes).hexdigest()
  return int(h_hex, 16) % ec.n

print('\nprvkey#', 2, ':', format(det_wallet1(mprvkey, 2), '#064x'))