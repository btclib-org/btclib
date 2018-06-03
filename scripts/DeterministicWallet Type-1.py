# -*- coding: utf-8 -*-
"""
Deterministic Wallet (Type-1)

Created on Thu Oct 12 09:27:42 2017

@author: dfornaro, fametrano
"""

from ECsecp256k1 import ec
from hashlib import sha256

# secret random number
r = 0x826402c114dd11f50447cc87c77c8deffedb1f8706dc08195da4363a67b57
print('\nsecret r:', format(r, '#066x'))

# number of key pairs to generate
nKeys = 3
p = [0] * nKeys
P = [(0,0)] * nKeys

for i in range(0, nKeys):
  # p = h(i|r)
  p[i] = sha256((hex(i)+hex(r)).encode()).digest()
  P[i] = ec.pointMultiply(p[i])
  print('\nprvkey#', i, ': 0x', p[i].hex(), sep='')
  print(  'PubKey#', i, ': ', format(P[i][0], '#064x'), sep='')
  print(  '          ', format(P[i][1], '#064x'), sep='')
