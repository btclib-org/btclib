# -*- coding: utf-8 -*-
"""
Deterministic Wallet (Type-1)

Created on Thu Oct 12 09:27:42 2017

@author: dfornaro, fametrano
"""

from ECsecp256k1 import ec
from hashlib import sha256
from random import randint

# secret random number
r = randint(0, ec.order-1)
r = 0x8bdcb1ee7a0baf6520d09c67a06dcf1f8cf0c2123475a1c1fcf6ff5989de84ca
print('\nr =', hex(r), '\n')

# number of key pairs to generate
nKeys = 3
p = [0] * nKeys
P = [(0,0)] * nKeys

for i in range(0, nKeys):
  # h(i|r)
  h_i_r = sha256((hex(i)+hex(r)).encode()).digest()
  p[i] = h_i_r % ec.order
  P[i] = ec.pointMultiply(p[i])
  print('prKey#', i, ':\n', p[i].hex(), sep='')
  print('PubKey#', i, ':\n', hex(P[i][0]), '\n', hex(P[i][1]), '\n', sep='')
