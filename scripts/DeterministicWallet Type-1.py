# -*- coding: utf-8 -*-
"""
Created on Thu Oct 12 09:27:42 2017

@author: dfornaro, fametrano
"""
#### Deterministic Wallet (Type-1) ####

from secp256k1 import order, G, modInv, pointAdd, pointMultiply
from hashlib import sha256
import random


# secret random number
r = random.randint(0, order-1)
print('\nr =', hex(r), '\n')

# number of key pairs to generate
nKeys = 3
p = [0] * nKeys
P = [(0,0)] * nKeys

for i in range(0, nKeys):
  # H(i|r)
  H_i_r = int(sha256((hex(i)+hex(r)).encode()).hexdigest(), 16) %order
  p[i] = H_i_r
  P[i] = pointMultiply(p[i], G)
  print('prKey#', i, ':\n', hex(p[i]), sep='')
  print('PubKey#', i, ':\n', hex(P[i][0]), '\n', hex(P[i][1]), '\n', sep='')
