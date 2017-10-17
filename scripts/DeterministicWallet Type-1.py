# -*- coding: utf-8 -*-
"""
Created on Thu Oct 12 09:27:42 2017

@author: dfornaro
"""
#### Deterministic Wallet (Type-1) ####

from secp256k1 import order, G, modInv, pointAdd, pointMultiply
from hashlib import sha256
import random


# secret random number
r = random.randint(0, order-1)

print('\nr =', hex(r), '\n')

# number of address to generate
n_address = 3
privKey = [0] * n_address
PubKey = [(0,0)] * n_address

for i in range(0, n_address):
  # H(i|r)
  H_i_r = int(sha256((hex(i)+hex(r)).encode()).hexdigest(), 16) %order
  privKey[i] = H_i_r
  PubKey[i] = pointMultiply(privKey[i], G)
  print('privateKey#', i, ':\n', hex(privKey[i]), sep='')
  print('    PubKey#', i, ':\n', hex(PubKey[i][0]), '\n', hex(PubKey[i][1]), '\n', sep='')
