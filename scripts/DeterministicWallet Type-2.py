# -*- coding: utf-8 -*-
"""
Created on Thu Oct 12 11:18:33 2017

@author: dfornaro
"""

#### Deterministic Wallet (Type-2) ####

from secp256k1 import order, G, modInv, pointAdd, pointMultiply
from hashlib import sha256
import random


# secret random number
m = random.randint(0, order-1)
print('secret m:', hex(m),'\n')

# public random number
r = random.randint(0, order-1)
print('public r:', hex(r))

# Master PublicKey:
M = pointMultiply(m, G)
print('MasterPublicKey:\n', hex(M[0]), '\n', hex(M[1]), '\n')

n_address = 3
privKey = [0] * n_address
PubKey = [(0,0)] * n_address

# PubKeys can be calculated without using privKeys
for i in range(0, n_address):
  # H(i|r)
  H_i_r = int(sha256((hex(i)+hex(r)).encode()).hexdigest(), 16) %order
  PubKey[i] = pointAdd(M , pointMultiply(H_i_r, G))                 

# check that PubKeys match with privKeys
for i in range(0, n_address):
  # H(i|r)
  H_i_r = int(sha256((hex(i)+hex(r)).encode()).hexdigest(), 16) %order
  privKey[i] = (m + H_i_r) %order
  assert PubKey[i] == pointMultiply(privKey[i], G)
  print('privateKey#', i, ':\n', hex(privKey[i]), sep='')
  print('    PubKey#', i, ':\n', hex(PubKey[i][0]), '\n', hex(PubKey[i][1]), '\n', sep='')
