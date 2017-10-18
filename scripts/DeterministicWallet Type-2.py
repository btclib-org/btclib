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
mp = random.randint(0, order-1)
print('secret master private key:', hex(mp),'\n')

# public random number
r = random.randint(0, order-1)
print('public ephemeral key:', hex(r))

# Master PublicKey:
MP = pointMultiply(mp, G)
print('Master PublicKey:\n', hex(MP[0]), '\n', hex(MP[1]), '\n')

n_address = 3
p = [0] * n_address
P = [(0,0)] * n_address

# PubKeys can be calculated without using privKeys
for i in range(0, n_address):
  # H(i|r)
  H_i_r = int(sha256((hex(i)+hex(r)).encode()).hexdigest(), 16) %order
  P[i] = pointAdd(MP, pointMultiply(H_i_r, G))                 

# check that PubKeys match with privKeys
for i in range(0, n_address):
  # H(i|r)
  H_i_r = int(sha256((hex(i)+hex(r)).encode()).hexdigest(), 16) %order
  p[i] = (mp + H_i_r) %order
  assert P[i] == pointMultiply(p[i], G)
  print('prKey#', i, ':\n', hex(p[i]), sep='')
  print('PubKey#', i, ':\n', hex(P[i][0]), '\n', hex(P[i][1]), '\n', sep='')
