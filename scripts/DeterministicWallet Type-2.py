#!/usr/bin/env python3

from ECsecp256k1 import ec
from hashlib import sha256
from random import randint

# master keys
print('\nmaster keys')
# private key
mp = 0xcb1ee7a0baf6520d09c67a06dcf1f8cf0c2123475a1c1fcf6ff5989de84ca
print('prvkey:', format(mp, '#066x'))
MP = ec.pointMultiply(mp)
print('PubKey:', format(MP[0], '#066x'))
print('       ', format(MP[1], '#066x'))


# public random number
r = randint(0, 2**256-1)
print('\nephkey:', format(r, '#066x'))

# number of key pairs to generate
nKeys = 3
p = [0] * nKeys
P = [(0,0)] * nKeys

# PubKeys can be calculated without using prvkeys
for i in range(0, nKeys):
    # h(i|r)
    h_i_r = sha256((hex(i)+hex(r)).encode()).digest()
    P[i] = ec.pointAdd(MP, ec.pointMultiply(h_i_r))                 

# check that PubKeys match with prvkeys
for i in range(0, nKeys):
    # h(i|r)
    h_i_r = sha256((hex(i)+hex(r)).encode()).digest()
    p[i] = (mp + int.from_bytes(h_i_r, 'big'))
    assert P[i] == ec.pointMultiply(p[i])
    print('\nprvkey#', i, ': ', format(p[i], '#064x'), sep='')
    print(  'PubKey#', i, ': ', format(P[i][0], '#064x'), sep='')
    print(  '          ', format(P[i][1], '#064x'), sep='')
