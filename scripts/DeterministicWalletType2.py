#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Deterministic Wallet (Type-2)
"""

import random
from hashlib import sha256 as hf

from btclib.ec import pointMult
from btclib.ecurves import secp256k1 as ec
from btclib.ecutils import bits2int

# master prvkey
mprvkey = random.getrandbits(ec.nlen) % ec.n
print('\nmaster private key:', hex(mprvkey))

# Master Pubkey:
mpubkey = pointMult(ec, mprvkey, ec.G)
print('Master Public Key:', hex(mpubkey[0]))
print('                  ', hex(mpubkey[1]))

# public random number
r = random.getrandbits(ec.nlen)
print('\npublic ephemeral key:', format(r, '#064x'))

q = []
hint = []
rbytes = r.to_bytes(ec.nsize, 'big')
nKeys = 3
for i in range(nKeys):
  ibytes = i.to_bytes(ec.nsize, 'big')
  hd = hf(ibytes + rbytes).digest()
  hint.append(bits2int(ec, hd))
  q.append((mprvkey + hint[i]) % ec.n)
  Q = pointMult(ec, q[i], ec.G)
  print('\nprvkey#', i, ':', hex(q[i]))
  print('Pubkey#',   i, ':', hex(Q[0]))
  print('           ',       hex(Q[1]))

# Pubkeys could be calculated without using prvkeys
for i in range(nKeys):
  Q = ec.add(mpubkey, pointMult(ec, hint[i], ec.G))
  assert Q == pointMult(ec, q[i], ec.G)
