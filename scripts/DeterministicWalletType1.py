#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Deterministic Wallet (Type-1)
"""

import random
from hashlib import sha256 as hf

from btclib.ec import pointMult
from btclib.ecurves import secp256k1 as ec
from btclib.ecutils import bits2int

# master prvkey
mprvkey = random.getrandbits(ec.nlen) % ec.n
print('\nmaster private key =', hex(mprvkey))

mprvkey_bytes = mprvkey.to_bytes(ec.nlen, 'big')
nKeys = 3
for i in range(nKeys):
  ibytes = i.to_bytes(ec.nlen, 'big')
  hd = hf(ibytes + mprvkey_bytes).digest()
  q = bits2int(ec, hd)
  Q = pointMult(ec, q, ec.G)
  print('\nprvkey#', i, ':', hex(q))
  print('Pubkey#',   i, ':', hex(Q[0]))
  print('           ',       hex(Q[1]))
