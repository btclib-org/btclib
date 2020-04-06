#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from btclib.curvemult import mult
from btclib.curves import secp256k1 as ec
from btclib.dsa import recover_pubkeys, sign, verify

print("\n*** EC:")
print(ec)

print("\n0. Message to be signed")
msg1 = "Paolo is afraid of ephemeral random numbers"
print(msg1)

print("1. Key generation")
q = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
q = q % ec.n
Q = mult(q, ec.G)
print(f"prvkey:    {hex(q).upper()}")
print(f"PubKey: {'02' if Q[1] % 2 == 0 else '03'} {hex(Q[0]).upper()}")


print("2. Sign message")
r1, s1 = sign(msg1, q)
print(f"    r1:    {hex(r1).upper()}")
print(f"    s1:    {hex(s1).upper()}")


print("3. Verify signature")
print(verify(msg1, Q, (r1, s1)))


print("4. Recover keys")
keys = recover_pubkeys(msg1, (r1, s1))
for i, key in enumerate(keys):
    print(f" key#{i}: {'02' if key[1] % 2 == 0 else '03'} {hex(key[0]).upper()}")


print("\n** Malleated signature")
sm = ec.n - s1
print(f"    r1:    {hex(r1).upper()}")
print(f"    sm:    {hex(sm).upper()}")


print("** Verify malleated signature")
print(verify(msg1, Q, (r1, sm)))


print("** Recover keys")
keys = recover_pubkeys(msg1, (r1, sm))
for i, key in enumerate(keys):
    print(f" key#{i}: {'02' if key[1] % 2 == 0 else '03'} {hex(key[0]).upper()}")


print("\n0. Another message to sign")
msg2 = "and Paolo is right to be afraid"
print(msg2)


print("2. Sign message")
r2, s2 = sign(msg2, q)
print(f"    r2:    {hex(r2).upper()}")
print(f"    s2:    {hex(s2).upper()}")


print("3. Verify signature")
print(verify(msg2, Q, (r2, s2)))


print("4. Recover keys")
keys = recover_pubkeys(msg2, (r2, s2))
for i, key in enumerate(keys):
    print(f" key#{i}: {'02' if key[1] % 2 == 0 else '03'} {hex(key[0]).upper()}")
