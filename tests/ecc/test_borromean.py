#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.borromean` module."

import secrets
from collections import defaultdict
from typing import Dict, List

from btclib.alias import Point
from btclib.ecc import borromean, dsa


def test_borromean() -> None:
    nring = 4  # FIXME randomize; minimum number of rings?
    ring_sizes = [1 + secrets.randbelow(7) for _ in range(nring)]
    sign_key_idx = [secrets.randbelow(size) for size in ring_sizes]

    pubk_rings: Dict[int, List[Point]] = defaultdict(list)
    sign_keys: List[int] = []
    for i in range(nring):
        for j in range(ring_sizes[i]):
            priv_key, pub_key = dsa.gen_keys()
            pubk_rings[i].append(pub_key)
            if j == sign_key_idx[i]:
                sign_keys.append(priv_key)

    msg = "Borromean ring signature".encode()
    sig = borromean.sign(msg, list(range(1, 5)), sign_key_idx, sign_keys, pubk_rings)

    borromean.assert_as_valid(msg, sig[0], sig[1], pubk_rings)
    assert borromean.verify(msg, sig[0], sig[1], pubk_rings)
    assert not borromean.verify("another message", sig[0], sig[1], pubk_rings)
    assert not borromean.verify(0, sig[0], sig[1], pubk_rings)  # type: ignore
