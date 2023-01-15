#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for the `btclib.borromean` module."""

from btclib.ecc import borromean, dsa


def test_borromean() -> None:
    nring = 4  # FIXME minimum number of rings?
    # ring_sizes = [1 + random.randrange(7) for _ in range(nring)]
    # sign_key_idx = [random.randrange(size) for size in ring_sizes]
    # derandomize test to ensure code coverage
    ring_sizes = [3, 4, 6, 7]
    sign_key_idx = [2, 1, 0, 5]

    key_rings = [[dsa.gen_keys() for _ in range(ring_sizes[i])] for i in range(nring)]
    sign_keys = [key_rings[i][sign_key_idx[i]][0] for i in range(nring)]
    pubk_rings = [
        [key_rings[i][j][1] for j in range(ring_sizes[i])] for i in range(nring)
    ]

    msg = b"Borromean ring signature"
    sig = borromean.sign(
        msg, list(range(1, nring + 1)), sign_key_idx, sign_keys, pubk_rings
    )

    borromean.assert_as_valid(msg, sig[0], sig[1], pubk_rings)
    assert borromean.verify(msg, sig[0], sig[1], pubk_rings)
    assert not borromean.verify("another message", sig[0], sig[1], pubk_rings)
    assert not borromean.verify(0, sig[0], sig[1], pubk_rings)  # type: ignore[arg-type]
