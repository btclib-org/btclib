#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Borromean signature functions."""
from __future__ import annotations

import secrets
from hashlib import sha256 as hf  # FIXME any hf
from typing import List, Sequence

from btclib.alias import Octets, Point
from btclib.ec import bytes_from_point, double_mult, mult, secp256k1
from btclib.exceptions import BTClibRuntimeError
from btclib.utils import bytes_from_octets, int_from_bits

ec = secp256k1  # FIXME any curve

# TODO test corner case on low-cardinality curves


def _hash(m: bytes, R: bytes, i: int, j: int) -> bytes:
    temp = b"".join(
        [m, R, i.to_bytes(4, "big", signed=False), j.to_bytes(4, "big", signed=False)]
    )
    return hf(temp).digest()


PubkeyRing = Sequence[Point]


def _get_msg_format(msg: bytes, pubk_rings: Sequence[PubkeyRing]) -> bytes:
    t = b"".join(
        b"".join(bytes_from_point(Q, ec) for Q in pubk_ring) for pubk_ring in pubk_rings
    )
    return hf(msg + t).digest()


SValues = Sequence[List[int]]


def _initialize(
    msg: Octets, pubk_rings: Sequence[PubkeyRing]
) -> tuple[bytes, bytes, SValues]:
    msg_ = bytes_from_octets(msg)
    m = _get_msg_format(msg_, pubk_rings)
    e = [[0] * len(pubk_ring) for pubk_ring in pubk_rings]
    return msg_, m, e


def sign(
    msg: Octets,
    ks: Sequence[int],
    sign_key_idx: Sequence[int],
    sign_keys: Sequence[int],
    pubk_rings: Sequence[PubkeyRing],
) -> tuple[bytes, SValues]:
    """Borromean ring signature - signing algorithm.

    https://github.com/ElementsProject/borromean-signatures-writeup
    https://github.com/Blockstream/borromean_paper/blob/master/borromean_draft_0.01_9ade1e49.pdf

    inputs:
    - msg: message to be signed (bytes)
    - sign_key_idx: list of indexes representing each signing key per ring
    - sign_keys: list containing the whole set of signing keys (one per ring)
    - pubk_rings: dictionary of sequences representing single rings of pub_keys
    """
    # sourcery skip: low-code-quality
    msg, m, e = _initialize(msg, pubk_rings)
    e0bytes = m
    s = [
        [secrets.randbits(256) for _ in range(len(pubk_ring))]
        for pubk_ring in pubk_rings
    ]

    # step 1
    for i, (pubk_ring, j_star, k) in enumerate(zip(pubk_rings, sign_key_idx, ks)):
        keys_size = len(pubk_ring)
        start_idx = (j_star + 1) % keys_size
        r = bytes_from_point(mult(k), ec)
        if start_idx != 0:
            for j in range(start_idx, keys_size):
                e[i][j] = int_from_bits(_hash(m, r, i, j), ec.nlen) % ec.n
                # edge case that cannot be reproduced in the test suite
                if not 0 < e[i][j] < ec.n:
                    err_msg = "implausibile signature failure"  # pragma: no cover
                    raise BTClibRuntimeError(err_msg)  # pragma: no cover
                t = double_mult(-e[i][j], pubk_ring[j], s[i][j], ec.G)
                r = bytes_from_point(t, ec)
        e0bytes += r
    e0 = hf(e0bytes).digest()
    # step 2
    for i, (j_star, k) in enumerate(zip(sign_key_idx, ks)):
        e[i][0] = int_from_bits(_hash(m, e0, i, 0), ec.nlen) % ec.n
        # edge case that cannot be reproduced in the test suite
        if not 0 < e[i][0] < ec.n:
            err_msg = "implausibile signature failure"  # pragma: no cover
            raise BTClibRuntimeError(err_msg)  # pragma: no cover
        for j in range(1, j_star + 1):
            s[i][j - 1] = secrets.randbits(256)
            t = double_mult(-e[i][j - 1], pubk_rings[i][j - 1], s[i][j - 1], ec.G)
            r = bytes_from_point(t, ec)
            e[i][j] = int_from_bits(_hash(m, r, i, j), ec.nlen) % ec.n
            # edge case that cannot be reproduced in the test suite
            if not 0 < e[i][j] < ec.n:
                err_msg = "implausibile signature failure"  # pragma: no cover
                raise BTClibRuntimeError(err_msg)  # pragma: no cover
        s[i][j_star] = k + sign_keys[i] * e[i][j_star]
    return e0, s


def verify(
    msg: Octets, e0: bytes, s: SValues, pubk_rings: Sequence[PubkeyRing]
) -> bool:
    """Borromean ring signature - verification algorithm.

    inputs:

    - msg: message to be signed
    - e0: pinned e-value needed to start the verification algorithm
    - s: s-values, both real (one per ring) and forged
    - pubk_rings: sequence of PubKey rings
    """
    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        return assert_as_valid(msg, e0, s, pubk_rings)
    except Exception:  # pylint: disable=broad-except
        return False


def assert_as_valid(
    msg: Octets, e0: bytes, s: SValues, pubk_rings: Sequence[PubkeyRing]
) -> bool:
    msg, m, e = _initialize(msg, pubk_rings)
    e0bytes = m

    for i, pubk_ring in enumerate(pubk_rings):
        keys_size = len(pubk_ring)
        e[i][0] = int_from_bits(_hash(m, e0, i, 0), ec.nlen) % ec.n
        # edge case that cannot be reproduced in the test suite
        if e[i][0] == 0:
            err_msg = "implausibile signature failure"  # pragma: no cover
            raise BTClibRuntimeError(err_msg)  # pragma: no cover
        r = b"\0x00"
        for j in range(keys_size):
            t = double_mult(-e[i][j], pubk_ring[j], s[i][j], ec.G)
            r = bytes_from_point(t, ec)
            if j != keys_size - 1:
                h = _hash(m, r, i, j + 1)
                e[i][j + 1] = int_from_bits(h, ec.nlen) % ec.n
                # edge case that cannot be reproduced in the test suite
                if e[i][j + 1] == 0:
                    err_msg = "implausibile signature failure"  # pragma: no cover
                    raise BTClibRuntimeError(err_msg)  # pragma: no cover
            else:
                e0bytes += r
    e0_prime = hf(e0bytes).digest()
    return e0_prime == e0
