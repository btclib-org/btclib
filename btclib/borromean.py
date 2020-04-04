#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import random
from collections import defaultdict
from hashlib import sha256 as hf  # FIXME: any hf
from typing import Dict, List, Sequence, Tuple, Union

from .alias import Point
from .curvemult import double_mult, mult
from .curves import secp256k1 as ec  # FIXME: any curve
from .utils import String, int_from_bits, octets_from_point, point_from_octets

# FIXME: should be urandom, but then tests would be non-deterministic
random.seed(42)

PubkeyRing = Dict[int, Sequence[Point]]
SValues = Dict[int, Sequence[int]]


def _hash(m: bytes, R: bytes, i: int, j: int) -> bytes:
    temp = m + R
    temp += i.to_bytes(4, byteorder='big') + j.to_bytes(4, byteorder='big')
    return hf(temp).digest()


def _get_msg_format(msg: bytes, pubk_rings: PubkeyRing) -> bytes:
    rings = len(pubk_rings)
    for i in range(rings):
        for P in pubk_rings[i]:
            msg += octets_from_point(P, True, ec)
    return hf(msg).digest()


def sign(msg: String,
         k: Sequence[int],
         sign_key_idx: Sequence[int],
         sign_keys: Sequence[int],
         pubk_rings: PubkeyRing) -> Tuple[bytes, SValues]:
    """Borromean ring signature - signing algorithm

        https://github.com/ElementsProject/borromean-signatures-writeup
        https://github.com/Blockstream/borromean_paper/blob/master/borromean_draft_0.01_9ade1e49.pdf

        inputs:
        - msg: message to be signed (bytes)
        - sign_key_idx: list of indexes representing each signing key per ring
        - sign_keys: list containing the whole set of signing keys (one per ring)
        - pubk_rings: dictionary of sequences representing single rings of pubkeys
    """

    if isinstance(msg, str):
        msg = msg.encode()
    m = _get_msg_format(msg, pubk_rings)

    e0bytes = m
    s: SValues = defaultdict(list)
    e: SValues = defaultdict(list)
    ring_size = len(pubk_rings)
    # step 1
    for i in range(ring_size):
        keys_size = len(pubk_rings[i])
        s[i] = [0]*keys_size
        e[i] = [0]*keys_size
        j_star = sign_key_idx[i]
        start_idx = (j_star + 1) % keys_size
        R = octets_from_point(mult(k[i]), True, ec)
        if start_idx != 0:
            for j in range(start_idx, keys_size):
                s[i][j] = random.getrandbits(256)
                e[i][j] = int_from_bits(_hash(m, R, i, j), ec)
                assert 0 < e[i][j] < ec.n, "sign fail: how did you do that?!?"
                T = double_mult(-e[i][j], pubk_rings[i][j], s[i][j])
                R = octets_from_point(T, True, ec)
        e0bytes += R
    e0 = hf(e0bytes).digest()
    # step 2
    for i in range(ring_size):
        e[i][0] = int_from_bits(_hash(m, e0, i, 0), ec)
        assert 0 < e[i][0] < ec.n, "sign fail: how did you do that?!?"
        j_star = sign_key_idx[i]
        for j in range(1, j_star+1):
            s[i][j-1] = random.getrandbits(256)
            T = double_mult(-e[i][j-1], pubk_rings[i][j-1], s[i][j-1])
            R = octets_from_point(T, True, ec)
            e[i][j] = int_from_bits(_hash(m, R, i, j), ec)
            assert 0 < e[i][j] < ec.n, "sign fail: how did you do that?!?"
        s[i][j_star] = k[i] + sign_keys[i]*e[i][j_star]
    return e0, s


def verify(msg: String, e0: bytes, s: SValues, pubk_rings: PubkeyRing) -> bool:
    """Borromean ring signature - verification algorithm

    inputs:

    - msg: message to be signed (bytes)
    - e0: pinned e-value needed to start the verification algorithm
    - s: s-values, both real (one per ring) and forged
    - pubk_rings: dictionary of sequences representing single rings of pubkeys
    """

    if isinstance(msg, str):
        msg = msg.encode()

    # this is just a try/except wrapper for the Errors
    # raised by _verify
    try:
        return _verify(msg, e0, s, pubk_rings)
    except Exception:
        return False


def _verify(msg: bytes, e0: bytes, s: SValues, pubk_rings: PubkeyRing) -> bool:

    ring_size = len(pubk_rings)
    m = _get_msg_format(msg, pubk_rings)
    e: Dict[int, Sequence[int]] = defaultdict(list)
    e0bytes = m
    for i in range(ring_size):
        keys_size = len(pubk_rings[i])
        e[i] = [0]*keys_size
        e[i][0] = int_from_bits(_hash(m, e0, i, 0), ec)
        assert e[i][0] != 0, "invalid sig: how did you do that?!?"
        R = b'\0x00'
        for j in range(keys_size):
            T = double_mult(-e[i][j], pubk_rings[i][j], s[i][j])
            R = octets_from_point(T, True, ec)
            if j != len(pubk_rings[i])-1:
                e[i][j+1] = int_from_bits(_hash(m, R, i, j+1), ec)
                assert e[i][j+1] != 0, "invalid sig: how did you do that?!?"
            else:
                e0bytes += R
    e0_prime = hf(e0bytes).digest()
    return e0_prime == e0
