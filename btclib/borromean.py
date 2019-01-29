#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import random
from hashlib import sha256
from typing import List, Dict, Tuple
from collections import defaultdict

from btclib.ec import Point, pointMult, DblScalarMult    
from btclib.curves import secp256k1    
from btclib.utils import bits2int, point2octets, octets2point

# FIXME: should be urandom, but then tests would be non-deterministic
random.seed(42)

ec = secp256k1 # FIXME: any curve
hf = sha256 # FIXME: any hf

def _borromean_hash(msg: bytes, R: bytes, i: int, j: int) -> bytes:
    temp = msg + R + i.to_bytes(4, 'big') + j.to_bytes(4, 'big')
    return hf(temp).digest()


def _get_msg_format(msg: bytes, pubk_rings: Dict[int, List[Point]]) -> bytes:
    m = msg
    rings = len(pubk_rings)
    for i in range(rings):
        keys = len(pubk_rings[i])
        for j in range(keys):
            P = pubk_rings[i][j]
            Pbytes = point2octets(ec, P, True)
            m += Pbytes
    return hf(m).digest()


def borromean_sign(msg: bytes,
                   k: List[int],
                   sign_key_idx: List[int],
                   sign_keys: List[int],
                   pubk_rings: Dict[int, List[Point]]) -> Tuple[bytes, Dict[int, List[int]]]:
    """ Borromean ring signature - signing algorithm

        https://github.com/ElementsProject/borromean-signatures-writeup
        https://github.com/Blockstream/borromean_paper/blob/master/borromean_draft_0.01_9ade1e49.pdf

        inputs:
        - msg: msg to be signed (bytes)
        - sign_key_idx: list of indexes representing each signing key per ring
        - sign_keys: list containing the whole set of signing keys (one per ring)
        - pubk_rings: dictionary of lists where internal lists represent single rings of pubkeys
    """

    s: Dict[int, List[int]] = defaultdict(list)
    e: Dict[int, List[int]] = defaultdict(list)
    m = _get_msg_format(msg, pubk_rings)
    e0bytes = m
    ring_size = len(pubk_rings)
    # step 1
    for i in range(ring_size):
        keys_size = len(pubk_rings[i])
        s[i] = [0]*keys_size
        e[i] = [0]*keys_size
        j_star = sign_key_idx[i]
        start_idx = (j_star + 1) % keys_size
        R = point2octets(ec, pointMult(ec, k[i], ec.G), True)
        if start_idx != 0:
            for j in range(start_idx, keys_size):
                s[i][j] = random.getrandbits(256)
                e[i][j] = bits2int(ec, _borromean_hash(m, R, i, j))
                assert 0 < e[i][j] < ec.n, "sign fail: how did you do that?!?"
                T = DblScalarMult(ec, s[i][j], ec.G, -e[i][j], pubk_rings[i][j])
                R = point2octets(ec, T, True)
        e0bytes += R
    e0 = hf(e0bytes).digest()
    # step 2
    for i in range(ring_size):
        e[i][0] = bits2int(ec, _borromean_hash(m, e0, i, 0))
        assert 0 < e[i][0] < ec.n, "sign fail: how did you do that?!?"
        j_star = sign_key_idx[i]
        for j in range(1, j_star+1):
            s[i][j-1] = random.getrandbits(256)
            T = DblScalarMult(ec, s[i][j-1], ec.G, -e[i][j-1], pubk_rings[i][j-1])
            R = point2octets(ec, T, True)
            e[i][j] = bits2int(ec, _borromean_hash(m, R, i, j))
            assert 0 < e[i][j] < ec.n, "sign fail: how did you do that?!?"
        s[i][j_star] = k[i] + sign_keys[i]*e[i][j_star]
    return e0, s


def borromean_verify(msg: bytes,
                     e0: bytes,
                     s: Dict[int, List[int]],
                     pubk_rings: Dict[int, List[Point]]) -> bool:
    """ Borromean ring signature - verification algorithm

    inputs: 
    - msg: msg to be signed (bytes)
    - e0: pinned e-value needed to start the verification algorithm
    - s: s-values, both real (one per ring) and forged
    - pubk_rings: dictionary of lists where internal lists represent single rings of pubkeys
    """

    # this is just a try/except wrapper for the Errors
    # raised by _borromean_verify
    try:
        return _borromean_verify(msg, e0, s, pubk_rings)
    except Exception:
        return False


def _borromean_verify(msg: bytes,
                      e0: bytes,
                      s: Dict[int, List[int]],
                      pubk_rings: Dict[int, List[Point]]) -> bool:

    ring_size = len(pubk_rings)
    m = _get_msg_format(msg, pubk_rings)
    e: Dict[int, List[int]] = defaultdict(list)
    e0bytes = m
    for i in range(ring_size):
        keys_size = len(pubk_rings[i])
        e[i] = [0]*keys_size
        e[i][0] = bits2int(ec, _borromean_hash(m, e0, i, 0))
        assert e[i][0] != 0, "invalid sig: how did you do that?!?"
        R = b'\0x00'
        for j in range(keys_size):
            T = DblScalarMult(ec, s[i][j], ec.G, -e[i][j], pubk_rings[i][j])
            R = point2octets(ec, T, True)
            if j != len(pubk_rings[i])-1:
                e[i][j+1] = bits2int(ec, _borromean_hash(m, R, i, j+1))
                assert e[i][j+1] != 0, "invalid sig: how did you do that?!?"
            else:
                e0bytes += R
    e0_prime = hf(e0bytes).digest()
    return e0_prime == e0
