#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""sign-to-contract

    IDEA:
    Let c be a value (bytes) and P an Curve point, then
    c, P -> h(P||c)G + P
    is a commitment operation. (G generator, || concatenation)
    The signature contains an Curve point, thus it can become a commitment to c.

    HOW:
    when signing, generate a nonce (k) and compute a Curve point (R = kG)
    instead of proceeding using (k,R), compute a value (e) that is a
    commitment to c:
    e = hash(R||c)
    substitute the nonce k with k+e and R with R+eG, and proceed signing
    in the standard way, using (k+e,R+eG).

    COMMITMENT VERIFICATION:
    the verifier can see W.x (W = R+eG) on the signature
    the signer (and committer) provides R and c
    the verifier checks that:
    W.x = (R+eG).x (with e = hash(R||c))
"""

from typing import Optional, Tuple, Callable, Any

from btclib.curve import Curve, mult, Point
from btclib.utils import int_from_bits, point_from_octets, octets_from_point
from btclib.rfc6979 import rfc6979
from btclib import dsa
from btclib import ssa

Receipt = Tuple[int, Point]


def _tweak(c: bytes,
           ec: Curve,
           hf: Callable[[Any], Any],
           k: int) -> Tuple[Point, int]:
    """tweak kG

    returns:
    - point kG to tweak
    - tweaked private key k + h(kG||c), the corresponding pubkey is a commitment to kG, c
    """
    R = mult(ec, k, ec.G)
    e = hf(octets_from_point(ec, R, True) + c).digest()
    e = int.from_bytes(e, 'big')
    return R, (e + k) % ec.n


def ecdsa_commit_sign(c: bytes,
                      ec: Curve,
                      hf: Callable[[Any], Any],
                      m: bytes,
                      prvkey: int,
                      k: Optional[int] = None) -> Tuple[dsa.ECDS, Receipt]:
    if k is None:
        k = rfc6979(ec, hf, hf(m).digest(), prvkey)

    ch = hf(c).digest()

    # commit
    R, new_k = _tweak(ch, ec, hf, k)
    # sign
    sig = dsa.sign(ec, hf, m, prvkey, new_k)
    # commit receipt
    receipt = sig[0], R
    return sig, receipt


def ecssa_commit_sign(c: bytes,
                      ec: Curve,
                      hf: Callable[[Any], Any],
                      m: bytes,
                      prvkey: int,
                      k: Optional[int] = None) -> Tuple[ssa.ECSS, Receipt]:
    if k is None:
        k = rfc6979(ec, hf, m, prvkey)

    ch = hf(c).digest()

    # commit
    R, new_k = _tweak(ch, ec, hf, k)
    # sign
    sig = ssa.sign(ec, hf, m, prvkey, new_k)
    # commit receipt
    receipt = sig[0], R
    return sig, receipt

# FIXME: have create_commit instead of commit_sign


def verify_commit(c: bytes,
                  ec: Curve,
                  hf: Callable[[Any], Any],
                  receipt: Receipt) -> bool:
    w, R = receipt
    # w in [1..n-1] dsa
    # w in [1..p-1] ssa
    # different verify functions?
    
    # verify R is a good point?    

    ch = hf(c).digest()
    e = hf(octets_from_point(ec, R, True) + ch).digest()
    e = int_from_bits(ec, e)
    W = ec.add(R, mult(ec, e, ec.G))
    # different verify functions?
    # return w == W[0] # ECSS
    return w == W[0] % ec.n  # ECDS, FIXME: ECSSA
