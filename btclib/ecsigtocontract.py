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
    Let c be a value (bytes) and P an EC point, then
    c, P -> h(P||c)G + P
    is a commitment operation. (G generator, || concatenation)
    The signature contains an EC point, thus it can become a commitment to c.

    HOW:
    when signing, generate a nonce (k) and compute a EC point (R = kG)
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

from typing import Optional

from btclib.ec import Tuple, EC, pointMult, Point, octets2point, \
    point2octets
from btclib.rfc6979 import bits2int, rfc6979
from btclib.ecdsa import ecdsa_sign, ECDS
from btclib.ecssa import ecssa_sign, ECSS

Receipt = Tuple[int, Point]


def tweak(k: int, c: bytes, ec: EC, hf) -> Tuple[Point, int]:
    """tweak kG

    returns:
    - point kG to tweak
    - tweaked private key k + h(kG||c), the corresponding pubkey is a commitment to kG, c
    """
    R = pointMult(ec, k, ec.G)
    e = hf(point2octets(ec, R, True) + c).digest()
    e = int.from_bytes(e, 'big')
    return R, (e + k) % ec.n


def ecdsa_commit_sign(m: bytes,
                      prvkey: int,
                      c: bytes,
                      eph_prv: Optional[int],
                      ec: EC,
                      hf) -> Tuple[Tuple[int, int], Tuple[int, Point]]:
    mh = hf(m).digest()
    if eph_prv is None:
        eph_prv = rfc6979(prvkey, mh, ec, hf)

    ch = hf(c).digest()

    # commit
    R, eph_prv = tweak(eph_prv, ch, ec, hf)
    # sign
    sig = ecdsa_sign(m, prvkey, eph_prv, ec, hf)
    # commit receipt
    receipt = sig[0], R
    return sig, receipt


def ecssa_commit_sign(m: bytes,
                      prvkey: int,
                      c: bytes,
                      eph_prv: Optional[int],
                      ec: EC,
                      hf) -> Tuple[Tuple[int, int], Tuple[int, Point]]:
    ch = hf(c).digest()
    if eph_prv is None:
        eph_prv = rfc6979(prvkey, m, ec, hf)

    # commit
    R, eph_prv = tweak(eph_prv, ch, ec, hf)
    # sign
    sig = ecssa_sign(m, prvkey, eph_prv, ec, hf)
    # commit receipt
    receipt = sig[0], R
    return sig, receipt

# FIXME: have create_commit instead of commit_sign


def verify_commit(receipt: Receipt,
                  c: bytes,
                  ec: EC,
                  hf) -> bool:
    w, R = receipt
    # w in [1..n-1] dsa
    # w in [1..p-1] ssa
    # different verify functions?
    
    # verify R is a good point?    

    ch = hf(c).digest()
    e = hf(point2octets(ec, R, True) + ch).digest()
    e = bits2int(ec, e)
    W = ec.add(R, pointMult(ec, e, ec.G))
    # different verify functions?
    # return w == W[0] # ECSS
    return w == W[0] % ec.n  # ECDS
