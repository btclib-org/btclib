#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Include a commitment inside an elliptic curve DSA/SSA signature.

Let c be the commitment value and R a curve point, then

    e = hash(R||c)

is a commitment operation.

When signing, an ephemeral secret key k is generated and its
corresponding curve point R = kG is used. Here, instead of
using (k, R), compute the commitment to c

    e = hash(R||c),

tweak k with e and consequently substistute R with W = (k+e)G = R+eG,
the proceed signing in the standard way, using (k+e, W).

When the committer/signer will reveal R and c,
the verifier will check that

    W.x = (R+eG).x

with e = hash(R||c)) and W.x being known from the signature.
"""

from typing import Optional, Tuple

from .curve import Curve, Point
from .curvemult import mult
from .utils import int_from_bits, point_from_octets, octets_from_point, HashF
from .rfc6979 import rfc6979
from . import dsa
from . import ssa

# commitment receipt
Receipt = Tuple[int, Point]


def _tweak(ec: Curve, hf: HashF, c: bytes, k: int) -> Tuple[Point, int]:
    """Tweak kG with hash(kG||c).

    Return:
    - the point kG to tweak
    - tweaked private key k + hash(kG||c)
    """
    R = mult(ec, k)
    e = hf(octets_from_point(ec, R, True) + c).digest()
    e = int.from_bytes(e, 'big')
    return R, (e + k) % ec.n


def ecdsa_commit_sign(ec: Curve, hf: HashF, c: bytes, m: bytes, prvkey: int,
                      k: Optional[int] = None) -> Tuple[dsa.ECDS, Receipt]:
    """Include a commitment c inside an ECDSA signature."""

    if k is None:
        k = rfc6979(ec, hf, hf(m).digest(), prvkey)

    ch = hf(c).digest()

    # commit
    R, new_k = _tweak(ec, hf, ch, k)
    # sign
    sig = dsa.sign(ec, hf, m, prvkey, new_k)
    # commit receipt
    receipt = sig[0], R
    return sig, receipt


def ecssa_commit_sign(ec: Curve, hf: HashF, c: bytes, m: bytes, prvkey: int,
                      k: Optional[int] = None) -> Tuple[ssa.ECSS, Receipt]:
    """Include a commitment c inside an ECSSA signature."""

    if k is None:
        k = rfc6979(ec, hf, m, prvkey)

    ch = hf(c).digest()

    # commit
    R, new_k = _tweak(ec, hf, ch, k)
    # sign
    sig = ssa.sign(ec, hf, m, prvkey, new_k)
    # commit receipt
    receipt = sig[0], R
    return sig, receipt

# FIXME: have create_commit instead of commit_sign


def verify_commit(ec: Curve, hf: HashF, c: bytes, receipt: Receipt) -> bool:
    """Open the commitment c inside an EC DSA/SSA signature."""

    # FIXME: verify the signature

    w, R = receipt
    # w in [1..n-1] dsa
    # w in [1..p-1] ssa
    # different verify functions?

    # verify R is a good point?

    ch = hf(c).digest()
    e = hf(octets_from_point(ec, R, True) + ch).digest()
    e = int_from_bits(ec, e)
    W = ec.add(R, mult(ec, e))
    # different verify functions?
    # return w == W[0] # ECSS
    return w == W[0] % ec.n  # ECDS, FIXME: ECSSA
