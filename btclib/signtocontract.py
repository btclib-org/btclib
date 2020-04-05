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

from hashlib import sha256
from typing import Optional, Tuple, Union

from btclib import bip32

from . import dsa, ssa
from .alias import HashF, Octets, Point
from .curve import Curve
from .curvemult import mult
from .curves import secp256k1
from .rfc6979 import rfc6979
from .to_prvkey import to_prvkey_int
from .utils import (bytes_from_octets, bytes_from_point, int_from_bits,
                    point_from_octets)

# commitment receipt
Receipt = Tuple[int, Point]

def _tweak(c: Octets, k: int, ec: Curve, hf: HashF) -> Tuple[Point, int]:
    """Tweak kG with hash(kG||c).

    Return:
    - the point kG to tweak
    - tweaked private key k + hash(kG||c)
    """

    c = bytes_from_octets(c)
    R = mult(k, ec.G, ec)
    h = hf()
    h.update(bytes_from_point(R, True, ec) + c)
    e = int.from_bytes(h.digest(), byteorder='big')
    return R, (e + k) % ec.n


def ecdsa_commit_sign(c: Octets, m: Octets,
                      q: Union[int, bytes, str, bip32.XkeyDict],
                      k: Optional[int] = None,
                      ec: Curve = secp256k1,
                      hf: HashF = sha256) -> Tuple[Tuple[int, int], Receipt]:
    """Include a commitment c inside an ECDSA signature."""

    c = bytes_from_octets(c)
    m = bytes_from_octets(m)
    q = to_prvkey_int(q, ec)

    if k is None:
        h = hf()
        h.update(m)
        k = rfc6979(h.digest(), q, ec, hf)

    h = hf()
    h.update(c)
    ch = h.digest()

    # commit
    R, new_k = _tweak(ch, k, ec, hf)
    # sign
    sig = dsa.sign(m, q, new_k, ec, hf)
    # commit receipt
    receipt = sig[0], R
    return sig, receipt


def ecssa_commit_sign(c: Octets, m: Octets,
                      q: Union[int, bytes, str, bip32.XkeyDict],
                      k: Optional[int] = None,
                      ec: Curve = secp256k1,
                      hf: HashF = sha256) -> Tuple[Tuple[int, int], Receipt]:
    """Include a commitment c inside an ECSSA signature."""

    c = bytes_from_octets(c)
    m = bytes_from_octets(m)
    q = to_prvkey_int(q, ec)

    if k is None:
        k = ssa.k(m, q, ec, hf)

    h = hf()
    h.update(c)
    ch = h.digest()

    # commit
    R, new_k = _tweak(ch, k, ec, hf)
    # sign
    sig = ssa.sign(m, q, new_k, ec, hf)
    # commit receipt
    receipt = sig[0], R
    return sig, receipt

# FIXME: have create_commit instead of commit_sign


def verify_commit(c: Octets, receipt: Receipt,
                  ec: Curve = secp256k1, hf: HashF = sha256) -> bool:
    """Open the commitment c inside an EC DSA/SSA signature."""

    c = bytes_from_octets(c)

    # FIXME: verify the signature

    w, R = receipt
    # w in [1..n-1] dsa
    # w in [1..p-1] ssa
    # different verify functions?

    # verify R is a good point?

    h = hf()
    h.update(c)
    ch = h.digest()
    h = hf()
    h.update(bytes_from_point(R, True, ec) + ch)
    e = h.digest()
    e = int_from_bits(e, ec)
    W = ec.add(R, mult(e, ec.G, ec))
    # different verify functions?
    # return w == W[0] # ECSS
    return w == W[0] % ec.n  # ECDS, FIXME: ECSSA
