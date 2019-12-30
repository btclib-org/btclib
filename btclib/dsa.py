#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic Curve Digital Signature Algorithm (ECDSA).

   Implementation according to SEC 1 v.2:

   http://www.secg.org/sec1-v2.pdf

   specialized with bitcoin canonical 'low-s' encoding.
"""

from typing import Tuple, List, Optional

from .numbertheory import mod_inv
from .utils import int_from_bits, HashF
from .curve import Point, Curve, _mult_jac, _double_mult, double_mult
from .rfc6979 import _rfc6979

ECDS = Tuple[int, int]  # Tuple[scalar, scalar]


def sign(ec: Curve, hf: HashF, m: bytes, q: int,
         k: Optional[int] = None) -> ECDS:
    """ECDSA signature according to SEC 1 v.2 with canonical low-s encoding.

    The message m is first processed by hf, yielding the value

        mhd = hf(m),

    a sequence of bits of length *hlen*.

    Normally, hf is chosen such that its output length *hlen* is
    roughly equal to *nlen*, the bit-length of the group order *n*,
    since the overall security of the signature scheme will depend on
    the smallest of *hlen* and *nlen*; however, the ECDSA standard
    supports all combinations of *hlen* and *nlen*.

    See https://tools.ietf.org/html/rfc6979#section-3.2
    """

    # Steps numbering follows SEC 1 v.2 section 4.1.3

    mhd = hf(m).digest()                          # 4
    # mhd is transformed into an integer modulo ec.n using int_from_bits:
    c = int_from_bits(ec, mhd)                    # 5

    # The secret key q: an integer in the range 1..n-1.
    # SEC 1 v.2 section 3.2.1
    if not 0 < q < ec.n:
        raise ValueError(f"private key {hex(q)} not in [1, n-1]")

    if k is None:
        k = _rfc6979(ec, hf, c, q)                # 1
    if not 0 < k < ec.n:
        raise ValueError(f"ephemeral key {hex(k)} not in [1, n-1]")

    # second part delegated to helper function
    return _sign(ec, c, q, k)


def _sign(ec: Curve, c: int, q: int, k: int) -> ECDS:
    # Private function for test/dev purposes
    # it is assumed that q, k, and c are in [1, n-1]

    # Steps numbering follows SEC 1 v.2 section 4.1.3

    RJ = _mult_jac(ec, k, ec.GJ)                  # 1

    Rx = (RJ[0]*mod_inv(RJ[2]*RJ[2], ec._p)) % ec._p
    r = Rx % ec.n                                 # 2, 3
    if r == 0:  # r≠0 required as it multiplies the public key
        raise ValueError("r = 0, failed to sign")

    s = mod_inv(k, ec.n) * (c + r*q) % ec.n       # 6
    if s == 0:  # s≠0 required as verify will need the inverse of s
        raise ValueError("s = 0, failed to sign")

    # bitcoin canonical 'low-s' encoding for ECDSA signatures
    # it removes signature malleability as cause of transaction malleability
    # see https://github.com/bitcoin/bitcoin/pull/6769
    if s > ec.n / 2:
        s = ec.n - s

    return r, s


def verify(ec: Curve, hf: HashF, m: bytes, P: Point, sig: ECDS) -> bool:
    """ECDSA signature verification (SEC 1 v.2 section 4.1.4)."""

    # try/except wrapper for the Errors raised by _verify
    try:
        return _verify(ec, hf, m, P, sig)
    except Exception:
        return False


def _verify(ec: Curve, hf: HashF, m: bytes, P: Point, sig: ECDS) -> bool:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # The message digest mhd: a 32-byte array
    mhd = hf(m).digest()                                 # 2
    c = int_from_bits(ec, mhd)                           # 3

    # second part delegated to helper function
    return _verhlp(ec, c, P, sig)


def _verhlp(ec: Curve, c: int, P: Point, sig: ECDS) -> bool:
    # Private function for test/dev purposes

    # Fail if r is not [1, n-1]
    # Fail if s is not [1, n-1]
    r, s = _to_sig(ec, sig)                              # 1

    # Let P = point(pk); fail if point(pk) fails.
    ec.require_on_curve(P)
    if P[1] == 0:
        raise ValueError("public key is infinite")

    w = mod_inv(s, ec.n)
    u = c*w
    v = r*w                                              # 4
    # Let R = u*G + v*P.
    RJ = _double_mult(ec, v, (P[0], P[1], 1), u, ec.GJ)  # 5

    # Fail if infinite(R).
    assert RJ[2] != 0, "how did you do that?!?"          # 5

    Rx = (RJ[0]*mod_inv(RJ[2]*RJ[2], ec._p)) % ec._p
    x = Rx % ec.n                                        # 6, 7
    # Fail if r ≠ x(R) %n.
    return r == x                                        # 8


def pubkey_recovery(ec: Curve, hf: HashF, m: bytes, sig: ECDS) -> List[Point]:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See also https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106    
    """

    # The message digest mhd: a 32-byte array
    mhd = hf(m).digest()                                  # 1.5
    c = int_from_bits(ec, mhd)                            # 1.5

    return _pubkey_recovery(ec, c, sig)


def _pubkey_recovery(ec: Curve, c: int, sig: ECDS) -> List[Point]:
    # Private function provided for testing purposes only.

    r, s = _to_sig(ec, sig)

    # precomputations
    r1 = mod_inv(r, ec.n)
    r1s = r1*s
    r1e = -r1*c
    keys: List[Point] = list()
    for j in range(ec.h):                                 # 1
        x = (r + j*ec.n) % ec._p                          # 1.1
        try:  # TODO: check test reporting 1, 2, 3, or 4 keys
            # even root first for bitcoin message signing compatibility
            R = Point(x, ec.y_odd(x, 0))                  # 1.2, 1.3, and 1.4
            # skip 1.5: in this function, c is an input
            Q = double_mult(ec, r1s, R, r1e)              # 1.6.1
            if Q[1] != 0 and _verhlp(ec, c, Q, sig):      # 1.6.2
                keys.append(Q)
            R = ec.opposite(R)                            # 1.6.3
            Q = double_mult(ec, r1s, R, r1e)
            if Q[1] != 0 and _verhlp(ec, c, Q, sig):      # 1.6.2
                keys.append(Q)                            # 1.6.2
        except Exception:  # R is not a curve point
            pass
    return keys


def _to_sig(ec: Curve, sig: ECDS) -> ECDS:
    # check that the DSA signature is correct
    # and return the signature itself

    if len(sig) != 2:
        errMsg = f"invalid length {len(sig)} for ECDSA signature"
        raise TypeError(errMsg)

    # Fail if r is not [1, n-1]
    r = int(sig[0])
    if not 0 < r < ec.n:
        raise ValueError(f"r ({hex(r)}) not in [1, n-1]")

    # Fail if s is not [1, n-1]
    s = int(sig[1])
    if not 0 < s < ec.n:
        raise ValueError(f"s ({hex(r)}) not in [1, n-1]")

    return r, s
