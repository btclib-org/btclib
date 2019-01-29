#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic Curve Digital Signature Algorithm

   SEC 1 v.2 (http://www.secg.org/sec1-v2.pdf)
   with bitcoin canonical 'low-s' encoding for ECDSA signatures
"""

from typing import Tuple, List, Optional

from btclib.numbertheory import mod_inv
from btclib.ec import Point, EC, pointMult, DblScalarMult
from btclib.utils import bits2int
from btclib.rfc6979 import rfc6979

ECDS = Tuple[int, int]  # Tuple[scalar, scalar]


def ecdsa_sign(ec: EC, hf, M: bytes, d: int,
               k: Optional[int] = None) -> Tuple[int, int]:
    """ECDSA signing operation according to SEC 1

       http://www.secg.org/sec1-v2.pdf
       Steps numbering follows SEC 1 v.2 section 4.1.3
    """

    # https://tools.ietf.org/html/rfc6979#section-3.2
    # The message M is first processed by hf, yielding the value hd(m),
    # a sequence of bits of length hlen.  Normally, hf is chosen such that
    # its output length hlen is roughly equal to nlen, since the overall
    # security of the signature scheme will depend on the smallest of hlen
    # and nlen; however, the (EC)DSA standard support all combinations of
    # hlen and nlen.
    hd = hf(M).digest()                               # 4
    # H(m) is transformed into an integer modulo ec.n using bits2int:
    e = bits2int(ec, hd)                              # 5

    if k is None:
        k = rfc6979(ec, hf, hd, d)                    # 1
    if not 0 < k < ec.n:
        raise ValueError(f"ephemeral key {hex(k)} not in (0, n)")

    # second part delegated to helper function used in testing
    return _ecdsa_sign(ec, e, d, k)


def _ecdsa_sign(ec: EC, e: int, d: int, k: int) -> Tuple[int, int]:
    """Private function provided for testing purposes only."""
    # e is assumed to be valid
    # Steps numbering follows SEC 1 v.2 section 4.1.3

    # The secret key d: an integer in the range 1..n-1.
    # SEC 1 v.2 section 3.2.1
    if not 0 < d < ec.n:
        raise ValueError(f"private key {hex(d)} not in (0, n)")

    # Fail if k' = 0.
    if not 0 < k < ec.n:
        raise ValueError(f"ephemeral key {hex(k)} not in (0, n)")
    # Let R = k'G.
    R = pointMult(ec, k, ec.G)                        # 1

    r = R[0] % ec.n                                   # 2, 3
    if r == 0:  # r≠0 required as it multiplies the public key
        raise ValueError("r = 0, failed to sign")

    s = mod_inv(k, ec.n) * (e + r*d) % ec.n           # 6
    if s == 0:  # required as the inverse of s is needed
        raise ValueError("s = 0, failed to sign")

    # bitcoin canonical 'low-s' encoding for ECDSA signatures
    # it removes signature malleability as cause of transaction malleability
    # see https://github.com/bitcoin/bitcoin/pull/6769
    if s > ec.n / 2:
        s = ec.n - s

    return r, s


def ecdsa_verify(ec: EC, hf, M: bytes, P: Point, sig: ECDS) -> bool:
    """ECDSA veryfying operation to SEC 1

       See SEC 1 v.2 section 4.1.4
       http://www.secg.org/sec1-v2.pdf
    """

    # this is just a try/except wrapper for the Errors
    # raised by _ecssa_verify
    try:
        return _ecdsa_verify(ec, hf, M, P, sig)
    except Exception:
        return False


def _ecdsa_verify(ec: EC, hf, M: bytes, P: Point, sig: ECDS) -> bool:
    """Private function provided for testing purposes only.
    
       It raises Errors, while verify should always return True or False

       See SEC 1 v.2 section 4.1.4
       http://www.secg.org/sec1-v2.pdf
    """

    # The message digest m: a 32-byte array
    hd = hf(M).digest()                               # 2
    e = bits2int(ec, hd)                              # 3

    # Let P = point(pk); fail if point(pk) fails.
    # P on point will be checked below by DblScalarMult

    # second part delegated to helper function used in testing
    return _ecdsa_verhlp(ec, e, P, sig)


def _ecdsa_verhlp(ec: EC, e: int, P: Point, sig: ECDS) -> bool:
    """Private function provided for testing purposes only."""
    # Fail if r is not [1, n-1]
    # Fail if s is not [1, n-1]
    r, s = _to_dsasig(ec, sig)                        # 1

    # Let P = point(pk); fail if point(pk) fails.
    ec.requireOnCurve(P)
    if P[1] == 0:
        raise ValueError("public key is infinite")

    s1 = mod_inv(s, ec.n)
    u = e*s1
    v = r*s1                                          # 4
    # Let R = u*G + v*P.
    R = DblScalarMult(ec, u, ec.G, v, P)              # 5

    # Fail if infinite(R).
    assert R[1] != 0, "how did you do that?!?"        # 5

    v = R[0] % ec.n                                   # 6, 7
    # Fail if r ≠ x(R) %n.
    return r == v                                     # 8


def ecdsa_pubkey_recovery(ec: EC, hf, M: bytes, sig: ECDS) -> List[Point]:
    """ECDSA public key recovery operation according to SEC 1

       http://www.secg.org/sec1-v2.pdf
       See SEC 1 v.2 section 4.1.6
    """

    # The message digest m: a 32-byte array
    hd = hf(M).digest()                                     # 1.5
    e = bits2int(ec, hd)                                    # 1.5

    return _ecdsa_pubkey_recovery(ec, e, sig)


def _ecdsa_pubkey_recovery(ec: EC, e: int, sig: ECDS) -> List[Point]:
    """Private function provided for testing purposes only."""
    # ECDSA public key recovery operation according to SEC 1
    # http://www.secg.org/sec1-v2.pdf
    # See SEC 1 v.2 section 4.1.6

    r, s = _to_dsasig(ec, sig)

    # precomputations
    r1 = mod_inv(r, ec.n)
    r1s = r1*s
    r1e = -r1*e
    keys = []
    for j in range(ec.h):                                   # 1
        x = r + j*ec.n                                      # 1.1
        try:
            R = (x % ec._p, ec.yOdd(x, 1))                  # 1.2, 1.3, and 1.4
            # 1.5 already taken care outside this for loop
            Q = DblScalarMult(ec, r1s, R, r1e, ec.G)        # 1.6.1
            if Q[1] != 0 and _ecdsa_verhlp(ec, e, Q, sig):  # 1.6.2
                keys.append(Q)
            R = ec.opposite(R)                              # 1.6.3
            Q = DblScalarMult(ec, r1s, R, r1e, ec.G)
            if Q[1] != 0 and _ecdsa_verhlp(ec, e, Q, sig):  # 1.6.2
                keys.append(Q)                              # 1.6.2
        except Exception:  # R is not a curve point
            pass
    return keys


def _to_dsasig(ec: EC, sig: ECDS) -> Tuple[int, int]:
    """check DSA signature correct format and return the signature itself"""

    if len(sig) != 2:
        m = f"invalid length {len(sig)} for ECDSA signature"
        raise TypeError(m)

    # Fail if r is not [1, n-1]
    r = int(sig[0])
    if not 0 < r < ec.n:
        raise ValueError(f"r ({hex(r)}) not in [1, n-1]")

    # Fail if s is not [1, n-1]
    s = int(sig[1])
    if not 0 < s < ec.n:
        raise ValueError(f"s ({hex(r)}) not in [1, n-1]")

    return r, s
