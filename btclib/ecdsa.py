#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Elliptic Curve Digital Signature Algorithm

http://www.secg.org/sec1-v2.pdf
"""

from hashlib import sha256
from typing import List, Tuple, Optional, Union

from btclib.numbertheory import mod_inv
from btclib.ec import Point, EC, pointMult, DblScalarMult
from btclib.ecurves import secp256k1
from btclib.ecutils import octets2point, bits2int
from btclib.rfc6979 import rfc6979

ECDS = Tuple[int, int]


def ecdsa_sign(ec: EC, hf, M: bytes, d: int,
               k: Optional[int] = None) -> Tuple[int, int]:
    """ECDSA signing operation according to SEC 1

       http://www.secg.org/sec1-v2.pdf
       Steps numbering follows SEC 1 section 4.1.3
    """

    H = hf(M).digest()                                # 4
    e = bits2int(ec, H)                               # 5

    d %= ec.n  # FIXME ?

    if k is None:
        k = rfc6979(ec, hf, H, d)                     # 1
    k %= ec.n  # FIXME ?

    # second part delegated to helper function used in testing
    return _ecdsa_sign(ec, e, d, k)

# Private function provided for testing purposes only.


def _ecdsa_sign(ec: EC, e: int, d: int, k: int) -> Tuple[int, int]:

    # The secret key d: an integer in the range 1..n-1.
    if d == 0:
        raise ValueError("invalid (zero) private key")

    # Fail if k' = 0.
    if k == 0:
        raise ValueError("ephemeral key k=0 in ecdsa sign operation")
    # Let R = k'G.
    R = pointMult(ec, k, ec.G)                          # 1

    r = R[0] % ec.n                                     # 2, 3
    if r == 0:  # r≠0 required as it multiplies the public key
        raise ValueError("r = 0, failed to sign")

    s = mod_inv(k, ec.n) * (e + r*d) % ec.n             # 6
    if s == 0:  # required as the inverse of s is needed
        raise ValueError("s = 0, failed to sign")

    return r, s


def ecdsa_verify(ec: EC, hf, H: bytes, Q: Point, sig: ECDS) -> bool:
    """ECDSA veryfying operation to SEC 1

       See section 4.1.4
       http://www.secg.org/sec1-v2.pdf
    """

    # this is just a try/except wrapper
    # _ecssa_verify raises Errors
    try:
        return _ecdsa_verify(ec, hf, H, Q, sig)
    except Exception:
        return False

# Private function provided for testing purposes only.
# It raises Errors, while verify should always return True or False


def _ecdsa_verify(ec: EC, hf, H: bytes, P: Point, sig: ECDS) -> bool:
    # ECDSA veryfying operation to SEC 1
    # See section 4.1.4

    # The message digest m: a 32-byte array
    H = hf(H).digest()                                # 2
    e = bits2int(ec, H)                               # 3

    # Let P = point(pk); fail if point(pk) fails.
    # P on point will be checked below by DblScalarMult

    # second part delegated to helper function used in testing
    return _ecdsa_verhlp(ec, e, P, sig)

# Private function provided for testing purposes only.


def _ecdsa_verhlp(ec: EC, e: int, P: Point, sig: ECDS) -> bool:

    # Fail if r is not [1, n-1]
    # Fail if s is not [1, n-1]
    r, s = to_dsasig(ec, sig)                        # 1

    s1 = mod_inv(s, ec.n)
    u1 = e*s1
    u2 = r*s1                                           # 4
    R = DblScalarMult(ec, u1, ec.G, u2, P)  # 5

    # Fail if infinite(R).
    if R[1] == 0:
        return False

    v = R[0] % ec.n                                     # 6, 7
    # Fail if r ≠ x(R) %n.
    return r == v                                       # 8


def ecdsa_pubkey_recovery(ec: EC, hf, M: bytes, sig: ECDS) -> List[Point]:
    """ECDSA public key recovery operation according to SEC 1

       http://www.secg.org/sec1-v2.pdf
       See section 4.1.6
    """

    # The message digest m: a 32-byte array
    H = hf(M).digest()
    e = bits2int(ec, H)  # ECDSA verification step 3

    return _ecdsa_pubkey_recovery(ec, e, sig)

# Private function provided for testing purposes only.


def _ecdsa_pubkey_recovery(ec: EC, e: int, sig: ECDS) -> List[Point]:
    # ECDSA public key recovery operation according to SEC 1
    # See section 4.1.6

    r, s = to_dsasig(ec, sig)

    # precomputations
    r1 = mod_inv(r, ec.n)
    r1s = r1*s
    r1e = -r1*e
    keys = []
    for j in range(2):  # FIXME: use ec.cofactor+1 instead of 2
        x = r + j*ec.n  # 1.1
        try:
            R = (x, ec.yOdd(x, 1))  # 1.2, 1.3, and 1.4
            # 1.5 already taken care outside this for loop
            Q = DblScalarMult(ec, r1s, R, r1e, ec.G)  # 1.6.1
            # 1.6.2 is always satisfied for us, and we do not stop here
            keys.append(Q)
            R = ec.opposite(R)                                    # 1.6.3
            Q = DblScalarMult(ec, r1s, R, r1e, ec.G)
            keys.append(Q)
        except Exception:  # can't get a curve's point
            pass
    return keys


def to_dsasig(ec: EC, sig: ECDS) -> Tuple[int, int]:
    """check DSA signature correct format and return the signature itself"""

    if len(sig) != 2:
        m = "invalid length %s for ECDSA signature" % len(sig)
        raise TypeError(m)

    r = int(sig[0])
    if not (0 < r < ec.n):
        raise ValueError("r (%s) not in [1, n-1]" % r)

    s = int(sig[1])
    if not (0 < s < ec.n):
        raise ValueError("s (%s) not in [1, n-1]" % s)

    return r, s
