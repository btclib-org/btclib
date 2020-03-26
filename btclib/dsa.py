#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
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

from hashlib import sha256
from typing import List, Optional, Tuple, Union

from . import der
from .curve import Curve, Point
from .curvemult import _double_mult, _mult_jac, double_mult
from .curves import secp256k1
from .numbertheory import mod_inv
from .rfc6979 import _rfc6979
from .utils import (HashF, Octets, bytes_from_hexstring, int_from_bits,
                    point_from_octets)

# (r, s) or DER serialization (bytes or hex-string)
# DER can include sighash
Sig = Union[Tuple[int, int], Octets]


def serialize(r: int, s: int,
              sighash: Optional[Octets],
              ec: Curve = secp256k1) -> bytes:
    return der.serialize(r, s, sighash, ec)

def deserialize(sig: Octets,
                ec: Curve = secp256k1) -> Tuple[int, int, Optional[bytes]]:
    return der.deserialize(sig, ec)


def sign(msg: Union[bytes, str], q: int, k: Optional[int] = None,
         ec: Curve = secp256k1, hf: HashF = sha256) -> Tuple[int, int]:
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

    if isinstance(msg, str):
        msg = msg.encode()

    # Steps numbering follows SEC 1 v.2 section 4.1.3

    mhd = hf(msg).digest()                        # 4
    # mhd is transformed into an integer modulo ec.n using int_from_bits:
    c = int_from_bits(mhd, ec)                    # 5

    # The secret key q: an integer in the range 1..n-1.
    # SEC 1 v.2 section 3.2.1
    if not 0 < q < ec.n:
        raise ValueError(f"private key {hex(q)} not in [1, n-1]")

    if k is None:
        k = _rfc6979(c, q, ec, hf)                # 1
    if not 0 < k < ec.n:
        raise ValueError(f"ephemeral key {hex(k)} not in [1, n-1]")

    # second part delegated to helper function
    return _sign(c, q, k, ec)


def _sign(c: int, q: int, k: int, ec: Curve = secp256k1) -> Tuple[int, int]:
    # Private function for test/dev purposes
    # it is assumed that q, k, and c are in [1, n-1]

    # Steps numbering follows SEC 1 v.2 section 4.1.3

    RJ = _mult_jac(k, ec.GJ, ec)                  # 1

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


def verify(msg: Union[bytes, str],
           P: Union[Point, Octets],
           sig: Sig,
           ec: Curve = secp256k1, hf: HashF = sha256) -> bool:
    """ECDSA signature verification (SEC 1 v.2 section 4.1.4)."""

    # try/except wrapper for the Errors raised by _verify
    try:
        return _verify(msg, P, sig, ec, hf)
    except Exception:
        return False


def _verify(msg: Union[bytes, str],
            P: Union[Point, Octets],
            sig: Sig,
            ec: Curve = secp256k1, hf: HashF = sha256) -> bool:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    if isinstance(msg, str):
        msg = msg.encode()

    # The message digest mhd: a 32-byte array
    mhd = hf(msg).digest()                               # 2
    c = int_from_bits(mhd, ec)                           # 3

    # second part delegated to helper function
    return _verhlp(c, P, sig, ec)


def _verhlp(c: int,
            P: Union[Point, Octets],
            sig: Sig,
            ec: Curve = secp256k1) -> bool:
    # Private function for test/dev purposes

    # Let P = point(pk); fail if point(pk) fails.
    if not isinstance(P, tuple):
        P = point_from_octets(P, ec)
    else:
        ec.require_on_curve(P)
    if P[1] == 0:
        raise ValueError("public key is infinite")

    if not isinstance(sig, tuple):
        # sighash is not needed
        r, s, _ = der.deserialize(sig, ec)
    else:
        r, s = sig
        _check_sig(r, s, ec)                             # 1

    w = mod_inv(s, ec.n)
    u = c*w
    v = r*w                                              # 4
    # Let R = u*G + v*P.
    RJ = _double_mult(v, (P[0], P[1], 1), u, ec.GJ, ec)  # 5

    # Fail if infinite(R).
    assert RJ[2] != 0, "how did you do that?!?"          # 5

    Rx = (RJ[0]*mod_inv(RJ[2]*RJ[2], ec._p)) % ec._p
    x = Rx % ec.n                                        # 6, 7
    # Fail if r ≠ x(R) %n.
    return r == x                                        # 8


def pubkey_recovery(msg: Union[bytes, str], sig: Sig,
                    ec: Curve = secp256k1, hf: HashF = sha256) -> List[Point]:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See also https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106    
    """

    if isinstance(msg, str):
        msg = msg.encode()

    # The message digest mhd: a 32-byte array
    mhd = hf(msg).digest()                                # 1.5
    c = int_from_bits(mhd, ec)                            # 1.5

    return _pubkey_recovery(c, sig, ec)


def _pubkey_recovery(c: int, sig: Sig, ec: Curve = secp256k1) -> List[Point]:
    # Private function provided for testing purposes only.
    # TODO: use _double_mult instead of double_mult

    if not isinstance(sig, tuple):
        # sighash is not needed
        r, s, _ = der.deserialize(sig, ec)
    else:
        r, s = sig
        _check_sig(r, s, ec)

    # precomputations
    r1 = mod_inv(r, ec.n)
    r1s = r1*s
    r1e = -r1*c
    keys: List[Point] = list()
    # r = R[0] % ec.n
    # if ec.n < R[0] < ec._p (probable when cofactor ec.h > 1)
    # then both x=r and x=r+ec.n must be tested
    for j in range(ec.h):                                 # 1
        x = (r + j*ec.n) % ec._p                     # 1.1
        try:
            # even root first for bitcoin message signing compatibility
            R = x, ec.y_odd(x, False)                     # 1.2, 1.3, and 1.4
            # 1.5 has been performed in the pubkey_recovery calling function
            Q1 = double_mult(r1s, R, r1e, ec.G, ec)       # 1.6.1
            if Q1[1] != 0 and _verhlp(c, Q1, sig, ec):    # 1.6.2
                keys.append(Q1)
            R = ec.opposite(R)                            # 1.6.3
            Q2 = double_mult(r1s, R, r1e, ec.G, ec)
            if Q2[1] != 0 and _verhlp(c, Q2, sig, ec):    # 1.6.2
                keys.append(Q2)                           # 1.6.2
        except Exception:  # R is not a curve point
            pass
    return keys


def _check_sig(r: int, s: int, ec: Curve = secp256k1) -> None:
    # check that the DSA signature is correct
    # and return the signature itself

    # Fail if r is not [1, n-1]
    if not 0 < r < ec.n:
        raise ValueError(f"r ({hex(r)}) not in [1, n-1]")

    # Fail if s is not [1, n-1]
    if not 0 < s < ec.n:
        raise ValueError(f"s ({hex(s)}) not in [1, n-1]")
