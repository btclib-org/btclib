#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic Curve Schnorr Signature Algorithm.

Implementation according to bip-schnorr:
https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki.
"""

import heapq
import random
from typing import Tuple, Sequence, Optional, Callable, Any

from btclib.numbertheory import mod_inv, legendre_symbol
from btclib.curve import Point, Curve, mult, _mult_jac, double_mult, _double_mult, \
    _jac_from_aff, _multi_mult
from btclib.utils import int_from_bits, octets_from_point, octets_from_int
from btclib.rfc6979 import rfc6979

ECSS = Tuple[int, int]  # Tuple[field element, scalar]


def _ensure_msg_size(hf: Callable[[Any], Any], msg: bytes) -> None:
    if len(msg) != hf().digest_size:
        errmsg = f'message of wrong size: {len(msg)}'
        errmsg += f' instead of {hf().digest_size} bytes'
        raise ValueError(errmsg)


def _e(ec: Curve,
       hf: Callable[[Any], Any],
       r: int,
       P: Point,
       mhd: bytes) -> int:
    # Let e = int(hf(bytes(x(R)) || bytes(dG) || mhd)) mod n.
    h = hf()
    h.update(octets_from_int(r, ec.psize))
    h.update(octets_from_point(ec, P, True))
    h.update(mhd)
    e = int_from_bits(ec, h.digest())
    return e


def sign(ec: Curve,
         hf: Callable[[Any], Any],
         mhd: bytes,
         d: int,
         k: Optional[int] = None) -> ECSS:
    """ECSSA signing operation according to bip-schnorr.

    This signature scheme supports 32-byte messages.
    Differently from ECDSA, the 32-byte message can be a
    digest of other messages, but it does not need to.
    """

    # the bitcoin proposed standard is only valid for curves
    # whose prime p = 3 % 4
    if not ec.pIsThreeModFour:
        errmsg = 'curve prime p must be equal to 3 (mod 4)'
        raise ValueError(errmsg)

    # The message mhd: a 32-byte array
    _ensure_msg_size(hf, mhd)

    # The secret key d: an integer in the range 1..n-1.
    if not 0 < d < ec.n:
        raise ValueError(f"private key {hex(d)} not in [1, n-1]")
    P = mult(ec, d, ec.G)

    # Fail if k' = 0.
    if k is None:
        k = rfc6979(ec, hf, mhd, d)
    if not 0 < k < ec.n:
        raise ValueError(f"ephemeral key {hex(k)} not in [1, n-1]")

    # Let R = k'G.
    RJ = _mult_jac(ec, k, ec.GJ)

    # break the simmetry: any criteria might have been used,
    # jacobi is the proposed bitcoin standard
    # Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k'.
    if legendre_symbol(RJ[1]*RJ[2] % ec._p, ec._p) != 1:
        k = ec.n - k

    Z2 = RJ[2]*RJ[2]
    r = (RJ[0]*mod_inv(Z2, ec._p)) % ec._p

    # Let e = int(hf(bytes(x(R)) || bytes(dG) || mhd)) mod n.
    e = _e(ec, hf, r, P, mhd)

    s = (k + e*d) % ec.n  # s=0 is ok: in verification there is no inverse of s
    # The signature is bytes(x(R) || bytes((k + ed) mod n)).
    return r, s


def verify(ec: Curve,
           hf: Callable[[Any], Any],
           mhd: bytes,
           P: Point,
           sig: ECSS) -> bool:
    """ECSSA verification according to bip-schnorr."""

    # try/except wrapper for the Errors raised by _verify
    try:
        return _verify(ec, hf, mhd, P, sig)
    except Exception:
        return False


def _verify(ec: Curve,
            hf: Callable[[Any], Any],
            mhd: bytes,
            P: Point,
            sig: ECSS) -> bool:
    # This raises Exceptions, while verify should always return True or False

    # the bitcoin proposed standard is only valid for curves
    # whose prime p = 3 % 4
    if not ec.pIsThreeModFour:
        errmsg = 'curve prime p must be equal to 3 (mod 4)'
        raise ValueError(errmsg)

    # Let r = int(sig[ 0:32]).
    # Let s = int(sig[32:64]); fail if s is not [0, n-1].
    r, s = _to_sig(ec, sig)

    # The message mhd: a 32-byte array
    _ensure_msg_size(hf, mhd)

    # Let P = point(pk); fail if point(pk) fails.
    ec.require_on_curve(P)
    if P[1] == 0:
        raise ValueError("public key is infinite")

    # Let e = int(hf(bytes(r) || bytes(P) || mhd)) mod n.
    e = _e(ec, hf, r, P, mhd)

    # Let R = sG - eP.
    # in Jacobian coordinates
    R = _double_mult(ec, s, ec.GJ, -e, (P[0], P[1], 1))

    # Fail if infinite(R).
    if R[2] == 0:
        raise ValueError("sG - eP is infinite")

    # Fail if jacobi(R.y) ≠ 1.
    if legendre_symbol(R[1]*R[2] % ec._p, ec._p) != 1:
        raise ValueError("(sG - eP).y is not a quadratic residue")

    # Fail if R.x ≠ r.
    return R[0] == (R[2]*R[2]*r % ec._p)


def _pubkey_recovery(ec: Curve,
                     hf: Callable[[Any], Any],
                     e: int,
                     sig: ECSS) -> Point:
    # Private function provided for testing purposes only.

    r, s = _to_sig(ec, sig)

    K = r, ec.y_quadratic_residue(r, True)
    # FIXME y_quadratic_residue in Jacobian coordinates?

    if e == 0:
        raise ValueError("invalid (zero) challenge e")
    e1 = mod_inv(e, ec.n)
    P = double_mult(ec, e1*s, ec.G, -e1, K)
    assert P[1] != 0, "how did you do that?!?"
    return P


def _to_sig(ec: Curve, sig: ECSS) -> ECSS:
    # check that the SSA signature is correct
    # and return the signature itself

    # A signature sig: a 64-byte array.
    if len(sig) != 2:
        mhd = f"invalid length {len(sig)} for ECSSA signature"
        raise TypeError(mhd)

    # Let r = int(sig[ 0:32]).
    r = int(sig[0])

    # Let s = int(sig[32:64]); fail if s is not [0, n-1].
    s = int(sig[1])
    if not 0 <= s < ec.n:
        raise ValueError(f"s ({hex(s)}) not in [0, n-1]")

    return r, s


def batch_verify(ec: Curve,
                 hf: Callable[[Any], Any],
                 ms: Sequence[bytes],
                 P: Sequence[Point],
                 sig: Sequence[ECSS]) -> bool:
    """ECSSA batch verification according to bip-schnorr."""

    # try/except wrapper for the Errors raised by _batch_verify
    try:
        return _batch_verify(ec, hf, ms, P, sig)
    except Exception:
        return False


def _batch_verify(ec: Curve,
                  hf: Callable[[Any], Any],
                  ms: Sequence[bytes],
                  P: Sequence[Point],
                  sig: Sequence[ECSS]) -> bool:

    # the bitcoin proposed standard is only valid for curves
    # whose prime p = 3 % 4
    if not ec.pIsThreeModFour:
        errmsg = 'curve prime p must be equal to 3 (mod 4)'
        raise ValueError(errmsg)

    batch_size = len(P)
    if len(ms) != batch_size:
        errMsg = f"mismatch between number of pubkeys ({batch_size}) "
        errMsg += f"and number of messages ({len(ms)})"
        raise ValueError(errMsg)
    if len(sig) != batch_size:
        errMsg = f"mismatch between number of pubkeys ({batch_size}) "
        errMsg += f"and number of signatures ({len(sig)})"
        raise ValueError(errMsg)
    
    if batch_size == 1:
        return _verify(ec, hf, ms[0], P[0], sig[0])

    t = 0
    scalars: Sequence(int) = list()
    points: Sequence[Point] = list()
    for i in range(batch_size):
        r, s = _to_sig(ec, sig[i])
        _ensure_msg_size(hf, ms[i])
        ec.require_on_curve(P[i])
        e = _e(ec, hf, r, P[i], ms[i])
        # raises an error if y does not exist
        # no need to check for quadratic residue
        y = ec.y(r)

        # a in [1, n-1]
        # deterministically generated using a CSPRNG seeded by a
        # cryptographic hash (e.g., SHA256) of all inputs of the
        # algorithm, or randomly generated independently for each
        # run of the batch verification algorithm
        a = (1 if i == 0 else (1+random.getrandbits(ec.nlen)) % ec.n)
        scalars.append(a)
        points.append(_jac_from_aff((r, y)))
        scalars.append(a * e % ec.n)
        points.append(_jac_from_aff(P[i]))
        t += a * s

    TJ = _mult_jac(ec, t, ec.GJ)
    RHSJ = _multi_mult(ec, scalars, points)

    # return T == RHS, checked in Jacobian coordinates
    RHSZ2 = RHSJ[2] * RHSJ[2]
    TZ2 = TJ[2] * TJ[2]
    if (TJ[0] * RHSZ2)  % ec._p != (RHSJ[0] * TZ2) % ec._p:
        return False

    return (TJ[1] * RHSZ2 * RHSJ[2]) % ec._p == (RHSJ[1] * TZ2 * TJ[2]) % ec._p
