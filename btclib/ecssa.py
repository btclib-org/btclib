#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic Curve Schnorr Signature Algorithm

   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
"""

import heapq
import random
from typing import Tuple, List, Optional

from btclib.numbertheory import mod_inv, legendre_symbol
from btclib.ec import Point, EC, pointMult, DblScalarMult, \
    _jac_from_aff, _pointMultJacobian
from btclib.ecutils import bits2int, point2octets, int2octets
from btclib.rfc6979 import rfc6979

ECSS = Tuple[int, int]  # Tuple[Coordinate, int]


def _ecssa_e(ec: EC, hf, r: int, P: Point, m: bytes) -> int:
    # Let e = int(hf(bytes(x(R)) || bytes(dG) || m)) mod n.
    ebytes = int2octets(r, ec.psize) # FIXME: hsize, nsize ?
    ebytes += point2octets(ec, P, True)
    ebytes += m
    ebytes = hf(ebytes).digest()
    e = bits2int(ec, ebytes)
    return e


def ecssa_sign(ec: EC, hf, m: bytes, d: int,
               k: Optional[int] = None) -> Tuple[int, int]:
    """ECSSA signing operation according to bip-schnorr

       https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
    """

    # the bitcoin proposed standard is only valid for curves
    # whose prime p = 3 % 4
    if not ec.pIsThreeModFour:
        errmsg = 'curve prime p must be equal to 3 (mod 4)'
        raise ValueError(errmsg)

    # This signature scheme supports 32-byte messages.
    # Differently from ECDSA, the 32-byte message can be
    # a digest of other messages, but it does not need to.

    # The message m: a 32-byte array
    if len(m) != hf().digest_size:
        errmsg = f'message of wrong size: {len(m)}'
        errmsg += f' instead of {hf().digest_size}'
        raise ValueError(errmsg)

    # The secret key d: an integer in the range 1..n-1.
    if not 0 < d < ec.n:
        raise ValueError(f"private key {hex(d)} not in (0, n)")
    P = pointMult(ec, d, ec.G)

    # Fail if k' = 0.
    if k is None:
        k = rfc6979(ec, hf, m, d)
    if not 0 < k < ec.n:
        raise ValueError(f"ephemeral key {hex(k)} not in (0, n)")

    # Let R = k'G.
    R = pointMult(ec, k, ec.G)

    # Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k'.
    # break the simmetry: any criteria might have been used,
    # jacobi is the proposed bitcoin standard
    if legendre_symbol(R[1], ec._p) != 1:
        # no need to actually change R[1], as it is not used anymore
        # let just fix k instead, as that is used later
        k = ec.n - k

    # Let e = int(hf(bytes(x(R)) || bytes(dG) || m)) mod n.
    e = _ecssa_e(ec, hf, R[0], P, m)

    s = (k + e*d) % ec.n  # s=0 is ok: in verification there is no inverse of s
    # The signature is bytes(x(R)) || bytes(k + ed mod n).
    return R[0], s


def ecssa_verify(ec: EC, hf, m: bytes, P: Point, sig: ECSS) -> bool:
    """ECSSA veryfying operation according to bip-schnorr

       https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
    """

    # this is just a try/except wrapper
    # _ecssa_verify raises Errors
    try:
        return _ecssa_verify(ec, hf, m, P, sig)
    except Exception:
        return False


def _ecssa_verify(ec: EC, hf, m: bytes, P: Point, sig: ECSS) -> bool:
    """Private function provided for testing purposes only.
    
       It raises Errors, while verify should always return True or False

       https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
    """

    # the bitcoin proposed standard is only valid for curves
    # whose prime p = 3 % 4
    if not ec.pIsThreeModFour:
        errmsg = 'curve prime p must be equal to 3 (mod 4)'
        raise ValueError(errmsg)

    # Let r = int(sig[ 0:32]).
    # Let s = int(sig[32:64]); fail if s is not [0, n-1].
    r, s = _to_ssasig(ec, sig)

    # The message m: a 32-byte array
    if len(m) != hf().digest_size:
        errmsg = f'message of wrong size: {len(m)}'
        errmsg += f' instead of {hf().digest_size}'
        raise ValueError(errmsg)

    # Let P = point(pk); fail if point(pk) fails.
    ec.requireOnCurve(P)
    if P[1] == 0:
        raise ValueError("public key is infinite")

    # Let e = int(hf(bytes(r) || bytes(P) || m)) mod n.
    e = _ecssa_e(ec, hf, r, P, m)

    # Let R = sG - eP.
    R = DblScalarMult(ec, s, ec.G, -e, P)

    # Fail if infinite(R).
    if R[1] == 0:
        raise ValueError("sG - eP is infinite")

    # Fail if jacobi(y(R)) ≠ 1.
    if legendre_symbol(R[1], ec._p) != 1:
        raise ValueError("(sG - eP).y is not a quadratic residue")

    # Fail if x(R) ≠ r.
    return R[0] == r


def _ecssa_pubkey_recovery(ec: EC, hf, e: int, sig: ECSS) -> Point:
    """Private function provided for testing purposes only."""

    r, s = _to_ssasig(ec, sig)

    K = r, ec.yQuadraticResidue(r, True)

    if e == 0:
        raise ValueError("invalid (zero) challenge e")
    e1 = mod_inv(e, ec.n)
    P = DblScalarMult(ec, e1*s, ec.G, -e1, K)
    assert P[1] != 0, "how did you do that?!?"
    return P


def _to_ssasig(ec: EC, sig: ECSS) -> Tuple[int, int]:
    """check SSA signature format is correct and return the signature itself"""

    # A signature sig: a 64-byte array.
    if len(sig) != 2:
        m = f"invalid length {len(sig)} for ECSSA signature"
        raise TypeError(m)

    # Let r = int(sig[ 0:32]).
    r = int(sig[0])

    # Let s = int(sig[32:64]); fail if s is not [0, n-1].
    s = int(sig[1])  # FIXME: int from bytes ?
    if not 0 <= s < ec.n:
        raise ValueError(f"s ({hex(s)}) not in [0, n-1]")

    return r, s


def ecssa_batch_validation(ec: EC,
                           hf,
                           ms: List[bytes],
                           P: List[Point],
                           sig: List[ECSS]) -> bool:

    u = len(P)

    a = [1]
    # deterministically generated using a CSPRNG seeded by a cryptographic
    # hash (e.g., SHA256) of all inputs of the algorithm, or randomly generated
    # independently for each run of the batch verification algorithm
    for i in range(1, u):
        a.append(random.getrandbits(ec.nlen) % ec.n)

    mult = 0
    points = list()
    factors = list()
    for i in range(u):
        r, s = _to_ssasig(ec, sig[i])
        e = _ecssa_e(ec, hf, r, P[i], ms[i])

        y = ec.y(r)  # raises an error if y does not exist

        mult += a[i] * s % ec.n
        points.append(_jac_from_aff((r, y)))
        factors.append(a[i])
        points.append(_jac_from_aff(P[i]))
        factors.append(a[i] * e % ec.n)

    # Bos-coster's algorithm, source:
    # https://cr.yp.to/badbatch/boscoster2.py
    boscoster = list(zip([-n for n in factors], points))
    heapq.heapify(boscoster)
    while len(boscoster) > 1:
        aK1 = heapq.heappop(boscoster)
        aK2 = heapq.heappop(boscoster)
        a1, K1 = -aK1[0], aK1[1]
        a2, K2 = -aK2[0], aK2[1]
        K2 = ec._addJacobian(K1, K2)
        a1 -= a2
        if a1 > 0:
            heapq.heappush(boscoster, (-a1, K1))
        heapq.heappush(boscoster, (-a2, K2))
    aK = heapq.heappop(boscoster)

    RHSJ = _pointMultJacobian(ec, -aK[0], aK[1])
    TJ = _pointMultJacobian(ec, mult, ec.GJ)
    RHS = ec._affine_from_jac(RHSJ)
    T = ec._affine_from_jac(TJ)

    return T == RHS
