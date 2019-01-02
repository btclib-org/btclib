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
from typing import Tuple, List, Optional

from btclib.numbertheory import mod_inv, legendre_symbol
from btclib.ec import Point, EC, pointMult, DblScalarMult, \
    _jac_from_aff, _pointMultJacobian
from btclib.ecutils import bits2int, point2octets, int2octets
from btclib.rfc6979 import rfc6979

ECSS = Tuple[int, int]  # Tuple[Coordinate, int]


def _ecssa_e(ec: EC, hf, r: int, P: Point, m: bytes) -> int:
    # Let e = int(hf(bytes(x(R)) || bytes(dG) || m)) mod n.
    ebytes = int2octets(r, ec.bytesize) # FIXME: hlen, qlen, plen ?
    ebytes += point2octets(ec, P, True)
    ebytes += m
    ebytes = hf(ebytes).digest()
    e = bits2int(ec, ebytes)
    return e
    # should check for e == 0 ? FIXME


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
        errmsg = 'message of wrong size: %s' % len(m)
        errmsg += ' instead of %s' % hf().digest_size
        raise ValueError(errmsg)

    # The secret key d: an integer in the range 1..n-1.
    if not 0 < d < ec.n:
        raise ValueError("private key %X not in (0, n)" % d)
    P = pointMult(ec, d, ec.G)

    # Fail if k' = 0.
    if k is None:
        k = rfc6979(ec, hf, m, d)
    if not 0 < k < ec.n:
        raise ValueError("ephemeral key %X not in (0, n)" % k)

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
    if e == 0:
        raise ValueError("e = 0, signature would not depend on private key")

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

    # Let r = int(sig[ 0:32]); fail if r is not [0, p-1].
    # Let s = int(sig[32:64]); fail if s is not [0, n-1].
    r, s = to_ssasig(ec, sig)

    # The message m: a 32-byte array
    if len(m) != hf().digest_size:
        errmsg = 'message of wrong size: %s' % len(m)
        errmsg += ' instead of %s' % hf().digest_size
        raise ValueError(errmsg)

    # Let P = point(pk); fail if point(pk) fails.
    ec.requireOnCurve(P)
    if P[1] == 0:
        raise ValueError("public key is infinite")

    # Let e = int(hf(bytes(r) || bytes(P) || m)) mod n.
    e = _ecssa_e(ec, hf, r, P, m)
    if e == 0:
        raise ValueError("e = 0, signature does not depend on private key")

    # Let R = sG - eP.
    R = DblScalarMult(ec, s, ec.G, -e, P)

    # Fail if infinite(R).
    if R[1] == 0:
        raise ValueError("sG - eP is infinite")

    # Fail if jacobi(y(R)) ≠ 1.
    if legendre_symbol(R[1], ec._p) != 1:
        raise ValueError("y(sG - eP) is not a quadratic residue")

    # Fail if x(R) ≠ r.
    return R[0] == r


def _ecssa_pubkey_recovery(ec: EC, hf, e: int, sig: ECSS) -> Point:
    """Private function provided for testing purposes only."""

    r, s = to_ssasig(ec, sig)

    # could be obtained from to_ssasig...
    K = r, ec.yQuadraticResidue(r, True)

    if e == 0:
        raise ValueError("invalid (zero) challenge e")
    e1 = mod_inv(e, ec.n)
    P = DblScalarMult(ec, e1*s, ec.G, -e1, K)
    if P[1] == 0:
        raise ValueError("failed")
    return P


def to_ssasig(ec: EC, sig: ECSS) -> Tuple[int, int]:
    """check SSA signature format is correct and return the signature itself"""

    # A signature sig: a 64-byte array.
    if len(sig) != 2:
        m = "invalid length %s for ECSSA signature" % len(sig)
        raise TypeError(m)

    # Let r = int(sig[ 0:32]); fail if r is not [0, p-1].
    r = int(sig[0])
    # skip the following, as it is not really needed
    # assert 0 <= r < ec._p
    # moreover the real check would be to calculate R.y because
    # R.x is valid iif R.y does exist

    # Let s = int(sig[32:64]); fail if s is not [0, n-1].
    s = int(sig[1])
    if not 0 <= s < ec.n:
        raise ValueError("s (%X) not in [0, n-1]" % s)

    return r, s


def ecssa_batch_validation(ec: EC,
                           hf,
                           ms: List[bytes],
                           P: List[Point],
                           a: List[int], 
                           sig: List[ECSS]) -> bool:
    # initialization
    mult = 0
    points = list()
    factors = list()

    u = len(P)
    for i in range(u):
        r, s = to_ssasig(ec, sig[i])
        ebytes = r.to_bytes(32, byteorder="big")
        ebytes += point2octets(ec, P[i], True)
        ebytes += ms[i]
        ebytes = hf(ebytes).digest()
        e = bits2int(ec, ebytes)

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
    TJ = _pointMultJacobian(ec, mult, _jac_from_aff(ec.G))
    RHS = ec._affine_from_jac(RHSJ)
    T = ec._affine_from_jac(TJ)

    return  T == RHS
