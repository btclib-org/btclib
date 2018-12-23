#!/usr/bin/env python3

""" Elliptic Curve Schnorr Signature Algorithm
"""

import heapq
from hashlib import sha256
from typing import List

from btclib.ellipticcurves import Union, Tuple, Optional, \
                                  Scalar as PrvKey, Point as PubKey, \
                                  GenericPoint as GenericPubKey, \
                                  mod_inv, \
                                  EllipticCurve, jac_from_affine, \
                                  DoubleScalarMultiplication, \
                                  int_from_Scalar, tuple_from_Point, \
                                  bytes_from_Point
from btclib.rfc6979 import rfc6979
from btclib.ecsignutils import Message, Signature, int_from_hash

# https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki


# different structure, cannot compute e (int) before ecssa_sign_raw
def ecssa_sign(ec: EllipticCurve, msg: Message, q: PrvKey, eph_prv: Optional[PrvKey] = None, hasher = sha256) -> Signature:
    if isinstance(msg, str): m = hasher(msg.encode()).digest()
    else: m = msg
    q = int_from_Scalar(ec, q)
    eph_prv = None if eph_prv is None else int_from_Scalar(ec, eph_prv)
    return ecssa_sign_raw(ec, m, q, eph_prv, hasher) # FIXME: this is just the message hasher

# https://eprint.iacr.org/2018/068
def ecssa_sign_raw(ec: EllipticCurve, m: bytes, q: int, eph_prv: Optional[int] = None, hasher = sha256) -> Signature:
    G = jac_from_affine(ec.G) 
    Q = ec.pointMultiplyJacobian(q, G)
    k = rfc6979(q, m, hasher) if eph_prv is None else eph_prv
    K = ec.pointMultiplyJacobian(k, G)
    assert K is not None, 'sign fail'
    # break the simmetry:
    # any criteria might have been used, jacobi is bitcoin standard
    assert ec.pIsThreeModFour, 'not a proper curve, the relation p = 3 (mod 4) must hold'
    if ec.jacobi(K[1]) != 1:
        # no need to actually change K[1], as it is not used anymore
        # let just fix k instead, as it is used later
        k = ec.n - k
    ebytes = K[0].to_bytes(ec.bytesize, byteorder="big")
    ebytes += bytes_from_Point(ec, Q, True)
    ebytes += m
    ebytes = hasher(ebytes).digest()
    e = int_from_hash(ebytes, ec.n)
    s = (k + e * q) % ec.n
    assert s != 0, "sign fail"
    return K[0], s


def ecssa_verify(ec: EllipticCurve, msg: Message, ssasig: Signature, Q: GenericPubKey, hasher = sha256) -> bool:
    if isinstance(msg, str): m = hasher(msg.encode()).digest()
    else: m = msg
    check_ssasig(ec, ssasig)
    Q =  tuple_from_Point(ec, Q)
    return ecssa_verify_raw(ec, m, ssasig, Q, hasher) # FIXME: this is just the message hasher


def ecssa_verify_raw(ec: EllipticCurve, m: bytes, ssasig: Signature, Q: PubKey, hasher = sha256) -> bool:
    r, s = ssasig
    # FIXME: curve prime
    # if r >= ec.return_prime(): return False
    e = hasher(r.to_bytes(ec.bytesize, byteorder="big") + bytes_from_Point(ec, Q, True) + m).digest()
    e = int_from_hash(e, ec.n)
    # K = sG - eQ
    K = DoubleScalarMultiplication(ec, s, -e, ec.G, Q)
    if K is None:
        return False
    if ec.jacobi(K[1]) != 1:
        return False
    return K[0] == ssasig[0]

def ecssa_pubkey_recovery(ec: EllipticCurve, e: bytes, ssasig: Signature, hasher = sha256) -> PubKey:
    assert len(e) == 32
    check_ssasig(ec, ssasig)
    return ecssa_pubkey_recovery_raw(ec, e, ssasig) # FIXME: this is just the message hasher

def ecssa_pubkey_recovery_raw(ec: EllipticCurve, ebytes: bytes, ssasig: Signature) -> PubKey:
    r, s = ssasig
    K = (r, ec.yQuadraticResidue(r, True))
    e = int_from_hash(ebytes, ec.n)
    assert e != 0, "invalid challenge e"
    e1 = mod_inv(e, ec.n)
    Q = DoubleScalarMultiplication(ec, e1*s, -e1, ec.G, K)
    assert Q is not None, "failed"
    return Q

def check_ssasig(ec: EllipticCurve, ssasig: Signature) -> bool:
    """check sig has correct ssa format
    """
    assert type(ssasig) == tuple and len(ssasig) == 2 and \
           type(ssasig[0]) == int and type(ssasig[1]) == int, \
           "ssasig must be a tuple of 2 int"
    ec.yOdd(ssasig[0], False) # R.x is valid iif R.y does exist
    # FIXME: it might be 0 <= ssasig[1]
    assert 0 < ssasig[1] and ssasig[1] < ec.n, "s must be in [1..n]"
    return True

def ecssa_batch_validation(ec: EllipticCurve, ms: List[bytes], sig: List[Signature], Q: List[PubKey], a: List[int], hasher = sha256) -> bool:
    u = len(Q)
    # initialization
    mult = 0
    points = list()
    factors = list()

    for i in range(0, u):
        r, s = sig[i]
        ebytes = r.to_bytes(32, byteorder="big")
        ebytes += bytes_from_Point(ec, Q[i], True)
        ebytes += ms[i]
        ebytes = hasher(ebytes).digest()
        e = int_from_hash(ebytes, ec.n)

        # FIXME: curve prime
        p = ec._p
        c = (pow(r, 3) + 7) % p
        y = pow(c, (p + 1) // 4, p)
        assert pow(y, 2, p) == c

        mult += a[i] * s % ec.n
        points.append(jac_from_affine((r, y)))
        factors.append(a[i])
        points.append(jac_from_affine(Q[i]))
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
        K2 = ec.pointAddJacobian(K1, K2)
        a1 -= a2
        if a1 > 0: 
            heapq.heappush(boscoster,(-a1, K1))
        heapq.heappush(boscoster,(-a2, K2))
        
    aK = heapq.heappop(boscoster)
    RHS = ec.pointMultiplyJacobian(-aK[0], aK[1])
    
    return ec.pointMultiplyJacobian(mult, jac_from_affine(ec.G)) == RHS
