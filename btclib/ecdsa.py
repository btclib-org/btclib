#!/usr/bin/env python3

""" Elliptic Curve Digital Signature Algorithm
"""

from hashlib import sha256
from typing import List

from btclib.ellipticcurves import Union, Tuple, Optional, \
                                  Scalar as PrvKey, Point as PubKey, \
                                  GenericPoint as GenericPubKey, \
                                  mod_inv, \
                                  EllipticCurve, jac_from_affine, \
                                  DoubleScalarMultiplication, \
                                  int_from_Scalar, tuple_from_Point
from btclib.rfc6979 import rfc6979
from btclib.ecsignutils import Message, Signature, int_from_hash

def ecdsa_sign(ec: EllipticCurve, msg: Message, q: PrvKey, eph_prv: Optional[PrvKey] = None, hasher = sha256) -> Signature:
    if isinstance(msg, str): m = hasher(msg.encode()).digest()
    else: m = msg
    q = int_from_Scalar(ec, q)
    eph_prv = None if eph_prv is None else int_from_Scalar(ec, eph_prv)
    return ecdsa_sign_raw(ec, m, q, eph_prv)

def ecdsa_sign_raw(ec: EllipticCurve, m: bytes, q: int, eph_prv: Optional[int] = None, hasher = sha256) -> Signature:
    k = rfc6979(q, m, hasher) if eph_prv is None else eph_prv
    K = ec.pointMultiplyJacobian(k, jac_from_affine(ec.G))
    assert K is not None, 'K is None, failed to sign'
    r = K[0] % ec.n
    assert r != 0, "r=0, failed to sign"
    e = int_from_hash(m, ec.n)
    s = mod_inv(k, ec.n) * (e + q * r) % ec.n
    assert s != 0, "s=0, failed to sign"
    return r, s

def ecdsa_verify(ec: EllipticCurve, msg: Message, dsasig: Signature, Q: GenericPubKey, hasher = sha256) -> bool:
    if isinstance(msg, str): m = hasher(msg.encode()).digest()
    else: m = msg
    check_dsasig(ec, dsasig)
    Q = tuple_from_Point(ec, Q)
    return ecdsa_verify_raw(ec, m, dsasig, Q)

def ecdsa_verify_raw(ec: EllipticCurve, m: bytes, dsasig: Signature, Q: PubKey) -> bool:
    r, s = dsasig
    # FIXME: add r, s validation
    e = int_from_hash(m, ec.n)
    s1 = mod_inv(s, ec.n)
    # K = (r1*s)Q + (e*s1)G
    K = DoubleScalarMultiplication(ec, r*s1, e*s1, Q, ec.G)
    if K is None:
        return False
    return K[0] % ec.n == r

def ecdsa_pubkey_recovery(ec: EllipticCurve, msg: Message, dsasig: Signature, hasher = sha256) -> List[PubKey]:
    if isinstance(msg, str): m = hasher(msg.encode()).digest()
    else: m = msg
    check_dsasig(ec, dsasig)
    return ecdsa_pubkey_recovery_raw(ec, m, dsasig)

def ecdsa_pubkey_recovery_raw(ec: EllipticCurve, m: bytes, dsasig: Signature) -> List[PubKey]:
    keys = [PubKey]
    e = int_from_hash(m, ec.n)
    r, s = dsasig
    x = r
    # another good reason to have a class method returning p
    # (otherwise add the cofactor to the class structure)
    # FIXME: curve prime
    while x < ec._EllipticCurve__p: 
        try:
            Keven = (x, ec.yOdd(x, 0))
            Kodd  = (x, ec.yOdd(x, 1))
            x1 = mod_inv(x, ec.n)
            sx1 = s*x1
            ex1 =-e*x1
            keys += [DoubleScalarMultiplication(ec, sx1, ex1, Keven, ec.G),
                     DoubleScalarMultiplication(ec, sx1, ex1,  Kodd, ec.G)]
        except ValueError: # can't get a curve's point
            pass
        x = x + ec.n
    return keys

def check_dsasig(ec: EllipticCurve, dsasig: Signature) -> bool:
    """check sig has correct dsa format
    """
    assert type(dsasig) == tuple and len(dsasig) == 2 and \
           type(dsasig[0]) == int and type(dsasig[1]) == int, \
           "dsasig must be a tuple of 2 int"
    assert 0 < dsasig[0] and dsasig[0] < ec.n and \
           0 < dsasig[1] and dsasig[1] < ec.n, "r and s must be in [1..n]"
    return True
