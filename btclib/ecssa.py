#!/usr/bin/env python3

""" Elliptic Curve Schnorr Signature Algorithm
"""

from hashlib import sha256
from btclib.ellipticcurves import Union, Tuple, Optional, \
                                  Scalar as PrvKey, \
                                  Point as PubKey, GenericPoint as GenericPubKey, \
                                  mod_inv, \
                                  EllipticCurve, \
                                  int_from_Scalar, tuple_from_Point, bytes_from_Point
from btclib.rfc6979 import rfc6979
from btclib.ecsignutils import Message, Signature, int_from_hash

# %% ecssa sign
# https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki


# different structure, cannot compute e (int) before ecssa_sign_raw

def ecssa_sign(ec: EllipticCurve, m: Message, q: PrvKey, eph_prv: Optional[PrvKey] = None, hasher = sha256) -> Signature:
    assert ec.return_prime() % 4 == 3, 'not a proper curve, the relation p = 3 (mod 4) must hold'
    if type(m) == str: m = hasher(m.encode()).digest()
    q = int_from_Scalar(ec, q)
    eph_prv = rfc6979(q, m, hasher) if eph_prv is None else int_from_Scalar(ec, eph_prv)
    return ecssa_sign_raw(ec, m, q, eph_prv, hasher) # FIXME: this is just the message hasher

# https://eprint.iacr.org/2018/068
def ecssa_sign_raw(ec: EllipticCurve, m: bytes, q: int, eph_prv: int, hasher = sha256) -> Signature:
    K = ec.pointMultiply(eph_prv, ec.G)
    assert K != None, 'sign fail'
    # break the simmetry: any criteria could be used, jacobi is standard
    if ec.jacobi(K[1]) != 1:
        # no need to actually change R[1], as it is not used anymore
        # let's fix eph_prv instead, as it is used later
        eph_prv = ec.n - eph_prv
    e = hasher(K[0].to_bytes(ec.bytesize, byteorder="big") +
               bytes_from_Point(ec, ec.pointMultiply(q, ec.G), True) +
               m).digest()
    e = int_from_hash(e, ec.n) % ec.n
    assert e != 0, "sign fail"
    s = (eph_prv + e * q) % ec.n
    assert s != 0, "sign fail"
    return K[0], s


def ecssa_verify(ec: EllipticCurve, m: Message, ssasig: Signature, Q: GenericPubKey, hasher = sha256) -> bool:
    if type(m) == str: m = hasher(m.encode()).digest()
    check_ssasig(ec, ssasig)
    Q =  tuple_from_Point(ec, Q)
    return ecssa_verify_raw(ec, m, ssasig, Q, hasher) # FIXME: this is just the message hasher


def ecssa_verify_raw(ec: EllipticCurve, m: bytes, ssasig: Signature, Q: PubKey, hasher = sha256) -> bool:
    r, s = ssasig
    if r >= ec.return_prime():
        return False
    e = hasher(r.to_bytes(ec.bytesize, byteorder="big") + bytes_from_Point(ec, Q, True) + m).digest()
    e = int_from_hash(e, ec.n) % ec.n
    # R = sG - eP
    K = ec.pointAdd(ec.pointMultiply(s, ec.G), ec.pointMultiply(ec.n - e, Q))
    if K is None or ec.jacobi(K[1]) != 1:
        return False
    return K[0] == ssasig[0]


def ecssa_pubkey_recovery(ec: EllipticCurve, e: bytes, ssasig: Signature, hasher = sha256) -> PubKey:
    assert len(e) == 32
    check_ssasig(ec, ssasig)
    return ecssa_pubkey_recovery_raw(ec, e, ssasig) # FIXME: this is just the message hasher


def ecssa_pubkey_recovery_raw(ec: EllipticCurve, e: bytes, ssasig: Signature) -> PubKey:
    r, s = ssasig
    K = (r, ec.yQuadraticResidue(r, True))
    e = int_from_hash(e, ec.n) % ec.n
    assert e != 0, "invalid challenge e"
    e1 = mod_inv(e, ec.n)
    return ec.pointAdd(ec.pointMultiply((e1 * s) % ec.n, ec.G),
                       ec.pointMultiply(ec.n - e1, K))


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