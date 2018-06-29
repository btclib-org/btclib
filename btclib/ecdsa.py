#!/usr/bin/env python3

""" Elliptic Curve Digital Signature Algorithm
"""

from hashlib import sha256
from btclib.ellipticcurves import Union, Tuple, Optional, \
                                  Scalar as PrvKey, \
                                  Point as PubKey, GenericPoint as GenericPubKey, \
                                  mod_inv, int_from_Scalar, tuple_from_point, \
                                  secp256k1 as ec
from btclib.rfc6979 import rfc6979
from btclib.ecsignutils import Message, Signature, int_from_hash

def ecdsa_sign(m: Message, prvkey: PrvKey, eph_prv: Optional[PrvKey] = None, hasher = sha256) -> Signature:
    if type(m) == str: m = hasher(m.encode()).digest()
    prvkey = int_from_Scalar(ec, prvkey)
    eph_prv = rfc6979(prvkey, m, hasher) if eph_prv is None else int_from_Scalar(ec, eph_prv)
    return ecdsa_sign_raw(m, prvkey, eph_prv)


def ecdsa_sign_raw(m: bytes, prvkey: int, eph_prv: int) -> Signature:
    R = ec.pointMultiply(eph_prv, ec.G)
    r = R[0] % ec.order
    h = int_from_hash(m, ec.order)
    # assert h
    s = mod_inv(eph_prv, ec.order) * (h + prvkey * r) % ec.order
    assert r != 0 and s != 0, "failed to sign"
    return r, s


def ecdsa_verify(m: Message, dsasig: Signature, pubkey: GenericPubKey, hasher = sha256) -> bool:
    if type(m) == str: m = hasher(m.encode()).digest()
    check_dsasig(dsasig)
    pubkey = tuple_from_point(ec, pubkey)
    return ecdsa_verify_raw(m, dsasig, pubkey)


def ecdsa_verify_raw(m: bytes, dsasig: Signature, pubkey: PubKey) -> bool:
    h = int_from_hash(m, ec.order)
    r, s = dsasig
    s1 = mod_inv(s, ec.order)
    R = ec.pointAdd(ec.pointMultiply(r * s1 % ec.order, pubkey),
                    ec.pointMultiply(h * s1 % ec.order, ec.G))
    return R[0] % ec.order == r


def ecdsa_pubkey_recovery(m: Message, dsasig: Signature, odd1even0: int, hasher = sha256) -> PubKey:
    if type(m) == str: m = hasher(m.encode()).digest()
    check_dsasig(dsasig)
    assert odd1even0 in (0, 1)
    return ecdsa_pubkey_recovery_raw(m, dsasig, odd1even0)


def ecdsa_pubkey_recovery_raw(m: bytes, dsasig: Signature, odd1even0: int) -> PubKey:
    h = int_from_hash(m, ec.order)
    r, s = dsasig
    r1 = mod_inv(r, ec.order)
    R = (r, ec.y(r, odd1even0))
    return ec.pointAdd(ec.pointMultiply( s * r1 % ec.order, R),
                       ec.pointMultiply(-h * r1 % ec.order, ec.G))


def check_dsasig(dsasig: Signature) -> bool:
    """check sig has correct dsa format
    """
    assert type(dsasig) == tuple and len(dsasig) == 2 and \
           type(dsasig[0]) == int and type(dsasig[1]) == int, \
           "dsasig must be a tuple of 2 int"
    assert 0 < dsasig[0] and dsasig[0] < ec.order and \
           0 < dsasig[1] and dsasig[1] < ec.order, "r and s must be in [1..order]"
    return True
