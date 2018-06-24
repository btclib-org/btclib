#!/usr/bin/env python3

""" Elliptic Curve Digital Signature Algorithm
"""

from typing import Tuple
from hashlib import sha256
from btclib.ellipticcurves import secp256k1 as ec
from btclib.numbertheory import mod_inv
from btclib.rfc6979 import rfc6979
from btclib.ecsignutils import int_from_hash
from btclib.wifaddress import int_from_prvkey


def ecdsa_sign(m, prv, eph_prv = None, hasher = sha256) -> Tuple[int, int]:
    if type(m) == str: m = hasher(m.encode()).digest()
    prv = int_from_prvkey(prv)
    eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else int_from_prvkey(eph_prv)
    return ecdsa_sign_raw(m, prv, eph_prv)


def ecdsa_sign_raw(m: bytes, prv: int, eph_prv: int) -> Tuple[int, int]:
    R = ec.pointMultiply(eph_prv, ec.G)
    r = R[0] % ec.order
    h = int_from_hash(m, ec.order)
    # assert h
    s = mod_inv(eph_prv, ec.order) * (h + prv * r) % ec.order
    assert r != 0 and s != 0, "failed to sign"
    return r, s


def ecdsa_verify(m, dsasig: Tuple[int, int], pub, hasher = sha256) -> bool:
    if type(m) == str: m = hasher(m.encode()).digest()
    check_dsasig(dsasig)
    pub =  ec.tuple_from_point(pub)
    return ecdsa_verify_raw(m, dsasig, pub)


def ecdsa_verify_raw(m: bytes, dsasig: Tuple[int, int], pub: Tuple[int, int]) -> bool:
    h = int_from_hash(m, ec.order)
    r, s = dsasig
    s1 = mod_inv(s, ec.order)
    R = ec.pointAdd(ec.pointMultiply(r * s1 % ec.order, pub),
                    ec.pointMultiply(h * s1 % ec.order, ec.G))
    return R[0] % ec.order == r


def ecdsa_pubkey_recovery(m, dsasig, y_mod_2, hasher=sha256) -> Tuple[int, int]:
    if type(m) == str: m = hasher(m.encode()).digest()
    check_dsasig(dsasig)
    assert y_mod_2 in (0, 1)
    return ecdsa_pubkey_recovery_raw(m, dsasig, y_mod_2)


def ecdsa_pubkey_recovery_raw(m: bytes, dsasig: Tuple[int, int], y_mod_2) -> Tuple[int, int]:
    h = int_from_hash(m, ec.order)
    r, s = dsasig
    r1 = mod_inv(r, ec.order)
    R = (r, ec.y(r, y_mod_2))
    return ec.pointAdd(ec.pointMultiply( s * r1 % ec.order, R),
                       ec.pointMultiply(-h * r1 % ec.order, ec.G))


def check_dsasig(dsasig: Tuple[int, int]) -> bool:
    """check sig has correct dsa format
    """
    assert type(dsasig) == tuple and len(dsasig) == 2 and \
           type(dsasig[0]) == int and type(dsasig[1]) == int, \
           "dsasig must be a tuple of 2 int"
    assert 0 < dsasig[0] and dsasig[0] < ec.order and \
           0 < dsasig[1] and dsasig[1] < ec.order, "r and s must be in [1..order]"
    return True
