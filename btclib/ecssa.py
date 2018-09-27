#!/usr/bin/env python3

""" Elliptic Curve Schnorr Signature Algorithm
"""

from hashlib import sha256
from btclib.ellipticcurves import Union, Tuple, Optional, \
                                  Scalar as PrvKey, \
                                  Point as PubKey, GenericPoint as GenericPubKey, \
                                  mod_inv, \
                                  secp256k1 as ec, \
                                  int_from_Scalar, tuple_from_Point, bytes_from_Point
from btclib.rfc6979 import rfc6979
from btclib.ecsignutils import Message, Signature, int_from_hash

# %% ecssa sign
# https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki


# different structure, cannot compute e (int) before ecssa_sign_raw

def ecssa_sign(m: Message, prvkey: PrvKey, eph_prv: Optional[PrvKey] = None, hasher = sha256) -> Signature:
    if type(m) == str: m = hasher(m.encode()).digest()
    prvkey = int_from_Scalar(ec, prvkey)
    eph_prv = rfc6979(prvkey, m, hasher) if eph_prv is None else int_from_Scalar(ec, eph_prv)
    return ecssa_sign_raw(m, prvkey, eph_prv, hasher) # FIXME: this is just the message hasher

# https://eprint.iacr.org/2018/068
def ecssa_sign_raw(m: bytes, prvkey: int, eph_prv: int, hasher = sha256) -> Signature:
    R = ec.pointMultiply(eph_prv, ec.G)
    # break the simmetry: any criteria could be used, jacobi is standard
    if ec.jacobi(R[1]) != 1:
        # no need to actually change R[1], as it is not used anymore
        # let's fix eph_prv instead, as it is used later
        eph_prv = ec.order - eph_prv
    e = hasher(R[0].to_bytes(32, byteorder="big") +
               bytes_from_Point(ec, ec.pointMultiply(prvkey, ec.G), True) +
               m).digest()
    e = int_from_hash(e, ec.order)
    assert e != 0 and e < ec.order, "sign fail"
    s = (eph_prv + e * prvkey) % ec.order
    return R[0], s


def ecssa_verify(m: Message, ssasig: Signature, pubkey: GenericPubKey, hasher = sha256) -> bool:
    if type(m) == str: m = hasher(m.encode()).digest()
    check_ssasig(ssasig)
    pubkey =  tuple_from_Point(ec, pubkey)
    return ecssa_verify_raw(m, ssasig, pubkey, hasher) # FIXME: this is just the message hasher


def ecssa_verify_raw(m: bytes, ssasig: Signature, pub: PubKey, hasher = sha256) -> bool:
    r, s = ssasig
    e = hasher(r.to_bytes(32, byteorder="big") + bytes_from_Point(ec, pub, True) + m).digest()
    e = int_from_hash(e, ec.order)
    if e == 0 or e >= ec.order:
        return False
    R = ec.pointAdd(ec.pointMultiply(ec.order - e, pub), ec.pointMultiply(s, ec.G))
    if ec.jacobi(R[1]) != 1:
        return False
    return R[0] == ssasig[0]


def ecssa_pubkey_recovery(e: bytes, ssasig: Signature, hasher = sha256) -> PubKey:
    assert len(e) == 32
    check_ssasig(ssasig)
    return ecssa_pubkey_recovery_raw(e, ssasig) # FIXME: this is just the message hasher


def ecssa_pubkey_recovery_raw(e: bytes, ssasig: Signature) -> PubKey:
    r, s = ssasig
    R = (r, ec.yQuadraticResidue(r, True))
    e = int_from_hash(e, ec.order)
    assert e != 0 and e < ec.order, "invalid challenge e"
    e1 = mod_inv(e, ec.order)
    return ec.pointAdd(ec.pointMultiply((e1 * s) % ec.order, ec.G),
                       ec.pointMultiply(ec.order - e1, R))


def check_ssasig(ssasig: Signature) -> bool:
    """check sig has correct ssa format
    """
    assert type(ssasig) == tuple and len(ssasig) == 2 and \
           type(ssasig[0]) == int and type(ssasig[1]) == int, \
           "ssasig must be a tuple of 2 int"
    # TODO: maybe new ec.is_x_valid(x) method
    ec.yOdd(ssasig[0], False) # R.x is valid iif R.y does exist
    assert 0 < ssasig[1] and ssasig[1] < ec.order, "s must be in [1..order]"
    return True
