#!/usr/bin/env python3

from hashlib import sha256
from btclib.ellipticcurves import Optional, Tuple, \
                                  Scalar, Point, \
                                  secp256k1 as ec, \
                                  bytes_from_Point, int_from_Scalar, \
                                  tuple_from_Point
from btclib.rfc6979 import rfc6979
from btclib.ecdsa import ecdsa_sign, ecdsa_verify, check_dsasig, ecdsa_sign_raw
from btclib.ecssa import ecssa_sign, ecssa_verify, check_ssasig, ecssa_sign_raw
from btclib.ecsignutils import Message, Signature

Receipt = Tuple[Scalar, Point]

def tweak(k: int, c: bytes, hasher = sha256) -> Tuple[Point, Scalar]:
    """tweak kG

    returns:
    - point kG to tweak
    - tweaked private key k + h(kG||c), the corresponding pubkey is a commitment to kG, c
    """
    R = ec.pointMultiply(k, ec.G)
    e = hasher(bytes_from_Point(ec, R, True) + c).digest()
    e = int.from_bytes(e, 'big')
    return R, (e + k) % ec.n

def ecdsa_commit_and_sign(m: Message, prvkey: Scalar, c: Message, eph_prv: Optional[Scalar] = None, hasher = sha256) -> Tuple[Signature, Receipt]:
    if type(m) == str: m = hasher(m.encode()).digest()
    prvkey = int_from_Scalar(ec, prvkey)
    if type(c) == str: c = hasher(c.encode()).digest()
    eph_prv = rfc6979(prvkey, m, hasher) if eph_prv is None else int_from_Scalar(ec, eph_prv)

    # commit
    R, eph_prv = tweak(eph_prv, c, hasher)
    # sign
    sig = ecdsa_sign_raw(ec, m, prvkey, eph_prv)
    # commit receipt
    receipt = (sig[0], R)
    return sig, receipt

def ecssa_commit_and_sign(m: Message, prvkey: Scalar, c: Message, eph_prv: Optional[Scalar] = None, hasher = sha256) -> Tuple[Signature, Receipt]:
    if type(m) == str: m = hasher(m.encode()).digest()
    prvkey = int_from_Scalar(ec, prvkey)
    if type(c) == str: c = hasher(c.encode()).digest()
    eph_prv = rfc6979(prvkey, m, hasher) if eph_prv is None else int_from_Scalar(ec, eph_prv)

    # commit
    R, eph_prv = tweak(eph_prv, c, hasher)
    # sign
    sig = ecssa_sign_raw(ec, m, prvkey, eph_prv, hasher)
    # commit receipt
    receipt = (sig[0], R)
    return sig, receipt

# FIXME: have create_commit instead of ecdsa_commit_and_sign
#                                  and ecssa_commit_and_sign
def verify_commit(receipt: Receipt, c: Message, hasher = sha256) -> bool:
    w, R = receipt
    ec.yOdd(w, False)  # receipt[0] is valid iif its y does exist
    tuple_from_Point(ec, R)  # verify R is a good point
    if type(c) == str: c = hasher(c.encode()).digest()
    e = hasher(bytes_from_Point(ec, R, True) + c).digest()
    e = int.from_bytes(e, 'big')
    W = ec.pointAdd(R, ec.pointMultiply(e, ec.G))
    # w in [1..n-1] dsa
    # w in [1..p-1] ssa
    # different verify functions?
    return w % ec.n == W[0] % ec.n
