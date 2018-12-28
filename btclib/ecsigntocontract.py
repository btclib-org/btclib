#!/usr/bin/env python3

"""sign-to-contract

    IDEA:
    Let c be a value (bytes) and P an EC point, then
    c, P -> h(P||c)G + P
    is a commitment operation. (G generator, || concatenation)
    The signature contains an EC point, thus it can become a commitment to c.

    HOW:
    when signing, generate a nonce (k) and compute a EC point (R = kG)
    instead of proceeding using (k,R), compute a value (e) that is a
    commitment to c:
    e = hash(R||c)
    substitute the nonce k with k+e and R with R+eG, and proceed signing
    in the standard way, using (k+e,R+eG).

    COMMITMENT VERIFICATION:
    the verifier can see W.x (W = R+eG) on the signature
    the signer (and committer) provides R and c
    the verifier checks that:
    W.x = (R+eG).x (with e = hash(R||c))
"""

from typing import Optional

from btclib.ellipticcurves import EllipticCurve, pointMultiply, Tuple, \
    Scalar, Point, GenericPoint, bytes_from_Point, int_from_Scalar, \
    to_Point
from btclib.ecsignutils import int_from_hlenbytes, bytes_from_hlenbytes
from btclib.rfc6979 import rfc6979
from btclib.ecdsa import ecdsa_sign, ECDS
from btclib.ecssa import ecssa_sign, ECSS

Receipt = Tuple[Scalar, GenericPoint]


def tweak(k: int, c: bytes, ec: EllipticCurve, Hash) -> Tuple[Point, int]:
    """tweak kG

    returns:
    - point kG to tweak
    - tweaked private key k + h(kG||c), the corresponding pubkey is a commitment to kG, c
    """
    R = pointMultiply(ec, k, ec.G)
    e = Hash(bytes_from_Point(ec, R, True) + c).digest()
    e = int.from_bytes(e, 'big')
    return R, (e + k) % ec.n


def ecdsa_commit_and_sign(m: bytes,
                          prvkey: Scalar,
                          c: bytes,
                          eph_prv: Optional[Scalar],
                          ec: EllipticCurve,
                          Hash) -> Tuple[Tuple[int, int], Tuple[int, Point]]:
    mh = Hash(m).digest()
    prvkey = int_from_Scalar(ec, prvkey)
    eph_prv = rfc6979(
        prvkey, mh, ec, Hash) if eph_prv is None else int_from_Scalar(ec, eph_prv)

    ch = Hash(c).digest()

    # commit
    R, eph_prv = tweak(eph_prv, ch, ec, Hash)
    # sign
    sig = ecdsa_sign(m, prvkey, eph_prv, ec, Hash)
    # commit receipt
    receipt = sig[0], R
    return sig, receipt


def ecssa_commit_and_sign(m: bytes,
                          prvkey: Scalar,
                          c: bytes,
                          eph_prv: Optional[Scalar],
                          ec: EllipticCurve,
                          Hash) -> Tuple[Tuple[int, int], Tuple[int, Point]]:
    m = bytes_from_hlenbytes(m, Hash)
    prvkey = int_from_Scalar(ec, prvkey)
    ch = Hash(c).digest()
    eph_prv = rfc6979(
        prvkey, m, ec, Hash) if eph_prv is None else int_from_Scalar(ec, eph_prv)

    # commit
    R, eph_prv = tweak(eph_prv, ch, ec, Hash)
    # sign
    sig = ecssa_sign(m, prvkey, eph_prv, ec, Hash)
    # commit receipt
    receipt = sig[0], R
    return sig, receipt

# FIXME: have create_commit instead of commit_and_sign


def verify_commit(receipt: Receipt,
                  c: bytes,
                  ec: EllipticCurve,
                  Hash) -> bool:
    w, R = receipt
    # w in [1..n-1] dsa
    # w in [1..p-1] ssa
    # different verify functions?
    R = to_Point(ec, R)  # also verify R is a good point
    ch = Hash(c).digest()
    e = Hash(bytes_from_Point(ec, R, True) + ch).digest()
    e = int_from_hlenbytes(e, ec, Hash)
    W = ec.add(R, pointMultiply(ec, e, ec.G))
    # different verify functions?
    # return w == W[0] # ECSS
    return w == W[0] % ec.n  # ECDS
