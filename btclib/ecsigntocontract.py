#!/usr/bin/env python3

"""sign-to-contract

IDEA:
  Let c be a value (bytes) and P an EC point, then
    c, P -> h(P||c)G + P
  is a commitment operation. (G generator, || concatenation)
  The signature contains an EC point, thus it can become a
  commitment to c.
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
  the verifier checks that:   W.x = (R+eG).x
                              (with e = hash(R||c))
"""

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
    return R, (e + k) % ec.order

def ecdsa_commit_and_sign(m: Message, prvkey: Scalar, c: Message, eph_prv: Optional[Scalar] = None, hasher = sha256) -> Tuple[Signature, Receipt]:
    if type(m) == str: m = hasher(m.encode()).digest()
    prvkey = int_from_Scalar(ec, prvkey)
    if type(c) == str: c = hasher(c.encode()).digest()
    eph_prv = rfc6979(prvkey, m, hasher) if eph_prv is None else int_from_Scalar(ec, eph_prv)

    # commit
    R, eph_prv = tweak(eph_prv, c, hasher)
    # sign
    sig = ecdsa_sign_raw(m, prvkey, eph_prv)
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
    sig = ecssa_sign_raw(m, prvkey, eph_prv, hasher)
    # commit receipt
    receipt = (sig[0], R)
    return sig, receipt

# FIXME: have create_commit instead of ecdsa_commit_and_sign
#                                  and ecssa_commit_and_sign
def verify_commit(receipt: Receipt, c: Message, hasher = sha256) -> bool:
    w, R = receipt
    ec.yOdd(w, False)  # receipt[0] is valid iif its y does exist
    tuple_from_Point(ec, R)  # verify it is a good point
    if type(c) == str: c = hasher(c.encode()).digest()
    e = hasher(bytes_from_Point(ec, R, True) + c).digest()
    e = int.from_bytes(e, 'big')
    W = ec.pointAdd(R, ec.pointMultiply(e, ec.G))
    # w in [1..ec.order-1] dsa
    # w in [1..ec_prime-1] ssa
    # different verify functions?
    return w % ec.order == W[0] % ec.order
