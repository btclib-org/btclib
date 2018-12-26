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
from typing import Optional
from btclib.ellipticcurves import secp256k1 as ec, pointMultiply, \
                                  Tuple, Scalar, Point, \
                                  bytes_from_Point, int_from_Scalar, \
                                  to_Point
from btclib.rfc6979 import rfc6979
from btclib.ecsignutils import Message, Signature
from btclib.ecdsa import _ecdsa_sign
from btclib.ecssa import _ecssa_sign

Receipt = Tuple[Scalar, Point]

def tweak(k: int, c: bytes, Hash = sha256) -> Tuple[Point, Scalar]:
    """tweak kG

    returns:
    - point kG to tweak
    - tweaked private key k + h(kG||c), the corresponding pubkey is a commitment to kG, c
    """
    R = pointMultiply(ec, k, ec.G)
    e = Hash(bytes_from_Point(ec, R, True) + c).digest()
    e = int.from_bytes(e, 'big')
    return R, (e + k) % ec.n

def ecdsa_commit_and_sign(m: Message,
                          prvkey: Scalar,
                          c: Message,
                          eph_prv: Optional[Scalar] = None,
                          Hash = sha256) -> Tuple[Signature, Receipt]:
    mh = Hash(m).digest()
    prvkey = int_from_Scalar(ec, prvkey)
    ch = Hash(c).digest()
    eph_prv = rfc6979(prvkey, mh, Hash) if eph_prv is None else int_from_Scalar(ec, eph_prv)

    # commit
    R, eph_prv = tweak(eph_prv, ch, Hash)
    # sign
    sig = _ecdsa_sign(mh, prvkey, eph_prv, ec)
    # commit receipt
    receipt = (sig[0], R)
    return sig, receipt

def ecssa_commit_and_sign(m: Message,
                          prvkey: Scalar,
                          c: Message,
                          eph_prv: Optional[Scalar] = None,
                          Hash = sha256) -> Tuple[Signature, Receipt]:
    mh = Hash(m).digest()
    prvkey = int_from_Scalar(ec, prvkey)
    ch = Hash(c).digest()
    eph_prv = rfc6979(prvkey, mh, Hash) if eph_prv is None else int_from_Scalar(ec, eph_prv)

    # commit
    R, eph_prv = tweak(eph_prv, ch, Hash)
    # sign
    sig = _ecssa_sign(mh, prvkey, eph_prv, ec, Hash)
    # commit receipt
    receipt = (sig[0], R)
    return sig, receipt

# FIXME: have create_commit instead of commit_and_sign
def verify_commit(receipt: Receipt, c: Message, Hash = sha256) -> bool:
    w, R = receipt
    ec.yOdd(w, False)  # receipt[0] is valid iif its y does exist
    to_Point(ec, R)  # verify R is a good point
    ch = Hash(c).digest()
    e = Hash(bytes_from_Point(ec, R, True) + ch).digest()
    e = int.from_bytes(e, 'big')
    W = ec.add(R, pointMultiply(ec, e, ec.G))
    # w in [1..n-1] dsa
    # w in [1..p-1] ssa
    # different verify functions?
    return w % ec.n == W[0] % ec.n
