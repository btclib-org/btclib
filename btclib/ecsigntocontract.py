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
from btclib.ellipticcurves import secp256k1 as ec
from btclib.rfc6979 import rfc6979
from btclib.wifaddress import int_from_prvkey
from btclib.ecdsa import ecdsa_sign, ecdsa_verify, check_dsasig, ecdsa_sign_raw
from btclib.ecssa import ecssa_sign, ecssa_verify, check_ssasig, ecssa_sign_raw


def tweak(k, c, hasher=sha256):
    """tweak kG

    returns:
    - point kG to tweak
    - tweaked private key k + h(kG||c), the corresponding pubkey is a commitment to kG, c
    """
    R = ec.pointMultiply(k, ec.G)
    e = hasher(ec.bytes_from_point(R) + c).digest()
    e = int.from_bytes(e, 'big')
    return R, (e + k) % ec.order

def ecdsa_commit_and_sign(m, prv, c, eph_prv=None, hasher=sha256):
    prv = int_from_prvkey(prv)
    eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else int_from_prvkey(eph_prv)
    R, eph_prv = tweak(eph_prv, c, hasher)
    sig = ecdsa_sign_raw(m, prv, eph_prv)
    receipt = (sig[0], R)
    return sig, receipt

def ecssa_commit_and_sign(m, prv, c, eph_prv=None, hasher=sha256):
    prv = int_from_prvkey(prv)
    eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else int_from_prvkey(eph_prv)
    R, eph_prv = tweak(eph_prv, c, hasher)
    sig = ecssa_sign_raw(m, prv, eph_prv, hasher)
    receipt = (sig[0], R)
    return sig, receipt

# FIXME: have create_commit instead of ecdsa_commit_and_sign
#                                  and ecssa_commit_and_sign
def verify_commit(receipt, c, hasher=sha256):
    w, R = receipt
    ec.y(w, False)  # receipt[0] is valid iif its y does exist
    ec.tuple_from_point(R)  # verify it is a good point
    e = hasher(ec.bytes_from_point(R) + c).digest()
    e = int.from_bytes(e, 'big')
    W = ec.pointAdd(R, ec.pointMultiply(e, ec.G))
    return w % ec.order == W[0] % ec.order
    # weaker verfication! w in [1..ec.order-1] dsa
    #                     w in [1..ec_prime-1] ssa
    # choice to manage with the same function
