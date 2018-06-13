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
    e = hash(R.x||c)
  substitute the nonce k with k+e and R with R+eG, and proceed signing
  in the standard way, using (k+e,R+eG).
COMMITMENT VERIFICATION:
  the verifier can see W.x (W = R+eG) on the signature
  the signer (and committer) provides R and c
  the verifier checks that:   W.x = (R+eG).x
                              (with e = hash(R.x||c))
"""

from hashlib import sha256
from base58 import b58decode_check, base58digits as b58digits
from ECsecp256k1 import ec
from FiniteFields import mod_inv, mod_sqrt
from string import hexdigits
from rfc6979 import rfc6979
from ecsignutils import int_from_hash
from WIF_address import int_from_prvkey
from ecdsa import ecdsa_sign, ecdsa_verify, check_dsasig, ecdsa_pubkey_recovery, ecdsa_sign_raw
from ecssa import ecssa_sign, ecssa_verify, check_ssasig, ecssa_pubkey_recovery, ecssa_sign_raw


def tweak(k, c, hasher=sha256):
    """tweak kG

    returns:
    - point kG to tweak
    - tweaked private key k + h(kG||c), the corresponding pubkey is a commitment to kG, c
    """
    R = ec.pointMultiply(k)
    e = int_from_hash(hasher(R[0].to_bytes(32, 'big') + c).digest())
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

def verify_commit(receipt, c, hasher=sha256):
    ec.y(receipt[0], False) # receipt[0] is valid iif its y does exist
    ec.tuple_from_point(receipt[1]) # verify it is a good point
    w, R = receipt
    e = int_from_hash(hasher(R[0].to_bytes(32, 'big') + c).digest())
    W = ec.pointAdd(R, ec.pointMultiply(e))
    return w % ec.order == W[0] % ec.order
    # weaker verfication! w in [1..ec.order-1] dsa
    #                     w in [1..ec_prime-1] ssa
    # choice to manage with the same function


if __name__ == "__main__":
    prv = 0x1
    pub = ec.pointMultiply(prv)
    m = sha256("hello world".encode()).digest()
    c = sha256("sign to contract".encode()).digest()

    sig_ecdsa, receipt_ecdsa = ecdsa_commit_and_sign(m, prv, c)
    assert ecdsa_verify(m, sig_ecdsa, pub)
    assert pub in (ecdsa_pubkey_recovery(m, sig_ecdsa, 0), ecdsa_pubkey_recovery(m, sig_ecdsa, 1))
    assert verify_commit(receipt_ecdsa, c)

    sig_ecssa, receipt_ecssa = ecssa_commit_and_sign(m, prv, c)
    assert ecssa_verify(m, sig_ecssa, pub)
    assert pub in (ecssa_pubkey_recovery(m, sig_ecssa), ecssa_pubkey_recovery(m, sig_ecssa))
    assert verify_commit(receipt_ecssa, c)
