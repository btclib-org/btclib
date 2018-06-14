#!/usr/bin/env python3

""" Elliptic Curve Schnorr Signature Algorithm
"""

from hashlib import sha256
from ellipticcurves import secp256k1 as ec
from FiniteFields import mod_inv
from rfc6979 import rfc6979
from ecsignutils import int_from_hash
from WIF_address import int_from_prvkey

# %% ecssa sign
# https://github.com/sipa/secp256k1/blob/968e2f415a5e764d159ee03e95815ea11460854e/src/modules/schnorr/schnorr.md

# different structure, cannot compute e (int) before ecssa_sign_raw

def ecssa_sign(m, prv, eph_prv=None, hasher=sha256):
    if type(m) == str: m = hasher(m.encode()).digest()
    prv = int_from_prvkey(prv)
    eph_prv = rfc6979(prv, m, hasher) if eph_prv is None else int_from_prvkey(eph_prv)
    return ecssa_sign_raw(m, prv, eph_prv, hasher)

# https://eprint.iacr.org/2018/068
def ecssa_sign_raw(m, prv, eph_prv, hasher=sha256):
    R = ec.pointMultiply(eph_prv)
    if R[1] % 2 == 1:
        eph_prv = ec.order - eph_prv  # <=> R_y = ec_prime - R_y
    r = R[0] % ec.order # % ec.order ?
    e = hasher(R[0].to_bytes(32, 'big') + m).digest()
    e = int_from_hash(e, ec.order)
    assert e != 0 and e < ec.order, "sign fail"
    s = (eph_prv - e * prv) % ec.order
    return r, s


def ecssa_verify(m, ssasig, pub, hasher=sha256):
    if type(m) == str: m = hasher(m.encode()).digest()
    check_ssasig(ssasig)
    pub =  ec.tuple_from_point(pub)
    return ecssa_verify_raw(m, ssasig, pub, hasher)


def ecssa_verify_raw(m, ssasig, pub, hasher):
    R_x, s = ssasig[0].to_bytes(32, 'big'), ssasig[1]
    e = hasher(R_x + m).digest()
    e = int_from_hash(e, ec.order)
    if e == 0 or e >= ec.order:  # invalid e value
        return False
    # by choice at this level do not manage point at infinity (h = 0, R = 0G)
    R = ec.pointAdd(ec.pointMultiply(e, pub), ec.pointMultiply(s))
    if R[1] % 2 == 1:  # R.y odd
        return False
    return R[0] == ssasig[0]


def ecssa_pubkey_recovery(m, ssasig, hasher=sha256):
    if type(m) == str: m = hasher(m.encode()).digest()
    check_ssasig(ssasig)
    return ecssa_pubkey_recovery_raw(m, ssasig, hasher)


def ecssa_pubkey_recovery_raw(m, ssasig, hasher=sha256):
    R_x, s = ssasig
    R = (R_x, ec.y(R_x, 0))
    R_x = R_x.to_bytes(32, 'big')
    e = hasher(R_x + m).digest()
    e = int_from_hash(e, ec.order)
    assert e != 0 and e < ec.order, "invalid e value"
    e1 = mod_inv(e, ec.order)
    # by choice at this level do not manage point at infinity (h = 0, R = 0G)
    return ec.pointAdd(ec.pointMultiply(e1, R), ec.pointMultiply(-e1 * s % ec.order))


def check_ssasig(ssasig):
    """check sig has correct ssa format
    """
    assert type(ssasig) == tuple and len(ssasig) == 2 and \
          type(ssasig[0]) == int and type(ssasig[1]) == int, \
          "ssasig must be a tuple of 2 int"
    # TODO: maybe new ec.is_x_valid(x) method
    ec.y(ssasig[0], False) # R.x is valid iif R.y does exist
    assert 0 < ssasig[1] and ssasig[1] < ec.order, "s must be in [1..order]"


if __name__ == "__main__":
    prv = 0x1
    pub = ec.pointMultiply(prv)
    msg = 'Satoshi Nakamoto'
    expected_signature = (0x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8,
                          0x5c0eed7fda3782b5e439e100834390459828ef7089dbd375e48949224b6f82c0)
    # FIXME: the above sig was generated with this code,
    #        it would be better to use a sig
    #        genearated by other code to test against
    r, s = ecssa_sign(msg, prv)
    assert r == expected_signature[0] and \
           s in (expected_signature[1], ec.order - expected_signature[1])

    assert ecssa_verify(msg, (r, s), pub)

    assert pub in (ecssa_pubkey_recovery(msg, (r, s)), ecssa_pubkey_recovery(msg, (r, s)))
