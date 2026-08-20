# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Diffie-Hellman elliptic curve key agreement, per SEC 1 v.2.

Two parties, each holding the other's public key, compute the same
shared secret -- their key pair times the other's public point -- and
derive symmetric keying data from it through a key derivation
function. The curve and the KDF are the two things the parties must
agree on beforehand; SEC 1's KDF is `kdf.ansi_x9_63_kdf`, which
btclib.kdf holds beside RFC 5869's, and diffie_hellman is the agreement
built on it.

**Why `ecdh.shared_secret` of the bindings has no caller in btclib, and
this is the place that says so** (issue 909). That function multiplies
and hashes in one call, and the hash is SHA256 of the compressed shared
point with no way to change it: libsecp256k1 takes it as a C callback, so
exposing it would mean calling back into python from the middle of the
computation. Every ECDH-shaped computation here derives differently, so
what is delegated is the multiplication -- `keys.pubkey_tweak_mul`, which
is that same C multiplication, in constant time -- and the derivation
stays in python:

- `diffie_hellman` below runs SEC 1's ANSI-X9.63-KDF over the
  x-coordinate, under the hash function the caller passed;
- `ecc.ecies.derive_keys` hashes the *compressed point* with sha512 and
  cuts the 64 bytes three ways, which is BIE1's shape and not this one;
- `silent_payments.shared_secret` answers the point itself: BIP352 tags
  it with a counter afterwards, and a BIP375 psbt carries it as a point;
- `ecc.ellswift.xdh` is the exception that proves the rule. BIP324
  defines the hash, libsecp256k1 implements that definition, and it is
  delegated whole -- `ellswift.xdh` is one call there.

So the verdict is not that the function is wrong: it is that a shared
secret is a protocol's own derivation, and only a protocol agreeing with
libsecp256k1's default can hand the whole of it over. Three of the four
here do not, and the fourth already does.
"""

from __future__ import annotations

from hashlib import sha256

# the module and not the function it calls: `from btclib.kdf import
# ansi_x9_63_kdf` would bind that name here too, leaving
# `btclib.ecc.dh.ansi_x9_63_kdf` a live spelling of a function this
# module no longer defines, and `btclib.kdf` the only place it is
# defined is the whole of what moving it was for
from btclib import kdf
from btclib._libsecp256k1 import keys as libsecp256k1_keys
from btclib.alias import HashF, Point
from btclib.curves import Curve, bytes_from_point, mult, secp256k1
from btclib.curves.curve import _assert_valid_ec, _libsecp256k1_serves
from btclib.exceptions import BTClibRuntimeError

__all__ = [
    "diffie_hellman",
]


def diffie_hellman(
    dU: int,
    QV: Point,
    size: int,
    shared_info: bytes | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> bytes:
    """Diffie-Hellman elliptic curve key agreement scheme.

    http://www.secg.org/sec1-v2.pdf, section 6.1

    The shared point is the multiplication of a point that is not the
    generator, which is the one case `mult` does not delegate: on
    secp256k1 it is `secp256k1_ec_pubkey_tweak_mul` that computes it
    here, 15.2 us against the 549 of the Python endomorphism path and,
    dU being a secret, in constant time -- which that path is not.

    `ecdh.shared_secret` of the bindings is a different function and not
    a substitute: it hashes the compressed shared point with SHA256,
    where this derives through ANSI-X9.63-KDF. The module docstring above
    has that verdict for all four of btclib's ECDH-shaped computations.
    """
    _assert_valid_ec(ec)
    d = dU % ec.n

    # d == 0 is the infinity point, which the bindings reject as a
    # scalar; so is a low-order QV on a curve with a cofactor, which
    # they have no serialization for either. Both are the Python path's
    # to answer, and it answers them below
    if d and _libsecp256k1_serves(ec, None):
        # uncompressed, which is the cheap form to hand over: parsing 65
        # octets reads both coordinates where 33 are a field square root,
        # and the point is here to be written either way -- 12.6 us
        # against 14.7 for the multiplication that follows
        sec = libsecp256k1_keys.pubkey_tweak_mul(
            bytes_from_point(QV, ec, compressed=False), d
        )
        return kdf.ansi_x9_63_kdf(sec[1:], size, hf, shared_info)

    shared_secret_point = mult(dU, QV, ec)
    # a degenerate dU, zero mod n, maps every QV here
    if shared_secret_point[1] == 0:
        err_msg = "invalid (INF) key"
        raise BTClibRuntimeError(err_msg)
    shared_secret_field_element = shared_secret_point[0]
    z = shared_secret_field_element.to_bytes(ec.p_size, byteorder="big", signed=False)
    return kdf.ansi_x9_63_kdf(z, size, hf, shared_info)
