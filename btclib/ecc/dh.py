#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Diffie-Hellman elliptic curve key agreement, per SEC 1 v.2.

Two parties, each holding the other's public key, compute the same
shared secret -- their key pair times the other's public point -- and
derive symmetric keying data from it through a key derivation
function. The curve and the KDF are the two things the parties must
agree on beforehand; ansi_x9_63_kdf is SEC 1's KDF, and
diffie_hellman is the agreement built on it.
"""

from __future__ import annotations

from hashlib import sha256
from math import ceil

from btclib_libsecp256k1 import keys as libsecp256k1_keys

from btclib.alias import HashF, Point
from btclib.curves import Curve, bytes_from_point, mult, secp256k1
from btclib.curves.curve import _libsecp256k1_applicable
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.utils import is_integer

__all__ = [
    "ansi_x9_63_kdf",
    "diffie_hellman",
]


def ansi_x9_63_kdf(z: bytes, size: int, hf: HashF, shared_info: bytes | None) -> bytes:
    """Return keying data according to ANSI-X9.63-KDF.

    Return a keying data octet sequence of the requested size according
    to ANSI-X9.63-KDF specifications for the key derivation function.

    `size` is a positive number of octets, SEC 1's keydatalen: a
    BTClibTypeError if it is no integer, a BTClibValueError if it is zero,
    negative, or above what the hash function can derive.

    http://www.secg.org/sec1-v2.pdf,
    section 3.6.1
    """
    # the range is checked before the loop bound is computed from it, and
    # the type before the range. Unchecked, a negative size made the loop
    # empty and the final negative slice returned b"" -- an empty key
    # where the caller asked for keying material, which is the one answer
    # a key derivation function must never invent (issue 321). A float
    # went further still and reached that slice, leaving through a bare
    # TypeError from underneath the library rather than through its own
    # exception contract
    if not is_integer(size):
        raise BTClibTypeError(f"non-integer keying data size: {size}")
    # zero and not merely negative: SEC 1 3.6.1 states keydatalen as a
    # positive integer, and a caller asking for no octets of key is a
    # caller with a bug rather than one with an empty key
    if size <= 0:
        raise BTClibValueError(f"invalid keying data size: {size}")
    hf_size = hf().digest_size
    max_size = hf_size * (2**32 - 1)
    if size > max_size:
        raise BTClibValueError(f"cannot derive a key larger than {max_size} bytes")
    K_temp = []
    for counter in range(1, ceil(size / hf_size) + 1):
        h = hf()
        hash_input = (
            z
            + counter.to_bytes(4, byteorder="big", signed=False)
            + (b"" if shared_info is None else shared_info)
        )
        h.update(hash_input)
        K_temp.append(h.digest())
    return b"".join(K_temp)[:size]


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
    libsecp256k1's default, where this derives through ANSI-X9.63-KDF.
    """
    d = dU % ec.n

    # d == 0 is the infinity point, which the bindings reject as a
    # scalar; so is a low-order QV on a curve with a cofactor, which
    # they have no serialization for either. Both are the Python path's
    # to answer, and it answers them below
    if d and _libsecp256k1_applicable(ec):
        sec = libsecp256k1_keys.pubkey_tweak_mul(bytes_from_point(QV, ec), d)
        return ansi_x9_63_kdf(sec[1:], size, hf, shared_info)

    shared_secret_point = mult(dU, QV, ec)
    # a degenerate dU, zero mod n, maps every QV here
    if shared_secret_point[1] == 0:
        err_msg = "invalid (INF) key"
        raise BTClibRuntimeError(err_msg)
    shared_secret_field_element = shared_secret_point[0]
    z = shared_secret_field_element.to_bytes(ec.p_size, byteorder="big", signed=False)
    return ansi_x9_63_kdf(z, size, hf, shared_info)
