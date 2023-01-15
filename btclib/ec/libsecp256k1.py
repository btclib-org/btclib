#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Helper functions to use the libsecp256k1 python bindings."""

from __future__ import annotations

from btclib.alias import Integer, Point
from btclib.exceptions import BTClibRuntimeError
from btclib.utils import int_from_integer

LIBSECP256K1_AVAILABLE = True
LIBSECP256K1_ENABLED = False
try:
    # from secp256k1._libsecp256k1 import ffi, lib

    from btclib_libsecp256k1 import ffi, lib

    LIBSECP256K1_ENABLED = True
    # Keeping a single one of these is most efficient.
    ctx = lib.secp256k1_context_create(769)
    # ctx = lib.secp256k1_context_create(
    #    lib.SECP256K1_CONTEXT_SIGN | lib.SECP256K1_CONTEXT_VERIFY
    # )
    EC_COMPRESSED = 258  # lib.SECP256K1_EC_COMPRESSED
    EC_UNCOMPRESSED = 2  # lib.SECP256K1_EC_UNCOMPRESSED

except ImportError:  # pragma: no cover
    LIBSECP256K1_AVAILABLE = False


def is_enabled() -> bool:
    return LIBSECP256K1_ENABLED


def is_available() -> bool:
    return LIBSECP256K1_AVAILABLE


def pubkey_from_prvkey(prv_key: bytes | int, compressed: bool | None = None) -> bytes:
    """Derive public key from private key."""
    prv_key = prv_key.to_bytes(32, "big") if isinstance(prv_key, int) else prv_key
    compressed = True if compressed is None else compressed

    pubkey_ptr = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_create(ctx, pubkey_ptr, prv_key):
        raise BTClibRuntimeError("secp256k1_ec_pubkey_create failure")
    length_ = 33 if compressed else 65
    serialized_pubkey_ptr = ffi.new(f"char[{length_}]")
    length = ffi.new("size_t *", length_)
    lib.secp256k1_ec_pubkey_serialize(
        ctx,
        serialized_pubkey_ptr,
        length,
        pubkey_ptr,
        EC_COMPRESSED if compressed else EC_UNCOMPRESSED,
    )  # according to documentation, it always returns 1
    return ffi.unpack(serialized_pubkey_ptr, length_)


def mult(num: Integer) -> Point:
    """Multiply the generator point."""
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    m: int = int_from_integer(num) % order
    if m == 0:
        G_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        G_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        return G_x, G_y
    pub_key = pubkey_from_prvkey(m, compressed=False)
    return int.from_bytes(pub_key[1:33], "big"), int.from_bytes(pub_key[33:], "big")
