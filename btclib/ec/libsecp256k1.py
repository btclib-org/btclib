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

from btclib.alias import Point
from btclib.exceptions import BTClibRuntimeError

LIBSECP256K1_AVAILABLE = True
LIBSECP256K1_ENABLED = False
try:
    from secp256k1._libsecp256k1 import ffi, lib

    # LIBSECP256K1_ENABLED = True
    # Keeping a single one of these is most efficient.
    secp256k1_ctx = lib.secp256k1_context_create(
        lib.SECP256K1_CONTEXT_SIGN | lib.SECP256K1_CONTEXT_VERIFY
    )

except ImportError:  # pragma: no cover
    LIBSECP256K1_AVAILABLE = False


def is_enabled() -> bool:
    return LIBSECP256K1_ENABLED


def is_available() -> bool:
    return LIBSECP256K1_AVAILABLE


def mult(num: bytes | int) -> Point:
    """Multply the generator point."""
    privkey = num.to_bytes(32, "big") if isinstance(num, int) else num
    pubkey_ptr = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_create(secp256k1_ctx, pubkey_ptr, privkey):
        raise BTClibRuntimeError("secp256k1_ec_pubkey_create failure")
    serialized_pubkey_ptr = ffi.new("char[65]")
    length = ffi.new("size_t *", 65)
    if not lib.secp256k1_ec_pubkey_serialize(
        secp256k1_ctx, serialized_pubkey_ptr, length, pubkey_ptr, 2
    ):
        raise BTClibRuntimeError(
            "secp256k1_ec_pubkey_serialize failure"
        )  # pragma: no cover
    pubkey = ffi.unpack(serialized_pubkey_ptr, 65)
    return int.from_bytes(pubkey[1:33], "big"), int.from_bytes(pubkey[34:], "big")
