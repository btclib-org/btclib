# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Helper functions to use the libsecp256k1 python bindings."""

from __future__ import annotations

import secrets

from secp256k1._libsecp256k1 import ffi, lib

from btclib.ec.libsecp256k1 import secp256k1_ctx
from btclib.exceptions import BTClibRuntimeError


def ecdsa_sign(
    msg_bytes: bytes, prvkey: bytes | int, ndata: bytes | None = None
) -> bytes:
    """Create an ECDSA signature."""
    if isinstance(prvkey, int):
        prvkey_bytes = prvkey.to_bytes(32, "big")
    else:
        prvkey_bytes = prvkey

    sig = ffi.new("secp256k1_ecdsa_signature *")
    sig_bytes = ffi.new("char[73]")
    length = ffi.new("size_t *", 73)

    noncefc = ffi.NULL
    ndata = b"\x00" * (32 - len(ndata)) + ndata if ndata else ffi.NULL
    if not lib.secp256k1_ecdsa_sign(
        secp256k1_ctx, sig, msg_bytes, prvkey_bytes, noncefc, ndata
    ):
        raise BTClibRuntimeError("secp256k1_ecdsa_sign failed")
    if not lib.secp256k1_ecdsa_signature_serialize_der(
        secp256k1_ctx, sig_bytes, length, sig
    ):
        raise BTClibRuntimeError("secp256k1_ecdsa_signature_serialize_der failed")
    return ffi.unpack(sig_bytes, length[0])


def ecdsa_verify(msg_bytes: bytes, pubkey_bytes: bytes, signature_bytes: bytes) -> int:
    """Verify a ECDSA signature."""
    signature = ffi.new("secp256k1_ecdsa_signature *")
    lib.secp256k1_ecdsa_signature_parse_der(
        secp256k1_ctx, signature, signature_bytes, len(signature_bytes)
    )

    pubkey = ffi.new("secp256k1_pubkey *")
    lib.secp256k1_ec_pubkey_parse(
        secp256k1_ctx, pubkey, pubkey_bytes, len(pubkey_bytes)
    )

    return lib.secp256k1_ecdsa_verify(secp256k1_ctx, signature, msg_bytes, pubkey)


def ecssa_sign(
    msg_bytes: bytes, prvkey: bytes | int, aux_rand32: bytes | None = None
) -> bytes:
    """Create a Schnorr signature."""
    if isinstance(prvkey, int):
        prvkey_bytes = prvkey.to_bytes(32, "big")
    else:
        prvkey_bytes = prvkey

    keypair = ffi.new("secp256k1_keypair *")
    lib.secp256k1_keypair_create(secp256k1_ctx, keypair, prvkey_bytes)

    sig = ffi.new("char[64]")

    if not aux_rand32:
        aux_rand32 = secrets.token_bytes(32)
    aux_rand32 = b"\x00" * (32 - len(aux_rand32)) + aux_rand32
    if lib.secp256k1_schnorrsig_sign(
        secp256k1_ctx, sig, msg_bytes, keypair, aux_rand32
    ):
        return ffi.unpack(sig, 64)
    raise RuntimeError


def ecssa_verify(msg_bytes: bytes, pubkey_bytes: bytes, signature_bytes: bytes) -> int:
    """Verify a Schhnorr signature."""
    if len(pubkey_bytes) == 32:
        pubkey_bytes = b"\x02" + pubkey_bytes

    pubkey = ffi.new("secp256k1_pubkey *")
    lib.secp256k1_ec_pubkey_parse(
        secp256k1_ctx, pubkey, pubkey_bytes, len(pubkey_bytes)
    )

    xonly_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    lib.secp256k1_xonly_pubkey_from_pubkey(
        secp256k1_ctx, xonly_pubkey, ffi.new("int *"), pubkey
    )

    return lib.secp256k1_schnorrsig_verify(
        secp256k1_ctx, signature_bytes, msg_bytes, len(msg_bytes), xonly_pubkey
    )
