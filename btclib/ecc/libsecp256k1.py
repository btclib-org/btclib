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

from btclib.exceptions import BTClibRuntimeError

try:
    from btclib.ec.libsecp256k1 import ffi, lib, secp256k1_ctx

except ImportError:  # pragma: no cover
    pass


def ecdsa_sign(
    msg_hash: bytes, prvkey_: bytes | int, ndata: bytes | None = None
) -> bytes:
    """Create an ECDSA signature."""
    prvkey = prvkey_.to_bytes(32, "big") if isinstance(prvkey_, int) else prvkey_

    noncefc = ffi.NULL
    ndata = b"\x00" * (32 - len(ndata)) + ndata if ndata else ffi.NULL
    sig_ptr = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_sign(
        secp256k1_ctx, sig_ptr, msg_hash, prvkey, noncefc, ndata
    ):
        raise BTClibRuntimeError("secp256k1_ecdsa_sign failed")

    sig_der = ffi.new("char[73]")
    length = ffi.new("size_t *", 73)
    if not lib.secp256k1_ecdsa_signature_serialize_der(
        secp256k1_ctx, sig_der, length, sig_ptr
    ):
        raise BTClibRuntimeError("secp256k1_ecdsa_signature_serialize_der failed")

    return ffi.unpack(sig_der, length[0])


def ecdsa_verify(msg_hash: bytes, pubkey: bytes, sig: bytes) -> int:
    """Verify a ECDSA signature."""
    sig_ptr = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_signature_parse_der(
        secp256k1_ctx, sig_ptr, sig, len(sig)
    ):
        raise BTClibRuntimeError("secp256k1_ecdsa_signature_parse_der failed")

    pubkey_ptr = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(
        secp256k1_ctx, pubkey_ptr, pubkey, len(pubkey)
    ):
        raise BTClibRuntimeError("secp256k1_ec_pubkey_parse failed")

    return lib.secp256k1_ecdsa_verify(secp256k1_ctx, sig_ptr, msg_hash, pubkey_ptr)


def ecssa_sign(
    msg_hash: bytes, prvkey_: bytes | int, aux_rand32: bytes | None = None
) -> bytes:
    """Create a Schnorr signature."""
    prvkey = prvkey_.to_bytes(32, "big") if isinstance(prvkey_, int) else prvkey_

    keypair_ptr = ffi.new("secp256k1_keypair *")
    if not lib.secp256k1_keypair_create(secp256k1_ctx, keypair_ptr, prvkey):
        raise BTClibRuntimeError("secp256k1_keypair_create failed")

    if not aux_rand32:
        aux_rand32 = secrets.token_bytes(32)
    aux_rand32 = b"\x00" * (32 - len(aux_rand32)) + aux_rand32
    sig = ffi.new("char[64]")
    if lib.secp256k1_schnorrsig_sign(
        secp256k1_ctx, sig, msg_hash, keypair_ptr, aux_rand32
    ):
        return ffi.unpack(sig, 64)

    raise BTClibRuntimeError("secp256k1_schnorrsig_sign failed")


def ecssa_verify(msg_hash: bytes, pubkey: bytes, sig: bytes) -> int:
    """Verify a Schhnorr signature."""
    if len(pubkey) == 32:
        pubkey = b"\x02" + pubkey

    pubkey_ptr = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(
        secp256k1_ctx, pubkey_ptr, pubkey, len(pubkey)
    ):
        raise BTClibRuntimeError("secp256k1_ec_pubkey_parse failed")

    xonly_pubkey_ptr = ffi.new("secp256k1_xonly_pubkey *")
    if not lib.secp256k1_xonly_pubkey_from_pubkey(
        secp256k1_ctx, xonly_pubkey_ptr, ffi.new("int *"), pubkey_ptr
    ):
        raise BTClibRuntimeError("secp256k1_xonly_pubkey_from_pubkey failed")

    return lib.secp256k1_schnorrsig_verify(
        secp256k1_ctx, sig, msg_hash, len(msg_hash), xonly_pubkey_ptr
    )
