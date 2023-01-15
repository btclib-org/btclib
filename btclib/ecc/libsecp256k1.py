# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Helper functions to use the libsecp256k1 python bindings."""

from __future__ import annotations

import contextlib
import secrets

from btclib.exceptions import BTClibRuntimeError

with contextlib.suppress(ImportError):
    from btclib.ec.libsecp256k1 import ctx, ffi, lib


def ecdsa_sign_(msg_hash: bytes, prvkey_: bytes | int) -> bytes:
    """Create an ECDSA signature."""
    prv_key = prvkey_.to_bytes(32, "big") if isinstance(prvkey_, int) else prvkey_
    noncefc = ffi.NULL
    ndata = ffi.NULL
    sig_ptr = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_sign(ctx, sig_ptr, msg_hash, prv_key, noncefc, ndata):
        raise BTClibRuntimeError("secp256k1_ecdsa_sign failed")

    length_der = 72  # signature being low-s, 72 is enough
    sig_der = ffi.new(f"char[{length_der}]")
    length = ffi.new("size_t *", length_der)
    if not lib.secp256k1_ecdsa_signature_serialize_der(ctx, sig_der, length, sig_ptr):
        raise BTClibRuntimeError(  # pragma: no cover
            "secp256k1_ecdsa_signature_serialize_der failed"
        )

    return ffi.unpack(sig_der, length[0])


def ecdsa_verify_(
    msg_hash: bytes, pub_key: bytes, sig_der: bytes, lower_s: bool = True
) -> bool:
    """Verify a ECDSA signature."""
    sig_ptr = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_signature_parse_der(ctx, sig_ptr, sig_der, len(sig_der)):
        raise BTClibRuntimeError("secp256k1_ecdsa_signature_parse_der failed")

    if not lower_s:  # if lower-s is not to be enforced, then normalize
        lib.secp256k1_ecdsa_signature_normalize(ctx, sig_ptr, sig_ptr)

    pubkey_ptr = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey_ptr, pub_key, len(pub_key)):
        raise BTClibRuntimeError("secp256k1_ec_pubkey_parse failed")

    return lib.secp256k1_ecdsa_verify(ctx, sig_ptr, msg_hash, pubkey_ptr)


def ecssa_sign_(
    msg_hash: bytes, prvkey_: bytes | int, aux_rand32: bytes | None = None
) -> bytes:
    """Create a Schnorr signature."""
    prv_key = prvkey_.to_bytes(32, "big") if isinstance(prvkey_, int) else prvkey_

    keypair_ptr = ffi.new("secp256k1_keypair *")
    if not lib.secp256k1_keypair_create(ctx, keypair_ptr, prv_key):
        raise BTClibRuntimeError("secp256k1_keypair_create failed")

    if not aux_rand32:
        aux_rand32 = secrets.token_bytes(32)
    aux_rand32 = b"\x00" * (32 - len(aux_rand32)) + aux_rand32
    sig = ffi.new("char[64]")
    if lib.secp256k1_schnorrsig_sign(ctx, sig, msg_hash, keypair_ptr, aux_rand32):
        return ffi.unpack(sig, 64)

    raise BTClibRuntimeError("secp256k1_schnorrsig_sign failed")  # pragma: no cover


def ecssa_verify_(msg_hash: bytes, pub_key: bytes, sig: bytes) -> bool:
    """Verify a Schhnorr signature."""
    if len(pub_key) == 32:
        pub_key = b"\x02" + pub_key

    pubkey_ptr = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey_ptr, pub_key, len(pub_key)):
        raise BTClibRuntimeError("secp256k1_ec_pubkey_parse failed")

    xonly_pubkey_ptr = ffi.new("secp256k1_xonly_pubkey *")
    if not lib.secp256k1_xonly_pubkey_from_pubkey(
        ctx, xonly_pubkey_ptr, ffi.new("int *"), pubkey_ptr
    ):
        raise BTClibRuntimeError(
            "secp256k1_xonly_pubkey_from_pubkey failed"
        )  # pragma: no cover

    return lib.secp256k1_schnorrsig_verify(
        ctx, sig, msg_hash, len(msg_hash), xonly_pubkey_ptr
    )
