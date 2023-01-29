#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic Curve Schnorr Signature Algorithm (ECSSA).

This implementation is according to BIP340-Schnorr:

https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

The BIP340-Schnorr scheme uses as public key the x-coordinate (field element)
of the curve point associated to the private key 0 < q < n.
Therefore, for sepcp256k1 the public key size is 32 bytes.
Arguably, the knowledge of q as the discrete logarithm of Q
also implies the knowledge of n-q as discrete logarithm of -Q.
As such, {q, n-q} can be considered a single private key and
{Q, -Q} the associated public key characterized by the shared x_Q.

Also, BIP340 advocates its own SHA256 modification as hash function:
TaggedHash(tag, x) = SHA256(SHA256(tag)||SHA256(tag)||x)
The rationale is to make BIP340 signatures invalid for anything else
but Bitcoin and vice versa.

TaggedHash is used for both the challenge (with tag 'BIP0340/challenge')
and the deterministic nonce (with tag 'BIP0340/aux').

To allow for secure batch verification of multiple signatures,
BIP340-Schnorr uses a challenge that prevents public key recovery
from signature: c = TaggedHash('BIPSchnorr', x_k||x_Q||msg).

A custom deterministic algorithm for the ephemeral key (nonce)
is used for signing, instead of the RFC6979 standard:

nonce = TaggedHash('BIP0340/aux', q||msg)

Finally, BIP340-Schnorr adopts a robust [r][s] custom serialization
format, instead of the loosely specified ASN.1 DER standard.
The signature size is p-size*n-size, where p-size is the field element
(curve point coordinate) byte size and n-size is the scalar
(curve point multiplication coefficient) byte size.
For sepcp256k1 the resulting signature size is 64 bytes.
"""

from __future__ import annotations

import contextlib
import secrets
from dataclasses import InitVar, dataclass
from hashlib import sha256
from typing import Sequence, Union

from btclib.alias import BinaryData, HashF, Integer, JacPoint, Octets, Point
from btclib.bip32 import BIP32Key
from btclib.ec import Curve, libsecp256k1, secp256k1
from btclib.ec.curve import mult
from btclib.ec.curve_group import _double_mult, _mult, _multi_mult
from btclib.ecc.bip340_nonce import bip340_nonce_
from btclib.ecc.libsecp256k1 import ecssa_sign_, ecssa_verify_
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.hashes import reduce_to_hlen, tagged_hash
from btclib.number_theory import mod_inv
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.to_pub_key import point_from_pub_key
from btclib.utils import (
    bytes_from_octets,
    bytesio_from_binarydata,
    hex_string,
    int_from_bits,
)


@dataclass(frozen=True)
class Sig:
    """BIP340-Schnorr signature.

    - r is an x-coordinate _field_element_, 0 <= r < ec.p
    - s is a scalar, 0 <= s < ec.n (yes, for BIP340-Schnorr it can be zero)

    (ec.p is the field prime, ec.n is the curve order)
    """

    # 32 bytes x-coordinate field element
    r: int
    # 32 bytes scalar
    s: int
    ec: Curve = secp256k1
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        # r is a field element, fail if r is not a valid x-coordinate
        self.ec.y(self.r)

        # s is a scalar, fail if s is not in [0, n-1]
        if not 0 <= self.s < self.ec.n:
            err_msg = "scalar s not in 0..n-1: "
            err_msg += f"'{hex_string(self.s)}'" if self.s > 0xFFFFFFFF else f"{self.s}"
            raise BTClibValueError(err_msg)

    def serialize(self, check_validity: bool = True) -> bytes:
        if check_validity:
            self.assert_valid()

        out = self.r.to_bytes(self.ec.p_size, byteorder="big", signed=False)
        out += self.s.to_bytes(self.ec.n_size, byteorder="big", signed=False)
        return out

    @classmethod
    def parse(cls: type[Sig], data: BinaryData, check_validity: bool = True) -> Sig:
        stream = bytesio_from_binarydata(data)
        ec = secp256k1
        r = int.from_bytes(stream.read(ec.p_size), byteorder="big", signed=False)
        s = int.from_bytes(stream.read(ec.n_size), byteorder="big", signed=False)
        return cls(r, s, ec, check_validity)


# hex-string or bytes representation of an int
# 33 or 65 bytes or hex-string
# BIP32Key as dict or String
# tuple Point
BIP340PubKey = Union[Integer, Octets, BIP32Key, Point]


def point_from_bip340pub_key(x_Q: BIP340PubKey, ec: Curve = secp256k1) -> Point:
    """Return a verified-as-valid BIP340 public key as Point tuple.

    It supports:

    - BIP32 extended keys (bytes, string, or BIP32KeyData)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - BIP340 Octets (bytes or hex-string, p-size Point x-coordinate)
    - native tuple
    """
    # BIP 340 key as integer
    if isinstance(x_Q, int):
        return x_Q, ec.y_even(x_Q)

    # (tuple) Point, (dict or str) BIP32Key, or 33/65 bytes
    with contextlib.suppress(BTClibValueError):
        x_Q = point_from_pub_key(x_Q, ec)[0]
        return x_Q, ec.y_even(x_Q)
    # BIP 340 key as bytes or hex-string
    if isinstance(x_Q, (str, bytes)):
        Q = bytes_from_octets(x_Q, ec.p_size)
        x_Q = int.from_bytes(Q, "big", signed=False)
        return x_Q, ec.y_even(x_Q)

    raise BTClibTypeError("not a BIP340 public key")


def gen_keys(prv_key: PrvKey | None = None, ec: Curve = secp256k1) -> tuple[int, int]:
    """Return a BIP340 private/public (int, int) key-pair."""
    if prv_key is None:
        q = 1 + secrets.randbelow(ec.n - 1)
    else:
        q = int_from_prv_key(prv_key, ec)

    x_Q, y_Q = mult(q, ec=ec)
    if y_Q % 2:
        q = ec.n - q

    return q, x_Q


def challenge_(msg_hash: Octets, x_Q: int, x_K: int, ec: Curve, hf: HashF) -> int:
    # the message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    t = b"".join(
        [
            x_K.to_bytes(ec.p_size, byteorder="big", signed=False),
            x_Q.to_bytes(ec.p_size, byteorder="big", signed=False),
            msg_hash,
        ]
    )
    t = tagged_hash(b"BIP0340/challenge", t, hf)

    c: int = int_from_bits(t, ec.nlen) % ec.n
    if c == 0:
        raise BTClibRuntimeError("invalid zero challenge")  # pragma: no cover
    return c


def _sign_(c: int, q: int, nonce: int, r: int, ec: Curve) -> Sig:
    # Private function for testing purposes: it allows to explore all
    # possible value of the challenge c (for low-cardinality curves).
    # It assume that c is in [1, n-1], while q and nonce are in [1, n-1]
    if c == 0:  # c≠0 required as it multiplies the private key
        raise BTClibRuntimeError("invalid zero challenge")

    # s=0 is ok: in verification there is no inverse of s
    s = (nonce + c * q) % ec.n

    return Sig(r, s, ec)


def sign_(
    msg_hash: Octets,
    prv_key: PrvKey,
    aux: Octets | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Sig:
    """Sign a hf_len bytes message according to BIP340 signature algorithm.

    If the deterministic nonce is not provided, the BIP340 specification
    (not RFC6979) is used.
    """
    # the message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    aux = secrets.token_bytes(hf_len) if aux is None else bytes_from_octets(aux, hf_len)

    if ec == secp256k1 and hf == sha256 and libsecp256k1.is_available():
        return Sig.parse(ecssa_sign_(msg_hash, prv_key, aux))

    # k is the nonce: an integer in the range 1..n-1.
    k, x_K, q, x_Q = bip340_nonce_(msg_hash, prv_key, aux, ec, hf)

    # the challenge
    c = challenge_(msg_hash, x_Q, x_K, ec, hf)

    return _sign_(c, q, k, x_K, ec)


def sign(
    msg: Octets,
    prv_key: PrvKey,
    aux: Octets | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Sig:
    """Sign message according to BIP340 signature algorithm.

    The message msg is first processed by hf, yielding the value

        msg_hash = hf(msg),

    a sequence of bits of length *hf_len*.

    Normally, hf is chosen such that its output length *hf_len* is
    roughly equal to *nlen*, the bit-length of the group order *n*,
    since the overall security of the signature scheme will depend on
    the smallest of *hf_len* and *nlen*; however, ECSSA
    supports all combinations of *hf_len* and *nlen*.

    The BIP340 deterministic nonce (not RFC6979) is used.
    """
    msg_hash = reduce_to_hlen(msg, hf)
    return sign_(msg_hash, prv_key, aux, ec, hf)


def _assert_as_valid_(c: int, QJ: JacPoint, r: int, s: int, ec: Curve) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # Let K = sG - eQ.
    # in Jacobian coordinates
    KJ = _double_mult(ec.n - c, QJ, s, ec.GJ, ec)

    # The following check is prescribed by BIP340 but it is useless:
    # if moved after 'Fail if x_K ≠ r' it would never be executed
    # Fail if infinite(KJ).
    # Fail if y_K is odd.
    if ec.y_aff_from_jac(KJ) % 2:
        raise BTClibRuntimeError("y_K is odd")

    # Fail if x_K ≠ r
    if KJ[0] != KJ[2] * KJ[2] * r % ec.p:
        raise BTClibRuntimeError("signature verification failed")


def assert_as_valid_(
    msg_hash: Octets, Q: BIP340PubKey, sig: Sig | Octets, hf: HashF = sha256
) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False
    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.parse(sig)

    x_Q, y_Q = point_from_bip340pub_key(Q, sig.ec)

    if libsecp256k1.is_available() and sig.ec == secp256k1 and hf == sha256:
        pubkey_bytes = x_Q.to_bytes(32, "big")
        msg_hash = bytes_from_octets(msg_hash)
        if not ecssa_verify_(msg_hash, pubkey_bytes, sig.serialize()):
            raise BTClibRuntimeError("libsecp256k1.ecssa_verify_ failed")
        return

    # Let c = int(hf(bytes(r) || bytes(Q) || msg_hash)) mod n.
    c = challenge_(msg_hash, x_Q, sig.r, sig.ec, hf)
    _assert_as_valid_(c, (x_Q, y_Q, 1), sig.r, sig.s, sig.ec)


def assert_as_valid(
    msg: Octets, Q: BIP340PubKey, sig: Sig | Octets, hf: HashF = sha256
) -> None:
    msg_hash = reduce_to_hlen(msg, hf)
    assert_as_valid_(msg_hash, Q, sig, hf)


def verify_(
    msg_hash: Octets, Q: BIP340PubKey, sig: Sig | Octets, hf: HashF = sha256
) -> bool:
    """Verify the BIP340 signature of the provided message."""
    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        assert_as_valid_(msg_hash, Q, sig, hf)
    except Exception:  # pylint: disable=broad-except
        return False

    return True


def verify(msg: Octets, Q: BIP340PubKey, sig: Sig | Octets, hf: HashF = sha256) -> bool:
    """Verify the BIP340 signature of the provided message."""
    msg_hash = reduce_to_hlen(msg, hf)
    return verify_(msg_hash, Q, sig, hf)


def _recover_pub_key_(c: int, r: int, s: int, ec: Curve) -> int:
    # Private function provided for testing purposes only.
    if c == 0:
        raise BTClibRuntimeError("invalid zero challenge")

    KJ = r, ec.y_even(r), 1

    e1 = mod_inv(c, ec.n)
    QJ = _double_mult(ec.n - e1, KJ, e1 * s, ec.GJ, ec)
    # edge case that cannot be reproduced in the test suite
    if QJ[2] == 0:
        err_msg = "invalid (INF) key"  # pragma: no cover
        raise BTClibRuntimeError(err_msg)  # pragma: no cover
    return int(ec.x_aff_from_jac(QJ))


def _err_msg(size: int, msgs_or_sigs: str, arg2: Sequence[Octets | Sig]) -> str:
    err_msg = f"mismatch between number of pub_keys ({size}) "
    return f"{err_msg} and number of {msgs_or_sigs} ({len(arg2)})"


def assert_batch_as_valid_(
    m_hashes: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:
    batch_size = len(Qs)
    if batch_size == 0:
        raise BTClibValueError("no signatures provided")

    if len(m_hashes) != batch_size:
        raise BTClibValueError(_err_msg(batch_size, "messages", m_hashes))
    if len(sigs) != batch_size:
        raise BTClibValueError(_err_msg(batch_size, "signatures", sigs))
    if batch_size == 1:
        assert_as_valid_(m_hashes[0], Qs[0], sigs[0], hf)
        return None

    ec = sigs[0].ec
    if any(sig.ec != ec for sig in sigs):
        raise BTClibValueError("not the same curve for all signatures")
    t = 0
    scalars: list[int] = []
    points: list[JacPoint] = []
    for i, (msg_hash, Q, sig) in enumerate(zip(m_hashes, Qs, sigs)):
        msg_hash = bytes_from_octets(msg_hash, hf().digest_size)

        KJ = sig.r, ec.y_even(sig.r), 1

        x_Q, y_Q = point_from_bip340pub_key(Q, ec)
        QJ = x_Q, y_Q, 1

        c = challenge_(msg_hash, x_Q, sig.r, ec, hf)

        # rand in [1, n-1]
        # deterministically generated using a CSPRNG seeded by a
        # cryptographic hash (e.g., SHA256) of all inputs of the
        # algorithm, or randomly generated independently for each
        # run of the batch verification algorithm
        rand = 1 if i == 0 else 1 + secrets.randbelow(ec.n - 1)
        scalars.append(rand)
        points.append(KJ)
        scalars.append(rand * c % ec.n)
        points.append(QJ)
        t += rand * sig.s

    TJ = _mult(t, ec.GJ, ec)
    RHSJ = _multi_mult(scalars, points, ec)

    # return T == RHS, checked in Jacobian coordinates
    RHSZ2 = RHSJ[2] * RHSJ[2]
    TZ2 = TJ[2] * TJ[2]
    if (TJ[0] * RHSZ2 % ec.p != RHSJ[0] * TZ2 % ec.p) or (
        TJ[1] * RHSZ2 * RHSJ[2] % ec.p != RHSJ[1] * TZ2 * TJ[2] % ec.p
    ):
        raise BTClibRuntimeError("signature verification failed")
    return None


def assert_batch_as_valid(
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:
    m_hashes = [reduce_to_hlen(msg, hf) for msg in ms]
    return assert_batch_as_valid_(m_hashes, Qs, sigs, hf)


def batch_verify_(
    m_hashes: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> bool:
    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        assert_batch_as_valid_(m_hashes, Qs, sigs, hf)
    except Exception:  # pylint: disable=broad-except
        return False

    return True


def batch_verify(
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> bool:
    """Batch verification of BIP340 signatures."""
    m_hashes = [reduce_to_hlen(msg, hf) for msg in ms]
    return batch_verify_(m_hashes, Qs, sigs, hf)
