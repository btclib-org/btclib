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

The dropped 02/03 prefix is implicit, not lost: verification needs an
unambiguous Y, so BIP340 fixes it as even, and the x-only key is the
compressed key 02||x with its prefix left unsaid. Halving the set of
valid public keys costs no security -- whoever breaks an x-only key
breaks the full key at the price of a negation -- and taking the bare
x as the key refuses a malleability: a verifier that accepted a point
and negated its odd Y would make every signature valid for two keys.

Also, BIP340 advocates its own SHA256 modification as hash function:
TaggedHash(tag, x) = SHA256(SHA256(tag)||SHA256(tag)||x)
The rationale is to make BIP340 signatures invalid for anything else
but Bitcoin and vice versa.

TaggedHash is used for both the challenge (with tag 'BIP0340/challenge')
and the deterministic nonce (with tag 'BIP0340/aux').

To allow for secure batch verification of multiple signatures,
BIP340-Schnorr uses a challenge that prevents public key recovery
from signature: c = TaggedHash('BIP0340/challenge', x_k||x_Q||msg).

The challenge commits to the nonce point as well, and that dependency
is the Fiat-Shamir transform itself: hashing the commitment x_k
replaces the fresh challenge that an interactive verifier would send
only after receiving the commitment. Were c and the nonce chosen
independently, no private key would be needed: K = s*G - c*Q
satisfies verification for any Q.

A custom algorithm for the ephemeral key (nonce)
is used for signing, instead of the RFC6979 standard:

nonce = TaggedHash('BIP0340/nonce', t||x_Q||msg)
with t = q xor TaggedHash('BIP0340/aux', a), a the auxiliary randomness

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
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import overload

from btclib_libsecp256k1 import ssa as libsecp256k1_ssa

from btclib.alias import BinaryData, HashF, Integer, JacPoint, Octets, Point
from btclib.bip32 import BIP32Key
from btclib.curves import Curve, secp256k1
from btclib.curves.curve import _libsecp256k1_applicable, mult
from btclib.curves.curve_group import _mult, _multi_mult
from btclib.curves.curve_group_2 import double_mult_w_NAF
from btclib.ecc.bip340_nonce import bip340_nonce_
from btclib.ecc.commit_nonce import commit_entropy_, commit_nonce_, commit_point_
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

# btclib's own sign-to-contract tags, and the only invented thing in the
# scheme: libsecp256k1 has an ecdsa_s2c module and no schnorr one, and
# BIP340 says nothing about commitments, so there is no upstream string
# to copy and nothing to be interoperable with. Named for the standard
# rather than for btclib's `ssa`, and not under BIP0340/, which would
# claim the BIP defines this. Frozen all the same: a different string is
# a different scheme, and every signature already made would stop opening
_S2C_POINT_TAG = b"s2c/bip340/point"
_S2C_DATA_TAG = b"s2c/bip340/data"


@dataclass(frozen=True, init=False)
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

    # written out rather than an InitVar[bool] field and a __post_init__:
    # see the comment on dsa.Sig.__init__
    def __init__(
        self, r: int, s: int, ec: Curve = secp256k1, *, check_validity: bool = True
    ) -> None:
        object.__setattr__(self, "r", r)
        object.__setattr__(self, "s", s)
        object.__setattr__(self, "ec", ec)

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

    def serialize(self, *, check_validity: bool = True) -> bytes:
        if check_validity:
            self.assert_valid()

        out = self.r.to_bytes(self.ec.p_size, byteorder="big", signed=False)
        out += self.s.to_bytes(self.ec.n_size, byteorder="big", signed=False)
        return out

    @classmethod
    def parse(cls: type[Sig], data: BinaryData, *, check_validity: bool = True) -> Sig:
        stream = bytesio_from_binarydata(data)
        ec = secp256k1
        r = int.from_bytes(stream.read(ec.p_size), byteorder="big", signed=False)
        s = int.from_bytes(stream.read(ec.n_size), byteorder="big", signed=False)
        return cls(r, s, ec, check_validity=check_validity)


# hex-string or bytes representation of an int
# 33 or 65 bytes or hex-string
# BIP32Key as dict or String
# tuple Point
BIP340PubKey = Integer | Octets | BIP32Key | Point


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


def challenge_(msg: Octets, x_Q: int, x_K: int, ec: Curve, hf: HashF) -> int:
    # the message, of any size ("Messages of Arbitrary Size" in BIP340):
    # the tagged hash below absorbs any length unambiguously, x_K and x_Q
    # being fixed at p_size each
    msg = bytes_from_octets(msg)

    t = b"".join(
        [
            x_K.to_bytes(ec.p_size, byteorder="big", signed=False),
            x_Q.to_bytes(ec.p_size, byteorder="big", signed=False),
            msg,
        ]
    )
    t = tagged_hash(b"BIP0340/challenge", t, hf)

    c: int = int_from_bits(t, ec.nlen) % ec.n
    # c = 0 removes the public key from verification, which degenerates
    # to s*G = K: anyone satisfies that with K = s*G, one signature
    # valid under every key. BIP340 does not bother rejecting it, as on
    # secp256k1 reaching c = 0 means finding a preimage of zero for the
    # tagged hash; but this python path serves the low-cardinality test
    # curves too, where c = 0 is one challenge in n and the exhaustive
    # test shows the degenerate signature verifying under every key --
    # so refuse it here, for signing and verification alike
    if c == 0:
        raise BTClibRuntimeError("invalid zero challenge")
    return c


def _sign_(c: int, q: int, nonce: int, r: int, ec: Curve) -> Sig:
    # Private function for testing purposes: it allows to explore all
    # possible value of the challenge c (for low-cardinality curves).
    # That freedom is what Fiat-Shamir forbids -- the public API derives
    # c from the nonce point, committing before the challenge -- and it
    # is why this function must stay private.
    # It assume that c is in [1, n-1], while q and nonce are in [1, n-1]
    if c == 0:  # c≠0 required as it multiplies the private key
        raise BTClibRuntimeError("invalid zero challenge")

    # s=0 is ok: in verification there is no inverse of s
    s = (nonce + c * q) % ec.n

    return Sig(r, s, ec)


@overload
def sign_(
    msg: Octets,
    prv_key: PrvKey,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    commit_hash: None = None,
) -> Sig: ...


@overload
def sign_(
    msg: Octets,
    prv_key: PrvKey,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    commit_hash: Octets,
) -> tuple[Sig, Point]: ...


def sign_(
    msg: Octets,
    prv_key: PrvKey,
    aux: Octets | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
    *,
    commit_hash: Octets | None = None,
) -> Sig | tuple[Sig, Point]:
    """Sign a message of any size according to BIP340 signature algorithm.

    The message is signed as it is: BIP340 puts no size restriction on
    it, so this takes the BIP340 message itself, of any length. `sign` is
    the other spelling: it reduces its argument with hf first, which is
    what btclib's trailing underscore distinguishes -- whether the caller
    prepared the input or the library does it.

    If the deterministic nonce is not provided, the BIP340 specification
    (not RFC6979) is used.

    commit_hash is a value to commit to inside the nonce, sign-to-contract
    style: the signature is an ordinary BIP340 one, and the receipt
    returned beside it is what opens the commitment (see
    btclib.ecc.commit_nonce). Keyword-only, and the only argument that
    changes what is returned, so that neither is easy to pass by accident.
    A commitment does not displace aux: it joins it, both of them
    reaching the nonce as BIP340's auxiliary randomness.
    """
    msg = bytes_from_octets(msg)

    hf_len = hf().digest_size
    aux = secrets.token_bytes(hf_len) if aux is None else bytes_from_octets(aux, hf_len)

    # the committed value has to reach the nonce derivation, or two
    # commitments over one message hand out the private key -- see
    # commit_nonce. BIP340 has the slot for it and dsa does not: `a` is
    # whatever the signer wants mixed in, so aux and the commitment are
    # hashed together into it and both still count. That is why ssa keeps
    # taking its aux where dsa refuses a nonce beside a commitment: an
    # aux is an input to the derivation, a nonce is its answer
    if commit_hash is not None:
        aux = commit_entropy_(aux + bytes_from_octets(commit_hash), _S2C_DATA_TAG, hf)

    # len(msg) == 32 as well as the curve and the hash function: BIP340
    # takes a message of any size, but the bindings require 32 bytes --
    # "the message hash must be 32 bytes", measured on 0.7.1rc1 -- so
    # anything else takes the python path, which is the pattern already in
    # place for a caller-supplied nonce and for every other curve.
    # A commitment joins them: it tweaks the nonce, and the nonce is the
    # bindings' own to derive
    if len(msg) == 32 and _libsecp256k1_applicable(ec, hf) and commit_hash is None:
        # the bindings take a scalar, not the many representations of a
        # private key btclib accepts
        q = int_from_prv_key(prv_key, ec)
        return Sig.parse(libsecp256k1_ssa.sign(msg, q, aux))

    # k is the nonce: an integer in the range 1..n-1.
    k, x_K, q, x_Q = bip340_nonce_(msg, prv_key, aux, ec, hf)

    if commit_hash is None:
        # the challenge
        c = challenge_(msg, x_Q, x_K, ec, hf)
        return _sign_(c, q, k, x_K, ec)

    # the tweak moves the nonce's point, and BIP340 signs with the
    # even-y one: k comes back from bip340_nonce_ already normalized,
    # so it is the tweaked point whose parity is still to be settled --
    # and x_K, which the challenge commits to, is the tweaked one.
    # The receipt keeps the even-y point the tweak hashed
    k, receipt = commit_nonce_(commit_hash, k, _S2C_POINT_TAG, ec, hf)
    x_K, y_K = mult(k, ec=ec)
    if y_K % 2:
        k = ec.n - k

    c = challenge_(msg, x_Q, x_K, ec, hf)

    return _sign_(c, q, k, x_K, ec), receipt


@overload
def sign(
    msg: Octets,
    prv_key: PrvKey,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    commit: None = None,
) -> Sig: ...


@overload
def sign(
    msg: Octets,
    prv_key: PrvKey,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    commit: Octets,
) -> tuple[Sig, Point]: ...


def sign(
    msg: Octets,
    prv_key: PrvKey,
    aux: Octets | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
    *,
    commit: Octets | None = None,
) -> Sig | tuple[Sig, Point]:
    """Sign message according to BIP340 signature algorithm.

    The message msg is first processed by hf, yielding the value

    msg_hash = hf(msg),

    a sequence of bits of length *hf_len*.

    Normally, hf is chosen such that its output length *hf_len* is
    roughly equal to *nlen*, the bit-length of the group order *n*,
    since the overall security of the signature scheme will depend on
    the smallest of *hf_len* and *nlen*; however, ECSSA supports all
    combinations of *hf_len* and *nlen*.

    The BIP340 deterministic nonce (not RFC6979) is used.

    commit is a value to commit to inside the nonce, and is reduced by hf
    as msg is: `sign_` is the spelling that takes the two hashes.
    """
    msg_hash = reduce_to_hlen(msg, hf)
    if commit is None:
        return sign_(msg_hash, prv_key, aux, ec, hf)
    return sign_(msg_hash, prv_key, aux, ec, hf, commit_hash=reduce_to_hlen(commit, hf))


def _assert_as_valid_(c: int, QJ: JacPoint, r: int, s: int, ec: Curve) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # Let K = sG - eQ.
    # in Jacobian coordinates
    KJ = double_mult_w_NAF(ec.n - c, QJ, s, ec.GJ, ec)

    # The following check is prescribed by BIP340 but it is useless:
    # if moved after 'Fail if x_K ≠ r' it would never be executed
    # Fail if infinite(KJ).
    # Fail if y_K is odd.
    if ec.y_aff_from_jac(KJ) % 2:
        raise BTClibRuntimeError("y_K is odd")

    # Fail if x_K ≠ r
    if KJ[0] != KJ[2] * KJ[2] * r % ec.p:
        raise BTClibRuntimeError("signature verification failed")


def _assert_commitment_(
    commit_hash: Octets | None, receipt: Point | None, sig: Sig, hf: HashF
) -> None:
    # the two come together or not at all, and a BTClibTypeError says so
    # because verify answers False for anything that is merely an invalid
    # signature: a commitment nobody can open, or a receipt for a
    # commitment that was never named, is a caller error and has to be
    # heard as one
    if commit_hash is None:
        if receipt is not None:
            raise BTClibTypeError("receipt without the commitment it opens")
    elif receipt is None:
        raise BTClibTypeError("commitment without the receipt that opens it")
    else:
        # sig.r is a field element, the x-coordinate itself and not a
        # scalar reduced modulo the group order, so the recomputed point
        # is compared as it comes
        W = commit_point_(commit_hash, receipt, _S2C_POINT_TAG, sig.ec, hf)
        if sig.r != W[0]:
            raise BTClibRuntimeError("commitment verification failed")


def assert_as_valid_(
    msg: Octets,
    Q: BIP340PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit_hash: Octets | None = None,
    receipt: Point | None = None,
) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False
    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.parse(sig)

    # ahead of the dispatch below, which returns early: opening a
    # commitment and verifying a signature are two independent checks of
    # the same r, and both have to run whichever implementation answers
    # the second one
    _assert_commitment_(commit_hash, receipt, sig, hf)

    x_Q, y_Q = point_from_bip340pub_key(Q, sig.ec)
    msg = bytes_from_octets(msg)

    # len(msg) == 32 as well as the curve and the hash function: see sign_.
    # Reporting a message the bindings cannot take as a *failed
    # verification* would answer False to four of BIP340's own TRUE
    # vectors (issue 169), so the length decides which implementation
    # runs, not whether the answer is no
    if len(msg) == 32 and _libsecp256k1_applicable(sig.ec, hf):
        pubkey_bytes = x_Q.to_bytes(32, "big")
        if not libsecp256k1_ssa.verify(msg, pubkey_bytes, sig.serialize()):
            raise BTClibRuntimeError("signature verification failed")
        return

    # Let c = int(hf(bytes(r) || bytes(Q) || msg)) mod n.
    c = challenge_(msg, x_Q, sig.r, sig.ec, hf)
    _assert_as_valid_(c, (x_Q, y_Q, 1), sig.r, sig.s, sig.ec)


def assert_as_valid(
    msg: Octets,
    Q: BIP340PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit: Octets | None = None,
    receipt: Point | None = None,
) -> None:
    """Verify the BIP340 signature of hf(msg).

    The other spelling, ``assert_as_valid_``, takes the BIP340 message
    itself, of any size. This one reduces msg with hf first, and commit
    with it.

    Double backticks because rst reads a trailing underscore as a link
    reference: bare, this name makes sphinx -W fail with 'Unknown target
    name: "assert_as_valid"'.
    """
    commit_hash = None if commit is None else reduce_to_hlen(commit, hf)
    assert_as_valid_(
        reduce_to_hlen(msg, hf), Q, sig, hf, commit_hash=commit_hash, receipt=receipt
    )


def verify_(
    msg: Octets,
    Q: BIP340PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit_hash: Octets | None = None,
    receipt: Point | None = None,
) -> bool:
    """Verify the BIP340 signature of a message of any size.

    The message is taken as it is; `verify` is the spelling that reduces it
    with hf first.

    commit_hash and receipt open the commitment the nonce carries, and a
    signature that does not commit to that value is False as a forged one
    is: the answer is about this signature and this commitment, both.
    """
    # ValueError and BTClibRuntimeError, not Exception: an input that is not
    # a valid signature is False, and so is a verification that failed, but
    # a TypeError is neither -- an hf passed as sha256() instead of sha256
    # is a caller error: raise, rather than report an invalid signature.
    # BTClibRuntimeError by name and not RuntimeError, because
    # RecursionError is one and is not an answer about a signature
    try:
        assert_as_valid_(msg, Q, sig, hf, commit_hash=commit_hash, receipt=receipt)
    except (ValueError, BTClibRuntimeError):
        return False

    return True


def verify(
    msg: Octets,
    Q: BIP340PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit: Octets | None = None,
    receipt: Point | None = None,
) -> bool:
    """Verify the BIP340 signature of hf(msg).

    commit is reduced by hf as msg is; `verify_` is the spelling that
    takes the two hashes.
    """
    commit_hash = None if commit is None else reduce_to_hlen(commit, hf)
    return verify_(
        reduce_to_hlen(msg, hf), Q, sig, hf, commit_hash=commit_hash, receipt=receipt
    )


def _recover_pub_key_(c: int, r: int, s: int, ec: Curve) -> int:
    # Private function provided for testing purposes only.
    if c == 0:
        raise BTClibRuntimeError("invalid zero challenge")

    KJ = r, ec.y_even(r), 1

    e1 = mod_inv(c, ec.n)
    QJ = double_mult_w_NAF(ec.n - e1, KJ, e1 * s, ec.GJ, ec)
    # QJ = e1*(s*G - K) is INF whenever r is the x of s*G, y even
    if QJ[2] == 0:
        err_msg = "invalid (INF) key"
        raise BTClibRuntimeError(err_msg)
    return int(ec.x_aff_from_jac(QJ))


def _err_msg(size: int, msgs_or_sigs: str, arg2: Sequence[Octets | Sig]) -> str:
    err_msg = f"mismatch between number of pub_keys ({size}) "
    return f"{err_msg} and number of {msgs_or_sigs} ({len(arg2)})"


def assert_batch_as_valid_(
    msgs: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:
    batch_size = len(Qs)
    if batch_size == 0:
        raise BTClibValueError("no signatures provided")

    if len(msgs) != batch_size:
        raise BTClibValueError(_err_msg(batch_size, "messages", msgs))
    if len(sigs) != batch_size:
        raise BTClibValueError(_err_msg(batch_size, "signatures", sigs))
    if batch_size == 1:
        assert_as_valid_(msgs[0], Qs[0], sigs[0], hf)
        return

    ec = sigs[0].ec
    if any(sig.ec != ec for sig in sigs):
        raise BTClibValueError("not the same curve for all signatures")
    t = 0
    scalars: list[int] = []
    points: list[JacPoint] = []
    for i, (msg, Q, sig) in enumerate(zip(msgs, Qs, sigs, strict=True)):
        # any size, as in sign_ and assert_as_valid_
        msg = bytes_from_octets(msg)

        KJ = sig.r, ec.y_even(sig.r), 1

        x_Q, y_Q = point_from_bip340pub_key(Q, ec)
        QJ = x_Q, y_Q, 1

        c = challenge_(msg, x_Q, sig.r, ec, hf)

        # rand in 1..n-1
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
    return


def assert_batch_as_valid(
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:
    msgs = [reduce_to_hlen(msg, hf) for msg in ms]
    return assert_batch_as_valid_(msgs, Qs, sigs, hf)


def batch_verify_(
    msgs: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> bool:
    # ValueError and BTClibRuntimeError, not Exception: an input that is not
    # a valid signature is False, and so is a verification that failed, but
    # a TypeError is neither -- an hf passed as sha256() instead of sha256
    # is a caller error: raise, rather than report an invalid signature.
    # BTClibRuntimeError by name and not RuntimeError, because
    # RecursionError is one and is not an answer about a signature
    try:
        assert_batch_as_valid_(msgs, Qs, sigs, hf)
    except (ValueError, BTClibRuntimeError):
        return False

    return True


def batch_verify(
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> bool:
    """Batch verification of BIP340 signatures."""
    msgs = [reduce_to_hlen(msg, hf) for msg in ms]
    return batch_verify_(msgs, Qs, sigs, hf)
