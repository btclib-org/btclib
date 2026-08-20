# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""MuSig2 key and signature aggregation, according to BIP327.

https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki

MuSig2 turns many signers into one: their public keys aggregate into a
single x-only key Q, and their partial signatures into a single BIP340
signature that verifies under Q with `btclib.ecc.ssa` and with any other
BIP340 verifier. A verifier -- and the chain -- sees an ordinary
single-key Schnorr signature, which is where the privacy and the size
come from.

What is offered here is a primitive per round, not a function that
signs, because signing is interactive and no library call can be: the
signers exchange nonces, then partial signatures, and each exchange is
somebody else's network. The rounds are

- key aggregation, once per group: `key_sort`, `key_agg`, `apply_tweak`
  and `key_agg_and_tweak`, answering a `KeyAggContext`;
- round 1, the nonces: `nonce_gen` for each signer, then `nonce_agg`
  over what they published, which anyone can do;
- round 2, the partial signatures: `sign` (or `deterministic_sign`) for
  each signer, `partial_sig_verify` to hold a signer to what it sent,
  and `partial_sig_agg` for the aggregate signature.

The nonce is a *pair* of points, and that is the whole of what MuSig2
adds to its predecessor. A one-round scheme in which each signer
publishes a single R_i is broken by Wagner's generalized birthday
attack: an adversary opening many concurrent sessions solves for a
forgery on a message nobody signed. Committing two points and combining
them as R_1 + b*R_2, with b a hash of the aggregate nonce, the aggregate
key and the message, makes the effective nonce depend on values the
adversary cannot fix in advance -- and buys back the round that the
earlier commit-then-reveal defence had to spend. That defence was
itself a correction: MuSig's first proposal had two rounds and no nonce
commitment, and it was withdrawn once a signer choosing its nonce
adaptively -- after seeing everyone else's -- was shown to defeat the
proof.

Key aggregation is not a plain sum either: sum(P_i) lets a rogue signer
publish P_n = P - sum(P_1..P_n-1) for a P it controls, and sign alone
for the group. Each key therefore enters with a coefficient
a_i = hash(L, P_i), L being the hash of the whole list, so no signer can
choose its key knowing the others'.

Tweaking is what makes the aggregate key usable: a plain tweak is BIP32
derivation on top of the group key, an x-only tweak is a BIP341 taproot
commitment. `KeyAggContext` carries `gacc` and `tacc` across tweaks --
the accumulated negation and the accumulated tweak -- so that the
partial signatures still add up to a signature valid under the tweaked
key.

secp256k1 and sha256 are not parameters here, unlike everywhere else in
`btclib.ecc`. BIP327 is defined for that pair alone: the tags below, the
33-byte compressed points, the 32-byte scalars and the 66-byte nonces
are its serialization, and there is no other curve for which a test
vector exists. A `Curve` argument would advertise a genericity the
specification does not define and no vector could check.

The message is of any size, as in `btclib.ecc.ssa`: BIP327 states no
restriction, and two of its own vectors are an empty message and a
38-byte one.

One rule outlives every abstraction here: **a secret nonce signs once**.
Two signatures under one secnonce hand out the private key by
elementary algebra, which is why `sign` zeroes the bytearray it is given
rather than merely reading it.

Adaptor signatures are the one capability BIP327 does not cover:
`SessionContext.adaptor` carries a public point T, and
`partial_sig_agg_adaptor` -- the spelling for a session that carries
one, `partial_sig_agg` itself refusing that session -- answers a
*pre-signature*, a `PreSignature` rather than an `ssa.Sig` because it
does not verify, that `adapt` turns into a real signature given the
secret t behind T, or that `extract_adaptor` recovers t from, given
both the pre-signature and the signature `adapt` produced. Splitting
the entry point rather than widening `partial_sig_agg`'s return type
keeps every existing caller narrowing nothing, and matches where the
C library is going: secp256k1-zkp#330 is splitting
`musig_nonce_process` the same way, back to five arguments plus a
separate `musig_nonce_process_adaptor`, so the base API stays
uncontaminated by a capability most callers never touch. A DLC's
contract execution transaction, an atomic swap across two chains and a
payment channel's revocation all build on the same trade: whoever
completes the signature is whoever knew t, and revealing the signature
beside its pre-signature reveals t to anyone holding both.

There is no BIP for this and no vector file, so the construction is read
off secp256k1-zkp, the de facto specification:
https://github.com/BlockstreamResearch/secp256k1-zkp/blob/master/src/modules/musig/session_impl.h
and .../adaptor_impl.h beside it. Two details are where an
implementation goes wrong and zkp does not: T is added to R_1 *before*
b is hashed, not to the final R afterward, so the challenge itself
commits to T and it cannot be swapped in once b is fixed; and `adapt`
negates t exactly when the final nonce has odd y, because the
pre-signature's nonce is then really -(r+t)*G rather than (r+t)*G --
`adaptor_impl.h`'s own comment gives this reasoning in full.

Cross-validating this construction against zkp is
btclib-org/btclib#156's open question, not answered here: the vendored
library, mainline `bitcoin-core/secp256k1`, has no adaptor support at
all, so the round-trip tests below are this module's only check for
now.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from typing import TYPE_CHECKING

from btclib._libsecp256k1 import musig as libsecp256k1_musig
from btclib.alias import INF, Octets, Point
from btclib.curves import mult, multi_mult_var, secp256k1
from btclib.curves.curve import _libsecp256k1_serves, _sum_var, _tweak_add_var
from btclib.curves.sec_point import (
    bytes_from_point,
    bytes_from_prv_key_int,
    point_from_octets,
)
from btclib.ecc import ssa
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibValueError,
    InvalidContributionError,
)
from btclib.hashes import tagged_hash
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "KeyAggContext",
    "PreSignature",
    "SessionContext",
    "SessionValues",
    "adapt",
    "apply_tweak",
    "deterministic_sign",
    "extract_adaptor",
    "individual_pub_key",
    "key_agg",
    "key_agg_and_tweak",
    "key_sort",
    "nonce_agg",
    "nonce_gen",
    "nonce_gen_",
    "partial_sig_agg",
    "partial_sig_agg_adaptor",
    "partial_sig_verify",
    "partial_sig_verify_",
    "session_values",
    "sign",
]

# `SessionContext._bindings_ctx`'s element types, under TYPE_CHECKING for
# the reason `bip32.py`'s own `_PubKeyTweakChain` union is: `from __future__
# import annotations` leaves an annotation a string, so nothing here is
# evaluated at runtime and the bindings need not be installed for the
# module to import -- this is only for mypy, which runs where they are
if TYPE_CHECKING:
    from btclib_secp256k1.musig import KeyAggCache as _KeyAggCache
    from btclib_secp256k1.musig import Session as _Session

# the tags of BIP327, which are what makes a MuSig2 hash a MuSig2 hash:
# a different string is a different scheme, incompatible with every other
# implementation, so these are frozen by the specification and not by
# taste. 'KeyAgg list' and 'KeyAgg coefficient' carry no 'MuSig' prefix
# because BIP327 inherited them from the MuSig2 paper before the BIP had
# a number; copy them as they are
_KEY_AGG_LIST_TAG = b"KeyAgg list"
_KEY_AGG_COEFF_TAG = b"KeyAgg coefficient"
_AUX_TAG = b"MuSig/aux"
_NONCE_TAG = b"MuSig/nonce"
_NONCE_COEFF_TAG = b"MuSig/noncecoef"
_DET_NONCE_TAG = b"MuSig/deterministic/nonce"

# a compressed point, a scalar, a public nonce (two compressed points)
_PK_SIZE = 33
_SCALAR_SIZE = 32
_NONCE_SIZE = 66

# the infinity point as 33 zero bytes: not a SEC encoding at all -- SEC
# has none for it -- but the placeholder BIP327 defines so that an
# aggregate nonce is always 66 bytes on the wire
_INF_BYTES = bytes(_PK_SIZE)

# BIP327's reference raises several of its own verbatim strings besides
# the four named below -- "first secnonce value is out of range." here
# and its "second" twin, and "Public key does not match nonce_gen
# argument" among them (`sign`, further down). What earns a name here is
# not "BIP327's own": it is whether a vector compares the string byte for
# byte, `assert_error` doing that for a "value" case's `error.message` --
# a paraphrase there would cost the comparison and a translation table in
# the test would drift from both sides at once. Only the four below and
# "first secnonce value is out of range." are compared that way today;
# `_TWEAK_SIZE_ERR` is named and untested by any vector regardless, for
# the reader rather than the suite. Everything else raises what the
# btclib helper it called raises, verbatim BIP327 string or not
_TWEAK_SIZE_ERR = "The tweak must be a 32-byte array."
_TWEAK_RANGE_ERR = "The tweak must be less than n."
_TWEAK_INF_ERR = "The result of tweaking cannot be infinity."
_SIGNER_PK_ERR = "The signer's pubkey must be included in the list of pubkeys."


def _cbytes(P: Point) -> bytes:
    return bytes_from_point(P, secp256k1)


def _cbytes_ext(P: Point) -> bytes:
    """Serialize a point that may be the infinity one."""
    return _INF_BYTES if P[1] == 0 else _cbytes(P)


def _cpoint(octets: Octets) -> Point:
    """Deserialize a compressed point, refusing anything else.

    `point_from_octets` is the SEC parser and takes the uncompressed
    0x04 form too; the size check ahead of it is what makes this
    BIP327's `cpoint`, which is compressed-only -- a 33-byte input with
    an 0x04 prefix is then the wrong size for what its prefix announces,
    and is refused as such.
    """
    return point_from_octets(bytes_from_octets(octets, _PK_SIZE), secp256k1)


def _cpoint_ext(octets: Octets) -> Point:
    """Deserialize a point that may be the infinity one."""
    data = bytes_from_octets(octets, _PK_SIZE)
    return INF if data == _INF_BYTES else _cpoint(data)


def _bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def _pub_keys(pub_keys: Sequence[Octets]) -> tuple[bytes, ...]:
    return tuple(bytes_from_octets(pk, _PK_SIZE) for pk in pub_keys)


def _tweaks(tweaks: Sequence[Octets]) -> tuple[bytes, ...]:
    return tuple(bytes_from_octets(t) for t in tweaks)


def _require_same_length(tweaks: Sequence[bytes], is_xonly: Sequence[bool]) -> None:
    if len(tweaks) != len(is_xonly):
        err_msg = "The `tweaks` and `is_xonly` arrays must have the same length."
        raise BTClibValueError(err_msg)


def _flag(is_xonly: bool) -> bool:
    """Return the kind of a tweak, which is a `bool` and not a truth.

    `utils.is_integer`'s policy mirrored: there a boolean is refused
    where a number is meant, here anything but a boolean is refused where
    a kind is meant, and the boundary that motivates both is the same. A
    kind written down and read back -- json, a configuration file, a
    coordinator's message -- arrives as whatever it was written as, and
    `"false"` is true. What this one decides is which of two aggregate
    keys the group signs under, so a value read for its truth would put
    half the signers on the other key rather than raise.
    """
    assert_type(is_xonly, bool, "is_xonly")
    return is_xonly


def _flags(is_xonly: Sequence[bool]) -> tuple[bool, ...]:
    return tuple(_flag(flag) for flag in is_xonly)


def individual_pub_key(prv_key: PrvKey) -> bytes:
    """Return the plain (33-byte, compressed) public key of a signer."""
    return bytes_from_prv_key_int(int_from_prv_key(prv_key, secp256k1), secp256k1)


def key_sort(pub_keys: Sequence[Octets]) -> list[bytes]:
    """Return the public keys in lexicographic order.

    The order the signers agree on is theirs to choose -- key
    aggregation commits to the list as given, and a different order is a
    different aggregate key -- but sorting is the convention that lets a
    group reach the same key without a further round.

    A new list, where BIP327's reference sorts in place: a function that
    reorders its argument makes the key of whoever kept a reference to
    that list change under them.
    """
    return sorted(_pub_keys(pub_keys))


def _hash_pub_keys(pub_keys: tuple[bytes, ...]) -> bytes:
    return tagged_hash(_KEY_AGG_LIST_TAG, b"".join(pub_keys))


def _second_pub_key(pub_keys: tuple[bytes, ...]) -> bytes:
    """Return the first key that differs from the first one.

    Its coefficient is 1 rather than a hash, which saves one scalar
    multiplication per aggregation and is safe: with two distinct keys
    in the list, no signer can solve for the rogue key that a plain sum
    would allow. 33 zero bytes when every key is the same -- not a valid
    key, so no member of the list can be equal to it and take the
    exemption by accident.
    """
    return next((pk for pk in pub_keys[1:] if pk != pub_keys[0]), _INF_BYTES)


def _key_agg_coeff_(L: bytes, second: bytes, pub_key: bytes) -> int:
    if pub_key == second:
        return 1
    return int.from_bytes(tagged_hash(_KEY_AGG_COEFF_TAG, L + pub_key), "big") % (
        secp256k1.n
    )


@dataclass(frozen=True)
class KeyAggContext:
    """The aggregate public key, and what tweaking it has accumulated.

    - Q is the aggregate point, tweaks included
    - gacc is the product of the negations x-only tweaking has forced,
      1 or n-1: a signer multiplies its key by it, so that the partial
      signatures add up under the even-y Q a BIP340 verifier assumes
    - tacc is the sum of the tweaks, which `partial_sig_agg` adds in
      once for the group rather than each signer adding a share of it
    """

    Q: Point
    gacc: int
    tacc: int

    @property
    def x_only_pub_key(self) -> bytes:
        """Return the 32-byte x-only aggregate key to verify against."""
        return self.Q[0].to_bytes(secp256k1.p_size, "big")


def key_agg(pub_keys: Sequence[Octets]) -> KeyAggContext:
    """Aggregate plain public keys into a `KeyAggContext`.

    The order of the list is part of the key: aggregate the same keys in
    another order and the group is another group. `key_sort` is the
    usual way to agree on one.
    """
    pks = _pub_keys(pub_keys)
    L = _hash_pub_keys(pks)
    second = _second_pub_key(pks)
    # the whole sum handed over at once, rather than a multiplication per
    # key and a point addition of btclib's own between two of them: that
    # is what `multi_mult_var` is, and on secp256k1 every term stays
    # serialized inside the bindings from the first to the last
    points: list[Point] = []
    coefficients: list[int] = []
    for i, pk in enumerate(pks):
        try:
            points.append(_cpoint(pk))
        except BTClibValueError as e:
            raise InvalidContributionError(i, "pubkey") from e
        coefficients.append(_key_agg_coeff_(L, second, pk))
    # a group of one signer is a sum of one term, which `multi_mult_var`
    # refuses as not being a multi-mult at all: it is a multiplication,
    # and `mult` is the spelling of one
    Q = (
        mult(coefficients[0], points[0], secp256k1)
        if len(points) == 1
        else multi_mult_var(coefficients, points, secp256k1)
    )
    if Q[1] == 0:  # pragma: no cover
        # the coefficients are hashes, so cancelling them all out is the
        # discrete-log problem rather than a case to handle: raise where
        # BIP327's reference asserts, an assert being absent under -O
        raise BTClibRuntimeError("aggregate key is the infinity point")
    return KeyAggContext(Q, 1, 0)


def apply_tweak(
    key_agg_ctx: KeyAggContext, tweak: Octets, is_xonly: bool
) -> KeyAggContext:
    """Return the context tweaked by t, x-only or plain.

    An x-only tweak is a BIP341 taproot commitment: it applies to the
    even-y point, so an odd-y Q is negated first and the negation is
    accumulated in gacc for the signers to apply to their keys. A plain
    tweak is BIP32 derivation on the group key, and takes Q as it is.

    Which of the two is a `bool` and nothing else: the line below reads
    it beside the parity of Q, so a value read for its truth would tweak
    an odd-y key the other way and answer another aggregate key.
    """
    tweak = bytes_from_octets(tweak)
    if len(tweak) != _SCALAR_SIZE:
        raise BTClibValueError(_TWEAK_SIZE_ERR)
    Q, gacc, tacc = key_agg_ctx.Q, key_agg_ctx.gacc, key_agg_ctx.tacc
    g = secp256k1.n - 1 if (_flag(is_xonly) and Q[1] % 2) else 1
    t = int.from_bytes(tweak, "big")
    if t >= secp256k1.n:
        raise BTClibValueError(_TWEAK_RANGE_ERR)
    # g is 1 or n-1, so g*Q is Q or its negation and there is no scalar
    # multiplication to make of it: what is left is Q + t*G, which is
    # `_tweak_add_var`'s one call
    Q = _tweak_add_var(Q if g == 1 else secp256k1.negate(Q), t, secp256k1)
    if Q[1] == 0:
        # t*G cancelling g*Q exactly: unreachable for a tweak nobody
        # chose to do it, reachable for one that did, and a key of
        # infinity has no signature
        raise BTClibValueError(_TWEAK_INF_ERR)
    return KeyAggContext(Q, g * gacc % secp256k1.n, (t + g * tacc) % secp256k1.n)


def key_agg_and_tweak(
    pub_keys: Sequence[Octets],
    tweaks: Sequence[Octets],
    is_xonly: Sequence[bool],
) -> KeyAggContext:
    """Aggregate the keys, then apply the tweaks in order."""
    tweaks_ = _tweaks(tweaks)
    is_xonly = _flags(is_xonly)
    _require_same_length(tweaks_, is_xonly)
    key_agg_ctx = key_agg(pub_keys)
    for tweak, xonly in zip(tweaks_, is_xonly, strict=True):
        key_agg_ctx = apply_tweak(key_agg_ctx, tweak, xonly)
    return key_agg_ctx


def _nonce_hash(
    rand: bytes, pk: bytes, agg_pk: bytes, i: int, msg_prefixed: bytes, extra_in: bytes
) -> int:
    buf = b"".join(
        [
            rand,
            len(pk).to_bytes(1, "big"),
            pk,
            len(agg_pk).to_bytes(1, "big"),
            agg_pk,
            msg_prefixed,
            len(extra_in).to_bytes(4, "big"),
            extra_in,
            i.to_bytes(1, "big"),
        ]
    )
    return int.from_bytes(tagged_hash(_NONCE_TAG, buf), "big")


def nonce_gen_(
    rand_: Octets,
    prv_key: PrvKey | None,
    pub_key: Octets,
    agg_x_only_pub_key: Octets | None = None,
    msg: Octets | None = None,
    extra_in: Octets | None = None,
) -> tuple[bytearray, bytes]:
    """Return the (secnonce, pubnonce) pair of one signer, given ``rand_``.

    Double backticks because rst reads a trailing underscore as a link
    reference: bare, that name makes sphinx -W fail with 'Unknown target
    name: "rand"'.

    The randomness is the argument, which is what makes BIP327's nonce
    vectors reproducible; `nonce_gen` is the spelling that draws it, and
    is the one to call. That is btclib's trailing underscore again:
    whether the caller prepared the input or the library does it.

    Every other input is optional and every one of them is a defence:
    the private key masks the randomness, so that a broken RNG alone
    does not repeat a nonce; the aggregate key, the message and
    `extra_in` (a counter, a clock) separate a nonce from the nonce of
    another session. None is not the empty value -- an absent message
    and an empty message are different inputs to the hash, by a prefix
    byte -- so pass what is known and leave the rest out.

    The returned secnonce is a bytearray, and mutable on purpose: `sign`
    zeroes it, which is the only mechanism here that can stop the same
    nonce signing twice.
    """
    rand_ = bytes_from_octets(rand_, _SCALAR_SIZE)
    if prv_key is None:
        rand = rand_
    else:
        # the key is masked by xor with the hashed randomness, rather
        # than hashed together with it, as BIP340 does: the fewer
        # operations touch the secret, the less there is to measure
        q = int_from_prv_key(prv_key, secp256k1)
        rand = _bytes_xor(q.to_bytes(_SCALAR_SIZE, "big"), tagged_hash(_AUX_TAG, rand_))
    pk = bytes_from_octets(pub_key, _PK_SIZE)
    agg_pk = (
        b""
        if agg_x_only_pub_key is None
        else bytes_from_octets(agg_x_only_pub_key, secp256k1.p_size)
    )
    if msg is None:
        msg_prefixed = b"\x00"
    else:
        msg = bytes_from_octets(msg)
        msg_prefixed = b"\x01" + len(msg).to_bytes(8, "big") + msg
    extra = b"" if extra_in is None else bytes_from_octets(extra_in)

    k_1 = _nonce_hash(rand, pk, agg_pk, 0, msg_prefixed, extra) % secp256k1.n
    k_2 = _nonce_hash(rand, pk, agg_pk, 1, msg_prefixed, extra) % secp256k1.n
    # k_1 or k_2 zero would be a hash landing on a multiple of n, and the
    # point at infinity has no serialization: _cbytes below raises rather
    # than a check here answering a question that cannot come up
    pub_nonce = _cbytes(mult(k_1, ec=secp256k1)) + _cbytes(mult(k_2, ec=secp256k1))
    sec_nonce = bytearray(
        k_1.to_bytes(_SCALAR_SIZE, "big") + k_2.to_bytes(_SCALAR_SIZE, "big") + pk
    )
    return sec_nonce, pub_nonce


def nonce_gen(
    prv_key: PrvKey | None,
    pub_key: Octets,
    agg_x_only_pub_key: Octets | None = None,
    msg: Octets | None = None,
    extra_in: Octets | None = None,
) -> tuple[bytearray, bytes]:
    """Return the (secnonce, pubnonce) pair of one signer.

    Fresh randomness is drawn here; ``nonce_gen_`` is the spelling that
    takes it, for the test vectors.
    """
    return nonce_gen_(
        secrets.token_bytes(_SCALAR_SIZE),
        prv_key,
        pub_key,
        agg_x_only_pub_key,
        msg,
        extra_in,
    )


def nonce_agg(pub_nonces: Sequence[Octets]) -> bytes:
    """Aggregate the public nonces of round 1 into the 66-byte aggnonce.

    Anybody can do this -- there is no secret in it -- and a signer that
    disagrees with the result is free to recompute it: the aggregate
    nonce is checked by the signature it produces.

    Either half can come out the infinity point, which is where the
    33-zero-byte placeholder comes from: refusing it here would let one
    signer, by publishing the negation of what the others published,
    stop the session at will.
    """
    nonces = [bytes_from_octets(nonce, _NONCE_SIZE) for nonce in pub_nonces]
    agg_nonce = b""
    for j in (0, 1):
        R_j: list[Point] = []
        for i, pub_nonce in enumerate(nonces):
            try:
                R_j.append(_cpoint(pub_nonce[j * _PK_SIZE : (j + 1) * _PK_SIZE]))
            except BTClibValueError as e:
                raise InvalidContributionError(i, "pubnonce") from e
        # the terms handed over at once rather than added into a running
        # total that crossed the boundary at every signer: the sum at
        # infinity above is a value now, which is what the placeholder is
        agg_nonce += _cbytes_ext(_sum_var(R_j, secp256k1))
    return agg_nonce


@dataclass(frozen=True, init=False)
class SessionContext:
    """Everything the signers of one session have to agree on.

    The aggregate nonce, the public keys in the order they aggregate in,
    the tweaks with their kinds, and the message. Two signers with
    different session contexts produce partial signatures that do not
    add up, which `partial_sig_verify` is there to catch.

    `adaptor` is `None` for an ordinary session and a 33-byte compressed
    point T for an adaptor one -- session data every party signs under,
    not an argument to `sign`, since a signer that did not agree to T
    must not sign a pre-signature it becomes valid for. Optional and
    last, so an existing positional call is still five arguments and
    still means what it meant.
    """

    agg_nonce: bytes
    pub_keys: tuple[bytes, ...]
    tweaks: tuple[bytes, ...]
    is_xonly: tuple[bool, ...]
    msg: bytes
    adaptor: bytes | None

    # `session_values`'s memoized answer, PreparedPoint.fixed's idiom for
    # a derived value on an otherwise-frozen dataclass: `compare=False`
    # keeps it out of the generated `__eq__`/`__hash__` by construction,
    # which is what lets two contexts spelling the same session stay
    # equal whichever of them a caller has already signed with, rather
    # than by the field being merely undeclared. `init=False` on the
    # decorator means the class attribute this default becomes is what
    # every fresh instance reads until `session_values`'s own
    # `object.__setattr__` gives it an instance one
    _values: SessionValues | None = field(
        default=None, init=False, repr=False, compare=False
    )

    # `partial_sig_verify_`'s own delegated-arm cache, the same idiom as
    # `_values` above and for the same reason: `musig_pubkey_agg` (+ its
    # tweaks) into a `KeyAggCache` and `musig_nonce_process` into a
    # `Session` are per-session, not per-signer, so building them once and
    # reusing them for every signer verified against this context is what
    # makes delegating the per-signer arithmetic a net win rather than a
    # wash -- issue #1049's own measurement of `nonce_process` staying
    # flat regardless of how many signers a session has
    _bindings_ctx: tuple[_KeyAggCache, _Session] | None = field(
        default=None, init=False, repr=False, compare=False
    )

    # written out rather than an InitVar and a __post_init__: as in
    # ssa.Sig, and here it also normalizes -- the fields hold bytes and
    # tuples whatever the caller passed, so that a hex string and the
    # bytes it spells make one context and not two
    def __init__(
        self,
        agg_nonce: Octets,
        pub_keys: Sequence[Octets],
        tweaks: Sequence[Octets],
        is_xonly: Sequence[bool],
        msg: Octets,
        adaptor: Octets | None = None,
    ) -> None:
        object.__setattr__(self, "agg_nonce", bytes_from_octets(agg_nonce, _NONCE_SIZE))
        object.__setattr__(self, "pub_keys", _pub_keys(pub_keys))
        object.__setattr__(self, "tweaks", _tweaks(tweaks))
        object.__setattr__(self, "is_xonly", _flags(is_xonly))
        object.__setattr__(self, "msg", bytes_from_octets(msg))
        object.__setattr__(
            self,
            "adaptor",
            None if adaptor is None else bytes_from_octets(adaptor, _PK_SIZE),
        )
        _require_same_length(self.tweaks, self.is_xonly)


@dataclass(frozen=True)
class SessionValues:
    """What every party derives from a `SessionContext` before signing.

    - Q, gacc and tacc are the aggregate key and its tweak accumulators
    - b is the coefficient combining the two halves of the nonce
    - R is the effective nonce point, R_1 + b*R_2
    - e is the BIP340 challenge, over R, Q and the message
    - L, second and pub_keys_set are what a per-signer key-aggregation
      coefficient is computed from -- issue #1069, the same shape #1045
      solved for the fields above: fixed for the session, so computed
      here once rather than by every one of `_session_key_agg_coeff`'s
      2n callers
    """

    Q: Point
    gacc: int
    tacc: int
    b: int
    R: Point
    e: int
    L: bytes
    second: bytes
    pub_keys_set: frozenset[bytes]


def session_values(session_ctx: SessionContext) -> SessionValues:
    """Derive the session values from the context, as every party does.

    Memoized on `session_ctx`: `sign`, `partial_sig_verify_` and
    whichever of `partial_sig_agg` or `partial_sig_agg_adaptor` a
    session uses each call this once per signer, so one session that
    signs, verifies every partial signature and aggregates would
    otherwise run the O(n) key aggregation below 2n+1 times over
    inputs that never change -- one call to aggregate either way, the
    two never both reaching the same session.
    `SessionContext._values` is declared `compare=False`, so it is
    excluded from the dataclass's generated `__eq__` and `__hash__` by
    construction, and two contexts spelling the same session remain
    equal regardless of which one has already been used to sign;
    `object.__setattr__` reaches past `frozen=True` to set it, exactly
    as `SessionContext.__init__` already does for its declared fields.

    `L`, `second` and `pub_keys_set` are computed here too, once, and
    not because deriving them needs anything above -- they are pure
    functions of `session_ctx.pub_keys` alone, the same as `key_agg`'s
    own `L` and `second`, which it likewise computes once and reuses
    for every key. Computed again here rather than threaded out of
    `key_agg_and_tweak` above: doing that would widen
    `KeyAggContext`, which `btclib/psbt/musig2.py` and callers outside
    this module already read, for a value only `_session_key_agg_coeff`
    wants. What earns them a place on `SessionValues` instead of a
    second cached field on `SessionContext` is that every caller of
    `_session_key_agg_coeff` -- `sign` and `partial_sig_verify_` --
    already calls this function first, so a `SessionValues` field costs
    nothing beyond what assembling the session already paid for.
    """
    if session_ctx._values is not None:
        return session_ctx._values
    key_agg_ctx = key_agg_and_tweak(
        session_ctx.pub_keys, session_ctx.tweaks, session_ctx.is_xonly
    )
    Q = key_agg_ctx.Q
    x_Q = key_agg_ctx.x_only_pub_key
    try:
        R_1 = _cpoint_ext(session_ctx.agg_nonce[:_PK_SIZE])
        R_2 = _cpoint_ext(session_ctx.agg_nonce[_PK_SIZE:])
    except BTClibValueError as err:
        raise InvalidContributionError(None, "aggnonce") from err
    # the adaptor point, folded into R_1 before b is hashed and not into
    # the final R afterward: b must commit to T, or an adaptor could be
    # swapped in once the pre-signature is already fixed. With no
    # adaptor R_1 is unchanged and _cbytes_ext round-trips it back to
    # exactly the bytes session_ctx.agg_nonce already carried, which is
    # what keeps every BIP327 vector byte-identical to before this
    if session_ctx.adaptor is not None:
        try:
            T = _cpoint(session_ctx.adaptor)
        except BTClibValueError as err:
            raise InvalidContributionError(None, "adaptor") from err
        R_1 = secp256k1.add_var(R_1, T)
    t = tagged_hash(
        _NONCE_COEFF_TAG, _cbytes_ext(R_1) + _cbytes_ext(R_2) + x_Q + session_ctx.msg
    )
    b = int.from_bytes(t, "big") % secp256k1.n
    R = secp256k1.add_var(R_1, mult(b, R_2, secp256k1))
    # an aggregate nonce of infinity is a session the signers can still
    # complete: G stands in for R, the resulting signature is invalid
    # for everybody equally, and no signer is singled out as the one who
    # spoiled it -- BIP327 prefers that to an abort a single participant
    # can force
    if R[1] == 0:
        R = secp256k1.G
    # ssa.challenge_, so that the challenge of an aggregate signature is
    # the one btclib's own BIP340 verifier recomputes, byte for byte and
    # for a message of any size
    e = ssa.challenge_(session_ctx.msg, Q[0], R[0], secp256k1, sha256)
    L = _hash_pub_keys(session_ctx.pub_keys)
    second = _second_pub_key(session_ctx.pub_keys)
    pub_keys_set = frozenset(session_ctx.pub_keys)
    values = SessionValues(
        Q, key_agg_ctx.gacc, key_agg_ctx.tacc, b, R, e, L, second, pub_keys_set
    )
    # nothing cached here is secret -- Q, gacc, tacc, b, R, e, L, second
    # and pub_keys_set are all public -- so caching them on the context
    # changes no security property this module publishes
    object.__setattr__(session_ctx, "_values", values)
    return values


def _session_key_agg_coeff(session_ctx: SessionContext, pub_key: bytes) -> int:
    # issue #1069: this used to be three O(n) traversals of pub_keys per
    # call -- the membership test, `_hash_pub_keys`'s join-and-hash and
    # `_second_pub_key`'s scan -- and ran 2n times per session, once per
    # signer from `sign` and once per signer from `partial_sig_verify_`.
    # `session_values` now derives `L`, `second` and `pub_keys_set` once
    # per session instead, the same fixed-input shape issue #1045 solved
    # for the curve arithmetic above; what is left here is an O(1)
    # frozenset membership test and one hash of constant size.
    #
    # The membership test stays a check of its own rather than folding
    # into the frozenset lookup below it: `_SIGNER_PK_ERR` is one of
    # BIP327's verbatim messages, pinned byte for byte by the vectors,
    # and a dict access raising `KeyError` would not produce it
    values = session_values(session_ctx)
    if pub_key not in values.pub_keys_set:
        raise BTClibValueError(_SIGNER_PK_ERR)
    return _key_agg_coeff_(values.L, values.second, pub_key)


def sign(sec_nonce: bytearray, prv_key: PrvKey, session_ctx: SessionContext) -> bytes:
    """Return the 32-byte partial signature of one signer.

    The secnonce is consumed: its first 64 bytes are zeroed the moment
    they are read, before either is used for anything, so that calling
    this twice with the same bytearray reads two zero scalars and raises
    "out of range" instead of handing out the private key. That is why
    the argument is a bytearray and not bytes -- an immutable secnonce
    is one nothing can spend -- and why a caller must not keep a copy.

    `session_values` runs first, and that is the one thing this order
    leaves spendable: a session that does not assemble -- a pubnonce that
    is no point, a tweak out of range -- raises before the nonce is
    touched, so the same bytearray may be used for the corrected session.
    Nothing was signed with it, which is what makes reuse safe there and
    only there, and BIP327's reference implementation has the two calls
    in this order for the same reason.
    """
    values = session_values(session_ctx)
    k_1_ = int.from_bytes(sec_nonce[:_SCALAR_SIZE], "big")
    k_2_ = int.from_bytes(sec_nonce[_SCALAR_SIZE : 2 * _SCALAR_SIZE], "big")
    sec_nonce[: 2 * _SCALAR_SIZE] = bytearray(2 * _SCALAR_SIZE)
    if not 0 < k_1_ < secp256k1.n:
        raise BTClibValueError("first secnonce value is out of range.")
    if not 0 < k_2_ < secp256k1.n:
        raise BTClibValueError("second secnonce value is out of range.")
    # the signature is over the even-y R, so a signer whose contribution
    # sits on the odd-y one negates both halves of its secret nonce
    if values.R[1] % 2:
        k_1_, k_2_ = secp256k1.n - k_1_, secp256k1.n - k_2_

    d_ = int_from_prv_key(prv_key, secp256k1)
    pk = individual_pub_key(d_)
    if pk != bytes(sec_nonce[2 * _SCALAR_SIZE :]):
        raise BTClibValueError("Public key does not match nonce_gen argument")
    a = _session_key_agg_coeff(session_ctx, pk)
    g = 1 if values.Q[1] % 2 == 0 else secp256k1.n - 1
    d = g * values.gacc * d_ % secp256k1.n
    s = (k_1_ + values.b * k_2_ + values.e * a * d) % secp256k1.n
    return s.to_bytes(_SCALAR_SIZE, "big")


def _det_nonce_hash(
    prv_key: bytes, agg_other_nonce: bytes, agg_pk: bytes, msg: bytes, i: int
) -> int:
    buf = b"".join(
        [
            prv_key,
            agg_other_nonce,
            agg_pk,
            len(msg).to_bytes(8, "big"),
            msg,
            i.to_bytes(1, "big"),
        ]
    )
    return int.from_bytes(tagged_hash(_DET_NONCE_TAG, buf), "big")


def deterministic_sign(
    prv_key: PrvKey,
    agg_other_nonce: Octets,
    pub_keys: Sequence[Octets],
    tweaks: Sequence[Octets],
    is_xonly: Sequence[bool],
    msg: Octets,
    rand: Octets | None = None,
) -> tuple[bytes, bytes]:
    """Return the (pubnonce, partial signature) of a signer with no RNG.

    The two rounds collapse into one for the *last* signer to act: given
    the aggregate of everybody else's nonces, it derives its own from
    the secret key and the session rather than from randomness, and
    publishes nonce and partial signature together. That is the answer
    for a signing device that has no entropy source, and it is safe
    exactly once per (key, session): the derivation is a function of its
    inputs, so signing twice over different other-nonces with the same
    key is what a deterministic scheme must not do -- pass `rand` when
    there is any doubt.
    """
    q = int_from_prv_key(prv_key, secp256k1)
    sk = q.to_bytes(_SCALAR_SIZE, "big")
    if rand is not None:
        sk = _bytes_xor(sk, tagged_hash(_AUX_TAG, bytes_from_octets(rand)))
    agg_other_nonce = bytes_from_octets(agg_other_nonce, _NONCE_SIZE)
    msg = bytes_from_octets(msg)
    agg_pk = key_agg_and_tweak(pub_keys, tweaks, is_xonly).x_only_pub_key

    k_1 = _det_nonce_hash(sk, agg_other_nonce, agg_pk, msg, 0) % secp256k1.n
    k_2 = _det_nonce_hash(sk, agg_other_nonce, agg_pk, msg, 1) % secp256k1.n
    pub_nonce = _cbytes(mult(k_1, ec=secp256k1)) + _cbytes(mult(k_2, ec=secp256k1))
    sec_nonce = bytearray(
        k_1.to_bytes(_SCALAR_SIZE, "big")
        + k_2.to_bytes(_SCALAR_SIZE, "big")
        + individual_pub_key(q)
    )
    try:
        agg_nonce = nonce_agg([pub_nonce, agg_other_nonce])
    except InvalidContributionError as e:
        # whoever aggregated the other nonces is accountable for them,
        # and there is no signer index to name: what this party received
        # is one 66-byte value, not the nonces behind it
        raise InvalidContributionError(None, "aggothernonce") from e
    session_ctx = SessionContext(agg_nonce, pub_keys, tweaks, is_xonly, msg)
    return pub_nonce, sign(sec_nonce, q, session_ctx)


def _bindings_session(session_ctx: SessionContext) -> tuple[_KeyAggCache, _Session]:
    """Return the session's (KeyAggCache, Session) pair, building it once.

    `partial_sig_verify_`'s delegated arm alone, cached on `session_ctx`
    the way `session_values` caches `SessionValues` and for the same
    reason: `musig_pubkey_agg` (+ its tweaks) into a `KeyAggCache` and
    `musig_nonce_process` into a `Session` are per-session rather than
    per-signer work, so a session that gets every one of its n partial
    signatures verified pays for this once instead of n times -- which is
    what turns delegating the per-signer arithmetic into a net win rather
    than a wash, `nonce_process` alone measuring flat regardless of n
    (issue #1049).

    Every input here has already gone through `session_values`, which
    `partial_sig_verify_` calls before ever asking whether to delegate: a
    `pub_keys` entry that is not a point, a tweak out of range, or one
    that lands the aggregate on infinity has already raised there, so
    nothing below can fail on an input this module itself built and
    already validated.
    """
    if session_ctx._bindings_ctx is not None:
        return session_ctx._bindings_ctx
    cache = libsecp256k1_musig.KeyAggCache(session_ctx.pub_keys)
    for tweak, xonly in zip(session_ctx.tweaks, session_ctx.is_xonly, strict=True):
        (cache.pubkey_xonly_tweak_add if xonly else cache.pubkey_ec_tweak_add)(tweak)
    bindings_session = libsecp256k1_musig.Session(
        session_ctx.agg_nonce, session_ctx.msg, cache
    )
    bindings_ctx = (cache, bindings_session)
    object.__setattr__(session_ctx, "_bindings_ctx", bindings_ctx)
    return bindings_ctx


def partial_sig_verify_(
    psig: Octets, pub_nonce: Octets, pub_key: Octets, session_ctx: SessionContext
) -> bool:
    """Verify a partial signature against a prepared session context.

    `partial_sig_verify` is the other spelling: it aggregates the public
    nonces itself, which is what btclib's trailing underscore
    distinguishes -- whether the caller prepared the input or the
    library does it.

    Delegated to `btclib_secp256k1.musig` for secp256k1, sha256, a
    32-byte message and a session with no adaptor (issue #1049): the
    three point multiplications below are what a signer pays once per
    session and a verifier once per signer it checks, and are 3.7x
    slower here than in the bindings. secp256k1 and sha256 are this
    module's only pair (its own docstring), so `_libsecp256k1_serves`
    reduces to whether the bindings are installed and enabled.
    `musig_nonce_process` takes a fixed 32-byte `msg32` with no length
    parameter -- the shape of issue 169 without the `sign_custom` that
    resolved it there, and BIP327's own empty-message and
    38-byte-message vectors are what keeps this Python arm live and
    validated for a message of any size. The bindings have no adaptor
    extension at all (this module's own docstring's "Cross-validating
    this construction against zkp" paragraph), so a session that
    carries one takes the Python arm regardless of the other two
    conditions. Nothing else in this module is delegated -- `key_agg`,
    `key_sort` and `nonce_agg` measured too close to their Python cost,
    or run once per session already, to be worth a second code path.

    The signer's pubkey has to be one of the session's -- a membership
    test with no C equivalent, `musig_partial_sig_verify` answering a
    verdict for whatever pubkey it is given rather than asking whether it
    was ever aggregated. `_session_key_agg_coeff` is what checks it, and
    the delegated arm below calls it for that check alone, discarding the
    coefficient the bindings compute on their own -- *after* the
    delegated call, once C has parsed `pub_nonce` and `pub_key` without
    refusing them, exactly where the Python arm below checks it once it
    has computed `P` from the same two. Both arms therefore refuse a key
    that is malformed the same way -- the parse failure, whichever arm's
    parse finds it -- and a key that is well-formed but foreign the same
    other way, `_SIGNER_PK_ERR`, so which `BTClibValueError` a caller sees
    does not depend on which arm answered it.
    """
    values = session_values(session_ctx)
    psig_bytes = bytes_from_octets(psig, _SCALAR_SIZE)
    s = int.from_bytes(psig_bytes, "big")
    if s >= secp256k1.n:
        return False
    pub_nonce = bytes_from_octets(pub_nonce, _NONCE_SIZE)
    # ahead of pub_nonce's own point-parsing below: the delegated branch
    # needs pub_key as validated-length bytes before it can hand it to
    # the bindings, and this length check is the one line both arms
    # share, so it runs once here rather than once per arm. The only
    # input this ordering affects is a direct partial_sig_verify_ call
    # carrying both a wrong-length pub_key and a malformed pub_nonce at
    # once -- unreachable through partial_sig_verify, which screens both
    # first -- where pub_key's length is what raises rather than
    # pub_nonce's parse; the exception type is the same either way, and
    # no vector pins which one a caller sees
    pub_key = bytes_from_octets(pub_key, _PK_SIZE)
    if (
        _libsecp256k1_serves(secp256k1, sha256)
        and len(session_ctx.msg) == _SCALAR_SIZE
        and session_ctx.adaptor is None
    ):
        cache, bindings_session = _bindings_session(session_ctx)
        try:
            verified = bindings_session.partial_sig_verify(
                psig_bytes, pub_nonce, pub_key, cache
            )
        except ValueError as e:
            # a parse failure: `btclib_secp256k1.musig`'s own docstring --
            # "a parse failure ... tells this package nothing" -- so
            # there is no message of the bindings' own to translate, only
            # the contract this public function keeps on either arm: a
            # pubnonce or pubkey that is not a point is a BTClibValueError
            err_msg = "invalid pubnonce or pubkey"
            raise BTClibValueError(err_msg) from e
        _session_key_agg_coeff(session_ctx, pub_key)
        return bool(verified)
    R_s1 = _cpoint(pub_nonce[:_PK_SIZE])
    R_s2 = _cpoint(pub_nonce[_PK_SIZE:])
    R_s = secp256k1.add_var(R_s1, mult(values.b, R_s2, secp256k1))
    if values.R[1] % 2:
        R_s = secp256k1.negate(R_s)
    P = _cpoint(pub_key)
    a = _session_key_agg_coeff(session_ctx, pub_key)
    g = 1 if values.Q[1] % 2 == 0 else secp256k1.n - 1
    g = g * values.gacc % secp256k1.n
    lhs = mult(s, secp256k1.G, secp256k1)
    rhs = secp256k1.add_var(R_s, mult(values.e * a * g % secp256k1.n, P, secp256k1))
    return lhs == rhs


def partial_sig_verify(
    psig: Octets,
    pub_nonces: Sequence[Octets],
    pub_keys: Sequence[Octets],
    tweaks: Sequence[Octets],
    is_xonly: Sequence[bool],
    msg: Octets,
    i: int,
) -> bool:
    """Verify the partial signature of signer i, against its own nonce.

    Every signer should verify every other signer's partial signature
    before aggregating: an aggregate signature that does not verify says
    only that somebody misbehaved, while this says who.

    This spelling builds a fresh `SessionContext` on every call, so
    `session_values`'s memoization buys it nothing: calling this once
    per signer re-aggregates the keys once per signer. A caller that
    verifies every signer of one session should build the
    `SessionContext` once and call `partial_sig_verify_` with it
    instead, which is what shares the cached session values across
    those calls.
    """
    if len(pub_nonces) != len(pub_keys):
        err_msg = "The `pubnonces` and `pubkeys` arrays must have the same length."
        raise BTClibValueError(err_msg)
    agg_nonce = nonce_agg(pub_nonces)
    session_ctx = SessionContext(agg_nonce, pub_keys, tweaks, is_xonly, msg)
    return partial_sig_verify_(psig, pub_nonces[i], pub_keys[i], session_ctx)


@dataclass(frozen=True)
class PreSignature:
    """A MuSig2 pre-signature: (x_R, s_pre), over a session with an adaptor.

    `partial_sig_agg_adaptor` answers one of these; `ssa.Sig`'s whole
    point is a value that verifies, and a pre-signature does not, until
    `adapt` supplies the secret behind the adaptor. Keeping it a
    different class from `ssa.Sig`, rather than the same class either
    call might answer, is what stops a caller from handing this to
    `ssa.verify_` and reading a failure as "bad signature" rather than
    "not adapted yet" -- and what keeps `partial_sig_agg`'s own return
    type exactly what it already was. It carries no `serialize`/`parse`
    of its own: BIP373 has no field for a pre-signature
    (`btclib.ecc.musig2`'s own docstring says so), so there is no wire
    format to answer to yet, and one invented here would have no caller
    to check it against.
    """

    r: int
    s: int


def _agg_s(psigs: Sequence[Octets], session_ctx: SessionContext) -> tuple[int, int]:
    """Return (x_R, s), the sum partial_sig_agg and its adaptor twin share.

    Summing the psigs and adding the tweak contribution once. Neither
    caller below knows or needs to know whether the session carries an
    adaptor: `session_values` already folded T into R before either is
    called, so the sum is the same sum either way, and it is only the
    two callers that decide what the sum is allowed to mean.
    """
    values = session_values(session_ctx)
    s = 0
    for i, psig in enumerate(psigs):
        s_i = int.from_bytes(bytes_from_octets(psig, _SCALAR_SIZE), "big")
        if s_i >= secp256k1.n:
            raise InvalidContributionError(i, "psig")
        s = (s + s_i) % secp256k1.n
    # the tweaks enter the signature once, here, and not as a share each
    # signer adds: the group tweaked the key, no single signer did
    g = 1 if values.Q[1] % 2 == 0 else secp256k1.n - 1
    s = (s + values.e * g * values.tacc) % secp256k1.n
    return values.R[0], s


def partial_sig_agg(psigs: Sequence[Octets], session_ctx: SessionContext) -> ssa.Sig:
    """Aggregate the partial signatures into one BIP340 signature.

    An `ssa.Sig`, because that is what it is: the result verifies under
    the x-only aggregate key with `btclib.ecc.ssa.verify_` and with
    every other BIP340 verifier, and handing back 64 bytes would only
    make the caller parse them again to find out.

    Refuses a session that carries an adaptor: the sum is still missing
    the adaptor's secret, so it does not verify, and answering an
    `ssa.Sig` for it would claim otherwise -- `partial_sig_agg_adaptor`
    is the spelling for that session, answering a `PreSignature` instead.
    """
    if session_ctx.adaptor is not None:
        err_msg = "session carries an adaptor: call partial_sig_agg_adaptor instead"
        raise BTClibValueError(err_msg)
    x_R, s = _agg_s(psigs, session_ctx)
    return ssa.Sig(x_R, s, secp256k1)


def partial_sig_agg_adaptor(
    psigs: Sequence[Octets], session_ctx: SessionContext
) -> PreSignature:
    """Aggregate the partial signatures into a MuSig2 pre-signature.

    `partial_sig_agg`'s own arithmetic, over a session that carries an
    adaptor: the sum does not verify until `adapt` supplies the secret
    behind it, which is what makes the result a `PreSignature` and not
    an `ssa.Sig`.

    Refuses a session with no adaptor -- `partial_sig_agg` is the
    spelling for that one, answering an `ssa.Sig` the sum already is.
    """
    if session_ctx.adaptor is None:
        err_msg = "session carries no adaptor: call partial_sig_agg instead"
        raise BTClibValueError(err_msg)
    x_R, s = _agg_s(psigs, session_ctx)
    return PreSignature(x_R, s)


def adapt(pre_sig: PreSignature, t: PrvKey, session_ctx: SessionContext) -> ssa.Sig:
    """Complete a pre-signature into a signature, given the secret adaptor.

    `session_ctx` is the session `pre_sig` was built from -- the same
    one `partial_sig_agg_adaptor` took -- because the one bit this needs and
    does not carry on its own is the parity `session_values` already
    derived, `R[1] % 2` on the final nonce R = R_1 + T + b*R_2.

    BIP340 signs the even-y nonce; when the parity is odd, the
    pre-signature's x-only nonce is really that of -(r+t)*G rather than
    (r+t)*G, so completing it needs -t rather than t.
    `secp256k1_musig_adapt` (`adaptor_impl.h`) is the source of this and
    negates the same way, and is also this function's authority: no
    BIP or vector file covers adaptor signatures.

    Nothing here re-verifies the result: a wrong `t` returns a `Sig`
    that fails `ssa.assert_as_valid_`, which is the caller's to run
    against the aggregate key it already has.
    """
    values = session_values(session_ctx)
    t_ = int_from_prv_key(t, secp256k1)
    if values.R[1] % 2:
        t_ = secp256k1.n - t_
    s = (pre_sig.s + t_) % secp256k1.n
    return ssa.Sig(pre_sig.r, s, secp256k1)


def extract_adaptor(
    sig: ssa.Sig, pre_sig: PreSignature, session_ctx: SessionContext
) -> bytes:
    """Return the secret adaptor a signature reveals against its pre-signature.

    The inverse of `adapt`, over the same `session_ctx`: whoever holds a
    valid signature and the pre-signature it was adapted from recovers
    exactly the `t` that `adapt` consumed. That is the second half of
    what makes an adaptor signature useful -- releasing the signature is
    releasing the secret -- and it is why `sig` is not checked against
    the aggregate key here: extraction is arithmetic on two scalars, and
    a `sig` that does not verify still yields the `t` that would make it
    the one `adapt` would have produced from a matching `pre_sig`.
    """
    values = session_values(session_ctx)
    t = (sig.s - pre_sig.s) % secp256k1.n
    if values.R[1] % 2:
        t = -t % secp256k1.n
    return t.to_bytes(_SCALAR_SIZE, "big")
