# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Elliptic Curve Schnorr Signature Algorithm (ECSSA).

This implementation is according to BIP340-Schnorr:

https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

The public key is the x-coordinate -- a field element -- of the curve
point associated to the private key 0 < q < n, so on secp256k1 a
public key is 32 bytes. Knowing q as the discrete logarithm of Q is
knowing n-q as the discrete logarithm of -Q, so {q, n-q} acts as one
private key and {Q, -Q} as the public key their shared x_Q names.

The dropped 02/03 prefix is implicit, not lost: verification needs an
unambiguous Y, so BIP340 fixes it as even, and the x-only key is the
compressed key 02||x with its prefix left unsaid. Halving the set of
valid public keys costs no security -- whoever breaks an x-only key
breaks the full key at the price of a negation -- and taking the bare
x as the key refuses a malleability: a verifier that accepted a point
and negated its odd Y would make every signature valid for two keys.

The hash function is BIP340's tagged SHA256,
TaggedHash(tag, x) = SHA256(SHA256(tag)||SHA256(tag)||x),
which makes a BIP340 hash invalid under any other tag and any other
scheme; the challenge uses tag 'BIP0340/challenge', the deterministic
nonce 'BIP0340/aux' and 'BIP0340/nonce'.

The challenge commits to the public key as well as to the nonce
point, c = TaggedHash('BIP0340/challenge', x_k||x_Q||msg), which
rules out public key recovery and is what makes batch verification
sound.

The challenge commits to the nonce point as well, and that dependency
is the Fiat-Shamir transform itself: hashing the commitment x_k
replaces the fresh challenge that an interactive verifier would send
only after receiving the commitment. Were c and the nonce chosen
independently, no private key would be needed: K = s*G - c*Q
satisfies verification for any Q.

The deterministic nonce is BIP340's own, not RFC6979's:

nonce = TaggedHash('BIP0340/nonce', t||x_Q||msg)
with t = q xor TaggedHash('BIP0340/aux', a), a the auxiliary randomness

The serialization is the fixed-size [r][s] -- p-size plus n-size
bytes, 64 on secp256k1 -- not the loosely specified ASN.1 DER of
ECDSA.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from types import TracebackType
from typing import overload

from typing_extensions import Self

from btclib._libsecp256k1 import ssa as libsecp256k1_ssa
from btclib.alias import BinaryData, HashF, Integer, JacPoint, Octets, Point
from btclib.curves import (
    Curve,
    PreparedPoint,
    point_from_octets,
    scalar_from_prv_key,
    secp256k1,
)
from btclib.curves.curve import (
    _assert_valid_ec,
    _is_x_coordinate_var,
    _jac_double_mult,
    _libsecp256k1_serves,
    _multi_mult_x_only_var,
    _y_even_var,
    mult,
)
from btclib.curves.curve_group import HEX_THRESHOLD
from btclib.ecc.bip340_nonce import bip340_nonce_
from btclib.ecc.commit_nonce import commit_entropy_, commit_nonce_, commit_point_
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.hashes import _assert_valid_hf, reduce_to_hlen, tagged_hash
from btclib.number_theory import mod_inv_var
from btclib.utils import (
    assert_no_trailing,
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    hex_string,
    int_from_bits,
    int_from_integer,
    is_integer,
    is_octets,
)

__all__ = [
    "BIP340PubKey",
    "Sig",
    "Signer",
    "assert_as_valid",
    "assert_as_valid_",
    "assert_batch_as_valid",
    "assert_batch_as_valid_",
    "batch_verify",
    "batch_verify_",
    "challenge_",
    "gen_keys",
    "point_from_bip340pub_key",
    "sign",
    "sign_",
    "verify",
    "verify_",
]

# bitcoin-core/secp256k1#1140 ("Schnorr sign-to-contract and anti-exfil")
# spells these `s2c/schnorr/point` and `s2c/schnorr/data`, in
# src/modules/schnorrsig/main_impl.h at its head 49c31379, and this tree
# matches it byte for byte: if it lands, a commitment made here opens
# there. #1140 is open and unmerged, so it is a reference and not an
# authority -- its spelling can still change, and the pull request may
# never land at all. Named for the standard rather than for btclib's
# `ssa`, and not under BIP0340/, which would claim the BIP defines this.
# Frozen all the same: a different string is a different scheme, and
# every signature already made would stop opening
_S2C_POINT_TAG = b"s2c/schnorr/point"
_S2C_DATA_TAG = b"s2c/schnorr/data"

# BIP340 serializes a signature as thirty-two octets of r and thirty-two
# of s, on secp256k1 and by that BIP alone: a Sig on another curve has no
# encoding here to be a length of
_REQUIRED_LENGTH = 64


@dataclass(frozen=True, init=False)
class Sig:
    """A BIP340-Schnorr signature: (r, s).

    r is a field element, 0 <= r < ec.p, the x-coordinate of the nonce
    point; s is a scalar, 0 <= s < ec.n, and zero is valid here where
    dsa.Sig refuses it, BIP340 placing no lower bound.
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
        """Refuse an r that is no x-coordinate, or an s outside 0..n-1."""
        # the curve first, as in dsa.Sig.assert_valid and for its reason:
        # both fields below are read against it
        _assert_valid_ec(self.ec)

        # r is a field element, fail if r is not a valid x-coordinate.
        # The question is existence: BIP340 fixes the y even, and
        # verification recomputes the point from the scalars rather than
        # lifting this r, so _is_x_coordinate_var and not the _y_even_var that
        # was here (issue 622). The delegated lift was already cheap on
        # the accepting path, and what it saves there is not the reason:
        # _y_even_var falls back to ec.y_even_var for an x the bindings
        # refuse -- that being where the message naming the value comes
        # from -- so refusing cost the whole Python square root, several
        # times what verifying a good signature costs. The expensive
        # answer was the one an attacker picks, half of the field
        # elements being no x-coordinate and costing nothing to produce.
        #
        # A bool leaves the message here, which is where it belongs: r is
        # this signature's, and "invalid x-coordinate" did not say which
        # of the two fields was wrong. dsa.Sig phrases its own for the
        # same reason, with the congruence this one has no use for -- r
        # is a field element here, not a scalar reduced mod n
        if not _is_x_coordinate_var(self.r, self.ec):
            err_msg = "r is not a valid x-coordinate: "
            err_msg += f"'{hex_string(self.r)}'" if self.r > 0xFFFFFFFF else f"{self.r}"
            raise BTClibValueError(err_msg)

        # s is a scalar, fail if s is not in [0, n-1]
        if not 0 <= self.s < self.ec.n:
            err_msg = "scalar s not in 0..n-1: "
            err_msg += f"'{hex_string(self.s)}'" if self.s > 0xFFFFFFFF else f"{self.s}"
            raise BTClibValueError(err_msg)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return BIP340's fixed-size r || s, 64 bytes on secp256k1."""
        if check_validity:
            self.assert_valid()

        out = self.r.to_bytes(self.ec.p_size, byteorder="big", signed=False)
        out += self.s.to_bytes(self.ec.n_size, byteorder="big", signed=False)
        return out

    @classmethod
    def parse(cls: type[Sig], data: BinaryData, *, check_validity: bool = True) -> Sig:
        """Build a Sig from BIP340's r || s bytes, on secp256k1.

        The serialization does not name its curve, so parse reads the
        one BIP340 is defined over; a Sig on another curve is built
        directly.

        Sixty-four octets exactly, and a witness signature is not one:
        BIP341 appends the sighash type to it, which is a byte about the
        transaction and not part of the signature. Stripping it is the
        caller's, `signature[:64]`, as btclib's own script engine does
        after reading it.
        """
        stream = bytesio_from_binarydata(data)
        sig_bin = stream.read(_REQUIRED_LENGTH)

        # the length is checked whatever check_validity says, as
        # bms.Sig.parse checks its own: it is not an opinion about the
        # signature but what makes the two slices below mean anything.
        # Skipped, sixty-three octets would yield a Sig whose s is a
        # thirty-one-byte integer -- below the order, so valid -- and no
        # bytes at all would yield the Sig of (0, 0)
        if len(sig_bin) != _REQUIRED_LENGTH:
            err_msg = f"invalid decoded length: {len(sig_bin)}"
            err_msg += f" instead of {_REQUIRED_LENGTH}"
            raise BTClibValueError(err_msg)
        assert_no_trailing(data, stream, "BIP340 signature")

        ec = secp256k1
        r = int.from_bytes(sig_bin[: ec.p_size], byteorder="big", signed=False)
        s = int.from_bytes(sig_bin[ec.p_size :], byteorder="big", signed=False)
        return cls(r, s, ec, check_validity=check_validity)


# an x-only key is an x, and these are the ways of writing one down:
# the integer itself; p-size octets or their hex, which is BIP340's own
# encoding of it; the 33 or 65 octets of a SEC point, whose x it is; and
# the point, prepared or not. An extended key is not among them -- it is
# bip32's object, and turning one into a key is bip32's call to make
# (issue #1188)
BIP340PubKey = int | Octets | Point | PreparedPoint


def _x_from_bip340pub_key(x_Q: BIP340PubKey, ec: Curve) -> int:
    """Return the x-coordinate of a BIP340 public key, however spelled.

    The dispatch over the spellings, without the lift that
    `point_from_bip340pub_key` puts on top of it: what an x-only key is
    unlifted is an x, and a verification through the bindings has no use
    for the y -- `libsecp256k1_ssa.verify` takes the x-only octets, and
    proving x an x-coordinate is what parsing them does anyway (issue
    887).

    So the x that comes back here is not proved to be an x-coordinate of
    anything: it is validated as far as its spelling goes, and whoever
    lifts or parses it is what refuses the rest. Private for that reason.
    """
    # BIP340 key as integer, read through the library's one integer
    # coercion rather than taken as it comes: an x is a number, and a
    # bool is not one anywhere a number is (issue #326). This was the
    # last int spelling of a key outside that rule; the tuple arm below
    # is covered by `is_on_curve`'s own refusal of a bool coordinate
    # (issue #1249). `isinstance(True, int)` made `True` the key at
    # x = 1, an x-coordinate of secp256k1, so both arms lifted it and
    # both answered about it where `dsa.verify` refused the same value
    # as a type: two schemes disagreeing and not two arms, where the
    # private side of issue #1206 had one scheme answering two ways.
    if isinstance(x_Q, int):
        return int_from_integer(x_Q)

    if isinstance(x_Q, PreparedPoint):
        x_Q = x_Q.point
    if isinstance(x_Q, tuple):
        # the same check `to_pub_key.point_from_pub_key` made for a point
        # before this function stopped going through it: on the curve,
        # and a y that is not zero -- `alias` marks infinity that way,
        # no affine point of a prime-order group having y = 0
        if ec.is_on_curve(x_Q) and x_Q[1] != 0:
            return x_Q[0]
        raise BTClibValueError(f"not a valid public key: {x_Q}")

    if is_octets(x_Q):
        # every spelling `Octets` names, which is what
        # `bytes_from_octets` takes. Accepted at all three sizes here,
        # where the dispatch this replaces took them at the SEC two and
        # refused them at the x-only one, its fallback having asked for
        # `(str, bytes)`
        #
        # the two octet spellings are told apart by length and not by
        # trying one and catching the other: p-size is BIP340's x-only
        # encoding, and the SEC sizes are a point whose x this wants.
        # `point_from_octets` is the parse and the proof for the second,
        # where the first is unproved here on purpose -- what an x-only
        # key is unlifted is an x, and the docstring above says who
        # proves it
        # the sizes go to `bytes_from_octets` rather than to
        # `point_from_octets`, which knows the SEC two: the x-only one is
        # this function's to accept, so a caller refused by the parse
        # below would be told that BIP340's own encoding is a wrong size
        sizes = (ec.p_size, ec.p_size + 1, 2 * ec.p_size + 1)
        octets = bytes_from_octets(x_Q, sizes)
        if len(octets) == ec.p_size:
            return int.from_bytes(octets, "big", signed=False)
        return point_from_octets(octets, ec)[0]

    raise BTClibTypeError("not a BIP340 public key")


def point_from_bip340pub_key(x_Q: BIP340PubKey, ec: Curve = secp256k1) -> Point:
    """Return a verified-as-valid BIP340 public key as Point tuple.

    It supports:

    - an int, the x-coordinate itself
    - BIP340 Octets (bytes or hex-string, p-size Point x-coordinate)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - a PreparedPoint, read as the point it holds
    - native tuple
    """
    _assert_valid_ec(ec)

    # the lift is what validates the x, and the same one for every
    # spelling: an x-only key is an x and the even y that goes with it.
    # _y_even_var is ec.y_even_var answered by libsecp256k1 for secp256k1,
    # a fraction of the modular square root it replaces, and the Python
    # one for every other curve
    x = _x_from_bip340pub_key(x_Q, ec)
    return x, _y_even_var(x, ec)


def gen_keys(prv_key: Integer | None = None, ec: Curve = secp256k1) -> tuple[int, int]:
    """Return a BIP340 private/public (int, int) key-pair."""
    # as in dsa.gen_keys, and for its reason
    _assert_valid_ec(ec)

    if prv_key is None:
        q = 1 + secrets.randbelow(ec.n - 1)
    else:
        q = scalar_from_prv_key(prv_key, ec)

    x_Q, y_Q = mult(q, ec=ec)
    if y_Q % 2:
        q = ec.n - q

    return q, x_Q


def challenge_(msg: Octets, x_Q: int, x_K: int, ec: Curve, hf: HashF) -> int:
    """Return the BIP340 challenge scalar over a prepared message.

    TaggedHash(BIP0340/challenge, x_K || x_Q || msg), reduced mod n.
    The message enters as it is, of any size, which is what the
    trailing underscore says throughout this module: no reduction by
    hf happens here.
    """
    _assert_valid_ec(ec)

    # prepared is not unchecked: the trailing underscore skips the
    # reduction of msg, not `is_integer`'s policy on x_K and x_Q, which
    # `int_from_integer` would refuse a bool for on the coerced spelling
    # (issue #1248, CONTRIBUTING.md's "This repository in particular")
    if not is_integer(x_Q):
        raise BTClibTypeError(f"non-integer x-coordinate: {x_Q}")
    if not is_integer(x_K):
        raise BTClibTypeError(f"non-integer nonce x-coordinate: {x_K}")

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
    # tagged hash; but this Python path serves the low-cardinality test
    # curves too, where c = 0 is one challenge in n and the exhaustive
    # test shows the degenerate signature verifying under every key --
    # so refuse it here, for signing and verification alike
    if c == 0:
        raise BTClibRuntimeError("invalid zero challenge")
    return c


def _sign_(c: int, q: int, nonce: int, r: int, ec: Curve) -> Sig:
    # Private, for tests: it takes the challenge c as an argument, so
    # a test can explore every value of it on a low-cardinality curve.
    # That freedom is what Fiat-Shamir forbids -- the public API derives
    # c from the nonce point, committing before the challenge -- and it
    # is why this function must stay private.
    # c and q and nonce are assumed in 1..n-1
    if c == 0:  # c≠0 required as it multiplies the private key
        raise BTClibRuntimeError("invalid zero challenge")

    # s=0 is ok: in verification there is no inverse of s
    s = (nonce + c * q) % ec.n

    return Sig(r, s, ec)


@overload
def sign_(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    verify: bool = ...,
    commit_hash: None = None,
) -> Sig: ...


@overload
def sign_(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    verify: bool = ...,
    commit_hash: Octets,
) -> tuple[Sig, Point]: ...


def sign_(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
    *,
    verify: bool = True,
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

    verify asks for the signature to be checked before it is answered
    with, and defaults to True. Here the default is the specification's
    and not only this library's policy: BIP340 puts the step inside
    *Default Signing* -- "If Verify(bytes(P), m, sig) returns failure,
    abort" -- where ECDSA's comes from Bitcoin Core. The flag exists for
    the caller who has measured the check against their own threat model,
    and `dsa.sign_` is where the same keyword is described at length. A
    check that fails raises BTClibRuntimeError saying that signing
    produced a signature that does not verify -- the words both arms use
    and `dsa`'s own -- with what the verification saw kept as the cause.

    No pub_key beside it, and that absence is a decision rather than an
    omission. What such an argument buys in `dsa` is the generator
    multiplication the check would otherwise do per signature; here there
    is none to save, the keypair holding the point already, so the check
    costs what it costs whether the caller holds the key or not --
    btclib-secp256k1#224 is where that is measured, and #982 is where the
    two schemes are put side by side. It would buy nothing and sell one
    thing: a second reason a check can fail, and with it the
    discrimination step `dsa._abort_unless_checked` has to pay for.

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

    # the curve and the hash function decide this, and the size of the
    # message does not. `libsecp256k1_ssa.sign` accepts only a 32-byte
    # message -- "the message hash must be 32 bytes", measured on
    # 0.7.1rc1 -- but `sign_custom` beside it takes BIP340's message of
    # any size, so every length reaches the constant-time C instead of
    # the Python arithmetic SECURITY.md publishes as not being constant
    # time.
    #
    # One call rather than a branch on the length: for a 32-byte message
    # the two answer the same signature octet for octet, and the
    # extraparams struct sign_custom fills costs a shade more (best of
    # nine, 3000 calls each) -- not a second code path's worth of a
    # signature.
    #
    # A commitment stays with the Python path: it tweaks the nonce, and
    # the nonce is the bindings' own to derive
    if _libsecp256k1_serves(ec, hf) and commit_hash is None:
        # the bindings take a scalar, and so does this module now: what
        # the call still buys is the range check and the octets
        q = scalar_from_prv_key(prv_key, ec)
        # the caller's `verify`, crossing with the rest: the bindings
        # perform the check and there is nothing for this arm to add,
        # BIP340's step being a bare verification under a point the
        # keypair already holds. What it costs is measured where it is
        # performed -- cheaper than ECDSA's own analogous step,
        # btclib-secp256k1#224 -- and is not re-measured here, a figure
        # of theirs kept in this file being one that ages when they
        # change and says nothing when it does
        try:
            signature = libsecp256k1_ssa.sign_custom(msg, q, aux, verify=verify)
        except RuntimeError as e:
            # the refusal is theirs and the hierarchy has to be btclib's,
            # which is `dsa`'s rule at its own call into the bindings: a
            # caller catching BTClibException should not have to know
            # which arm answered. Their sentence is kept rather than
            # reworded, `_checked` below raising the same one, so the two
            # arms refuse in the same words as well as under the same type
            raise BTClibRuntimeError(str(e)) from e
        return Sig.parse(signature)

    # k is the nonce: an integer in the range 1..n-1.
    k, x_K, q, x_Q = bip340_nonce_(msg, prv_key, aux, ec, hf)

    def _checked(c: int, signature: Sig) -> Sig:
        # the same contract as the single call into the bindings above,
        # the same default and the same refusal: a fallback answering
        # differently from the arm it stands in for is two libraries
        # wearing one name, and the answer to a check that failed is half
        # of what it answers. The challenge is passed in because the
        # commitment path recomputes it after the tweak, and it is the
        # tweaked one the signature commits to.
        #
        # The lift is the one thing this arm pays that the delegated one
        # does not: `bip340_nonce_` computes Q to answer x_Q and keeps
        # only the x, so the even-y point has to be recovered here --
        # `assert_as_valid_` does the same and for the same reason. No
        # `pub_key` argument would remove it, the caller's key being
        # x-only in this scheme, which is the second half of why the
        # docstring declines one
        if not verify:
            return signature
        QJ = x_Q, _y_even_var(x_Q, ec), 1
        try:
            _assert_as_valid_(c, QJ, signature.r, signature.s, ec, ec._fixed_points)
        except (ValueError, BTClibRuntimeError) as e:
            # its words are a verifier's -- `y_K is odd`, `signature
            # verification failed`, `INF has no y-coordinate` -- and are
            # not this caller's: they say what the check saw, where a
            # signer needs to hear what happened, which is that the
            # computation went wrong. They cannot be changed either, the
            # public `assert_as_valid_` sharing them, so the signing
            # sentence is raised over them and they are kept as the
            # cause. It is the bindings' own sentence and `dsa`'s on both
            # of its arms.
            #
            # Both hierarchies, which is the pair this file catches at
            # `verify_` and `verify` and `dsa` catches at the same
            # helper: a K that lands on infinity has no y to answer with
            # and is a ValueError, and that is the shape a nonce zeroed
            # after its point was computed takes -- s = c*q, so
            # sG - cQ is the point at infinity. `BTClibRuntimeError` by
            # name and not `RuntimeError`, because a RecursionError is
            # one and is not an answer about a signature
            raise BTClibRuntimeError(
                "signing produced a signature that does not verify"
            ) from e
        return signature

    if commit_hash is None:
        # the challenge
        c = challenge_(msg, x_Q, x_K, ec, hf)
        return _checked(c, _sign_(c, q, k, x_K, ec))

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

    # the signature is checked and the receipt is not: what opens the
    # commitment is `commit_point_` under the same r, which the caller
    # verifies with commit_hash and receipt in hand
    return _checked(c, _sign_(c, q, k, x_K, ec)), receipt


@overload
def sign(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    verify: bool = ...,
    commit: None = None,
) -> Sig: ...


@overload
def sign(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    verify: bool = ...,
    commit: Octets,
) -> tuple[Sig, Point]: ...


def sign(
    msg: Octets,
    prv_key: Integer,
    aux: Octets | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
    *,
    verify: bool = True,
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

    verify asks for the signature to be checked before it is answered
    with, as in `sign_`, which is where the default and the absence of a
    pub_key beside it are explained.

    commit is a value to commit to inside the nonce, and is reduced by hf
    as msg is: `sign_` is the spelling that takes the two hashes.
    """
    msg_hash = reduce_to_hlen(msg, hf)
    if commit is None:
        return sign_(msg_hash, prv_key, aux, ec, hf, verify=verify)
    return sign_(
        msg_hash,
        prv_key,
        aux,
        ec,
        hf,
        verify=verify,
        commit_hash=reduce_to_hlen(commit, hf),
    )


class Signer:
    """Sign several messages under one key, building the keypair once.

    `sign_` builds a `secp256k1_keypair` and wipes it before returning,
    so a second signature under the same key builds it again -- and that
    keypair is a multiplication of the generator, about half of what a
    BIP340 signature costs. This holds one across calls instead, which is
    worth better than half a signature each time. The measurement per
    batch size is in the CHANGELOG entry that introduced this class, an
    entry being read as the history of a release where this is read as a
    statement about the code as it stands.

    The same signatures come out, `sign` here being `sign_` over the
    keypair the signer holds, with the same default aux -- 32 octets
    drawn afresh per signature where the caller names none. The octets
    are what comes back rather than a `Sig`, that being what the callers
    of this want: a psbt writes a signature into a field, and building a
    `Sig` to serialize it again is the round trip this saves beside the
    keypair.

    **What this hands the caller is the lifetime of a secret.**
    `sign_` owns a keypair for the length of a call and wipes it in a
    `finally`; a signer holds one until told to let go. `wipe` is that
    instruction and the `with` statement is how to give it without
    having to remember::

        with ssa.Signer(prv_key) as signer:
            ...

    which wipes on the way out whether the block ended in a signature or
    in an exception. A wiped signer refuses to sign rather than signing
    with the zeros, and cannot be revived. So this is for a caller that
    already holds the secret for several signatures -- `SoftwareSigner`
    signing every leaf a psbt names one key in -- and a lone signature
    that drops the key afterwards is what `sign_` already is.

    A curve or a hash function the bindings do not serve has no keypair
    to hold: there every signature is `sign_`'s, so `wipe` has no
    keypair to overwrite and the `with` still reads the same -- what it
    does on that arm is drop the scalar and stop the signing, which is
    all it can. And the scalar is held on that arm alone: where a keypair
    exists it holds the same secret in memory that can be overwritten, so
    a second copy as a python int would be kept for nothing. What is not
    solved either way is the object the private key arrived in, nor that
    scalar where the Python arm needs it -- an int cannot be overwritten,
    only dropped, and SECURITY.md's limitations section is where that is
    stated for the library at large.
    """

    def __init__(
        self, prv_key: Integer, ec: Curve = secp256k1, hf: HashF = sha256
    ) -> None:
        _assert_valid_hf(hf)
        # the scalar, whatever spelling the key arrived in, and the
        # validation with it -- this is a public constructor and the
        # refusal belongs at it rather than at the first signature
        self._q = scalar_from_prv_key(prv_key, ec)
        self._ec = ec
        self._hf = hf
        self._hf_len = hf().digest_size
        self._signer = (
            libsecp256k1_ssa.Signer(self._q) if _libsecp256k1_serves(ec, hf) else None
        )
        # the scalar is what the Python arm signs with, and nothing else
        # reads it: where a keypair was built it holds the same secret in
        # memory the bindings can overwrite, so keeping the int beside it
        # would be a second copy held for nothing -- and the copy that
        # cannot be erased, at that
        if self._signer is not None:
            self._q = 0
        self._wiped = False

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.wipe()

    def wipe(self) -> None:
        """Let go of the key, and refuse to sign afterwards.

        The keypair is overwritten where there is one, which is the half
        of this that really erases: it is libsecp256k1's own memory and
        the bindings write zeros over it. The scalar this was built from
        is a python int and is dropped rather than erased -- rebinding
        the attribute is the whole of what a caller can do about an
        immutable object, and SECURITY.md's limitations section is where
        that is stated for the library at large. So a wiped signer is one
        that cannot sign and holds no keypair, not one that has scrubbed
        every copy of the secret from the process.

        Idempotent, so that a caller may wipe a signer it is not sure
        about; the `with` statement is the customary way to run one.
        """
        if self._signer is not None:
            self._signer.wipe()
            self._signer = None
        self._q = 0
        self._wiped = True

    def sign_(
        self, msg: Octets, aux: Octets | None = None, *, verify: bool = True
    ) -> bytes:
        """Return the signature of a prepared message, as its octets.

        The message is signed as it is, of any size, which is what the
        trailing underscore says throughout this module.

        verify is the free function's, and this is the call where it is
        the largest share of what it turns off: the keypair was built
        when this signer was, so the signature is the cheap part and the
        check is not. See `sign_` for the default and for why no pub_key
        joins it.
        """
        if self._wiped:
            raise BTClibValueError("the signer is wiped")

        if self._signer is None:
            return sign_(
                msg, self._q, aux, self._ec, self._hf, verify=verify
            ).serialize()

        # the aux `sign_` would have drawn, drawn here for the same
        # reason: BIP340's auxiliary randomness is per signature, and a
        # signer reusing one would derive one nonce for two messages
        msg = bytes_from_octets(msg)
        aux = (
            secrets.token_bytes(self._hf_len)
            if aux is None
            else bytes_from_octets(aux, self._hf_len)
        )
        # `sign_custom` and not `sign`, for the reason `sign_` above
        # gives at its own dispatch: `sign` is the 32-byte entry point,
        # and BIP340 puts no size on its message. Signing through it
        # would put back the gate issue 169 removed -- and would put it
        # back in only one of this class's two arms, the python one
        # signing what the delegated one refused
        #
        # the caller's `verify`, and this is where the check is the
        # largest share of what it is added to: the keypair was built
        # when this signer was, so signing here is markedly cheaper than
        # a fresh signature, and the same check on it is 61% of the call
        # against 44% there (btclib-secp256k1#224). It is the
        # one of btclib's signing calls a caller would most plausibly
        # want to decline, which is why the keyword reaching here is the
        # point of exposing it at all
        try:
            return self._signer.sign_custom(msg, aux, verify=verify)
        except RuntimeError as e:
            # translated as at `sign_`'s own crossing above, and for the
            # same reason: this is the second of the two calls that let
            # the bindings' bare RuntimeError out
            raise BTClibRuntimeError(str(e)) from e

    def sign(
        self, msg: Octets, aux: Octets | None = None, *, verify: bool = True
    ) -> bytes:
        """Return the signature of a message, reducing it with hf first."""
        return self.sign_(reduce_to_hlen(msg, self._hf), aux, verify=verify)


def _assert_as_valid_(
    c: int, QJ: JacPoint, r: int, s: int, ec: Curve, fixed: frozenset[JacPoint]
) -> None:
    # Private function for test/dev purposes
    # `fixed` is dsa._assert_as_valid_'s: the points whose wNAF tables
    # are memoized, the key's among them where the caller prepared it
    # It raises Errors, while verify should always return True or False

    # Let K = sG - eQ.
    # in Jacobian coordinates, and through the dispatching double_mult_var of
    # curves.curve rather than the Python arithmetic under it: what
    # reaches here is the verification the bindings' own declined, which
    # is another curve or another hash function -- the size of the message
    # was the third of those and is not any more -- and on secp256k1 the
    # multiplication is still theirs, some thirty-five times under the
    # Python arithmetic. The whole verification follows it, the two lifts
    # around it -- the r of the signature and the x-only key -- being
    # theirs as well
    KJ = _jac_double_mult(ec.n - c, QJ, s, ec.GJ, ec, fixed)

    # The following check is prescribed by BIP340 but it is useless:
    # if moved after 'Fail if x_K ≠ r' it would never be executed
    # Fail if infinite(KJ).
    # Fail if y_K is odd.
    #
    # This arm names which check failed, "y_K is odd" here and
    # "signature verification failed" below, where the delegated one at
    # assert_as_valid_'s libsecp256k1_ssa.verify call always says the
    # latter -- it has a bool to work with and this function has the
    # arithmetic. Left unequal on purpose (issue 998, dsa.py's own
    # `_assert_as_valid_` reading the same for the reason stated there)
    if ec.y_aff_from_jac_var(KJ) % 2:
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


def _invalid_x(x: int) -> str:
    """Return the message an x that is no x-coordinate is refused with."""
    err_msg = "invalid x-coordinate: "
    return err_msg + (f"{hex_string(x)}" if x > HEX_THRESHOLD else f"{x}")


def _x_only_bytes(x: int, ec: Curve) -> bytes:
    """Return the 32 octets of an x, refusing what is no field element.

    The range check `int.to_bytes` cannot make on its own -- an x at or
    above 2**256 is an OverflowError about a builtin, and one between p
    and 2**256 is octets libsecp256k1 will refuse -- and the message is
    `ec.y_var`'s, spelled here rather than reached by calling it: this
    exists not to take that square root.

    Whether the x is an x-coordinate at all is not asked. What asks is
    the verification these octets are on their way to, whose parse is
    that same lift (issue 887); `_invalid_x` is the message for what it
    refuses.
    """
    if not 0 <= x < ec.p:
        err_msg = "x-coordinate not in 0..p-1: "
        err_msg += f"{hex_string(x)}" if x > HEX_THRESHOLD else f"{x}"
        raise BTClibValueError(err_msg)
    return x.to_bytes(ec.p_size, byteorder="big")


def assert_as_valid_(
    msg: Octets,
    Q: BIP340PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit_hash: Octets | None = None,
    receipt: Point | None = None,
) -> None:
    """Refuse an invalid BIP340 signature over a prepared message.

    The message enters as it is, of any size; assert_as_valid is the
    spelling that reduces with hf first. Errors carry the reason,
    ``verify_`` being the boolean answer. With commit_hash and receipt the
    sign-to-contract commitment is opened as well, an independent
    check of the same r.
    """
    # ahead of everything, and the one input whose refusal has to be a
    # TypeError: verify_ below turns a ValueError into False, so an hf
    # checked any later than this would be reported as a signature that
    # does not verify. hashes._assert_valid_hf has the rest
    _assert_valid_hf(hf)

    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.parse(sig)

    # ahead of the dispatch below, which returns early: opening a
    # commitment and verifying a signature are two independent checks of
    # the same r, and both have to run whichever implementation answers
    # the second one
    _assert_commitment_(commit_hash, receipt, sig, hf)

    # the x, and the y only where there is something to do with one: the
    # curve is `sig.ec`, which `sig.assert_valid` above has checked
    x_Q = _x_from_bip340pub_key(Q, sig.ec)
    msg = bytes_from_octets(msg)

    # the curve and the hash function, and not the size of the message:
    # see sign_. `libsecp256k1_ssa.verify` has always taken BIP340's
    # message of any size -- what sent the four arbitrary-size vectors of
    # issue 169 down the Python path was the 32-byte gate in front of it,
    # never the call itself, and they are verified here now
    if _libsecp256k1_serves(sig.ec, hf):
        # x proved an x-coordinate once, by the verification itself: that
        # parse is the lift, and validating the key before it would be the
        # same square root twice (issue 887). So nothing here proves the
        # key -- what a ValueError from below means is that it was no
        # point, which is this function's to phrase
        x_bytes = _x_only_bytes(x_Q, sig.ec)
        # check_validity=False, because assert_valid has just run above --
        # on the Sig handed in, or inside the Sig.parse that made one. What
        # it would run again is the lift of r, which is not free even
        # delegated and costs many times more where it is not
        sig_bytes = sig.serialize(check_validity=False)
        try:
            verified = libsecp256k1_ssa.verify(msg, x_bytes, sig_bytes)
        except ValueError as e:
            raise BTClibValueError(_invalid_x(x_Q)) from e
        if not verified:
            # one fixed sentence, because libsecp256k1 answers a bool and
            # this is btclib's own wording for it, not a report of which
            # BIP340 check failed -- the Python arm below says that
            # instead. Both raise BTClibRuntimeError, which is the
            # contract; the message is diagnostic, not API, and a caller
            # is not meant to branch on it (issue 998, deciding to leave
            # the two arms disagreeing on wording rather than making them
            # agree at the cost of the diagnosis or of a second
            # verification pass on this path)
            raise BTClibRuntimeError("signature verification failed")
        return

    # the lift the branch above does not need, and the validation of x_Q
    # with it: `_x_from_bip340pub_key` reads the key and proves nothing
    y_Q = _y_even_var(x_Q, sig.ec)
    # the key's own memoized tables where the caller prepared it, as in
    # `dsa.assert_as_valid_`, which is a fifth off a verification under
    # one key. The negation is in that set too, which is what makes it
    # answer here -- a prepared point of odd y is this same key, and the
    # lift above is the one of the two BIP340 names
    fixed = Q.fixed if isinstance(Q, PreparedPoint) else sig.ec._fixed_points
    # Let c = int(hf(bytes(r) || bytes(Q) || msg)) mod n.
    c = challenge_(msg, x_Q, sig.r, sig.ec, hf)
    _assert_as_valid_(c, (x_Q, y_Q, 1), sig.r, sig.s, sig.ec, fixed)


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
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states: what is not a valid signature
    # is False, and a caller's own mistake is refused before this rather
    # than excluded from the except
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
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states. `assert_as_valid` and not a
    # delegation to the prepared spelling: the reduction has to be inside
    # the try, or a message that is no octets is refused here where the
    # hash spelling answers False about it (issue #814)
    try:
        assert_as_valid(msg, Q, sig, hf, commit=commit, receipt=receipt)
    except (ValueError, BTClibRuntimeError):
        return False

    return True


def _recover_pub_key_(c: int, r: int, s: int, ec: Curve) -> int:
    # Private function provided for testing purposes only.
    if c == 0:
        raise BTClibRuntimeError("invalid zero challenge")

    KJ = r, _y_even_var(r, ec), 1

    e1 = mod_inv_var(c, ec.n)
    # libsecp256k1 recovers no x-only key -- its recovery module is ECDSA
    # ("recover(msg, signature, recid)") and its xonly module has no
    # recovery in it -- so the delegated double_mult_var is the whole of what
    # there is to gain here, and it is all of the cost, the Python
    # arithmetic costing some thirty times more. Which is also why
    # this stays private, with no public spelling above it: BIP340 has
    # no recovery flag to carry the
    # candidate, x-only keys leaving nothing for one to disambiguate
    QJ = _jac_double_mult(ec.n - e1, KJ, e1 * s, ec.GJ, ec, ec._fixed_points)
    # QJ = e1*(s*G - K) is INF whenever r is the x of s*G, y even, and
    # that answer comes back from the bindings too: a libsecp256k1 pubkey
    # is never the identity, so the sum is recognized from the coordinates
    # in curves.curve and handed back as the z == 0 tested here
    if QJ[2] == 0:
        err_msg = "invalid (INF) key"
        raise BTClibRuntimeError(err_msg)
    return int(ec.x_aff_from_jac_var(QJ))


def _err_msg(size: int, msgs_or_sigs: str, arg2: Sequence[Octets | Sig]) -> str:
    err_msg = f"mismatch between number of pub_keys ({size}) "
    return f"{err_msg} and number of {msgs_or_sigs} ({len(arg2)})"


def _assert_batch_sequences(
    msgs: Sequence[Octets], Qs: Sequence[BIP340PubKey], sigs: Sequence[Sig]
) -> None:
    """Refuse a batch parameter that is no sequence, naming which.

    What is not one was walked untouched, so a None left the zip of
    `assert_batch_as_valid_`, or the reduction of `assert_batch_as_valid`,
    as "not iterable" -- a complaint about iteration, from underneath the
    library, about a batch (issue #814). Both spellings ask it, the
    reduction being ahead of the prepared one.

    A `str` is a Sequence and stays one: run time cannot tell
    Sequence[Octets] from Sequence[str], so the elements are what answer
    for their own values -- that is about telling one Sequence[Octets]
    from another, though, and no Sequence at all is `msgs`'s own mistake
    to refuse: every Octets is itself a Sequence, so one message passed
    where the batch was meant would zip through its bytes and challenge
    each as its own message (issue #1405).
    """
    if is_octets(msgs):
        raise BTClibTypeError(f"invalid msgs type: {type(msgs).__name__}")
    for value, what in ((msgs, "msgs"), (Qs, "Qs"), (sigs, "sigs")):
        assert_type(value, Sequence, what)


def assert_batch_as_valid_(
    msgs: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:
    """Refuse an invalid signature in a batch of prepared messages.

    BIP340's batch verification: one multi-scalar equation over
    random coefficients -- and which signature failed is not in the
    answer, only that one did. Messages enter as they are; every
    signature must share one curve.

    **It is not the fast way to verify n signatures of secp256k1.**
    Measured against n delegated `verify_` calls, the batch costs about
    twice a `verify_` a signature, both flat in n, so there is no
    crossover at any batch size. libsecp256k1 has no batch verification to
    delegate to, checked at 687155df upstream and at the tip of
    secp256k1-zkp, whose half-aggregation is a different construction; so
    what the batch saves in multiplications it spends on a Python term per
    signature, against a whole verification that is one C call.

    Where it does win is the arithmetic it was written for. With the
    bindings switched off -- every other curve, and every other hash
    function -- the equation is one multi-scalar multiplication where n
    verifications are n double multiplications, and it overtakes them
    between four signatures and eight. That is the reason it stays, beside
    its being BIP340's own algorithm and the reference the delegated path
    is read against. Both measurements per batch size are in the CHANGELOG
    entry that took them, an entry being read as the history of a release
    where this is read as a statement about the code as it stands.

    **Which leaves the question of why secp256k1 runs the equation at
    all, rather than a loop of `verify_`.** That loop would be twice as
    fast and would say *which* signature failed, where this says only
    that one did, so it is not obviously the wrong answer -- and it is
    not taken. What a caller asks of this function is BIP340 batch
    verification: one equation over random coefficients, the construction
    with the security argument the BIP makes, and the thing an
    implementation is compared against. A dispatch that answered it with
    n independent verifications would answer the same *verdict* by a
    different computation, and would leave nothing running the equation
    on the curve where the equation is checkable against libsecp256k1 --
    which is what `test_batch_validation_on_the_python_path` uses it for.
    A caller who wants n verifications has `verify_` and a loop, and the
    figures above are here so that the choice is an informed one.

    Every signature is asked whether it is one, this being a public
    function handed objects somebody else built: the equation below is
    not that question, and answers a different one for an s outside
    0..n-1.
    """
    # ahead of everything, as in assert_as_valid_ and for the same reason:
    # batch_verify_ turns a ValueError into False
    _assert_valid_hf(hf)

    # and the three sequences, for that reason again
    _assert_batch_sequences(msgs, Qs, sigs)

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

    # from two upward the equation is what answers, and it is satisfied by
    # a signature BIP340 calls invalid: s and s + n are congruent modulo
    # the group order, so `mult(t)` cannot tell them apart, while
    # assert_as_valid_ -- and the batch_size == 1 shortcut above with it --
    # refuses the second. Nothing reaches this from the wire, a
    # non-canonical s not fitting in 32 bytes, so what it takes is a caller
    # building Sig objects with check_validity=False; that is supported,
    # which is why the check belongs here rather than nowhere. The half of
    # assert_valid the equation would catch anyway is r, whose lift below
    # fails for a field element that is no x-coordinate.
    # After the curve check and not before it, so a batch mixing curves is
    # still told that, rather than being asked whether one signature's r is
    # an x-coordinate of a curve the batch has no business holding
    for sig in sigs:
        sig.assert_valid()
    t = 0
    scalars: list[int] = []
    x_coords: list[int] = []
    for i, (msg, Q, sig) in enumerate(zip(msgs, Qs, sigs, strict=True)):
        # any size, as in sign_ and assert_as_valid_
        msg = bytes_from_octets(msg)  # noqa: PLW2901

        # the x of each term and no lift, both terms being the even-y
        # point an x names: r has been proved an x-coordinate by
        # `sig.assert_valid` above, and x_Q is proved by the
        # multiplication these terms are on their way to, whose parse is
        # that same lift -- `assert_as_valid_` takes the shape for the
        # same reason (issue 887). The range is still this side's to
        # refuse, `challenge_` writing x_Q into its preimage and
        # answering an OverflowError for what is no field element
        x_Q = _x_from_bip340pub_key(Q, ec)
        _x_only_bytes(x_Q, ec)

        c = challenge_(msg, x_Q, sig.r, ec, hf)

        # rand in 1..n-1
        # deterministically generated using a CSPRNG seeded by a
        # cryptographic hash (e.g., SHA256) of all inputs of the
        # algorithm, or randomly generated independently for each
        # run of the batch verification algorithm
        rand = 1 if i == 0 else 1 + secrets.randbelow(ec.n - 1)
        scalars.append(rand)
        x_coords.append(sig.r)
        scalars.append(rand * c % ec.n)
        x_coords.append(x_Q)
        t += rand * sig.s

    if mult(t, ec=ec) != _multi_mult_x_only_var(scalars, x_coords, ec):
        raise BTClibRuntimeError("signature verification failed")
    return


def assert_batch_as_valid(
    ms: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> None:
    """Refuse an invalid signature in a batch, reducing each message."""
    # ahead of the reduction, which walks `ms`: the prepared spelling asks
    # the same thing, and neither can rely on the other having asked
    _assert_batch_sequences(ms, Qs, sigs)

    msgs = [reduce_to_hlen(msg, hf) for msg in ms]
    return assert_batch_as_valid_(msgs, Qs, sigs, hf)


def batch_verify_(
    msgs: Sequence[Octets],
    Qs: Sequence[BIP340PubKey],
    sigs: Sequence[Sig],
    hf: HashF = sha256,
) -> bool:
    """Answer whether every signature in the batch verifies.

    Messages enter prepared, as in ``assert_batch_as_valid_``; a failed
    verification and a malformed input are both False, a caller error
    still raises.
    """
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states: what is not a valid signature
    # is False, and a caller's own mistake is refused before this rather
    # than excluded from the except
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
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states. `assert_batch_as_valid` and not a
    # delegation to the prepared spelling: the reduction has to be inside
    # the try, or a message that is no octets is refused here where the
    # hash spelling answers False about it (issue #814)
    try:
        assert_batch_as_valid(ms, Qs, sigs, hf)
    except (ValueError, BTClibRuntimeError):
        return False

    return True
