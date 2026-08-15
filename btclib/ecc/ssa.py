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

import contextlib
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import overload

from btclib_secp256k1 import ssa as libsecp256k1_ssa

from btclib.alias import BinaryData, HashF, Integer, JacPoint, Octets, Point
from btclib.bip32 import BIP32Key
from btclib.curves import Curve, PreparedPoint, secp256k1
from btclib.curves.curve import (
    _assert_valid_ec,
    _is_x_coordinate_var,
    _jac_double_mult,
    _libsecp256k1_serves,
    _y_even_var,
    mult,
    multi_mult_var,
)
from btclib.curves.curve_group import HEX_THRESHOLD
from btclib.ecc.bip340_nonce import bip340_nonce_
from btclib.ecc.commit_nonce import commit_entropy_, commit_nonce_, commit_point_
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.hashes import _assert_valid_hf, reduce_to_hlen, tagged_hash
from btclib.number_theory import mod_inv_var
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.to_pub_key import point_from_pub_key
from btclib.utils import (
    assert_no_trailing,
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    hex_string,
    int_from_bits,
)

__all__ = [
    "BIP340PubKey",
    "Sig",
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

# btclib's own sign-to-contract tags, and the only invented thing in the
# scheme: libsecp256k1 has an ecdsa_s2c module and no schnorr one, and
# BIP340 says nothing about commitments, so there is no upstream string
# to copy and nothing to be interoperable with. Named for the standard
# rather than for btclib's `ssa`, and not under BIP0340/, which would
# claim the BIP defines this. Frozen all the same: a different string is
# a different scheme, and every signature already made would stop opening
_S2C_POINT_TAG = b"s2c/bip340/point"
_S2C_DATA_TAG = b"s2c/bip340/data"

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
        # was here (issue 622). The delegated lift was already 2.9 us
        # against 75 on the accepting path, and 0.65 of that is not the
        # reason: _y_even_var falls back to ec.y_even_var for an x the bindings
        # refuse -- that being where the message naming the value comes
        # from -- so refusing cost the whole Python square root, 78.7 us
        # against the 22.4 of verifying a good signature. The expensive
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


# hex-string or bytes representation of an int
# 33 or 65 bytes or hex-string
# BIP32Key as dict or String
# tuple Point
BIP340PubKey = Integer | Octets | BIP32Key | Point | PreparedPoint


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
    # BIP340 key as integer
    if isinstance(x_Q, int):
        return x_Q

    # (tuple) Point, (dict or str) BIP32Key, or 33/65 bytes
    # both classes, this being a guess at the spelling: a type no public
    # key has may still be a BIP340 one -- an int is, and is a private
    # key to `to_pub_key` -- so the refusal that names BIP340 is the one
    # at the end
    with contextlib.suppress(BTClibTypeError, BTClibValueError):
        return point_from_pub_key(x_Q, ec)[0]
    # BIP340 key as bytes or hex-string
    if isinstance(x_Q, (str, bytes)):
        return int.from_bytes(bytes_from_octets(x_Q, ec.p_size), "big", signed=False)

    raise BTClibTypeError("not a BIP340 public key")


def point_from_bip340pub_key(x_Q: BIP340PubKey, ec: Curve = secp256k1) -> Point:
    """Return a verified-as-valid BIP340 public key as Point tuple.

    It supports:

    - BIP32 extended keys (bytes, string, or BIP32KeyData)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - BIP340 Octets (bytes or hex-string, p-size Point x-coordinate)
    - native tuple
    """
    _assert_valid_ec(ec)

    # the lift is what validates the x, and the same one for every
    # spelling: an x-only key is an x and the even y that goes with it.
    # _y_even_var is ec.y_even_var answered by libsecp256k1 for secp256k1,
    # 2.9 us against the 75 of a modular square root, and the Python one
    # for every other curve
    x = _x_from_bip340pub_key(x_Q, ec)
    return x, _y_even_var(x, ec)


def gen_keys(prv_key: PrvKey | None = None, ec: Curve = secp256k1) -> tuple[int, int]:
    """Return a BIP340 private/public (int, int) key-pair."""
    # as in dsa.gen_keys, and for its reason
    _assert_valid_ec(ec)

    if prv_key is None:
        q = 1 + secrets.randbelow(ec.n - 1)
    else:
        q = int_from_prv_key(prv_key, ec)

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

    # the curve and the hash function decide this, and the size of the
    # message does not. `libsecp256k1_ssa.sign` is the 32-byte entry point
    # the length used to gate on -- "the message hash must be 32 bytes",
    # measured on 0.7.1rc1 -- but `sign_custom` beside it takes BIP340's
    # message of any size, so every length now reaches the constant-time C
    # instead of the Python arithmetic SECURITY.md publishes as not being
    # constant time.
    #
    # One call rather than a branch on the length: for a 32-byte message
    # the two answer the same signature octet for octet, and the
    # extraparams struct sign_custom fills costs 15.66 us against 15.43
    # (best of nine, 3000 calls each) -- not a second code path's worth of
    # a signature that is 15.
    #
    # A commitment stays with the Python path: it tweaks the nonce, and
    # the nonce is the bindings' own to derive
    if _libsecp256k1_serves(ec, hf) and commit_hash is None:
        # the bindings take a scalar, not the many representations of a
        # private key btclib accepts
        q = int_from_prv_key(prv_key, ec)
        return Sig.parse(libsecp256k1_ssa.sign_custom(msg, q, aux))

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
    # multiplication is still theirs, 28 us against 1.02 ms. This whole
    # verification is then 38 us against 1.17 ms, the two lifts around it
    # -- the r of the signature and the x-only key -- being theirs as well
    KJ = _jac_double_mult(ec.n - c, QJ, s, ec.GJ, ec, fixed)

    # The following check is prescribed by BIP340 but it is useless:
    # if moved after 'Fail if x_K ≠ r' it would never be executed
    # Fail if infinite(KJ).
    # Fail if y_K is odd.
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
        # delegated: 0.14 us against 3.1, of a verification that is 21 in
        # total
        sig_bytes = sig.serialize(check_validity=False)
        try:
            verified = libsecp256k1_ssa.verify(msg, x_bytes, sig_bytes)
        except ValueError as e:
            raise BTClibValueError(_invalid_x(x_Q)) from e
        if not verified:
            raise BTClibRuntimeError("signature verification failed")
        return

    # the lift the branch above does not need, and the validation of x_Q
    # with it: `_x_from_bip340pub_key` reads the key and proves nothing
    y_Q = _y_even_var(x_Q, sig.ec)
    # the key's own memoized tables where the caller prepared it, as in
    # `dsa.assert_as_valid_`: 531.2 us against 664.5 under one key. The
    # negation is in that set too, which is what makes it answer here --
    # a prepared point of odd y is this same key, and the lift above is
    # the one of the two BIP340 names
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
    # there is to gain here, and it is all of the cost: 3540 us against
    # 109 for this function. Which is also why this stays private, with no
    # public spelling above it: BIP340 has no recovery flag to carry the
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
    for their own values.
    """
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
    random coefficients, cheaper than one verification per signature
    -- and which signature failed is not in the answer, only that one
    did. Messages enter as they are; every signature must share one
    curve.

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
    points: list[Point] = []
    for i, (msg, Q, sig) in enumerate(zip(msgs, Qs, sigs, strict=True)):
        # any size, as in sign_ and assert_as_valid_
        msg = bytes_from_octets(msg)  # noqa: PLW2901

        K = sig.r, _y_even_var(sig.r, ec)

        x_Q, y_Q = point_from_bip340pub_key(Q, ec)

        c = challenge_(msg, x_Q, sig.r, ec, hf)

        # rand in 1..n-1
        # deterministically generated using a CSPRNG seeded by a
        # cryptographic hash (e.g., SHA256) of all inputs of the
        # algorithm, or randomly generated independently for each
        # run of the batch verification algorithm
        rand = 1 if i == 0 else 1 + secrets.randbelow(ec.n - 1)
        scalars.append(rand)
        points.append(K)
        scalars.append(rand * c % ec.n)
        points.append((x_Q, y_Q))
        t += rand * sig.s

    # the public mult and multi_mult_var, in affine coordinates, rather than
    # the Jacobian functions of curve_group underneath them and an
    # equality of projective coordinates: those two are where the
    # libsecp256k1 dispatch lives, and this sum is the one place in btclib
    # that hands the bindings many scalars at once, libsecp256k1 exposing
    # no batch verification of its own. Four signatures, i.e. the eight
    # terms above: 2.4 ms of Python arithmetic against 122 us, and
    # assert_batch_as_valid_ as a whole 3.4 ms against 158 us -- what is
    # left being two lifts and a challenge per signature, some 9 us of
    # which the lifts are libsecp256k1's. The two affine
    # conversions the equality costs on every other curve are one modular
    # inversion each, next to a multi_mult_var of all the terms
    if mult(t, ec=ec) != multi_mult_var(scalars, points, ec):
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
