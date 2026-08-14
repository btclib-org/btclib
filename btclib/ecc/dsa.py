# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Elliptic Curve Digital Signature Algorithm (ECDSA).

Implementation according to SEC 1 v.2:

http://www.secg.org/sec1-v2.pdf

specialized with bitcoin canonical 'lower-s' form, which is what ``sign``
produces: a high-s signature is non-standard and does not relay, so
normalizing is the signer's job. Verification and recovery take both
forms and offer no flag to refuse either -- which form s carries was
decided by whoever signed, and refusing one refuses a signature that
signer was free to make. The rule survives where it belongs: in ``sign``,
in the script engine's own flags, and in the leading-underscore functions
a test asks for it with.

``sign`` also grinds for a low-R signature -- one byte shorter in DER --
by default, as Core does; ``_grind_low_r`` is the loop and says why. Its
default goes with the nonce's: ``grind=True`` and ``nonce=None``, so a
caller who wants the nonce asks for ``grind=False`` and gets an error
rather than a guess if they forget.

``sign`` also takes a value to commit to inside the nonce,
sign-to-contract style (see btclib.ecc.commit_nonce for the tweak), and
the four ``anti_exfil_*`` functions here are the protocol that
construction exists to support: the ECDSA Anti-Exfil Protocol, whose
five steps and reasoning are in ``anti_exfil_host_commit``.
"""

from __future__ import annotations

import contextlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from typing import overload

from btclib_secp256k1 import dsa as libsecp256k1_dsa
from btclib_secp256k1 import keys as libsecp256k1_keys
from btclib_secp256k1 import recovery as libsecp256k1_recovery

from btclib import var_bytes
from btclib.alias import BinaryData, HashF, JacPoint, Octets, Point
from btclib.curves import Curve, mult, secp256k1
from btclib.curves.curve import (
    _assert_valid_ec,
    _is_x_coordinate_var,
    _jac_double_mult,
    _libsecp256k1_serves,
    _y_even_var,
)
from btclib.ecc.commit_nonce import commit_entropy_, commit_nonce_, commit_point_
from btclib.ecc.rfc6979_nonce import _rfc6979_nonce_, challenge_
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.hashes import _assert_valid_hf, reduce_to_hlen
from btclib.number_theory import mod_inv, mod_inv_var
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.to_pub_key import PubKey, point_from_pub_key, pub_keyinfo_from_pub_key
from btclib.utils import (
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    hex_string,
)

__all__ = [
    "Sig",
    "anti_exfil_host_commit",
    "anti_exfil_host_verify",
    "anti_exfil_sign",
    "anti_exfil_signer_commit",
    "assert_as_valid",
    "assert_as_valid_",
    "crack_prv_key_var",
    "crack_prv_key_var_",
    "gen_keys",
    "recover_pub_key",
    "recover_pub_key_",
    "recover_pub_keys",
    "recover_pub_keys_",
    "sign",
    "sign_",
    "sign_recoverable",
    "sign_recoverable_",
    "verify",
    "verify_",
]

_DER_SCALAR_MARKER = b"\x02"
_DER_SIG_MARKER = b"\x30"

# libsecp256k1's own sign-to-contract tags, byte for byte, so that a
# commitment made here opens under secp256k1_ecdsa_s2c_verify_commit and
# the two fixed vectors of its test suite are reproduced. They are what
# makes this construction that one and not a lookalike, so they are
# frozen: a different string is a different scheme, and every signature
# already made would stop opening
_S2C_POINT_TAG = b"s2c/ecdsa/point"
_S2C_DATA_TAG = b"s2c/ecdsa/data"


def _serialize_scalar(scalar: int) -> bytes:
    # 'highest bit set' padding included here
    scalar_size = scalar.bit_length() // 8 + 1
    scalar_bytes = scalar.to_bytes(scalar_size, byteorder="big", signed=False)
    return _DER_SCALAR_MARKER + var_bytes.serialize(scalar_bytes)


def _parse_der_value(stream: BytesIO) -> bytes:
    """Return the [size][value] octets a DER element announced.

    var_bytes reports a size that overruns the buffer, or a zero one, as
    a BTClibRuntimeError; here both mean the DER is malformed, and the
    callers that filter parse failures -- psbt_in._assert_valid_partial_sigs
    among them -- catch BTClibValueError alone.
    """
    try:
        return var_bytes.parse(stream, forbid_zero_size=True)
    except BTClibRuntimeError as e:
        raise BTClibValueError(f"invalid DER length: {e}") from e


def _deserialize_scalar(sig_data_stream: BytesIO, strict: bool) -> int:
    marker = sig_data_stream.read(1)
    if marker != _DER_SCALAR_MARKER:
        err_msg = f"invalid value header: {marker.hex()}"
        err_msg += f", instead of integer element {_DER_SCALAR_MARKER.hex()}"
        raise BTClibValueError(err_msg)

    scalar_bytes = _parse_der_value(sig_data_stream)

    if strict:
        # a leading zero byte is legal only to keep a value whose highest
        # bit is set from reading as negative: any other one is a
        # non-minimal encoding, which BIP66 rejects.
        # The length test has to come first, and so does strict: with the
        # three conditions in the other order a one-byte scalar -- the
        # zero of 020100 -- indexed past the end of the buffer, raising
        # the IndexError that no caller of a parser thinks to catch
        if len(scalar_bytes) > 1 and scalar_bytes[0] == 0 and scalar_bytes[1] < 0x80:
            raise BTClibValueError("invalid 'highest bit set' padding")
        if scalar_bytes[0] >= 0x80:
            raise BTClibValueError("invalid negative scalar")

    # unsigned, never negative: abs() would be a no-op
    return int.from_bytes(scalar_bytes, byteorder="big", signed=False)


@dataclass(frozen=True, init=False)
class Sig:
    """ECDSA signature with strict ASN.1 DER serialization.

    Strict, because BIP66 mandates it: lax DER validation (e.g. OpenSSL
    ignores extra padding) leaves the encoding malleable, and with it
    the transaction hash.

    source:
    https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki

    BIP66 mandates a strict DER format:

    Format:
    [0x30] [data-size][0x02][r-size][r][0x02][s-size][s]

    * 0x30: header byte to indicate compound structure
    * data-size: 1-byte size descriptor of the following data
    * 0x02: header byte indicating an integer
    * r-size: 1-byte size descriptor of the r value that follows
    * r: arbitrary-size big-endian r value.
        It must use the shortest possible encoding for
        a positive integers: no null bytes at the start,
        except a single one when the next byte has its highest bit set
        (to avoid being interpreted as a negative number)
    * 0x02: header byte indicating an integer
    * s-size: 1-byte size descriptor of the s value that follows
    * s: arbitrary-size big-endian s value. Same rules as for r apply

    There are 7 bytes of meta-data:

    * compound header, compound size,
    * value header, r-value size,
    * value header, s-value size

    The ECDSA signature (r, s) should be 64 bytes,
    r and s being 32 bytes integers each;
    however, integers in DER are signed,
    so if the value being encoded is greater than 2^128,
    a 33rd byte is added in front.
    Bitcoin has a "low s" rule for the s value to be below ec.n,
    but it is only a standardness rule miners are allowed to ignore.
    Moreover, no such rule exists for r.
    """

    # 32 bytes scalar, 0 < r < ec.n (ec.n is the curve order)
    r: int
    # 32 bytes scalar, 0 < s < ec.n (ec.n is the curve order)
    s: int
    ec: Curve = secp256k1

    # written out, as in every other constructor taking this flag: an
    # InitVar[bool] field with field(kw_only=True) and a __post_init__
    # would also keep the flag keyword-only, but every signature taking
    # check_validity is written out, and spelling a few differently would
    # make them the exceptions.
    # init=False rather than relying on dataclasses leaving a hand-written
    # __init__ alone, which it does but by way of an implementation detail
    # of _set_new_attribute
    def __init__(
        self, r: int, s: int, ec: Curve = secp256k1, *, check_validity: bool = True
    ) -> None:
        object.__setattr__(self, "r", r)
        object.__setattr__(self, "s", s)
        object.__setattr__(self, "ec", ec)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse an r or s outside 1..n-1, or an r no x is congruent to."""
        # the curve first: it is what 1..n-1 is measured in, and
        # check_validity=False is what makes a Sig holding an ec of no
        # curve type reachable at all -- built with the flag off, or the
        # field assigned afterwards, as psbt.assert_valid's int fields are
        _assert_valid_ec(self.ec)

        # r is a scalar, fail if r is not in [1, n-1]
        if not 0 < self.r < self.ec.n:
            err_msg = "scalar r not in 1..n-1: "
            err_msg += f"'{hex_string(self.r)}'" if self.r > 0xFFFFFFFF else f"{self.r}"
            raise BTClibValueError(err_msg)

        # ensure r is congruent to a valid x-coordinate.
        # r is a scalar, i.e. reduced mod n, so it does not name the
        # x-coordinate it came from: every x = r + j*ec.n below ec.p is a
        # candidate, and trying them is btclib's arithmetic either way.
        # What is delegated is the question asked of each -- whether some
        # point of the curve has that x -- which for secp256k1 is
        # ec_pubkey_parse of the compressed key 0x02 || x, 2.4 us against
        # the 75 of a modular square root whose y is of no use here
        r = self.r
        congruence_not_found = True
        while congruence_not_found and r < self.ec.p:
            if _is_x_coordinate_var(r, self.ec):
                congruence_not_found = False
            else:
                r += self.ec.n
        if congruence_not_found:
            err_msg = "r is not (congruent to) a valid x-coordinate: "
            err_msg += f"'{hex_string(self.r)}'" if self.r > 0xFFFFFFFF else f"{self.r}"
            raise BTClibValueError(err_msg)

        # s is a scalar, fail if s is not in [1, n-1]
        if not 0 < self.s < self.ec.n:
            err_msg = "scalar s not in 1..n-1: "
            err_msg += f"'{hex_string(self.s)}'" if self.s > 0xFFFFFFFF else f"{self.s}"
            raise BTClibValueError(err_msg)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Serialize an ECDSA signature to strict ASN.1 DER representation."""
        if check_validity:
            self.assert_valid()

        out = _serialize_scalar(self.r)
        out += _serialize_scalar(self.s)
        return _DER_SIG_MARKER + var_bytes.serialize(out)

    @classmethod
    def parse(
        cls: type[Sig],
        data: BinaryData,
        *,
        check_validity: bool = True,
        strict: bool = True,
    ) -> Sig:
        """Return a Sig by parsing binary data.

        Deserialize a strict ASN.1 DER representation of an ECDSA
        signature.

        strict says whether the encoding must be the canonical one, which
        is Bitcoin Core's `IsValidSignatureEncoding` and covers what comes
        *after* the sequence as well as what is in it: a byte too many is
        not a DER signature either, and neither is a scalar written with a
        leading zero it does not need or without one it does. What it does
        not cover, and what a caller has to strip, is a sighash type byte
        -- a script signature and a psbt partial signature both carry one,
        and neither is a bare DER encoding.

        It is read for its truth and not asked for its type, which is the
        classification `tests/bool_parameter_test.py` records: the flag
        decides whether the call refuses, and the signature parsed out of
        an encoding both readings accept is one signature. Worth knowing
        which direction each accident goes, though, because they are not
        symmetric: `"false"` out of a configuration file is truthy and
        therefore strict, while a `None` from a lookup that found nothing
        is the lax one -- so a caller who means the canonical encoding
        should pass `True` rather than whatever a table answered.
        """
        stream = bytesio_from_binarydata(data)
        ec = secp256k1

        # 0x30, then data-size, 0x02, r-size, r, 0x02, s-size, s
        marker = stream.read(1)
        if marker != _DER_SIG_MARKER:
            err_msg = f"invalid compound header: {marker.hex()}"
            err_msg += f", instead of DER sequence tag {_DER_SIG_MARKER.hex()}"
            raise BTClibValueError(err_msg)

        # then data-size, 0x02, r-size, r, 0x02, s-size, s
        sig_data = _parse_der_value(stream)

        # then 0x02, r-size, r, 0x02, s-size, s
        sig_data_substream = bytesio_from_binarydata(sig_data)
        r = _deserialize_scalar(sig_data_substream, strict)
        s = _deserialize_scalar(sig_data_substream, strict)

        # to prevent malleability
        # the sig_data_substream must have been consumed entirely
        if sig_data_substream.read(1) != b"":
            err_msg = "invalid DER sequence length"
            raise BTClibValueError(err_msg)

        # and so must the stream: unchecked, bytes after the sequence
        # would be read as part of nothing and silently dropped,
        # Sig.parse(der + b"\x01") answering with the Sig of der. Core
        # checks the whole element with one size equation --
        # `(lenR + lenS + 7) != sig.size()` in IsValidSignatureEncoding --
        # and a two-byte hash type is what leaves a byte behind once the
        # engine has stripped one, which is the script_tests.json vector
        # "P2PK with multi-byte hashtype, with DERSIG" (issue #129).
        #
        # Under strict alone, because that is where Core has it too:
        # IsValidSignatureEncoding is called for DERSIG, STRICTENC and
        # LOW_S and not otherwise, and fix_signature parses with
        # strict=False for exactly the flags Core leaves it out for. A
        # stream is held to the same rule as a bytes buffer, no caller in
        # this library parsing a signature out of the middle of one.
        #
        # This is the one parser in btclib with a flag in front of that
        # rule, and the flag is Core's: btclib/utils.py states the rule
        # everything else follows, where a complete octet string is one
        # whole object and nothing may follow it
        if strict and stream.read(1) != b"":
            raise BTClibValueError("trailing bytes after the DER sequence")

        return cls(r, s, ec, check_validity=check_validity)


def gen_keys(prv_key: PrvKey | None = None, ec: Curve = secp256k1) -> tuple[int, Point]:
    """Return a private/public (int, Point) key-pair."""
    # here rather than in the branch below that reads n off the curve: a
    # key that was given reaches int_from_prv_key's own check, and one
    # that is drawn reaches nothing else
    _assert_valid_ec(ec)

    if prv_key is None:
        # q in the range [1, ec.n-1]
        q = 1 + secrets.randbelow(ec.n - 1)
    else:
        q = int_from_prv_key(prv_key, ec)

    # mult, not the _mult under it: the scalar is the private key and the
    # point is the generator, which is the one multiplication libsecp256k1
    # is dispatched to -- constant time there, and 8.1 us against 862.
    # ssa.gen_keys computes this very point the same way
    return q, mult(q, ec=ec)


def _sign_recoverable_(
    c: int, q: int, nonce: int, lower_s: bool, ec: Curve
) -> tuple[Sig, int]:
    # Private, for tests: it takes the challenge c as an argument, so
    # a test can explore every value of it on a low-cardinality curve.
    # c is assumed in 0..n-1, q and nonce in 1..n-1
    # Steps numbering follows SEC 1 v.2 section 4.1.3
    # affine coordinates of K (field elements); mult dispatches the
    # generator to libsecp256k1 on secp256k1, which is where this
    # function is reached from whenever the bindings decline the whole
    # signature -- another hash function, another curve, a nonce the
    # caller imposed, a sign-to-contract commitment. The nonce is secret,
    # and what multiplies it is regular in it either way: constant-time C
    # on secp256k1, and `_mult_fixed_base` on every other curve, whose
    # additions are the same for every scalar. The affine conversion the
    # Jacobian form would have saved is one mod_inv_var, of a Z that
    # `_blinded_jac` has randomized
    K = mult(nonce, ec=ec)  # 1
    x_K = K[0]
    # mod n makes it a scalar
    r = x_K % ec.n  # 2, 3
    if r == 0:  # r≠0 required as it multiplies the public key
        raise BTClibRuntimeError("failed to sign: r = 0")

    # blinded, and it is the one inverse in this module that has to be:
    # the nonce is the secret here, an extended Euclid takes the
    # iterations its input asks for, and a duration that follows a
    # nonce's bit-length is what the Minerva attack turns into the key.
    # Everything else dsa inverts -- a signature's s, its r, a
    # verification's Z -- is public and takes the plain `mod_inv_var`
    s = mod_inv(nonce, ec.n) * (c + r * q) % ec.n  # 6
    if s == 0:  # s≠0 required as verify will need the inverse of s
        raise BTClibRuntimeError("failed to sign: s = 0")

    # the key_id is what step 2 threw away, and nothing else. r is x_K
    # reduced mod n, so recovering the key from it takes two things the
    # signer has in hand and the signature does not carry: how many times
    # ec.n came off x_K -- SEC 1 v.2 section 4.1.6's j -- and which of the
    # two roots of x_K is y_K. `_recover_pub_key_` reads them back as
    # `key_id >> 1` and `key_id & 0b01`, so this is that encoding written
    # from the other side, and it is why a signer never has to search:
    # the two bits were computed above and discarded.
    #
    # x_K // ec.n rather than `2 if x_K != r else 0`: the two agree
    # wherever x_K < 2*ec.n, which on secp256k1 is every point --
    # libsecp256k1 spells it `is_odd(r.y) | (overflow ? 2 : 0)` -- but a
    # cofactor above 1 leaves room for a j of 2 or 3, which the boolean
    # would report as 1
    key_id = 2 * (x_K // ec.n) + (K[1] & 1)

    # bitcoin canonical 'low-s' encoding for ECDSA signatures
    # it removes signature malleability as cause of transaction malleability
    # see https://github.com/bitcoin/bitcoin/pull/6769
    if lower_s and s > ec.n // 2:
        s = ec.n - s  # s = - s % ec.n
        # negating s mirrors K, so the parity bit flips while j does not:
        # x_K is the one coordinate the reflection leaves alone.
        # libsecp256k1 has the same `*recid ^= 1` beside the same negation
        key_id ^= 1

    return Sig(r, s, ec), key_id


def _sign_(c: int, q: int, nonce: int, lower_s: bool, ec: Curve) -> Sig:
    # Private function for testing purposes: _sign_recoverable_ without
    # the key_id, which is two bit operations over a y_K-coordinate `mult`
    # returns anyway. One signing body, projected, rather than a second
    # copy of the arithmetic that would be cheaper by nothing measurable
    return _sign_recoverable_(c, q, nonce, lower_s, ec)[0]


def _is_low_r(r: int, ec: Curve) -> bool:
    # Core's SigHasLowR, read off the scalar rather than off the 32 bytes
    # it takes the top byte of: DER prepends a 0x00 to a value whose
    # highest bit is set, to keep it from reading as negative, so r costs
    # the pad exactly when it does not fit n_size bytes as a signed
    # integer. On secp256k1 that is r < 2**255, and it is the size
    # _serialize_scalar arrives at from the same bit_length
    return r.bit_length() < 8 * ec.n_size


def _grind_entropy(counter: int) -> bytes | None:
    # None, not 32 zero bytes, for the first attempt: ndata is appended
    # to the key and the message, so zeros are additional data like any
    # other and the nonce would not be RFC6979's
    return None if counter == 0 else counter.to_bytes(32, byteorder="little")


def _grind_low_r(attempt: Callable[[int], Sig], grind: bool, ec: Curve) -> Sig:
    """Sign until r is low, `attempt(counter)` being one signature.

    Core's low-R grinding, from its PR 13666 and its default since 0.17:
    an r with its highest bit set costs a byte of DER pad, in every input
    that carries the signature, and re-signing with different extra
    entropy draws another r. Half of the draws are low already, so the
    expected cost is one extra signature and the expected saving half a
    byte.

    The sequence is Core's `CKey::Sign`, and it has to be, or a signature
    is reproducible only against this library: attempt 0 passes no extra
    entropy at all -- so a first draw that is already low is the plain
    RFC6979 signature, grinding or not -- and attempt i passes i as 32
    little-endian bytes, which is Core's `WriteLE32` into a zeroed
    `extra_entropy[32]` for every counter it reaches, electrum-ecc's
    `counter.to_bytes(32, "little")` and embit's the same.

    No attempt cap. Core has none, and one would answer an event of
    probability 2**-k with an error a caller can do nothing about; embit
    breaks its loop at 200, which is a 2**-200 signature that is not low-R
    rather than a refusal.
    """
    sig = attempt(0)
    if not grind:
        return sig

    counter = 0
    while not _is_low_r(sig.r, ec):
        counter += 1
        sig = attempt(counter)
    return sig


@overload
def sign_(
    msg_hash: Octets,
    prv_key: PrvKey,
    nonce: PrvKey | None = ...,
    lower_s: bool = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    grind: bool = ...,
    commit_hash: None = None,
) -> Sig: ...


@overload
def sign_(
    msg_hash: Octets,
    prv_key: PrvKey,
    nonce: PrvKey | None = ...,
    lower_s: bool = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    grind: bool = ...,
    commit_hash: Octets,
) -> tuple[Sig, Point]: ...


def sign_(
    msg_hash: Octets,
    prv_key: PrvKey,
    nonce: PrvKey | None = None,
    lower_s: bool = True,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
    *,
    grind: bool = True,
    commit_hash: Octets | None = None,
) -> Sig | tuple[Sig, Point]:
    """Sign a hf_len bytes message according to ECDSA signature algorithm.

    If the deterministic nonce is not provided, the RFC6979
    specification is used.

    grind asks for a low-R signature, one byte shorter in DER:
    `_grind_low_r` is the loop, Core's since its 0.17 and its default
    there and here, so that a btclib signature is the one Core would have
    made. Its default pairs with the nonce's: `grind=True` and
    `nonce=None`, the signature of a key and a message and nothing else.

    A caller who wants the nonce -- or a commitment, which owns the extra
    entropy the counter travels through -- asks for `grind=False` in so
    many words, because grinding is a search over nonces and a nonce that
    is given leaves nothing to search. The two together are refused rather
    than one of them quietly winning: which one would win is exactly what
    a caller pinning a signature cannot afford to guess.

    Keyword-only, rather than beside lower_s where it belongs by subject:
    ec and hf are positional here and a flag inserted before them would
    renumber both.

    commit_hash is a value to commit to inside the nonce, sign-to-contract
    style: the signature is an ordinary one, and the receipt returned
    beside it is what opens the commitment (see
    btclib.ecc.commit_nonce). Keyword-only, and the only argument that
    changes what is returned, so that neither is easy to pass by accident.
    A commitment derives its own nonce and cannot be given one: the
    derivation is where half of the scheme's security is.
    """
    # the message msg_hash: a hf_len array
    # both flags decide which signature comes back -- lower_s which of the
    # two s values, grind whether the nonce is searched for a low r -- so
    # both are kinds and neither is read for its truth
    assert_type(lower_s, bool, "lower_s")
    assert_type(grind, bool, "grind")

    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    # the secret key q: an integer in the range 1..n-1.
    # SEC 1 v.2 section 3.2.1
    q = int_from_prv_key(prv_key, ec)

    # the committed value has to reach the nonce derivation, or the
    # untweaked nonce is a function of the message and the key alone and
    # two commitments over one message hand out the private key -- see
    # commit_nonce. A nonce of the caller's leaves nowhere to put it, so
    # it is refused rather than silently not committed to; libsecp256k1
    # spells the same rule as a VERIFY_CHECK that s2c goes with the
    # default nonce function and no other
    if commit_hash is not None and nonce is not None:
        raise BTClibValueError("a commitment derives its own nonce")

    # grinding is a search over nonces, so it needs the derivation to be
    # its own: a nonce the caller chose is the nonce and there is nothing
    # left to draw, and a commitment already owns the extra entropy the
    # counter would travel through. The second is not only an encoding
    # clash -- grinding a nonce is exactly the freedom the anti-exfil
    # protocol takes away from a signing device, see
    # anti_exfil_host_commit, and this is the call that protocol signs
    # through
    if grind and (nonce is not None or commit_hash is not None):
        raise BTClibValueError("grinding derives its own nonce")

    # a nonce provided by the caller is the nonce, while what
    # libsecp256k1 takes is extra entropy for the RFC6979 nonce it
    # derives itself: the two cannot be the same argument, so a
    # requested nonce is for the Python implementation below to use.
    # A commitment is that same entropy, and the bindings' sign() does
    # not expose it either, so it is the Python path that commits.
    # A grinding counter is that entropy too, and this is the one place
    # it is not the reason to decline: `ndata` is what the bindings take
    # it as, so grinding stays where the signing is
    if (
        _libsecp256k1_serves(ec, hf)
        and nonce is None
        and lower_s
        and commit_hash is None
    ):
        return _grind_low_r(
            lambda counter: Sig.parse(
                libsecp256k1_dsa.sign(msg_hash, q, _grind_entropy(counter))
            ),
            grind,
            ec,
        )

    # the challenge
    c = challenge_(msg_hash, ec, hf)  # 4, 5

    if commit_hash is None:
        # nonce: an integer in the range 1..n-1.
        if nonce is not None:
            # second part delegated to helper function
            return _sign_(c, q, int_from_prv_key(nonce, ec), lower_s, ec)
        return _grind_low_r(
            lambda counter: _sign_(
                c,
                q,
                _rfc6979_nonce_(c, q, ec, hf, _grind_entropy(counter)),  # 1
                lower_s,
                ec,
            ),
            grind,
            ec,
        )

    # the commitment enters twice: once as RFC6979 additional data, so
    # that this nonce belongs to this commitment, and once as the tweak.
    # The challenge does not depend on the nonce, so the second is a
    # substitution and nothing else: one signing path
    entropy = commit_entropy_(commit_hash, _S2C_DATA_TAG, hf)
    nonce = _rfc6979_nonce_(c, q, ec, hf, entropy)
    nonce, receipt = commit_nonce_(commit_hash, nonce, _S2C_POINT_TAG, ec, hf)
    return _sign_(c, q, nonce, lower_s, ec), receipt


@overload
def sign(
    msg: Octets,
    prv_key: PrvKey,
    nonce: PrvKey | None = ...,
    lower_s: bool = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    grind: bool = ...,
    commit: None = None,
) -> Sig: ...


@overload
def sign(
    msg: Octets,
    prv_key: PrvKey,
    nonce: PrvKey | None = ...,
    lower_s: bool = ...,
    ec: Curve = ...,
    hf: HashF = ...,
    *,
    grind: bool = ...,
    commit: Octets,
) -> tuple[Sig, Point]: ...


def sign(
    msg: Octets,
    prv_key: PrvKey,
    nonce: PrvKey | None = None,
    lower_s: bool = True,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
    *,
    grind: bool = True,
    commit: Octets | None = None,
) -> Sig | tuple[Sig, Point]:
    """ECDSA signature with canonical low-s preference.

    Implemented according to SEC 1 v.2 The message msg is first
    processed by hf, yielding the value

    msg_hash = hf(msg),

    a sequence of bits of length *hf_len*.

    Normally, hf is chosen such that its output length *hf_len* is
    roughly equal to *nlen*, the bit-length of the group order *n*,
    since the overall security of the signature scheme will depend on
    the smallest of *hf_len* and *nlen*; however, the ECDSA standard
    supports all combinations of *hf_len* and *nlen*.

    RFC6979 is used for deterministic nonce.

    grind asks for a low-R signature, as in `sign_`, which is where the
    loop and the default are explained.

    commit is a value to commit to inside the nonce, and is reduced by hf
    as msg is: `sign_` is the spelling that takes the two hashes.

    See
    https://www.rfc-editor.org/rfc/rfc6979.html#section-3.2
    """
    msg_hash = reduce_to_hlen(msg, hf)
    if commit is None:
        return sign_(msg_hash, prv_key, nonce, lower_s, ec, hf, grind=grind)
    commit_hash = reduce_to_hlen(commit, hf)
    return sign_(
        msg_hash, prv_key, nonce, lower_s, ec, hf, grind=grind, commit_hash=commit_hash
    )


def sign_recoverable_(
    msg_hash: Octets,
    prv_key: PrvKey,
    nonce: PrvKey | None = None,
    lower_s: bool = True,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> tuple[Sig, int]:
    """Sign a hf_len bytes message, naming the key_id that recovers the key.

    The signature `sign_` gives, and beside it the key_id
    `recover_pub_key_` takes to answer the signer's own public key: the
    same value the recovery flag of a message signature carries.

    A spelling of its own rather than a flag on `sign_`, as
    libsecp256k1 has `ecdsa_sign_recoverable` beside `ecdsa_sign`: a
    second argument changing what is returned would multiply into four
    return shapes with the commitment, which is also why no commitment is
    taken here (see `sign_`). Nothing is published that a plain signature
    keeps: the key_id is derivable from any signature by recovering the
    four candidates and seeing which is the signer's, so what this saves
    is that search and not a secret.

    No `grind` either, and here it is not a matter of the shape: a
    recoverable signature is 65 bytes of r, s and the flag, with no DER
    pad for a low r to save. Core has the same asymmetry, `CKey::Sign`
    grinding and `CKey::SignCompact` passing a null ndata and looping over
    nothing.
    """
    # the message msg_hash: a hf_len array
    assert_type(lower_s, bool, "lower_s")

    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    # the secret key q: an integer in the range 1..n-1.
    # SEC 1 v.2 section 3.2.1
    q = int_from_prv_key(prv_key, ec)

    # as in sign_: a nonce of the caller's is the nonce, where what the
    # bindings take is extra entropy for the RFC6979 nonce they derive
    # themselves, so a requested nonce is for the Python path below. The
    # recoverable signing they offer is lower-s like the plain one, and
    # lower_s=False is the caller asking for the s that was computed
    if _libsecp256k1_serves(ec, hf) and nonce is None and lower_s:
        # the compact form, r || s, and the recid beside it: the DER
        # encoding sign_ parses would have to be taken apart again, the
        # key_id being what this call is made for
        sig_bytes, key_id = libsecp256k1_recovery.sign(msg_hash, q)
        n_size = ec.n_size
        r = int.from_bytes(sig_bytes[:n_size], byteorder="big", signed=False)
        s = int.from_bytes(sig_bytes[n_size:], byteorder="big", signed=False)
        return Sig(r, s, ec), key_id

    # the challenge
    c = challenge_(msg_hash, ec, hf)  # 4, 5

    # nonce: an integer in the range 1..n-1.
    if nonce is None:
        nonce = _rfc6979_nonce_(c, q, ec, hf, None)  # 1
    else:
        nonce = int_from_prv_key(nonce, ec)
    # second part delegated to helper function
    return _sign_recoverable_(c, q, nonce, lower_s, ec)


def sign_recoverable(
    msg: Octets,
    prv_key: PrvKey,
    nonce: PrvKey | None = None,
    lower_s: bool = True,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> tuple[Sig, int]:
    """ECDSA signature and the key_id that recovers the signing key.

    `sign` with the key_id beside it; `sign_recoverable_` is the spelling
    that takes the message hash.
    """
    msg_hash = reduce_to_hlen(msg, hf)
    return sign_recoverable_(msg_hash, prv_key, nonce, lower_s, ec, hf)


def _assert_as_valid_(
    c: int, QJ: JacPoint, r: int, s: int, ec: Curve, *, lower_s: bool
) -> None:
    # Private function for test/dev purposes

    if lower_s and s > ec.n // 2:
        raise BTClibValueError("not a low s")

    w = mod_inv_var(s, ec.n)
    u = c * w % ec.n
    v = r * w % ec.n  # 4
    # Let K = u*G + v*Q.
    # the dispatching double_mult_var of curves.curve, not the Python
    # arithmetic under it: what reaches here is the verification the
    # bindings' own ecdsa_verify declined -- another hash function, a
    # commitment to check, a caller-imposed nonce, a curve of its own --
    # and on secp256k1 the multiplication is theirs all the same, 28 us
    # against 1.02 ms, which is this whole verification 61 us against
    # 1.10 ms of it
    KJ = _jac_double_mult(v, QJ, u, ec.GJ, ec)  # 5

    # Fail if infinite(K).
    # K = w*(c + r*q)*G is INF whenever c == -r*q (mod n)
    if KJ[2] == 0:  # 5
        err_msg = "invalid (INF) key"
        raise BTClibRuntimeError(err_msg)

    # affine x_K-coordinate of K, and the inversion stays. Comparing
    # r*Z^2 with KJ[0] instead is libsecp256k1's `secp256k1_gej_eq_x_var`,
    # one squaring and one product against an extended Euclid, over the
    # field elements that reduce to r -- one candidate where n is above
    # p/2 and more where the cofactor makes room. It measures 1.00x here:
    # the bindings hand back a point whose Z is 1, so the inversion this
    # path pays is of one, and where the multiplication is Python's it is
    # 8.8 us of a verification that is 1148
    x_K = (KJ[0] * mod_inv_var(KJ[2] * KJ[2], ec.p)) % ec.p
    # Fail if r ≠ x_K %n.
    if r != x_K % ec.n:  # 6, 7, 8
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
        # sig.r is the tweaked nonce's x-coordinate reduced modulo the
        # group order, as signing left it, so the recomputed point is
        # reduced too
        W = commit_point_(commit_hash, receipt, _S2C_POINT_TAG, sig.ec, hf)
        if sig.r != W[0] % sig.ec.n:
            raise BTClibRuntimeError("commitment verification failed")


def assert_as_valid_(
    msg_hash: Octets,
    key: PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit_hash: Octets | None = None,
    receipt: Point | None = None,
) -> None:
    """Refuse an invalid ECDSA signature over a message hash.

    The message enters already reduced -- msg_hash, not the message --
    which is what the trailing underscore says; assert_as_valid is the
    spelling that reduces with hf first. Errors carry the reason,
    ``verify_`` being the boolean answer. With commit_hash and receipt the
    sign-to-contract commitment is opened as well.

    Both forms of s are accepted, and there is no flag to ask otherwise:
    which of the two a signature carries was decided by whoever signed it,
    so a verifier refusing one is refusing a signature the signer was free
    to make. The low-s rule belongs to the signer -- ``sign`` applies it --
    and to the script engine, which reads it off its own flags.
    """
    # ahead of everything, and the one input whose refusal has to be a
    # TypeError: verify_ below turns a ValueError into False, so an hf
    # checked any later than this would be reported as a signature that
    # does not verify. hashes._assert_valid_hf has the rest
    _assert_valid_hf(hf)

    # key is a PubKey, not a Key: verification is where a private key
    # accepted for a public one does real harm, silently checking a
    # signature against a public key derived from the very secret handed
    # in — a check that proves nothing about the signer. The Key union
    # and its point_from_key/pub_keyinfo_from_key helpers keep the
    # convenience for address and script builders, where deriving from
    # one's own private key is what the caller asked for. The narrowing
    # is not just an annotation: the helpers called below reject a WIF
    # and an xprv too, which a PubKey annotation cannot rule out, both
    # being strings
    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.parse(sig)

    # ahead of the dispatch below, which returns early: opening a
    # commitment and verifying a signature are two independent checks of
    # the same r, and both have to run whichever implementation answers
    # the second one
    _assert_commitment_(commit_hash, receipt, sig, hf)

    if _libsecp256k1_serves(sig.ec, hf):
        msg_hash_bytes = bytes_from_octets(msg_hash, 32)
        pubkey_bytes = pub_keyinfo_from_pub_key(key)[0]
        # check_validity=False, because assert_valid has just run above --
        # on the Sig handed in, or inside the Sig.parse that made one.
        # What it would run again is the congruence check of r, which is
        # not free even delegated: 0.54 us against 3.1, of a verification
        # that is 22 in total
        sig_bytes = sig.serialize(check_validity=False)
        # libsecp256k1 rejects what is not in the lower-s form, and which
        # form a signature is in was the signer's choice: normalize, rather
        # than refuse what the signer was free to produce
        sig_bytes = libsecp256k1_dsa.normalize(sig_bytes)
        if not libsecp256k1_dsa.verify(msg_hash_bytes, pubkey_bytes, sig_bytes):
            raise BTClibRuntimeError("signature verification failed")
        return

    c = challenge_(msg_hash, sig.ec, hf)  # 2, 3
    Q = point_from_pub_key(key, sig.ec)
    QJ = Q[0], Q[1], 1
    # second part delegated to helper function
    _assert_as_valid_(c, QJ, sig.r, sig.s, sig.ec, lower_s=False)


def assert_as_valid(
    msg: Octets,
    key: PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit: Octets | None = None,
    receipt: Point | None = None,
) -> None:
    """Refuse an invalid ECDSA signature, reducing the message with hf."""
    msg_hash = reduce_to_hlen(msg, hf)
    commit_hash = None if commit is None else reduce_to_hlen(commit, hf)
    assert_as_valid_(msg_hash, key, sig, hf, commit_hash=commit_hash, receipt=receipt)


def verify_(
    msg_hash: Octets,
    key: PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit_hash: Octets | None = None,
    receipt: Point | None = None,
) -> bool:
    """ECDSA signature verification (SEC 1 v.2 section 4.1.4).

    commit_hash and receipt open the commitment the nonce carries, and a
    signature that does not commit to that value is False as a forged one
    is: the answer is about this signature and this commitment, both.
    """
    # The comment every boolean verification in this library points at.
    #
    # ValueError and BTClibRuntimeError, not Exception: a value that is
    # not a valid signature is False, and so is a verification that
    # failed. A value of a type this function does not declare is
    # neither, and reaches the caller: the classes that say so are
    # TypeErrors -- `_assert_valid_hf` for an hf passed as sha256()
    # instead of sha256, `to_pub_key` for what is no spelling of a key --
    # and no TypeError is in the tuple below, so none of them has to be
    # refused ahead of the try to get out.
    #
    # The line is the annotation, and not which built-in a helper happens
    # to derive from: those two coincide only by accident, which is what
    # issue #745 found, and issue #814 is where the annotation was chosen
    # over the accident. CONTRIBUTING.md's "Every public function
    # validates its inputs" states the rule for the library.
    #
    # BTClibRuntimeError by name and not RuntimeError, because
    # RecursionError is one and is not an answer about a signature
    try:
        assert_as_valid_(
            msg_hash, key, sig, hf, commit_hash=commit_hash, receipt=receipt
        )
    except (ValueError, BTClibRuntimeError):
        return False

    return True


def verify(
    msg: Octets,
    key: PubKey,
    sig: Sig | Octets,
    hf: HashF = sha256,
    *,
    commit: Octets | None = None,
    receipt: Point | None = None,
) -> bool:
    """ECDSA signature verification (SEC 1 v.2 section 4.1.4).

    commit is reduced by hf as msg is; `verify_` is the spelling that
    takes the two hashes.
    """
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states. `assert_as_valid` and not a
    # delegation to the prepared spelling: the reduction has to be inside
    # the try, or a message that is no octets is refused here where the
    # hash spelling answers False about it (issue #814)
    try:
        assert_as_valid(msg, key, sig, hf, commit=commit, receipt=receipt)
    except (ValueError, BTClibRuntimeError):
        return False

    return True


def anti_exfil_host_commit(rho: Octets, hf: HashF = sha256) -> bytes:
    """Return the host's commitment to rho: step 1 of the anti-exfil protocol.

    A signing device that picks its own nonce can leak the private key
    through the nonces themselves, a few bits per signature, and no
    signature says that it did. The ECDSA Anti-Exfil Protocol takes that
    choice away: the host contributes randomness to the nonce derivation,
    so the device has nothing left to grind. Which only holds if the
    device publishes the nonce's point *before* it learns the randomness
    -- otherwise it grinds the randomness against candidate nonces until
    one carries the bits it wants out -- so the exchange is a
    commit-reveal handshake of five steps:

    1. the host draws rho and sends ``anti_exfil_host_commit(rho)``
    2. the device answers with ``anti_exfil_signer_commit(msg_hash,
       prv_key, commitment)``, the point R its nonce will have
    3. the host reveals rho
    4. the device signs, ``anti_exfil_sign(msg_hash, prv_key, rho)``
    5. the host checks ``anti_exfil_host_verify`` against the R of step 2
       and the rho it drew in step 1

    rho is hf_len bytes from a cryptographically secure generator, and it
    stays secret until step 2 has been answered: revealed earlier it is
    the device's to grind, which is the whole of what this prevents.

    **Restarting the protocol takes exactly the same rho**, and the host
    checks that the device answers step 2 with exactly the same R. A
    device that could make the host draw again by failing would be
    choosing which nonces reach real signatures, one abort at a time --
    selective aborting is a bias like any other, and libsecp256k1 puts
    the scale on it: some hundred aborts before there is a plausible
    attack, accumulating across a replacement of every device involved,
    though not across a replacement of the keys.

    The commitment is the committed value as it enters the nonce
    derivation -- ``commit_entropy_`` under the sign-to-contract data
    tag, and nothing else -- which is what lets step 2 and step 4 reach
    one nonce: the device derives it from this hash, and recomputes the
    same hash from rho when it signs.
    """
    return commit_entropy_(bytes_from_octets(rho, hf().digest_size), _S2C_DATA_TAG, hf)


def anti_exfil_signer_commit(
    msg_hash: Octets,
    prv_key: PrvKey,
    host_commitment: Octets,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Point:
    """Return the signer's public nonce R: step 2 of the anti-exfil protocol.

    The point of the nonce the device is going to use, published before
    the host reveals what its commitment commits to. Nothing is signed
    here, and that is the shape the protocol needs: R is a promise, and
    step 4 is what keeps it.

    The commitment travels as RFC6979 section 3.6 additional data,
    exactly as the committed value does in ``sign_``, so the two derive
    one nonce and the R below is the receipt that signature will open
    with.
    """
    c = challenge_(msg_hash, ec, hf)
    q = int_from_prv_key(prv_key, ec)
    entropy = bytes_from_octets(host_commitment, hf().digest_size)
    return mult(_rfc6979_nonce_(c, q, ec, hf, entropy), ec.G, ec)


def anti_exfil_sign(
    msg_hash: Octets,
    prv_key: PrvKey,
    rho: Octets,
    lower_s: bool = True,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Sig:
    """Sign committing to the host's rho: step 4 of the anti-exfil protocol.

    Sign-to-contract with rho as the committed value, which is all step 4
    is: ``sign_`` with that commitment. The receipt it returns is dropped
    rather than passed on, because the host has it already -- it is the R
    of step 2, and a host taking the device's word for it here would be
    accepting a nonce point chosen *after* rho was revealed, which is the
    one thing the ordering exists to rule out.

    **The device keeps no state between step 2 and step 4.** It does not
    check rho against the commitment it was given: it re-derives the
    commitment from rho, and the nonce from that. A rho that does not
    match yields a different nonce, so the host's step 5 fails and the
    exchange is over -- and because the R of step 2 belonged to the
    commitment it was derived from, no nonce is ever used twice and the
    device's key is never the thing at risk.
    """
    # grind=False, and it is the protocol that requires it rather than the
    # encoding: grinding a nonce is the freedom this exchange takes away
    # from the device, which promised R in step 2 and would be drawing a
    # different nonce here. `sign_` refuses the pair anyway, a commitment
    # owning the entropy a counter would travel through, so this says out
    # loud what would otherwise be an error message
    sig, _ = sign_(
        msg_hash,
        prv_key,
        None,
        lower_s,
        ec,
        hf,
        grind=False,
        commit_hash=bytes_from_octets(rho, hf().digest_size),
    )
    return sig


def anti_exfil_host_verify(
    msg_hash: Octets,
    key: PubKey,
    sig: Sig | Octets,
    rho: Octets,
    receipt: Point,
    hf: HashF = sha256,
) -> bool:
    """Check the signature against R and rho: step 5 of the anti-exfil protocol.

    Two questions answered as one, and the host needs both: that this is
    a valid signature, and that its nonce is the R of step 2 tweaked by
    the rho of step 1. Either alone is worth nothing -- a valid signature
    over a nonce nobody constrained is the exfiltration this protects
    against, and a commitment that opens under an invalid signature is
    not a signature. Which ``verify_`` already does in one call, both
    checks running against the same r.

    receipt is the R of step 2, what libsecp256k1 calls the opening.
    False and not an exception for everything that fails, as ``verify_``
    answers: a rho of the wrong size is a rho this commitment does
    not open to.
    """
    return verify_(msg_hash, key, sig, hf, commit_hash=rho, receipt=receipt)


def _recover_pub_keys_(
    c: int, r: int, s: int, ec: Curve, *, lower_s: bool
) -> list[JacPoint]:
    # Private function provided for testing purposes only.

    # The Python enumeration: `recover_pub_keys_` above asks the bindings
    # for each of the four recids instead, so what reaches here is every
    # other curve, every other hash function, and the tests that switch the
    # dispatch off -- where this is the implementation held against the
    # bindings, they being the authority on the answer.
    #
    # The two have to answer the same list and not merely the same set,
    # dropped candidates included, which is what those tests asserted
    # before the delegation existed and assert of both paths now.
    #
    # every candidate is a key_id, so this is _recover_pub_key_ over the
    # whole range of them and nothing else: a j in [0, ec.cofactor] (step
    # 1 of SEC 1 v.2 section 4.1.6) and a y_K-coordinate parity, the even
    # root first for bitcoin message signing compatibility. Which is the
    # order key_id numbers them in, so range() is the loop.
    #
    # It costs a mod_inv_var per candidate rather than hoisting the
    # precomputation out of the loop. Not hoisted, because the plural is
    # `_recover_pub_key_` over a range of key_ids and nothing else: issue
    # 183 was the two implementations disagreeing while each held its own
    # copy of this arithmetic, so the singular stays the only place the
    # arithmetic is written.
    keys: list[JacPoint] = []
    for key_id in range(2 * (ec.cofactor + 1)):
        # a candidate can fail any of the three refusals of step 1.6:
        # x_K = r + j*ec.n may be no field element -- which is most of
        # them, r + ec.n < ec.p being some 2^-127 of signatures on
        # secp256k1 -- or no x-coordinate of the curve, or the key it
        # yields may be INF. All three mean "not this one", not "no key",
        # so the list is dense and shorter than the range: it is what a
        # caller indexes to name a key_id, which is only that key_id when
        # no earlier candidate dropped out
        with contextlib.suppress(BTClibValueError, BTClibRuntimeError):
            keys.append(_recover_pub_key_(key_id, c, r, s, ec, lower_s=lower_s))
    return keys


def recover_pub_keys_(
    msg_hash: Octets, sig: Sig | Octets, hf: HashF = sha256
) -> list[Point]:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See Also:
    - https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106

    """
    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.parse(sig)

    # The message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    # the enumeration is btclib's loop and not a function libsecp256k1
    # has, but each candidate in it is a recid the bindings answer for, so
    # what runs here is a `recover` call per candidate: 42 us against 1381
    # (issue 286). A recid is two bits, i.e. every candidate a curve of
    # cofactor 1 has, and _libsecp256k1_serves admits no other curve --
    # secp256k1's cofactor is 1, so the range below is the
    # `range(2 * (ec.cofactor + 1))` of the Python enumeration above, in
    # the same order, key_id by key_id
    if _libsecp256k1_serves(sig.ec, hf):
        keys: list[Point] = []
        # and it is two candidates rather than four for every signature
        # anybody made: recid 2 and 3 are j = 1, i.e. x_K = r + ec.n, which
        # needs r + ec.n < ec.p -- some 2^-127 of signatures on secp256k1.
        # The same screen `_recover_pub_key_` applies on the other side,
        # and the one libsecp256k1 applies on its own: what is skipped is a
        # crossing whose answer is a refusal on that very range test, so
        # the candidates that survive are unchanged
        for key_id in range(4 if sig.r + sig.ec.n < sig.ec.p else 2):
            # a candidate that recovers nothing is dropped rather than
            # reported, as in _recover_pub_keys_: the bindings' refusal
            # arrives as the BTClibValueError _libsecp256k1_recover_sec_
            # maps it to
            with contextlib.suppress(BTClibValueError, BTClibRuntimeError):
                keys.append(
                    _libsecp256k1_recover_point_(key_id, msg_hash, sig, lower_s=False)
                )
        return keys

    c = challenge_(msg_hash, sig.ec, hf)  # 1.5

    QJs = _recover_pub_keys_(c, sig.r, sig.s, sig.ec, lower_s=False)
    # the candidates converted together: one extended Euclid for the list
    # where one per candidate is what the loop above would have paid
    return sig.ec.aff_from_jac_batch_var(QJs)


def recover_pub_keys(msg: Octets, sig: Sig | Octets, hf: HashF = sha256) -> list[Point]:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See Also:
    - https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106

    """
    msg_hash = reduce_to_hlen(msg, hf)
    return recover_pub_keys_(msg_hash, sig, hf)


def _recover_pub_key_(
    key_id: int, c: int, r: int, s: int, ec: Curve, *, lower_s: bool
) -> JacPoint:
    # Private function provided for testing purposes only: r and s are
    # assumed in 1..n-1, which is what every caller's Sig validation
    # establishes and what the two shortcuts below rest on.

    # the low-s rule first, where `_libsecp256k1_recover_sec_` also asks
    # it: it is a property of the signature and not of the candidate, so
    # every key_id answers it the same way and none of the arithmetic
    # below is needed to say so
    if lower_s and s > ec.n // 2:
        raise BTClibValueError("not a low s")

    # whether step 1.6.2 has anything left to check, which is a property
    # of the curve and not of the signature (issue 890). With cofactor 1
    # the curve has ec.n points and every one of them is a multiple of G,
    # so the scalars below -- reduced modulo ec.n, as scalars are -- act on
    # a lifted K the way SEC 1's arithmetic says they do, and the two
    # comparisons this enables are argued for where they are made. Above 1
    # a lift need not land in the prime-order subgroup, the reduction is
    # then not a no-op, and the verification is doing real work: secp112r2
    # has cofactor 4, and its recovery answers four keys of ten candidates
    prime_order = ec.cofactor == 1

    # r is x_K reduced mod n, so it does not determine x_K:
    # if ec.n < K[0] < ec.p (likely when cofactor ec.cofactor > 1)
    # then both x_K=r and x_K=r+ec.n must be tested
    #
    # key_id is the parity bit and the j above it, so j is a shift and not
    # a mask: `key_id & 0b110` would read the bits in place, making j 2, 4
    # or 6 where SEC 1 counts 1, 2, 3 -- key_id 2 asking for x_K =
    # r + 2*ec.n and skipping the r + ec.n that is the whole point of a
    # second candidate. libsecp256k1 spells the same two bits `recid & 2`
    # for the order to add and `recid & 1` for the parity, i.e. this.
    # Reaching it needs r + ec.n < ec.p, some 2^-127 of signatures on
    # secp256k1 and no signer's own output -- `key_id = pub_keys.index(Q)`
    # cannot name a candidate that failed -- but a key_id arrives from
    # outside too, in the recovery flag of a message signature
    j = key_id >> 1  # allow for key_id in [0, 7]
    x_K = r + j * ec.n  # 1.1

    if prime_order:
        # screened rather than reduced, which is the screen libsecp256k1
        # imposes on its own side -- `recover_pub_key_`'s comment states
        # it, "the bindings require r < ec.p - ec.n for j = 1" -- and half
        # of what leaves step 1.6.2 a comparison. A `% ec.p` answers
        # x_K = r + j*ec.n - m*ec.p for some m >= 1 instead, and no such
        # candidate can pass 1.6.2: that step asks x_K % ec.n == r, which
        # would need m*ec.p ≡ 0 mod ec.n, and ec.n divides neither ec.p
        # nor an m this small. So a wrapped x_K is refused here by one
        # comparison, where the reduction spent a Python square root and a
        # double multiplication to refuse it -- the trade
        # `_is_x_coordinate_var`'s docstring exists not to make, reached by
        # a caller who could have skipped the question (issue 891).
        #
        # A negative x_K is the same refusal: nothing outside 0..p-1 is a
        # field element, and a key_id below zero is what reaches it
        if not 0 <= x_K < ec.p:
            err_msg = f"invalid key_id ({key_id}): x_K is not a field element"
            raise BTClibValueError(err_msg)
    else:
        x_K %= ec.p

    # the precomputations, below the screen and not above it: a
    # candidate the comparison refuses has no use for them, and on
    # secp256k1 that is key_id 2 and 3 of every signature anybody made
    # -- which is the reason the low-s rule is asked first, one line of
    # arithmetic further up
    r_1 = mod_inv_var(r, ec.n)
    r1s = r_1 * s % ec.n
    r1e = -r_1 * c % ec.n

    # even root first for Bitcoin Core compatibility
    i = key_id & 0b01
    # the delegating lift of curves.curve: this function is the Python
    # path of recovery, but the root it takes to turn a candidate x_K into
    # a point is libsecp256k1's for secp256k1 all the same -- reached with
    # a key_id above 3, which the dispatch does not hand over
    y = _y_even_var(x_K, ec)
    y_K = ec.p - y if i else y
    KJ = x_K, y_K, 1  # 1.2, 1.3, and 1.4
    # 1.5 has been performed in the recover_pub_keys calling function
    #
    # delegated as the lift above is: this is the Python path of recovery
    # -- the named candidate goes to secp256k1_ecdsa_recover instead, and
    # the enumeration has no counterpart to go to at all -- but the
    # arithmetic under it is libsecp256k1's for secp256k1 all the same:
    # 708 us against 49 for the whole of this function, and 1347 against
    # 107 for the enumeration that runs it once per candidate.
    # The mean over 40 random keys, and a recovery needs the population
    # stated where a signature does not: what the enumeration costs
    # depends on how many of its candidates lift, which is a property of
    # the signature and not of the machine.
    #
    # It is the same point either way and not the same triple: what comes
    # back is _jac_from_aff, i.e. z == 1, where the wNAF answered whatever
    # representative its ladder reached. Every caller converts with
    # aff_from_jac_var, which is what a Jacobian coordinate is for
    QJ = _jac_double_mult(r1s, KJ, r1e, ec.GJ, ec)  # 1.6.1

    # INF is no public key, and step 1.6.2 does not refuse it: with Q at
    # infinity the K' that verification recomputes is the lift itself, so
    # the congruence holds and the INF was reported as a recovered key,
    # (5, 0) once converted -- btclib's sentinel for infinity and no key
    # at all. Q is INF whenever s*K == c*G, which is no signature anybody
    # made and is a `Sig` a caller may still hand in.
    # `ssa._recover_pub_key_` has always tested its own, for this reason
    if QJ[2] == 0:
        err_msg = "invalid (INF) key"
        raise BTClibRuntimeError(err_msg)

    if prime_order:
        # and step 1.6.2 has nothing else left to ask. Verification
        # recomputes K' = s^-1*(c*G + r*Q); substituting the Q that 1.6.1
        # has just built, r^-1*(s*K - c*G), gives K' = K identically, for
        # every r and s. What the step then asks is x_K % ec.n == r, and
        # x_K is r + j*ec.n with r < ec.n, so that holds by construction as
        # well -- the screen above being what rules out the x_K that is
        # neither, and the infinity test above the degenerate answer.
        #
        # secp256k1_ecdsa_recover makes no verification pass either, and
        # `_libsecp256k1_recover_sec_`'s comment below is where that
        # argument is written out: this is the arm it did not cover. What
        # the multiplication also bought was a cross-check of 1.6.1 --
        # issue 183 was the two implementations disagreeing while each held
        # its own copy of this arithmetic -- and that guarantee is the
        # suite's now, where it already lives: the bindings are the
        # authority this path is held against, candidate by candidate and
        # key_id by key_id (issue 890)
        return QJ

    # lower_s=False, the rule having been asked at the top of this function
    # for every candidate: what is left here is the step itself, and
    # nothing about the form of the signature
    _assert_as_valid_(c, QJ, r, s, ec, lower_s=False)  # 1.6.2
    return QJ


def _libsecp256k1_recover_sec_(
    key_id: int, msg_hash: bytes, sig: Sig, compressed: bool, *, lower_s: bool
) -> bytes:
    # Private function: the caller has asked _libsecp256k1_serves
    # already, and hands in a 32-byte msg_hash and a key_id in [0, 3].
    #
    # secp256k1_ecdsa_recover is step 1.6 of SEC 1 v.2 section 4.1.6 for
    # the one named candidate: 16 us here against the 708 of the Python
    # path, which is `recover_pub_key` 22 us against 694 once the Sig
    # validation both of them pay is counted in, the mean over 40 random
    # keys. It answers sec octets rather than a point, which is what an
    # address wants, so bms hashes these very bytes and never builds a
    # point.
    #
    # Step 1.6.2 -- that the recovered key verifies the signature -- is
    # not skipped by delegating: the key returned satisfies the signature
    # equation by construction, and a candidate whose x-coordinate is not
    # on the curve is the failure caught below. Which is the argument
    # `_recover_pub_key_` makes on its own side now, the screen there
    # being what the bindings impose here.
    #
    # The lower-s rule is checked here and not there, and only when asked
    # for: the recoverable parser takes any s in [1, n-1], as it must, a
    # malleated signature recovering a key too. Nothing in the public
    # surface asks -- which form s took was the signer's choice -- so this
    # is the private spelling of the same question _assert_as_valid_
    # answers with this very message, and it exists so that the two
    # implementations of the step can be held to one answer under it
    if lower_s and sig.s > sig.ec.n // 2:
        raise BTClibValueError("not a low s")

    n_size = sig.ec.n_size
    compact = sig.r.to_bytes(n_size, byteorder="big", signed=False)
    compact += sig.s.to_bytes(n_size, byteorder="big", signed=False)
    try:
        sec = libsecp256k1_recovery.recover(msg_hash, compact, key_id)
    except ValueError as e:
        # a bare ValueError is not what the Python path raises for a
        # candidate that recovers nothing -- BTClibValueError when x_K
        # misses the curve, BTClibRuntimeError when the key it yields does
        # not verify -- and bms.sign suppresses those two by name, which a
        # ValueError does not answer to, being their base and not a
        # subclass
        raise BTClibValueError(f"invalid key_id or signature: {e}") from e

    if compressed:
        return sec
    # the bindings serialize compressed unless asked otherwise, and the
    # rf <= 30 case of a message signature hashes the uncompressed form:
    # 29 us against the 19 above, the difference being a pubkey_parse
    # undoing a serialization the same library has just made -- which
    # recover leaves no way around, answering octets and not a pubkey
    return libsecp256k1_keys.serialize(libsecp256k1_keys.parse(sec), compressed=False)


def _libsecp256k1_recover_point_(
    key_id: int, msg_hash: bytes, sig: Sig, *, lower_s: bool
) -> Point:
    # Private function: the caller has asked _libsecp256k1_serves
    # already, and hands in a 32-byte msg_hash and a key_id in [0, 3].
    #
    # 0x04 || x || y (SEC 1 v.2, section 2.3.3), read rather than parsed
    # through point_from_octets: this is a point libsecp256k1 has just
    # created, and proving it on the curve again is work with a known
    # answer. The two callers are the named candidate and the enumeration
    # over all four of them, which is the only reason this is a function:
    # bms wants the octets and never builds the point at all.
    sec = _libsecp256k1_recover_sec_(
        key_id, msg_hash, sig, compressed=False, lower_s=lower_s
    )
    p_size = sig.ec.p_size
    return (
        int.from_bytes(sec[1 : 1 + p_size], byteorder="big", signed=False),
        int.from_bytes(sec[1 + p_size :], byteorder="big", signed=False),
    )


def recover_pub_key_(
    key_id: int,
    msg_hash: Octets,
    sig: Sig | Octets,
    hf: HashF = sha256,
) -> Point:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See Also:
    - https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106

    """
    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.parse(sig)

    # The message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    # a recid is two bits, i.e. a key_id in [0, 3], which is every
    # candidate a curve of cofactor 1 has; _recover_pub_key_ below reads a
    # key_id up to 7 as j up to 3, and no j above 1 is reachable on
    # secp256k1 anyway -- x_K = r + 2*ec.n exceeds ec.p for every r.
    # Where both answer, they answer the same, and now by the same test:
    # the bindings require r < ec.p - ec.n for j = 1, and that is the
    # screen the Python path applies to its own x_K
    if _libsecp256k1_serves(sig.ec, hf) and 0 <= key_id <= 3:
        return _libsecp256k1_recover_point_(key_id, msg_hash, sig, lower_s=False)

    c = challenge_(msg_hash, sig.ec, hf)  # 1.5

    QJ = _recover_pub_key_(key_id, c, sig.r, sig.s, sig.ec, lower_s=False)
    return sig.ec.aff_from_jac_var(QJ)


def recover_pub_key(
    key_id: int,
    msg: Octets,
    sig: Sig | Octets,
    hf: HashF = sha256,
) -> Point:
    """ECDSA public key recovery (SEC 1 v.2 section 4.1.6).

    See Also:
    - https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106#18106

    """
    msg_hash = reduce_to_hlen(msg, hf)
    return recover_pub_key_(key_id, msg_hash, sig, hf)


def crack_prv_key_var_(
    msg_hash1: Octets,
    sig1: Sig | Octets,
    msg_hash2: Octets,
    sig2: Sig | Octets,
    hf: HashF = sha256,
) -> tuple[int, int]:
    """Return (private key, nonce) from two signatures sharing a nonce.

    The classic nonce-reuse break: two signatures with one r over two
    message hashes are two linear equations in the nonce and the key.
    The messages enter already reduced; crack_prv_key_var reduces first.
    """
    if isinstance(sig1, Sig):
        sig1.assert_valid()
    else:
        sig1 = Sig.parse(sig1)

    if isinstance(sig2, Sig):
        sig2.assert_valid()
    else:
        sig2 = Sig.parse(sig2)

    ec = sig2.ec
    if sig1.ec != ec:
        raise BTClibValueError("not the same curve in signatures")
    if sig1.r != sig2.r:
        raise BTClibValueError("not the same r in signatures")
    if sig1.s == sig2.s:
        raise BTClibValueError("identical signatures")

    c_1 = challenge_(msg_hash1, ec, hf)
    c_2 = challenge_(msg_hash2, ec, hf)

    nonce = (c_1 - c_2) * mod_inv_var(sig1.s - sig2.s, ec.n) % ec.n
    q = (sig2.s * nonce - c_2) * mod_inv_var(sig1.r, ec.n) % ec.n
    return q, nonce


def crack_prv_key_var(
    msg1: Octets,
    sig1: Sig | Octets,
    msg2: Octets,
    sig2: Sig | Octets,
    hf: HashF = sha256,
) -> tuple[int, int]:
    """Return (private key, nonce) from two signatures sharing a nonce.

    As ``crack_prv_key_var_``, with each message reduced by hf first.
    """
    msg_hash1 = reduce_to_hlen(msg1, hf)
    msg_hash2 = reduce_to_hlen(msg2, hf)

    return crack_prv_key_var_(msg_hash1, sig1, msg_hash2, sig2, hf)
