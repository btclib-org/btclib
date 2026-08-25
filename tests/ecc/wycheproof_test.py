# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Wycheproof's adversarial secp256k1 vectors, ECDSA and ECDH.

https://github.com/C2SP/wycheproof, which is where bitcoin-core/secp256k1
takes the same two algorithms' vectors from; `tests/_data/README.md` pins
the revision of every file read here, names the ones deliberately left
out and why, and `WYCHEPROOF_COPYING` beside them is the Apache-2.0
licence they arrive under.

What they add to the BIP and RFC vectors already here is the adversarial
half. Those are what a correct signer produces; these are what an
attacker sends: DER that was malleated rather than computed, r and s
placed on and just over the boundaries of 1..n-1, a hash chosen for its
long runs of equal bits, an r that makes the Strauss-Shamir sum inside
`_jac_double_mult` land on infinity, and public keys off the curve, on
another curve, or on no curve at all.

`result` is the verdict, and it has three values rather than two:
`valid` must verify, `invalid` must not, and `acceptable` is either --
a case whose encoding is outside the standard while the value it encodes
is right, where the one wrong answer is accepting it and computing
something else. Asserted as that third answer rather than resolved to
one of the other two: which way an `acceptable` case falls is a property
of how strict a parser is, and pinning it here would make a legitimate
loosening or tightening of one look like a regression.

Two profiles of ECDSA, which is why two of the files are the same
algorithm over the same curve and hash. `EcdsaBitcoinVerify` requires the
strict DER encoding bitcoin requires, where `EcdsaVerify` accepts the BER
forms a generic parser takes, and `Sig.parse` is the strict one: the
`BerEncodedSignature` and `InvalidEncoding` cases are `invalid` in the
first file and `valid` in the second, and btclib answers with the first.

What it does not share is the low-s rule, and the two files say so by
naming the same signature twice: tcId 1 and tcId 388 of the bitcoin file
are tcId 5 and tcId 392 of the generic one -- one key and one signature
each time, `invalid` there and `valid` here. btclib answers `valid` for
all four, which form s took having been the signer's choice, so a verifier
has no standing to refuse it (issue 695); the rule itself lives on in
`sign` and in the leading-underscore spellings. `_generic_valid` below is
how those two are found, and says why a flag would find only one.

Hash functions beyond sha256, for the same reason in a second direction.
Bitcoin signs with sha256 and nothing else, so the sha512, SHA3 and SHAKE
files are not bitcoin signatures and are not here pretending to be: what
they hold to account is the *generic* ECDSA `dsa.verify_` promises, and
they are the only adversarial vectors that reach it.
`_libsecp256k1_serves` declines every hash but sha256, so those files
land on the Python path by construction rather than by the switch -- the
path `SECURITY.md` publishes as not constant-time, under an adversary for
the first time.

The SHAKE files arrive through an adapter, `_PinnedXof` below, because an
extendable-output function is not a `HashF` and `src/btclib/alias.py` states
that it is not: a SHAKE's `digest()` takes the output length that a
`HashObject`'s does not declare, and its `digest_size` reads 0. The
adapter pins a length rather than the library growing one, and it is
`n_size` here because that is the width `challenge_` reads: any length
from there up is the same test, a SHAKE's output being a stream whose
longer forms have these very bytes as their prefix. What the adapter is
not is a route to signing with SHAKE -- `dsa.sign` derives its nonce
through RFC6979, which is HMAC, and HMAC over an XOF is not defined.

Which implementations answer is therefore read off the hash rather than
asserted: `_paths` below. Under sha256 a vector runs twice, against the
bindings and against the Python arithmetic underneath them -- the
bindings being the authority on the answer, Wycheproof on what the
answer should be. Under any other hash the bindings never answer at all,
so it runs once.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from hashlib import sha3_256, sha3_512, sha256, sha512, shake_128, shake_256
from io import BytesIO
from typing import Any, Protocol

import pytest

from btclib import kdf
from btclib.alias import HashF, HashObject, Point
from btclib.curves import mult, point_from_octets, secp256k1
from btclib.ecc import dh, dsa
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from tests import load, vector_id
from tests.curves.curve_test import no_bindings

_ECDSA_BITCOIN = "ecdsa_secp256k1_sha256_bitcoin_test.json"
_ECDSA = "ecdsa_secp256k1_sha256_test.json"
_ECDSA_SHA512 = "ecdsa_secp256k1_sha512_test.json"
_ECDSA_SHA3_256 = "ecdsa_secp256k1_sha3_256_test.json"
_ECDSA_SHA3_512 = "ecdsa_secp256k1_sha3_512_test.json"
_ECDSA_SHAKE128 = "ecdsa_secp256k1_shake128_test.json"
_ECDSA_SHAKE256 = "ecdsa_secp256k1_shake256_test.json"
_ECDSA_P1363 = "ecdsa_secp256k1_sha256_p1363_test.json"
_ECDSA_SHA512_P1363 = "ecdsa_secp256k1_sha512_p1363_test.json"
_ECDSA_SHAKE128_P1363 = "ecdsa_secp256k1_shake128_p1363_test.json"
_ECDSA_SHAKE256_P1363 = "ecdsa_secp256k1_shake256_p1363_test.json"
_ECDH = "ecdh_secp256k1_test.json"
_ECDH_WEBCRYPTO = "ecdh_secp256k1_webcrypto_test.json"

# the DER tags the SubjectPublicKeyInfo below is made of
_SEQUENCE = 0x30
_BIT_STRING = 0x03
_OBJECT_IDENTIFIER = 0x06

# id-ecPublicKey (1.2.840.10045.2.1) and secp256k1 (1.3.132.0.10), as the
# two OIDs are encoded rather than as the dotted numbers they decode to:
# what the extractor needs is to recognize these two and no others, and
# an OID decoder written to reach that answer is a parser of its own with
# its own edge cases, none of which is btclib's
_ID_EC_PUBLIC_KEY = bytes.fromhex("2a8648ce3d0201")
_SECP256K1 = bytes.fromhex("2b8104000a")

# the octets of keying data asked of the KDF: any size answers the same
# question, this one being the size of the shared field element itself
_KEY_SIZE = 32


def _read_element(stream: BytesIO) -> tuple[int, bytes]:
    """Return the tag and the value of one DER element, strictly.

    Strictly in the three ways these vectors attack: a length that
    overruns what is left of the buffer, a long form used for a length
    the short form encodes, and a long form so wide that the length is
    not a length at all. The third has to be refused before the read
    rather than after it: `read` of 2**64 - 1 raises `OverflowError`
    from underneath the interpreter, which is neither a verdict about
    the key nor an exception any caller of a parser catches, and
    upstream's `uint64 overflow in length of ...` cases are built out of
    exactly that. Four octets is the bound because the whole structure is
    a curve identifier and a point.
    """
    tag = stream.read(1)
    size = stream.read(1)
    if not tag or not size:
        raise BTClibValueError("truncated DER element")
    length = size[0]
    if length & 0x80:
        size_size = length & 0x7F
        size_bytes = stream.read(size_size)
        if not 0 < size_size <= 4 or len(size_bytes) != size_size:
            raise BTClibValueError("invalid DER length")
        length = int.from_bytes(size_bytes, byteorder="big")
        if length < 0x80:
            raise BTClibValueError("non-minimal DER length")
    value = stream.read(length)
    if len(value) != length:
        raise BTClibValueError("truncated DER value")
    return tag[0], value


def _point_from_spki(der: bytes) -> Point:
    """Return the secp256k1 point an X.509 SubjectPublicKeyInfo carries.

    Wycheproof hands an ECDH public key ASN.1-encoded, where btclib's key
    boundary is a point and a curve, so something has to read the
    envelope. It is the test's reader and not btclib's, and the split is
    worth stating: the structure, the two OIDs and the unused-bit count
    are refused here, while the point itself -- off the curve, at
    infinity, of a length no SEC 1 encoding has -- is refused by
    `point_from_octets`, which is the check the vectors are aimed at.

    That the curve OID is read at all is what makes the `WrongCurve`
    group a rejection for the right reason. Those points are on other
    curves, so the coordinates alone would be refused as off secp256k1
    with overwhelming probability and the test would pass while asking
    nothing about the identifier the attacker actually changed.
    """
    stream = BytesIO(der)
    tag, spki = _read_element(stream)
    if tag != _SEQUENCE or stream.read(1):
        raise BTClibValueError("not one DER SEQUENCE")

    body = BytesIO(spki)
    tag, algorithm = _read_element(body)
    if tag != _SEQUENCE:
        raise BTClibValueError("no AlgorithmIdentifier")
    tag, key = _read_element(body)
    if tag != _BIT_STRING or body.read(1):
        raise BTClibValueError("no key BIT STRING")

    parameters = BytesIO(algorithm)
    tag, value = _read_element(parameters)
    if tag != _OBJECT_IDENTIFIER or value != _ID_EC_PUBLIC_KEY:
        raise BTClibValueError("not an EC public key")
    tag, value = _read_element(parameters)
    if tag != _OBJECT_IDENTIFIER or value != _SECP256K1 or parameters.read(1):
        raise BTClibValueError("not a secp256k1 key")

    # the leading octet of a BIT STRING is the number of unused bits in
    # its last one, and a key is a whole number of octets: anything but
    # zero there is a key this is not reading
    if not key or key[0]:
        raise BTClibValueError("invalid unused bit count")
    return point_from_octets(key[1:], secp256k1)


def _b64url(field: str) -> bytes:
    """Decode one JWK field: base64url with the padding RFC 7517 omits.

    `base64.urlsafe_b64decode` still asks for it, so it is put back here
    rather than the call being told to tolerate its absence.
    """
    return base64.urlsafe_b64decode(field + "=" * (-len(field) % 4))


def _point_from_jwk(jwk: dict[str, Any]) -> Point:
    """Return the secp256k1 point a JWK EC public key carries.

    Wycheproof's webcrypto file hands an ECDH public key JWK-encoded
    (RFC 7517), where `_point_from_spki` above reads the same agreement's
    X.509 form. `crv` is checked before `x` and `y` are decoded at all,
    for the same reason `_point_from_spki` reads the curve OID before the
    coordinates: `WrongCurve` cases carry a `crv` other than `P-256K`,
    some of them at a coordinate width secp256k1 itself uses, so refusing
    on the identifier is what makes the refusal about the curve the
    attacker actually changed rather than a coincidence of size or of
    the coordinates.
    """
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256K":
        raise BTClibValueError("not a secp256k1 EC JWK")
    x = _b64url(jwk["x"])
    y = _b64url(jwk["y"])
    return point_from_octets(b"\x04" + x + y, secp256k1)


def _digest(hf: HashF, data: bytes) -> bytes:
    """Hash `data` once, through the two calls a `HashF` actually offers.

    Not `hf(data)`, which is what hashlib allows and what the alias does
    not: `HashF` is `Callable[[], HashObject]` on purpose, so that a
    one-shot digest function cannot be passed where an updatable one is
    meant. `hashlib.sha256` accepts the argument anyway, which is what
    makes the distinction invisible until mypy is asked -- and a test
    module reaching around a type the library states is a test of
    something else.
    """
    hash_object = hf()
    hash_object.update(data)
    return hash_object.digest()


class _Xof(Protocol):
    """What a SHAKE offers: a digest of the length asked of it.

    `hashlib.shake_128` and `shake_256` satisfy this and not
    `alias.HashObject`, and the argument of `digest` is the whole of the
    difference -- an XOF has no output length of its own to report, which
    is why its `digest_size` is 0 rather than a size.
    """

    @property
    def block_size(self) -> int:
        """Return the internal block length in bytes."""
        ...

    @property
    def name(self) -> str:
        """Return the name hashlib.new would accept."""
        ...

    def update(self, data: Any, /) -> None:
        """Absorb more data, as hashlib's update does."""
        ...

    def digest(self, length: int, /) -> bytes:
        """Return that many bytes of output."""
        ...

    def hexdigest(self, length: int, /) -> str:
        """Return that many bytes of output, as a hex string."""
        ...

    def copy(self) -> _Xof:
        """Return a clone that can absorb independently."""
        ...


class _PinnedXof:
    """A SHAKE at a pinned output length, which is a `HashObject`.

    The one thing it adds is the length, and it adds it where the length
    is missing: everything else is the wrapped SHAKE answering for
    itself, `name` and `block_size` included, so a failure names the
    function that computed the digest rather than this class.

    A test's adapter, deliberately not a library one. `HashF` admitting
    an XOF would admit it to `dsa.sign` as well, whose nonce is RFC6979
    -- HMAC, which over an XOF is not defined -- and would answer inside
    a test module a question `src/btclib/alias.py` states the answer to.
    """

    def __init__(self, xof: _Xof, size: int) -> None:
        self.xof = xof
        self.size = size

    @property
    def digest_size(self) -> int:
        """Return the pinned digest length in bytes."""
        return self.size

    @property
    def block_size(self) -> int:
        """Return the wrapped function's internal block length."""
        return self.xof.block_size

    @property
    def name(self) -> str:
        """Return the wrapped function's name."""
        return self.xof.name

    def update(self, data: Any, /) -> None:
        """Absorb more data."""
        self.xof.update(data)

    def digest(self) -> bytes:
        """Return the digest, at the pinned length."""
        return self.xof.digest(self.size)

    def hexdigest(self) -> str:
        """Return the digest as a hex string, at the pinned length."""
        return self.xof.hexdigest(self.size)

    def copy(self) -> HashObject:
        """Return a clone that can absorb independently."""
        return _PinnedXof(self.xof.copy(), self.size)


def _pinned(xof: Callable[[], _Xof], size: int) -> HashF:
    """Return the `HashF` an XOF is not: a constructor of sized objects.

    A fresh SHAKE per call, not one shared by every caller: a `HashF` is
    a constructor, and two signatures verified out of one hash object
    would absorb each other's messages.
    """
    return lambda: _PinnedXof(xof(), size)


# the pinned length: n_size, and any length from there up is the same
# test. `challenge_` takes the leftmost `nlen` bits of the message hash,
# and a SHAKE's output is a stream, so a longer digest has these very
# bytes as its prefix -- measured, all four files verify identically at
# 32 and at 64
_SHAKE128 = _pinned(shake_128, secp256k1.n_size)
_SHAKE256 = _pinned(shake_256, secp256k1.n_size)


def _paths(hf: HashF) -> list[bool]:
    """Say which implementations answer a vector: both, or Python alone.

    `_libsecp256k1_serves` compares the hash function by identity and
    admits sha256 alone, so under sha512 or SHA3 the bindings decline
    before the dispatch is even reached. Running such a vector a second
    time with the dispatch patched off would be the same Python
    arithmetic twice, the first of the two named `bindings` and saying
    what did not happen -- and a report whose ids are not true is worse
    than a shorter one.
    """
    return [True, False] if hf is sha256 else [False]


def _vector_id(prefix: str, test: dict[str, Any], *, bindings: bool) -> str:
    """Name a case: which file, upstream's own numbering, which path.

    `tcId` is unique within a file and is what a reader greps for in it;
    the prefix is what keeps two files' tcId 5 apart. The path is part of
    the name rather than a second `parametrize` because it is not a free
    axis: `_paths` decides it per file.
    """
    path = "bindings" if bindings else "python"
    return f"{prefix}-{vector_id(test['tcId'], test['comment'])}-{path}"


def _signature_vectors(fname: str, prefix: str, hf: HashF, *extra: Any) -> list[Any]:
    """Flatten the groups of a verification file: a key, then a case.

    A Wycheproof group is a public key and the cases made against it, so
    the key is repeated into each parameter rather than the group being
    the unit of the test: what a failure has to name is the case.
    """
    return [
        pytest.param(
            group["publicKey"]["uncompressed"],
            test,
            *extra,
            hf,
            bindings,
            id=_vector_id(prefix, test, bindings=bindings),
        )
        for group in load("ecc", "_data", fname)["testGroups"]
        for test in group["tests"]
        for bindings in _paths(hf)
    ]


def test_pinned_xof() -> None:
    """The adapter pins the output length and answers for nothing else.

    A test of the harness rather than of btclib, and it earns its place
    twice: the SHAKE files below are read through this class, so a class
    that quietly hashed something else would make them pass while
    testing nothing; and the pinned length is only free because a SHAKE's
    output is a stream, which is asserted here rather than asserted by
    running every vector a second time at another length.
    """
    hash_object = _SHAKE128()
    hash_object.update(b"btclib")
    reference = shake_128(b"btclib")

    assert hash_object.digest_size == secp256k1.n_size
    assert hash_object.block_size == reference.block_size
    assert hash_object.name == reference.name
    assert hash_object.digest() == reference.digest(secp256k1.n_size)
    assert hash_object.hexdigest() == reference.hexdigest(secp256k1.n_size)

    clone = hash_object.copy()
    clone.update(b"!")
    assert clone.digest() != hash_object.digest()

    wider = _pinned(shake_128, 2 * secp256k1.n_size)()
    wider.update(b"btclib")
    assert wider.digest()[: secp256k1.n_size] == hash_object.digest()


def _generic_valid() -> frozenset[tuple[str, str]]:
    """Return the (key, signature) pairs the generic profile calls valid.

    Which is how the two verdicts btclib no longer shares with the bitcoin
    profile are found, rather than by naming their numbers: one key, one
    signature, `invalid` under the bitcoin profile and `valid` under the
    generic one is a case whose only defect is the form of s, and that is
    the rule a verifier no longer applies (issue 695). There are two of
    them, and a flag reaches only the first -- tcId 1 is
    `SignatureMalleabilityBitcoin`, while tcId 388, "edge case for
    signature malleability", is flagged `ArithmeticError` along with six
    cases that are invalid for their arithmetic and not for their s.
    """
    return frozenset(
        (group["publicKey"]["uncompressed"], test["sig"])
        for group in load("ecc", "_data", _ECDSA)["testGroups"]
        for test in group["tests"]
        if test["result"] == "valid"
    )


@pytest.mark.parametrize(
    "key, vector, low_s_exempt, hf, bindings",
    _signature_vectors(_ECDSA_BITCOIN, "bitcoin", sha256, _generic_valid())
    + _signature_vectors(_ECDSA, "ecdsa", sha256, frozenset())
    + _signature_vectors(_ECDSA_SHA512, "sha512", sha512, frozenset())
    + _signature_vectors(_ECDSA_SHA3_256, "sha3-256", sha3_256, frozenset())
    + _signature_vectors(_ECDSA_SHA3_512, "sha3-512", sha3_512, frozenset())
    + _signature_vectors(_ECDSA_SHAKE128, "shake128", _SHAKE128, frozenset())
    + _signature_vectors(_ECDSA_SHAKE256, "shake256", _SHAKE256, frozenset()),
)
def test_ecdsa_der(
    key: str,
    vector: dict[str, Any],
    low_s_exempt: frozenset[tuple[str, str]],
    hf: HashF,
    bindings: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a DER-encoded signature, in the profile the file is for.

    `verify_` and not `verify`: Wycheproof signs the message hashed once,
    where `verify` reduces with `reduce_to_hlen` and so hashes twice --
    bitcoin's rule, and not this vector's.

    The DER goes in as octets rather than as a parsed `Sig`, which is
    what puts `Sig.parse` inside the answer: a signature whose encoding
    is malformed is invalid, and the file's `InvalidEncoding`,
    `BerEncodedSignature` and `MissingZero` cases are all of them cases
    where nothing but the encoding is wrong.

    `hf` is the file's own, and it reaches `challenge_` as well as the
    message: a digest wider than the order is truncated to the leftmost
    `nlen` bits there, which is what the sha512 and SHA3-512 files
    exercise and what the sha256 ones cannot.
    """
    if not bindings:
        no_bindings(monkeypatch)

    msg_hash = _digest(hf, bytes.fromhex(vector["msg"]))
    sig = bytes.fromhex(vector["sig"])
    verified = dsa.verify_(msg_hash, key, sig, hf)
    # `_generic_valid` above is where the exemption comes from, and why it
    # is not a flag and not a list of tcIds
    assert verified == (vector["result"] == "valid" or (key, sig.hex()) in low_s_exempt)


@pytest.mark.parametrize(
    "key, vector, hf, bindings",
    _signature_vectors(_ECDSA_P1363, "p1363", sha256)
    + _signature_vectors(_ECDSA_SHA512_P1363, "p1363-sha512", sha512)
    + _signature_vectors(_ECDSA_SHAKE128_P1363, "p1363-shake128", _SHAKE128)
    + _signature_vectors(_ECDSA_SHAKE256_P1363, "p1363-shake256", _SHAKE256),
)
def test_ecdsa_p1363(
    key: str,
    vector: dict[str, Any],
    hf: HashF,
    bindings: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify a raw r and s signature, reaching `Sig` with no DER in front.

    btclib has no IEEE P1363 parser -- a bitcoin signature is DER -- so
    the split is the test's, and with it the size rule: r and s are each
    a whole field element wide, and `SignatureSize` is upstream's name
    for the shorter encodings some libraries accept. That leaves `Sig`
    itself answering for the pair, which is the point of the file: its
    `RangeCheck` and `InvalidSignature` cases are r and s at 0, at n, and
    at n plus a valid value, none of which any DER framing can hide.

    No exemption is needed here, none of these files having a bitcoin
    profile: the sha256 one's tcId 1 is the malleable high-s signature and
    is `valid`, which is the answer `verify_` gives everywhere now.

    The size rule is the encoding's and not the hash's, so it is `n_size`
    twice over under sha512 as under sha256: P1363 pads each of r and s
    to the width of the order, which no wider digest changes.
    """
    if not bindings:
        no_bindings(monkeypatch)

    raw = bytes.fromhex(vector["sig"])
    size = secp256k1.n_size
    if len(raw) != 2 * size:
        assert vector["result"] != "valid"
        return
    try:
        sig = dsa.Sig(
            int.from_bytes(raw[:size], byteorder="big"),
            int.from_bytes(raw[size:], byteorder="big"),
        )
    except BTClibValueError:
        assert vector["result"] != "valid"
        return

    msg_hash = _digest(hf, bytes.fromhex(vector["msg"]))
    assert dsa.verify_(msg_hash, key, sig, hf) == (vector["result"] == "valid")


@pytest.mark.parametrize(
    "vector, bindings",
    [
        pytest.param(test, bindings, id=_vector_id("ecdh", test, bindings=bindings))
        for group in load("ecc", "_data", _ECDH)["testGroups"]
        for test in group["tests"]
        # sha256, so both: the KDF below is SEC 1's over sha256 and the
        # agreement itself is a multiplication the bindings do answer
        for bindings in _paths(sha256)
    ],
)
def test_ecdh(
    vector: dict[str, Any], bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Agree on a shared key, or refuse the public key offered for it.

    Two assertions of one agreement. The first is Wycheproof's own datum,
    the x-coordinate of the shared point, which `mult` answers directly;
    the second is that `diffie_hellman` derived its keying data from that
    same point -- SEC 1's KDF stands between the two, so the expected
    octets are that KDF over upstream's `shared` rather than over
    anything computed here.

    The `invalid` half asserts a refusal instead, and it is the half the
    file is mostly made of: `InvalidCurveAttack` and `WrongCurve` are a
    private key multiplied into a group the sender chose, which leaks
    it. `EdgeCaseSharedSecret` and `EdgeCaseDoubling` are the same
    question asked the other way round -- a point that must be answered
    correctly rather than refused -- so a `dh` that refused everything
    would fail this file just as one that accepted everything does.
    """
    if not bindings:
        no_bindings(monkeypatch)

    prv_key = int(vector["private"], 16)
    try:
        pub_key = _point_from_spki(bytes.fromhex(vector["public"]))
        shared_key = dh.diffie_hellman(prv_key, pub_key, _KEY_SIZE)
    except (BTClibValueError, BTClibRuntimeError):
        assert vector["result"] != "valid"
        return

    assert vector["result"] != "invalid"
    shared = bytes.fromhex(vector["shared"])
    assert mult(prv_key, pub_key, secp256k1)[0] == int.from_bytes(
        shared, byteorder="big"
    )
    assert shared_key == kdf.ansi_x9_63_kdf(shared, _KEY_SIZE, sha256, None)


@pytest.mark.parametrize(
    "vector, bindings",
    [
        pytest.param(
            test, bindings, id=_vector_id("ecdh-webcrypto", test, bindings=bindings)
        )
        for group in load("ecc", "_data", _ECDH_WEBCRYPTO)["testGroups"]
        for test in group["tests"]
        # sha256, for the reason given at test_ecdh's own parametrization
        for bindings in _paths(sha256)
    ],
)
def test_ecdh_webcrypto(
    vector: dict[str, Any], bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Agree on a shared key from JWK-encoded keys, or refuse the public one.

    The webcrypto file's cases are `test_ecdh`'s own file (`_ECDH`)
    re-encoded rather than a second set of agreements --
    `tests/_data/README.md` is where the two were measured to share their
    valid cases' shared secrets. What differs is the encoding, so
    `_point_from_jwk` stands in for `_point_from_spki` and the private
    key comes from the JWK `d` field rather than from a hex string; the
    assertions below are `test_ecdh`'s own.
    """
    if not bindings:
        no_bindings(monkeypatch)

    prv_key = int.from_bytes(_b64url(vector["private"]["d"]), byteorder="big")
    try:
        pub_key = _point_from_jwk(vector["public"])
        shared_key = dh.diffie_hellman(prv_key, pub_key, _KEY_SIZE)
    except (BTClibValueError, BTClibRuntimeError):
        assert vector["result"] != "valid"
        return

    assert vector["result"] != "invalid"
    shared = bytes.fromhex(vector["shared"])
    assert mult(prv_key, pub_key, secp256k1)[0] == int.from_bytes(
        shared, byteorder="big"
    )
    assert shared_key == kdf.ansi_x9_63_kdf(shared, _KEY_SIZE, sha256, None)
