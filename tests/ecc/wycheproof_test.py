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
algorithm over the same curve and hash. `EcdsaBitcoinVerify` is btclib's
`lower_s=True` default and refuses the malleable high-s twin;
`EcdsaVerify` is `lower_s=False` and accepts it. Their tcId 5 is the same
key and the same signature under both, `invalid` in the first file and
`valid` in the second, so a `lower_s` wired the wrong way round fails one
of the two files whichever way it is wired -- which neither file could
report on its own.

Four hash functions, for the same reason in a second direction. Bitcoin
signs with sha256 and nothing else, so the sha512 and SHA3 files are not
bitcoin signatures and are not here pretending to be: what they hold to
account is the *generic* ECDSA `dsa.verify_` promises, and they are the
only adversarial vectors that reach it. `_libsecp256k1_applicable`
declines every hash but sha256, so those files land on the Python path
by construction rather than by a patch -- the path `SECURITY.md`
publishes as not constant-time, under an adversary for the first time.

Which implementations answer is therefore read off the hash rather than
asserted: `_paths` below. Under sha256 a vector runs twice, against the
bindings and against the Python arithmetic underneath them -- the
bindings being the authority on the answer, Wycheproof on what the
answer should be. Under any other hash the bindings never answer at all,
so it runs once.
"""

from __future__ import annotations

from hashlib import sha3_256, sha3_512, sha256, sha512
from io import BytesIO
from types import ModuleType
from typing import Any

import pytest

from btclib.alias import HashF, Point
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
_ECDSA_P1363 = "ecdsa_secp256k1_sha256_p1363_test.json"
_ECDSA_SHA512_P1363 = "ecdsa_secp256k1_sha512_p1363_test.json"
_ECDH = "ecdh_secp256k1_test.json"

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


def _python_path(monkeypatch: pytest.MonkeyPatch, module: ModuleType) -> None:
    """Send the dispatch, and the arithmetic under it, down the Python path.

    Two patches because there are two dispatches: the module's own decides
    whether libsecp256k1 answers the whole verification or agreement, and
    `curves.curve`'s decides it again for each multiplication the Python
    implementation of that then makes -- `_jac_double_mult` delegates too,
    so patching only the first leaves the arithmetic where it was.
    """
    no_bindings(monkeypatch)
    monkeypatch.setattr(module, "_libsecp256k1_applicable", lambda *_: False)


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


def _paths(hf: HashF) -> list[bool]:
    """Say which implementations answer a vector: both, or Python alone.

    `_libsecp256k1_applicable` compares the hash function by identity and
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


@pytest.mark.parametrize(
    "key, vector, lower_s, hf, bindings",
    _signature_vectors(_ECDSA_BITCOIN, "bitcoin", sha256, True)
    + _signature_vectors(_ECDSA, "ecdsa", sha256, False)
    + _signature_vectors(_ECDSA_SHA512, "sha512", sha512, False)
    + _signature_vectors(_ECDSA_SHA3_256, "sha3-256", sha3_256, False)
    + _signature_vectors(_ECDSA_SHA3_512, "sha3-512", sha3_512, False),
)
def test_ecdsa_der(
    key: str,
    vector: dict[str, Any],
    lower_s: bool,
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
        _python_path(monkeypatch, dsa)

    msg_hash = _digest(hf, bytes.fromhex(vector["msg"]))
    sig = bytes.fromhex(vector["sig"])
    verified = dsa.verify_(msg_hash, key, sig, lower_s, hf)
    assert verified == (vector["result"] == "valid")


@pytest.mark.parametrize(
    "key, vector, hf, bindings",
    _signature_vectors(_ECDSA_P1363, "p1363", sha256)
    + _signature_vectors(_ECDSA_SHA512_P1363, "p1363-sha512", sha512),
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

    `lower_s=False` for both files, neither having a bitcoin profile: the
    sha256 one's tcId 1 is the malleable high-s signature and is `valid`.

    The size rule is the encoding's and not the hash's, so it is `n_size`
    twice over under sha512 as under sha256: P1363 pads each of r and s
    to the width of the order, which no wider digest changes.
    """
    if not bindings:
        _python_path(monkeypatch, dsa)

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
    assert dsa.verify_(msg_hash, key, sig, False, hf) == (vector["result"] == "valid")


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
        _python_path(monkeypatch, dh)

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
    assert shared_key == dh.ansi_x9_63_kdf(shared, _KEY_SIZE, sha256, None)
