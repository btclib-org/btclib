# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.borromean` module."""

import hashlib
import inspect
import secrets
from collections.abc import Callable
from hashlib import sha256
from io import BytesIO

import pytest

from btclib.alias import Point
from btclib.curves import Curve, mult, secp256k1
from btclib.ecc import borromean, dsa
from btclib.ecc.borromean import BorromeanSig
from btclib.exceptions import (
    BorromeanRingError,
    BTClibTypeError,
    BTClibValueError,
)
from tests.curves.curve_test import low_card_curves


def test_borromean() -> None:
    """Round-trip a four-ring signature, and check the failure modes."""
    nring = 4
    # fixed rather than drawn at random: a ring the draw makes short
    # leaves some of the loop below unrun, and the coverage gate then
    # moves on its own
    ring_sizes = [3, 4, 6, 7]
    sign_key_idx = [2, 1, 0, 5]

    key_rings = [[dsa.gen_keys() for _ in range(ring_sizes[i])] for i in range(nring)]
    sign_keys = [key_rings[i][sign_key_idx[i]][0] for i in range(nring)]
    pubk_rings = [
        [key_rings[i][j][1] for j in range(ring_sizes[i])] for i in range(nring)
    ]

    msg = b"Borromean ring signature"
    sig = borromean.sign(
        msg, list(range(1, nring + 1)), sign_key_idx, sign_keys, pubk_rings
    )
    assert isinstance(sig, BorromeanSig)
    assert sig.ec is secp256k1

    borromean.assert_as_valid(msg, sig, pubk_rings)
    assert borromean.verify(msg, sig, pubk_rings)
    # the serialized octets verify too, and are what a caller reaches
    # for once the signature leaves the process: verify/assert_as_valid
    # parse them back with BorromeanSig.parse, which reads secp256k1
    # and sha256 -- this signature's own, here
    assert borromean.verify(msg, sig.serialize(), pubk_rings)
    borromean.assert_as_valid(msg, sig.serialize(), pubk_rings)

    # bytes, not str: a str msg is taken as hex, so "another message"
    # would fail to parse and never reach the ring verification
    assert not borromean.verify(b"another message", sig, pubk_rings)
    # a msg that is neither bytes nor a hex-str is a caller error, and
    # verify says so instead of answering False: catching Exception would
    # report an int msg as a failed ring signature
    with pytest.raises(BTClibTypeError, match="invalid octets type: int"):
        borromean.verify(0, sig, pubk_rings)  # type: ignore[arg-type]

    # a forged signature must raise, not merely return a falsy value:
    # assert_as_valid is called as a statement, so a return value
    # would be silently discarded. No ring of its own: the mismatch is
    # in the final e0 check, a property of the whole signature
    with pytest.raises(
        BorromeanRingError, match="signature verification failed"
    ) as excinfo:
        borromean.assert_as_valid(b"another message", sig, pubk_rings)
    assert (excinfo.value.ring, excinfo.value.position) == (None, None)


def test_borromean_sig_serialization_matches_zkps_layout() -> None:
    """e0 || s, ec.n_size bytes per s, ring-major -- byte for byte.

    secp256k1-zkp's `rangeproof` module writes exactly this for this
    signature (`secp256k1_rangeproof_sign_impl`, one `e0[32]` then one
    `secp256k1_scalar_get_b32` per public key in ring order), and this
    checks the layout against a hand-built expectation rather than
    trusting `serialize`'s own loop to have done what its docstring
    says.
    """
    ring_sizes = [2, 3]
    sign_key_idx = [0, 2]
    key_rings = [[dsa.gen_keys() for _ in range(size)] for size in ring_sizes]
    sign_keys = [key_rings[i][sign_key_idx[i]][0] for i in range(2)]
    pubk_rings = [[key_rings[i][j][1] for j in range(ring_sizes[i])] for i in range(2)]
    msg = b"wire format"

    sig = borromean.sign(msg, [1, 2], sign_key_idx, sign_keys, pubk_rings)
    data = sig.serialize()

    assert data[:32] == sig.e0
    offset = 32
    for ring in sig.s:
        for value in ring:
            chunk = data[offset : offset + 32]
            assert int.from_bytes(chunk, "big") == value
            offset += 32
    assert offset == len(data)

    rsizes = [len(ring) for ring in pubk_rings]
    parsed = BorromeanSig.parse(data, rsizes)
    assert parsed == sig
    assert borromean.verify(msg, parsed, pubk_rings)


def test_borromean_sig_parse_refuses_short_and_trailing_data() -> None:
    """`parse` checks the length of every field, and what follows them.

    e0 and each s are read with `read_exactly`, which is what makes a
    short buffer a `BTClibValueError` rather than a `BorromeanSig`
    whose last scalar is a few bytes narrower than the rest;
    `assert_no_trailing` is what refuses bytes appended after a
    complete signature -- the malleability two different byte strings
    decoding to the one object would otherwise be. This drives the
    three properties `tests/parse_contract_test.py` holds every other
    `parse` to, `BorromeanSig` excluded there because its `rsizes`
    makes the boundary the caller's rather than the encoding's own --
    driven here with the `rsizes` a real `pubk_rings` carries instead.
    """
    ring_sizes = [2]
    key_ring = [dsa.gen_keys() for _ in range(2)]
    sign_keys = key_ring[0][0]
    pubk_rings = [[key_ring[0][1], key_ring[1][1]]]
    msg = b"parse"

    sig = borromean.sign(msg, [1], [0], [sign_keys], pubk_rings)
    data = sig.serialize()

    # no prefix of the encoding is an object, at every offset
    for size in range(len(data)):
        with pytest.raises(BTClibValueError):
            BorromeanSig.parse(data[:size], ring_sizes)

    # the octets are one whole object: what follows them is refused,
    # hex-string included
    assert BorromeanSig.parse(data, ring_sizes) == sig
    with pytest.raises(BTClibValueError, match="bytes after the borromean ring"):
        BorromeanSig.parse(data + b"\x00", ring_sizes)
    with pytest.raises(BTClibValueError, match="bytes after the borromean ring"):
        BorromeanSig.parse((data + b"\x00").hex(), ring_sizes)

    # a stream may carry more, and is left on the byte after the object
    stream = BytesIO(data + b"junk")
    assert BorromeanSig.parse(stream, ring_sizes) == sig
    assert stream.read() == b"junk"

    # the two specific fields a truncation lands in, named
    with pytest.raises(BTClibValueError, match="not enough data for the borromean e0"):
        BorromeanSig.parse(data[:16], ring_sizes)
    with pytest.raises(
        BTClibValueError, match=r"not enough data for the borromean s \(ring 0"
    ):
        BorromeanSig.parse(data[:40], ring_sizes)


def test_borromean_sig_assert_valid_holds_s_to_0_n() -> None:
    """A scalar out of `0..n-1` is refused at construction, not later.

    `check_validity=False` is what lets an out-of-range value into the
    object at all, `dsa.Sig`/`ssa.Sig` doing the same for the same
    reason: a test exploring the boundary needs to build the invalid
    value before refusing it.
    """
    ec = secp256k1
    Q1 = mult(1, ec.G, ec)
    with pytest.raises(BTClibValueError, match="scalar s not in 0..n-1"):
        BorromeanSig((0).to_bytes(32, "big"), [[ec.n]], ec)

    sig = BorromeanSig((0).to_bytes(32, "big"), [[ec.n]], ec, check_validity=False)
    with pytest.raises(
        BTClibValueError, match=r"scalar s not in 0..n-1.*ring 0, position 0"
    ):
        sig.assert_valid()
    with pytest.raises(BTClibValueError, match="scalar s not in 0..n-1"):
        sig.serialize()
    # Q1 unused otherwise -- kept to mirror the other low-cardinality
    # tests' setup and to document that assert_valid does not touch the
    # curve's points at all, only its order
    assert Q1


def test_borromean_sig_refuses_no_rings() -> None:
    """A signature with no rings signs nothing, built directly or parsed.

    `BorromeanSig.parse`'s `rsizes` defaults to `()` only so a
    wrong-typed `data` argument is still refused ahead of it, as
    `tests/serialization_boundary_test.py`'s table requires of every
    `parse`'s own extra argument -- not because an empty ring structure
    is a value worth accepting. This is what closes that gap: a caller
    who leaves `rsizes` out and hands real octets to `parse` is refused
    here rather than handed an object that looks like a signature and
    is not one.
    """
    with pytest.raises(BTClibValueError, match="no rings"):
        BorromeanSig((0).to_bytes(32, "big"), [])

    # the exact shape a caller who forgot rsizes on real octets would
    # trip: e0 alone, no trailing bytes for assert_no_trailing to catch
    # first -- assert_valid is what catches it instead
    with pytest.raises(BTClibValueError, match="no rings"):
        BorromeanSig.parse((0).to_bytes(32, "big"))


def test_challenge_hash_matches_zkps_preimage_order() -> None:
    """`_hash`'s preimage order, pinned against secp256k1-zkp's by hand.

    secp256k1-zkp's rangeproof module builds this challenge as `e || m
    || ring || pos` (`secp256k1_borromean_hash`,
    `src/modules/rangeproof/borromean_impl.h`, read at its current tip
    on 2026-08-20): the point -- or the `e0` closing the rings -- first,
    then the message hash, then the ring index and the position each as
    4 bytes big-endian (issue #1070). There is no vendored zkp in this
    tree to call, so this pins that order computed by hand from zkp's
    documented source rather than from any live cross-check against
    zkp's own code -- and pins it against a `m || R || i || j` order,
    which is what this function computed, and what this test would have
    caught, before #1070.
    """
    m = hashlib.sha256(b"message hash, pretending to be one").digest()
    r = hashlib.sha256(b"nonce point, or e0, pretending to be one").digest()
    ring, position = 3, 7
    expected = hashlib.sha256(
        r + m + ring.to_bytes(4, "big") + position.to_bytes(4, "big")
    ).digest()

    assert borromean._hash(m, r, ring, position, sha256) == expected
    # the order the preimage used to have, and would still equal if
    # #1070 had not been fixed
    swapped = hashlib.sha256(
        m + r + ring.to_bytes(4, "big") + position.to_bytes(4, "big")
    ).digest()
    assert borromean._hash(m, r, ring, position, sha256) != swapped


def test_the_curve_and_the_hash_function_are_parameters() -> None:
    """As module globals, selecting either would be process-wide.

    Choosing another curve or hash would mean rebinding an attribute of
    btclib.ecc.borromean, which changes the algorithm for every other
    caller in the process. They are arguments, with the same defaults
    and in the same position as in dsa, ssa and pedersen.
    """
    assert not hasattr(borromean, "ec")
    assert not hasattr(borromean, "hf")

    signature = inspect.signature(borromean.sign)
    assert list(signature.parameters)[-2:] == ["ec", "hf"]
    assert signature.parameters["ec"].default is secp256k1
    assert signature.parameters["hf"].default is sha256
    for func in (borromean.verify, borromean.assert_as_valid):
        parameters = inspect.signature(func).parameters
        assert list(parameters)[-2:] == ["ec", "hf"]
        assert parameters["ec"].default is secp256k1
        assert parameters["hf"].default is sha256


def test_another_hash_function_gives_another_signature() -> None:
    """The hf argument is threaded all the way down, not merely accepted."""
    msg = "0f" * 32
    nring = 2
    ring_sizes = [2, 2]
    sign_key_idx = [0, 1]

    prv_keys: list[list[int]] = [[] for _ in range(nring)]
    pub_keys: list[list[Point]] = [[] for _ in range(nring)]
    sign_keys = []
    for i in range(nring):
        for _j in range(ring_sizes[i]):
            prv_key, pub_key = dsa.gen_keys()
            prv_keys[i].append(prv_key)
            pub_keys[i].append(pub_key)
        sign_keys.append(prv_keys[i][sign_key_idx[i]])
    ks = [1 + secrets.randbelow(secp256k1.n - 1) for _ in range(nring)]

    sig_256 = borromean.sign(msg, ks, sign_key_idx, sign_keys, pub_keys)
    sig_512 = borromean.sign(
        msg, ks, sign_key_idx, sign_keys, pub_keys, hf=hashlib.sha512
    )
    assert sig_256.e0 != sig_512.e0
    # e0's width is the digest's, not the curve's: sha512 doubles it
    assert len(sig_256.e0) == 32
    assert len(sig_512.e0) == 64

    # each verifies under its own hash function and under no other
    assert borromean.verify(msg, sig_256, pub_keys)
    assert borromean.verify(msg, sig_512, pub_keys, hf=hashlib.sha512)
    assert not borromean.verify(msg, sig_256, pub_keys, hf=hashlib.sha512)
    assert not borromean.verify(msg, sig_512, pub_keys)


# a message per curve, because a low-cardinality curve makes the corner
# case below a one-in-n event rather than a 2**-255 one: on ec17_13 the
# messages 0 and 1 hit a zero e and cannot be signed at all, which is the
# next test
ROUND_TRIP_MSG = {
    "ec13_11": 0,
    "ec13_19": 0,
    "ec17_13": 2,
    "ec17_23": 0,
    "ec19_13": 0,
    "ec19_23": 0,
    "ec23_19": 0,
    "ec23_31": 0,
}


@pytest.mark.parametrize("name", ROUND_TRIP_MSG)
def test_another_curve_signs_and_verifies(name: str) -> None:
    """The ec argument has to reach the arithmetic, not only the encodings.

    It did not: `mult(k)` and `double_mult_var(-e, Q, s, ec.G)` were called
    without ec, so every point was computed on secp256k1 -- ec.G being
    merely a *point* argument -- and then encoded against ec. The first
    bytes_from_point raised "y-coordinate not in 1..p-1" with a
    secp256k1-sized coordinate in the message, so no curve but secp256k1
    could sign at all, and the corner case issue 183 asked about was
    unreachable rather than untested.
    """
    ec = low_card_curves[name]
    msg = ROUND_TRIP_MSG[name].to_bytes(4, "big")
    pubk_rings = [[mult(2, ec.G, ec)]]

    sig = borromean.sign(msg, [3], [0], [2], pubk_rings, ec=ec)
    assert sig.ec is ec
    # s's width comes from ec, not from a hardcoded 32: ec13_11's n
    # fits in far fewer bytes than secp256k1's
    assert len(sig.serialize()) == 32 + ec.n_size

    borromean.assert_as_valid(msg, sig, pubk_rings, ec=ec)
    assert borromean.verify(msg, sig, pubk_rings, ec=ec)
    assert not borromean.verify(b"\xff\xff\xff\xff", sig, pubk_rings, ec=ec)
    # a BorromeanSig argument carries its own ec, as ssa.Sig does, so
    # verify's ec default is not what decides the curve here -- omitting
    # ec=ec still verifies. The octets it serializes to do not: parsed
    # with ec defaulting to secp256k1, every s is read ec13_11's few
    # bytes short of secp256k1's n_size, so this is where "the ec
    # argument has to reach the arithmetic" still bites
    assert borromean.verify(msg, sig, pubk_rings)
    assert not borromean.verify(msg, sig.serialize(), pubk_rings)


def test_a_zero_e_is_a_one_in_n_event_on_a_low_cardinality_curve() -> None:
    """The corner case issue 183 asked for: e = 0 mod n, and no signature.

    `e = int_from_bits(hash, ec.nlen) % ec.n` is zero for about one message
    in n, so on ec13_11 it is one in eleven where on secp256k1 it is one in
    2**255. Each guard is reached with a single-key ring or a two-key ring
    signed at index 0, both of which make `sign` deterministic: the s-values
    it draws at random are either overwritten by the signer or used only
    after the e that is being tested.
    """
    ec = low_card_curves["ec13_11"]
    Q1, Q2 = mult(1, ec.G, ec), mult(2, ec.G, ec)
    err_msg = "implausible signature failure"

    # step 2, the e derived from e0
    with pytest.raises(BorromeanRingError, match=err_msg) as excinfo:
        borromean.sign(b"\x00\x00\x00\x00", [3], [0], [1], [[Q1]], ec=ec)
    assert (excinfo.value.ring, excinfo.value.position) == (0, 0)

    # step 1, the e derived from the nonce's own point
    with pytest.raises(BorromeanRingError, match=err_msg) as excinfo:
        borromean.sign(b"\x00\x00\x00\x00", [1], [0], [1], [[Q1, Q2]], ec=ec)
    assert (excinfo.value.ring, excinfo.value.position) == (0, 1)

    # and both guards in verification, where nothing is random: the first
    # e of a ring, and one derived from a preceding r. Both e0 values are
    # specific to #1070's preimage order -- e || m || ring || pos -- and
    # were found by searching, not derived
    sig1 = BorromeanSig((0).to_bytes(32, "big"), [[1]], ec=ec)
    with pytest.raises(BorromeanRingError, match=err_msg) as excinfo:
        borromean.assert_as_valid(b"\x00\x00\x00\x00", sig1, [[Q1]], ec=ec)
    assert (excinfo.value.ring, excinfo.value.position) == (0, 0)

    sig2 = BorromeanSig((47).to_bytes(32, "big"), [[1, 1]], ec=ec)
    with pytest.raises(BorromeanRingError, match=err_msg) as excinfo:
        borromean.assert_as_valid(b"\x00\x00\x00\x00", sig2, [[Q1, Q2]], ec=ec)
    assert (excinfo.value.ring, excinfo.value.position) == (0, 1)

    # verify answers False, as it does for any input that is not a valid
    # signature: BTClibRuntimeError is one of the two it catches
    assert not borromean.verify(b"\x00\x00\x00\x00", sig1, [[Q1]], ec=ec)


def test_the_point_at_infinity_is_the_other_corner_case() -> None:
    """`s*G - e*Q` can be INF, and `_bytes_from_ring_point` is what names it.

    The one-in-n neighbour of a zero e: `r` is a hash input,
    `bytes_from_point` is what produces it, and there is no
    serialization of the point at infinity to hash -- `bytes_from_point`
    itself raises a bare `BTClibValueError` for that, with no ring and
    no position. `_bytes_from_ring_point` wraps it into a
    `BorromeanRingError` instead, the same as the "implausible signature
    failure" guards beside it, ring and position both in hand at every
    call site that wraps it.
    """
    ec = low_card_curves["ec13_11"]
    Q1 = mult(1, ec.G, ec)

    # this e0, like the ones above, is specific to #1070's preimage
    # order and was found by searching
    sig = BorromeanSig((14).to_bytes(32, "big"), [[1]], ec=ec)
    with pytest.raises(BorromeanRingError, match="no bytes representation") as excinfo:
        borromean.assert_as_valid(b"\x00\x00\x00\x00", sig, [[Q1]], ec=ec)
    assert (excinfo.value.ring, excinfo.value.position) == (0, 0)
    # BorromeanRingError being a BTClibRuntimeError, the other exception
    # verify catches
    assert not borromean.verify(b"\x00\x00\x00\x00", sig, [[Q1]], ec=ec)


def test_one_nonce_and_one_signing_index_per_ring() -> None:
    """A short ks truncated the loops and signed a subset of the rings.

    `zip(..., strict=True)` is what caught it, with the message "zip()
    argument 3 is shorter than argument 1" -- a `BTClibValueError`'s
    class carrying none of its content, naming an argument position of
    `zip` and no parameter of `sign`. The check is `sign`'s own now, and
    `strict=True` stays as the assertion that the two cannot drift
    apart.

    `sign_keys` is part of the same check: step 2 indexes it per ring
    (`sign_keys[i]`), so a short one is the same ring-count exposure
    `assert_as_valid` refuses for a mismatched `s`, checked here before
    either walk for the same reason.
    """
    ring_sizes = [3, 4]
    sign_key_idx = [2, 1]
    key_rings = [[dsa.gen_keys() for _ in range(size)] for size in ring_sizes]
    sign_keys = [key_rings[i][sign_key_idx[i]][0] for i in range(2)]
    pubk_rings = [[key_rings[i][j][1] for j in range(ring_sizes[i])] for i in range(2)]
    msg = b"Borromean ring signature"

    assert isinstance(
        borromean.sign(msg, [1, 2], sign_key_idx, sign_keys, pubk_rings), BorromeanSig
    )

    err_msg = "2 rings, 2 signing indexes, 1 nonces and 2 signing keys"
    with pytest.raises(BTClibValueError, match=err_msg):
        borromean.sign(msg, [1], sign_key_idx, sign_keys, pubk_rings)
    err_msg = "2 rings, 1 signing indexes, 2 nonces and 2 signing keys"
    with pytest.raises(BTClibValueError, match=err_msg):
        borromean.sign(msg, [1, 2], sign_key_idx[:1], sign_keys, pubk_rings)
    err_msg = "2 rings, 2 signing indexes, 2 nonces and 1 signing keys"
    with pytest.raises(BTClibValueError, match=err_msg):
        borromean.sign(msg, [1, 2], sign_key_idx, sign_keys[:1], pubk_rings)


def test_a_ring_shape_that_disagrees_with_pubk_rings_is_refused() -> None:
    """A caller-built BorromeanSig whose shape disagrees with pubk_rings.

    `assert_as_valid` raises `BTClibValueError`, naming the ring and the
    counts, for a `sig.s` whose shape does not match `pubk_rings`: the
    two cases issue #1088 names separately, a ring with fewer scalars
    than keys and fewer rings than `pubk_rings` -- "the same defect one
    level up". `verify` is asserted for each case too, and not only
    `assert_as_valid`: it is documented to answer `False` for an invalid
    signature, and only calling it exercises that promise for this
    input.
    """
    ec = secp256k1
    q1 = mult(1, ec.G, ec)
    q2 = mult(2, ec.G, ec)

    # one ring, two keys, one s-value: fewer scalars than keys
    sig = BorromeanSig((0).to_bytes(32, "big"), [[5]], ec)
    err_msg = "ring 0 has 1 s-value for 2 keys"
    with pytest.raises(BTClibValueError, match=err_msg):
        borromean.assert_as_valid(b"msg", sig, [[q1, q2]])
    assert not borromean.verify(b"msg", sig, [[q1, q2]])

    # one ring in the signature, two in pubk_rings: fewer rings
    err_msg = "2 pubkey rings and 1 s-value ring"
    with pytest.raises(BTClibValueError, match=err_msg):
        borromean.assert_as_valid(b"msg", sig, [[q1], [q2]])
    assert not borromean.verify(b"msg", sig, [[q1], [q2]])


def test_a_ring_with_no_keys_is_refused() -> None:
    """A ring of size zero signs nothing, even where every shape agrees.

    `_assert_matches_pubk_rings` only compares the *counts* of two
    arguments, so `sig.s == [[]]` against `pubk_rings == [[]]` passes it
    -- both are one ring of zero. The walk still cannot run: `sign`'s
    step 1 divides by `keys_size` (`ZeroDivisionError`), and
    `assert_as_valid` indexes `e[i][0]` on the empty list `_initialize`
    builds for it (`IndexError`), neither a `BTClibValueError` nor a
    `BTClibRuntimeError`, so the second escaped `verify`'s own
    `except (ValueError, BTClibRuntimeError)` (issue #1094).

    The fix is `BorromeanSig.assert_valid`'s own new check, so it holds
    at construction already -- before `assert_as_valid` or `verify` are
    even reached -- and `sign`'s new bound on `sign_key_idx[i]`, which a
    zero-size ring fails for every value since no index is valid there.
    """
    ec = secp256k1

    with pytest.raises(BTClibValueError, match="ring 0 has no keys"):
        BorromeanSig((0).to_bytes(32, "big"), [[]], ec)

    sig = BorromeanSig((0).to_bytes(32, "big"), [[]], ec, check_validity=False)
    with pytest.raises(BTClibValueError, match="ring 0 has no keys"):
        borromean.assert_as_valid(b"msg", sig, [[]])
    assert not borromean.verify(b"msg", sig, [[]])

    err_msg = "ring 0 has 0 keys, sign_key_idx 0 is not a valid index"
    with pytest.raises(BTClibValueError, match=err_msg):
        borromean.sign(b"msg", [1], [0], [1], [[]])


def test_sign_key_idx_out_of_range_is_refused() -> None:
    """A sign_key_idx[i] that is not a position in its own ring.

    `sign`'s existing shape check compares the *counts* of `pubk_rings`,
    `sign_key_idx`, `ks` and `sign_keys`, which all agree here -- one
    entry each. Nothing bounded what `sign_key_idx[0]` itself pointed
    at: too large a value walked `s[i][j - 1]` and `pubk_rings[i][j - 1]`
    past the end of the ring's tuple in step 2, a bare `IndexError`
    (issue #1095); a negative one wrapped to a Python-legal index and
    signed a position other than the one it named, silently producing a
    signature that does not verify rather than raising anything at all.
    Both are now `BTClibValueError`, naming the ring, its size and the
    index, before either step runs.
    """
    ec = secp256k1
    q1 = mult(1, ec.G, ec)
    q2 = mult(2, ec.G, ec)

    err_msg = "ring 0 has 2 keys, sign_key_idx 5 is not a valid index"
    with pytest.raises(BTClibValueError, match=err_msg):
        borromean.sign(b"msg", [1], [5], [1], [[q1, q2]])

    err_msg = "ring 0 has 2 keys, sign_key_idx -1 is not a valid index"
    with pytest.raises(BTClibValueError, match=err_msg):
        borromean.sign(b"msg", [1], [-1], [1], [[q1, q2]])


# each maps an s-value to a key `_guess_signer` maximizes over the ring: a
# published signature must not let any of them recover which position was
# the real signer. "bit_length" and "value" are the two the unreduced real
# s used to fail on -- twice the bits and, following from that, easily the
# largest integer in the ring; "value mod 4" is neither, and is here so
# that the test is not merely bit_length restated
_S_VALUE_STATISTICS: dict[str, Callable[[int], int]] = {
    "bit_length": int.bit_length,
    "value": lambda x: x,
    "value mod 4": lambda x: x % 4,
}


def _guess_signer(s: tuple[int, ...], statistic: Callable[[int], int]) -> int:
    return max(range(len(s)), key=lambda j: statistic(s[j]))


def _assert_no_statistic_of_s_correlates_with_the_signer(
    ec: Curve, ring_size: int, trials: int, tolerance: float
) -> None:
    """Sign `trials` times with the real index re-drawn every time.

    None of `_S_VALUE_STATISTICS` may guess the real index at better than
    chance, `1 / ring_size`. `tolerance` is a margin over chance for the
    binomial noise of `trials` draws, not an allowance for a weaker
    correlation: the bit_length statistic that used to leak the signer
    scored close to 1.0, not chance plus a little.
    """
    prv_keys = [1 + secrets.randbelow(ec.n - 1) for _ in range(ring_size)]
    pubk_ring = [mult(q, ec.G, ec) for q in prv_keys]
    msg = b"anonymity"
    correct = dict.fromkeys(_S_VALUE_STATISTICS, 0)
    for _ in range(trials):
        sign_idx = secrets.randbelow(ring_size)
        while True:
            k = 1 + secrets.randbelow(ec.n - 1)
            try:
                sig = borromean.sign(
                    msg, [k], [sign_idx], [prv_keys[sign_idx]], [pubk_ring], ec=ec
                )
            except BorromeanRingError:
                # the "implausible signature failure" guards, and the
                # point-at-infinity corner case beside them -- both
                # documented in borromean.sign as one-in-n events on a
                # low-cardinality curve rather than the 2**-255 and
                # 2**-128 accidents they are on secp256k1, so this loop
                # sees several of them per ring and reaches this branch
                # at ordinary odds
                continue
            break
        for name, statistic in _S_VALUE_STATISTICS.items():
            if _guess_signer(sig.s[0], statistic) == sign_idx:
                correct[name] += 1
    chance = 1 / ring_size
    for name, count in correct.items():
        rate = count / trials
        assert rate < chance + tolerance, f"{name} correlates with the signer: {rate}"


def test_no_statistic_of_s_correlates_with_the_signer() -> None:
    """The property a ring signature exists for, checked rather than assumed.

    Before the fix, the real signer's s-value was unreduced and about
    twice the bit length of the forged ones, so `max(s, key=bit_length)`
    named the signer with no cryptanalysis at all. Reducing the real
    value and drawing the forged ones from the same range removes the
    signal; this asserts that removal statistically instead of taking it
    on faith.
    """
    _assert_no_statistic_of_s_correlates_with_the_signer(
        secp256k1, ring_size=8, trials=300, tolerance=0.15
    )


def test_no_statistic_of_s_correlates_with_the_signer_on_a_low_cardinality_curve() -> (
    None
):
    """The same property where the second half of the fix bites.

    `randbits(256)` is uniform over `[0, 2**256)`, not over the scalars;
    the gap is a `2**-127` fraction of secp256k1's range and invisible
    there, but on a curve whose order is small relative to 256 bits a
    forged value drawn that way is the one a statistic can still pick
    out. `randbelow(ec.n)` draws forged and real values from the same
    distribution regardless of the curve, which is what this checks.
    """
    ec = low_card_curves["ec23_31"]
    _assert_no_statistic_of_s_correlates_with_the_signer(
        ec, ring_size=4, trials=300, tolerance=0.25
    )
