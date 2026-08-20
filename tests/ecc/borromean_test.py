# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.borromean` module."""

import hashlib
import inspect
import secrets
from collections.abc import Callable
from hashlib import sha256

import pytest

from btclib.alias import Point
from btclib.curves import Curve, mult, secp256k1
from btclib.ecc import borromean, dsa
from btclib.exceptions import (
    BTClibRuntimeError,
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

    borromean.assert_as_valid(msg, sig[0], sig[1], pubk_rings)
    assert borromean.verify(msg, sig[0], sig[1], pubk_rings)
    # bytes, not str: a str msg is taken as hex, so "another message"
    # would fail to parse and never reach the ring verification
    assert not borromean.verify(b"another message", sig[0], sig[1], pubk_rings)
    # a msg that is neither bytes nor a hex-str is a caller error, and
    # verify says so instead of answering False: catching Exception would
    # report an int msg as a failed ring signature
    with pytest.raises(BTClibTypeError, match="invalid octets type: int"):
        borromean.verify(0, sig[0], sig[1], pubk_rings)  # type: ignore[arg-type]

    # a forged signature must raise, not merely return a falsy value:
    # assert_as_valid is called as a statement, so a return value
    # would be silently discarded
    err_msg = "signature verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        borromean.assert_as_valid(b"another message", sig[0], sig[1], pubk_rings)


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
    assert sig_256[0] != sig_512[0]

    # each verifies under its own hash function and under no other
    assert borromean.verify(msg, sig_256[0], sig_256[1], pub_keys)
    assert borromean.verify(msg, sig_512[0], sig_512[1], pub_keys, hf=hashlib.sha512)
    assert not borromean.verify(
        msg, sig_256[0], sig_256[1], pub_keys, hf=hashlib.sha512
    )
    assert not borromean.verify(msg, sig_512[0], sig_512[1], pub_keys)


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

    e0, s = borromean.sign(msg, [3], [0], [2], pubk_rings, ec=ec)

    borromean.assert_as_valid(msg, e0, s, pubk_rings, ec=ec)
    assert borromean.verify(msg, e0, s, pubk_rings, ec=ec)
    assert not borromean.verify(b"\xff\xff\xff\xff", e0, s, pubk_rings, ec=ec)
    # and it is a signature on that curve, not on secp256k1
    assert not borromean.verify(msg, e0, s, pubk_rings)


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
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        borromean.sign(b"\x00\x00\x00\x00", [1], [0], [1], [[Q1]], ec=ec)

    # step 1, the e derived from the nonce's own point
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        borromean.sign(b"\x00\x00\x00\x01", [3], [0], [1], [[Q1, Q2]], ec=ec)

    # and both guards in verification, where nothing is random: the first
    # e of a ring, and one derived from a preceding r
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        borromean.assert_as_valid(
            b"\x00\x00\x00\x00", (8).to_bytes(32, "big"), [[1]], [[Q1]], ec=ec
        )
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        borromean.assert_as_valid(
            b"\x00\x00\x00\x00", (0).to_bytes(32, "big"), [[1, 1]], [[Q1, Q2]], ec=ec
        )
    # verify answers False, as it does for any input that is not a valid
    # signature: BTClibRuntimeError is one of the two it catches
    assert not borromean.verify(
        b"\x00\x00\x00\x00", (8).to_bytes(32, "big"), [[1]], [[Q1]], ec=ec
    )


def test_the_point_at_infinity_is_the_other_corner_case() -> None:
    """`s*G - e*Q` can be INF, and the hash input has no encoding for it.

    The one-in-n neighbour of a zero e, and unguarded on purpose: `r` is a
    hash input, `bytes_from_point` is what produces it, and there is no
    serialization of the point at infinity to hash. So it raises where a
    zero e raises "implausible signature failure", and the caller's answer
    is another nonce -- on secp256k1, a 2**-128 event nobody will see.
    """
    ec = low_card_curves["ec13_11"]
    Q1 = mult(1, ec.G, ec)

    with pytest.raises(BTClibValueError, match="no bytes representation"):
        borromean.assert_as_valid(
            b"\x00\x00\x00\x00", (21).to_bytes(32, "big"), [[1]], [[Q1]], ec=ec
        )
    # ValueError being the other exception verify catches
    assert not borromean.verify(
        b"\x00\x00\x00\x00", (21).to_bytes(32, "big"), [[1]], [[Q1]], ec=ec
    )


def test_one_nonce_and_one_signing_index_per_ring() -> None:
    """A short ks truncated the loops and signed a subset of the rings.

    `zip(..., strict=True)` is what caught it, with the message "zip()
    argument 3 is shorter than argument 1" -- a `BTClibValueError`'s
    class carrying none of its content, naming an argument position of
    `zip` and no parameter of `sign`. The check is `sign`'s own now, and
    `strict=True` stays as the assertion that the two cannot drift
    apart.
    """
    ring_sizes = [3, 4]
    sign_key_idx = [2, 1]
    key_rings = [[dsa.gen_keys() for _ in range(size)] for size in ring_sizes]
    sign_keys = [key_rings[i][sign_key_idx[i]][0] for i in range(2)]
    pubk_rings = [[key_rings[i][j][1] for j in range(ring_sizes[i])] for i in range(2)]
    msg = b"Borromean ring signature"

    assert borromean.sign(msg, [1, 2], sign_key_idx, sign_keys, pubk_rings)

    err_msg = "2 rings, 2 signing indexes and 1 nonces"
    with pytest.raises(BTClibValueError, match=err_msg):
        borromean.sign(msg, [1], sign_key_idx, sign_keys, pubk_rings)
    err_msg = "2 rings, 1 signing indexes and 2 nonces"
    with pytest.raises(BTClibValueError, match=err_msg):
        borromean.sign(msg, [1, 2], sign_key_idx[:1], sign_keys, pubk_rings)


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


def _guess_signer(s: list[int], statistic: Callable[[int], int]) -> int:
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
                _, s = borromean.sign(
                    msg, [k], [sign_idx], [prv_keys[sign_idx]], [pubk_ring], ec=ec
                )
            except (BTClibRuntimeError, BTClibValueError):
                # the "implausible signature failure" guards, and the
                # point-at-infinity corner case beside them that raises
                # a BTClibValueError instead -- both documented in
                # borromean.sign as one-in-n events on a low-cardinality
                # curve rather than the 2**-255 and 2**-128 accidents
                # they are on secp256k1, so this loop sees several of
                # them per ring and reaches this branch at ordinary odds
                continue
            break
        for name, statistic in _S_VALUE_STATISTICS.items():
            if _guess_signer(s[0], statistic) == sign_idx:
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
