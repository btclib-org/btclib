# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.muhash` module.

`tests/_data/chacha20_vectors.json` and `muhash_vectors.json`
(`tests/_data/README.md` is where both are derived from and pinned) check
the two primitives `MuHash3072` is built from against Bitcoin Core's own
`src/test/crypto_tests.cpp`, before the properties that are not
vector-driven -- order-independence, insert/remove cancellation, and the
serialize/deserialize round trip -- are checked directly.
"""

from __future__ import annotations

from typing import Any

import pytest

from btclib import muhash as muhash_module
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.muhash import MuHash3072, _chacha20_keystream
from tests import load, vector_id

_CHACHA20_VECTORS = load("_data", "chacha20_vectors.json")
_CHACHA20_IDS = [
    vector_id(index, "message" if v["message"] else "keystream", v["seek"])
    for index, v in enumerate(_CHACHA20_VECTORS)
]

_MUHASH_VECTORS = load("_data", "muhash_vectors.json")


@pytest.mark.parametrize("vector", _CHACHA20_VECTORS, ids=_CHACHA20_IDS)
def test_chacha20_keystream_matches_core(vector: dict[str, Any]) -> None:
    """`_chacha20_keystream` reproduces `crypto_tests.cpp`'s own vectors.

    RFC 7539/8439's own Appendix A vectors among them --
    `tests/_data/README.md` names which. A message-bearing vector's own
    expected bytes are ciphertext (`message` XOR keystream), matching
    `TestChaCha20`'s own two modes; vector 20's `seek` sits one below
    2**32, so its second of two blocks is the one place this exercises
    the 32-bit block-counter overflow into the nonce's own first word.
    """
    key = bytes.fromhex(vector["key"])
    nonce_words = (
        vector["nonce_first"],
        vector["nonce_second"] & 0xFFFFFFFF,
        (vector["nonce_second"] >> 32) & 0xFFFFFFFF,
    )
    expected = bytes.fromhex(vector["keystream_or_ciphertext"])
    blocks = (len(expected) + 63) // 64
    keystream = _chacha20_keystream(
        key, blocks, nonce_words=nonce_words, counter=vector["seek"]
    )[: len(expected)]
    if vector["message"]:
        message = bytes.fromhex(vector["message"])
        result = bytes(a ^ b for a, b in zip(message, keystream, strict=True))
    else:
        result = keystream
    assert result == expected


def test_muhash_insert_then_remove_matches_core_vector() -> None:
    """Core's own `FromInt(0)*FromInt(1)/FromInt(2)` cancellation vector.

    `uint256{"..."}` reverses relative to its own display hex
    (`uint256.h`'s own "Hex representation" comment), so the raw digest
    this produces is the vector's own bytes reversed --
    `tests/_data/README.md`'s own entry is where that convention is
    confirmed against the pinned source rather than assumed.
    """
    vector = _MUHASH_VECTORS["insert_then_remove"]
    accumulator = MuHash3072()
    for element in vector["insert"]:
        accumulator.insert(bytes.fromhex(element))
    for element in vector["remove"]:
        accumulator.remove(bytes.fromhex(element))
    expected = bytes.fromhex(vector["digest_uint256_hex"])[::-1]
    assert accumulator.digest == expected


def test_muhash_serialize_matches_core_vector() -> None:
    """`serialize` matches `MuHash3072::SERIALIZE_METHODS`'s own bytes."""
    vector = _MUHASH_VECTORS["serialization"]
    accumulator = MuHash3072()
    for element in vector["insert"]:
        accumulator.insert(bytes.fromhex(element))
    assert accumulator.serialize.hex() == vector["serialized_hex"]


def test_muhash_overflow_vector() -> None:
    """A numerator the modulus does not yet reduce still finalizes correctly.

    `HexStr(out4)` in `crypto_tests.cpp` hex-encodes the raw digest
    directly, unlike the `uint256{"..."}` comparisons the other two
    vectors use -- **not** reversed, `tests/_data/README.md`'s own entry
    is where that difference between the two Core assertion macros is
    confirmed rather than assumed uniform.
    """
    vector = _MUHASH_VECTORS["overflow"]
    accumulator = MuHash3072.deserialize(bytes.fromhex(vector["serialized_hex"]))
    assert accumulator.digest == bytes.fromhex(vector["digest_hex_direct"])


def test_muhash_deserialize_round_trips_through_serialize() -> None:
    """`deserialize(serialize)` reproduces the same digest."""
    accumulator = MuHash3072()
    accumulator.insert(b"one element")
    accumulator.remove(b"a second, different element")
    restored = MuHash3072.deserialize(accumulator.serialize)
    assert restored.digest == accumulator.digest


def test_muhash_singleton_matches_insert_into_the_empty_set() -> None:
    """`MuHash3072.singleton(x)` is `MuHash3072(); m.insert(x)`."""
    element = b"a lone element"
    singleton = MuHash3072.singleton(element)
    inserted = MuHash3072()
    inserted.insert(element)
    assert singleton.digest == inserted.digest


def test_muhash_insert_is_order_independent() -> None:
    """H(a)+H(b) == H(b)+H(a) -- MuHash's own defining property."""
    first = MuHash3072()
    first.insert(b"alpha")
    first.insert(b"beta")

    second = MuHash3072()
    second.insert(b"beta")
    second.insert(b"alpha")

    assert first.digest == second.digest


def test_muhash_remove_cancels_the_matching_insert() -> None:
    """Insert then remove of the same element restores the empty digest.

    Core's own `test/fuzz/muhash.cpp` fuzzes exactly this property over
    arbitrary elements; this checks one.
    """
    accumulator = MuHash3072()
    accumulator.insert(b"an element")
    accumulator.remove(b"an element")
    assert accumulator.digest == MuHash3072().digest


def test_muhash_removes_cancel_regardless_of_insert_order() -> None:
    """Z = X*Y, divided back by Y then X, reaches the empty digest.

    The same shape Core's own `muhash_tests` checks algebraically
    (`z *= x; z *= y; y *= x; z /= y`, reducing to the identity): the
    element removed does not have to be removed in the order it was
    inserted for the two to cancel.
    """
    z = MuHash3072()
    z.insert(b"X")
    z.insert(b"Y")
    z.remove(b"Y")
    z.remove(b"X")
    assert z.digest == MuHash3072().digest


def test_mutating_the_per_element_hash_breaks_the_core_vector() -> None:
    """A one-byte perturbation of `_num3072`'s own input is not silent.

    Mutation evidence for the whole chain
    `test_muhash_insert_then_remove_matches_core_vector` pins: flipping
    one byte of what `_num3072` hashes changes the digest it produces,
    which is what makes that vector able to fail at all rather than
    passing by construction. Exercised here as `MuHash3072.insert` on the
    flipped element rather than by patching `_num3072` itself, so this
    test survives a change to that function's own internals.
    """
    vector = _MUHASH_VECTORS["insert_then_remove"]
    flipped = bytearray(bytes.fromhex(vector["insert"][0]))
    flipped[0] ^= 0xFF

    accumulator = MuHash3072()
    accumulator.insert(bytes(flipped))
    accumulator.insert(bytes.fromhex(vector["insert"][1]))
    for element in vector["remove"]:
        accumulator.remove(bytes.fromhex(element))

    expected = bytes.fromhex(vector["digest_uint256_hex"])[::-1]
    assert accumulator.digest != expected


def test_insert_refuses_a_value_of_the_wrong_type() -> None:
    """`insert` is an `Octets` parameter, so a float is the caller's mistake."""
    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        MuHash3072().insert(1.5)  # type: ignore[arg-type]


def test_remove_refuses_a_value_no_valid_octets_carries() -> None:
    """A hex string of odd length is a value, not a type, mistake."""
    with pytest.raises(BTClibValueError, match="invalid hex string"):
        MuHash3072().remove("9")


def test_deserialize_refuses_the_wrong_length() -> None:
    """`deserialize` wants exactly 768 bytes: two 384-byte numbers."""
    with pytest.raises(BTClibValueError, match="invalid size"):
        MuHash3072.deserialize(b"\x00" * 767)


def test_module_exports_only_muhash3072() -> None:
    """`__all__` is what ISS #1066's exception rests on: no cipher offered."""
    assert muhash_module.__all__ == ["MuHash3072"]
