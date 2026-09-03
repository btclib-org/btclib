# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bolt9` module.

The table is a transcription, so what a test can hold it to is its shape
-- a key per pair, and the even bit of it -- and the two bits BOLT11's
own examples make load-bearing: 8 and 14, which its valid "supports
features 8, 14 and 99" invoice sets, and 100, which its one invalid
feature example sets. `tests/bolt11_test.py` drives those two invoices
themselves.

The Dependencies column is the same kind of transcription and is held to
the same kind of shape, with one addition: the walk over it ends because
the table has no cycle, so a cycle is what one of the tests below refuses.
Every row of that column is asked for in turn, which is what a
mistranscribed bit fails. A chain -- a dependency that has one of its own
-- is what `_walk_dependencies` is separable for: BOLT9 assigns none at
the pinned revision, so the transitive step is driven over a table
written here instead.
"""

from __future__ import annotations

import pytest

from btclib.bolt9 import (
    FEATURE_DEPENDENCIES,
    FEATURE_NAMES,
    _walk_dependencies,
    unknown_even_bits,
    unmet_dependencies,
)
from btclib.exceptions import BTClibValueError


def test_every_key_is_the_even_bit_of_its_pair() -> None:
    """A pair is recorded once, under the compulsory half of it."""
    assert all(bit % 2 == 0 for bit in FEATURE_NAMES)


def test_no_two_pairs_share_a_name() -> None:
    """A name is a feature, so a repeated one would be a mistranscription."""
    assert len(set(FEATURE_NAMES.values())) == len(FEATURE_NAMES)


def test_a_feature_vector_of_assigned_bits_is_known() -> None:
    """Every bit BOLT9 assigns, even and odd halves alike, at once."""
    features = 0
    for bit in FEATURE_NAMES:
        features |= (1 << bit) | (1 << (bit + 1))
    assert unknown_even_bits(features) == ()


def test_no_feature_bits_at_all() -> None:
    """An invoice stating no `9` field is a zero, and states nothing."""
    assert unknown_even_bits(0) == ()


def test_an_unassigned_odd_bit_is_never_returned() -> None:
    """It's ok to be odd, whether or not the pair is assigned."""
    assert unknown_even_bits(1 << 99) == ()
    assert unknown_even_bits(1 << 3) == ()


def test_unassigned_even_bits_come_back_lowest_first() -> None:
    """Two gaps in BOLT9's own numbering, and the bit past its end."""
    assert unknown_even_bits((1 << 100) | (1 << 2) | (1 << 30)) == (2, 30, 100)


def test_an_assigned_bit_beside_an_unassigned_one() -> None:
    """`option_payment_metadata` is known; the bit above its pair is not."""
    assert FEATURE_NAMES[48] == "option_payment_metadata"
    assert unknown_even_bits((1 << 48) | (1 << 52)) == (52,)


def test_a_negative_feature_vector_is_refused() -> None:
    """A bit vector has no sign, and int_from_integer reads one."""
    with pytest.raises(BTClibValueError, match="negative feature vector"):
        unknown_even_bits(-1)


def test_every_dependency_is_between_assigned_features() -> None:
    """Both ends of a row: a feature depending, and one depended on."""
    for bit, required in FEATURE_DEPENDENCIES.items():
        assert bit in FEATURE_NAMES
        assert all(dependency in FEATURE_NAMES for dependency in required)


def test_no_feature_depends_on_itself() -> None:
    """Directly or through a chain, which is what ends the walk.

    Its own closure rather than `_walk_dependencies`: that one is what
    this guarantees terminates, so asking it would be asking the question
    of itself, and the answer to a cycle would be a hung suite.
    """
    for bit in FEATURE_DEPENDENCIES:
        reached: set[int] = set()
        frontier = set(FEATURE_DEPENDENCIES[bit])
        while frontier:
            assert bit not in frontier, f"feature {bit} depends on itself"
            reached |= frontier
            frontier = {
                further
                for required in frontier
                for further in FEATURE_DEPENDENCIES.get(required, ())
            } - reached


def test_every_row_of_the_column_is_asked_for() -> None:
    """Each feature alone, so each row answers for itself."""
    for bit, required in FEATURE_DEPENDENCIES.items():
        assert unmet_dependencies(1 << bit) == tuple(
            (bit, dependency) for dependency in required
        )


def test_a_vector_depending_on_nothing_is_met() -> None:
    """No `9` field at all, and a feature with an empty Dependencies cell."""
    assert unmet_dependencies(0) == ()
    assert unmet_dependencies(1 << 48) == ()


def test_the_optional_half_meets_a_dependency() -> None:
    """`payment_secret` offered rather than required still satisfies it."""
    assert unmet_dependencies((1 << 16) | (1 << 15)) == ()
    assert unmet_dependencies((1 << 16) | (1 << 14)) == ()


def test_the_optional_half_carries_its_own_dependencies() -> None:
    """A feature is stated by either of its bits, and depends either way."""
    assert unmet_dependencies(1 << 17) == ((16, 14),)


def test_two_features_short_of_their_dependencies_come_back_lowest_first() -> None:
    """`basic_mpp` and `option_zeroconf`, each missing its own."""
    assert unmet_dependencies((1 << 50) | (1 << 16)) == ((16, 14), (50, 46))


def test_a_negative_vector_is_refused_here_too() -> None:
    """The same read of a bit vector as `unknown_even_bits` does."""
    with pytest.raises(BTClibValueError, match="negative feature vector"):
        unmet_dependencies(-1)


def test_a_chain_is_followed_to_its_end() -> None:
    """The transitive step, over a table shaped like BOLT9's and chained.

    Setting 4 asks for 8, which the vector does not set and which asks for
    12 in turn; 16 is set, so nothing is asked of it.
    """
    dependencies = {4: (8,), 8: (12,), 16: (18,)}
    assert _walk_dependencies(dependencies, (1 << 4) | (1 << 16) | (1 << 18)) == (
        (4, 8),
        (8, 12),
    )
