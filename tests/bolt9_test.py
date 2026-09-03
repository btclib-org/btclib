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
"""

from __future__ import annotations

import pytest

from btclib.bolt9 import FEATURE_NAMES, unknown_even_bits
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
