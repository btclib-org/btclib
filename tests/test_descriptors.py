#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.descriptors` module."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib.descriptors import (
    __descsum_expand,
    descriptor_checksum,
    descriptor_from_address,
)
from btclib.exceptions import BTClibValueError
from tests import vectors

CHECKSUM_VECTORS = [
    pytest.param(
        descriptor_data["desc"],
        descriptor_data["checksum"],
        id=vectors.vector_id(index, descriptor_data["desc"]),
    )
    for index, descriptor_data in enumerate(
        vectors.load("_data", "descriptor_checksums.json", encoding="utf-8")
    )
]


# descriptors taken from https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
# checksum calculated using https://docs.rs/bdk/latest/bdk/descriptor/checksum/fn.get_checksum.html
@pytest.mark.parametrize(("descriptor", "checksum"), CHECKSUM_VECTORS)
def test_checksum(descriptor: str, checksum: str) -> None:
    assert descriptor_checksum(descriptor) == checksum


def test_invalid_charset() -> None:
    with pytest.raises(BTClibValueError):
        __descsum_expand("è")


def test_addr() -> None:
    address = "bc1qnehtvnd4fedkwjq6axfgsrxgllwne3k58rhdh0"
    descriptor = "addr(bc1qnehtvnd4fedkwjq6axfgsrxgllwne3k58rhdh0)#s2y3vepm"
    assert descriptor_from_address(address) == descriptor


# what a descriptor is made of: the checksum alphabet is defined over
# these, and a character outside it is a different error
DESCRIPTOR_CHARS = (
    "0123456789()[],'/*abcdefgh@:$%{}"
    "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
    'ijklmnopqrstuvwxyzABCDEFGH`#"\\ '
)
DESCRIPTOR = st.text(alphabet=DESCRIPTOR_CHARS, min_size=1, max_size=60)


@given(descriptor=DESCRIPTOR)
def test_checksum_is_eight_characters(descriptor: str) -> None:
    assert len(descriptor_checksum(descriptor)) == 8


@given(
    descriptor=DESCRIPTOR,
    position=st.integers(min_value=0),
    replacement=st.sampled_from(DESCRIPTOR_CHARS),
)
def test_a_changed_character_changes_the_checksum(
    descriptor: str, position: int, replacement: str
) -> None:
    """A single substitution is what the BIP-380 checksum must catch.

    It is designed to catch any error of up to four characters, so one
    is the case it must never miss -- and the case a wallet meets, a
    descriptor being something a person retypes.
    """
    i = position % len(descriptor)
    mutated = descriptor[:i] + replacement + descriptor[i + 1 :]
    if mutated == descriptor:
        return
    assert descriptor_checksum(mutated) != descriptor_checksum(descriptor)
