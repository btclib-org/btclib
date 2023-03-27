#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.descriptors` module."

import json
from pathlib import Path

import pytest

from btclib.descriptors import (
    __descsum_expand,
    descriptor_checksum,
    descriptor_from_address,
)
from btclib.exceptions import BTClibValueError


# descriptors taken from https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
# checksum calculated using https://docs.rs/bdk/latest/bdk/descriptor/checksum/fn.get_checksum.html
def test_checksum():

    filename = Path(__file__).parent / "_data" / "descriptor_checksums.json"
    with open(filename, "r", encoding="utf-8") as file:
        data = json.load(file)

    for descriptor_data in data:
        descriptor = descriptor_data["desc"]
        checksum = descriptor_data["checksum"]
        assert descriptor_checksum(descriptor) == checksum


def test_invalid_charset():

    with pytest.raises(BTClibValueError):
        __descsum_expand("è")


def test_addr():

    address = "bc1qnehtvnd4fedkwjq6axfgsrxgllwne3k58rhdh0"
    descriptor = "addr(bc1qnehtvnd4fedkwjq6axfgsrxgllwne3k58rhdh0)#s2y3vepm"
    assert descriptor_from_address(address) == descriptor
