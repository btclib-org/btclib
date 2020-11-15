#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for `btclib.psbt` module

test_vector from https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

import json
from os import path

import pytest

from btclib.psbt import Psbt


def test2_vectors_bip174() -> None:
    "Test https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki"

    data_folder = path.join(path.dirname(__file__), "test_data")
    filename = path.join(data_folder, "bip174_test_vectors.json")
    with open(filename, "r") as file_:
        # json.dump(test_vectors, f, indent=4)
        test_vectors = json.load(file_)

    for i, test_vector in enumerate(test_vectors["invalid psbts"]):
        with pytest.raises(Exception) as excinfo:
            Psbt.decode(test_vector["encoded psbt"])
        assert test_vector["error message"] in str(
            excinfo.value
        ), f"Case {i+1}: {test_vector['description']}\n{excinfo.value}"

    for i, test_vector in enumerate(test_vectors["valid psbts"]):
        try:
            Psbt.decode(test_vector["encoded psbt"])
        except Exception as e:  # pragma: no cover
            print(f"Case {i+1}: {test_vector['description']}")  # pragma: no cover
            raise e  # pragma: no cover
