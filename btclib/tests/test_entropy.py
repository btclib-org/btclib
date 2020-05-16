#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.entropy` module."

import math
import secrets

import pytest

from btclib.entropy import (
    _entropy_from_indexes,
    _indexes_from_entropy,
    binstr_from_entropy,
    randbinstr,
)


def test_indexes():
    for entropy in ("0", "00000000000"):
        indexes = _indexes_from_entropy(entropy, 2048)
        assert indexes, [0]
    entropy = "000000000000"
    indexes = _indexes_from_entropy(entropy, 2048)
    assert indexes, [0, 0]

    test_indexes = [
        [1268, 535, 810, 685, 433, 811, 1385, 1790, 421, 570, 567, 1313],
        [0, 0, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 0],
        [0, 0, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 0],
    ]
    for indx in test_indexes:
        entropy = _entropy_from_indexes(indx, 2048)
        indexes = _indexes_from_entropy(entropy, 2048)
        assert indexes, indx


def test_conversions():

    test_vectors = [
        "10101011" * 32,
        "00101011" * 32,
        "00000000" + "10101011" * 31,
    ]

    for entr in test_vectors:
        assert binstr_from_entropy(entr) == entr
        assert binstr_from_entropy(int(entr, 2)) == entr
        assert binstr_from_entropy(bin(int(entr, 2))) == entr
        assert binstr_from_entropy(int(entr, 2).to_bytes(32, "big")) == entr

    entr = "10" + "11111111" * 32
    binary_number = bin(int(entr, 2))
    assert binstr_from_entropy(binary_number) == binstr_from_entropy(entr[:-2])

    # the 32 bytes integer has its leftmost bit set to 0
    entr = secrets.randbits(255)
    binstr_entropy = binstr_from_entropy(entr)
    assert len(binstr_entropy), 256

    # 257 bits
    entr = 1 << 256
    binstr_entropy = binstr_from_entropy(entr)
    assert len(binstr_entropy), 256

    exp_int_entropy = entr >> 1
    entr = int(binstr_entropy, 2)
    assert entr, exp_int_entropy


def test_exceptions():
    binstr_entropy1 = "00011010" * 27  # 216 bits
    binstr_entropy = binstr_entropy1[2:]  # 214 bits

    entropy = binstr_from_entropy(binstr_entropy, 214)
    assert entropy, binstr_entropy
    err_msg = "Wrong number of bits: "  # 214 is not in [128, 160, 192, 224, 256]
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_entropy(binstr_entropy)
    err_msg = "Wrong number of bits: "  # 214 is not in [216]
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_entropy(binstr_entropy, 216)

    int_entropy = int(binstr_entropy, 2)  # 213 bits
    entropy = binstr_from_entropy(int_entropy, 214)
    assert entropy, binstr_entropy
    entropy = binstr_from_entropy(int_entropy, 256)
    assert len(entropy), 256
    assert int(entropy, 2), int_entropy
    entropy = binstr_from_entropy(int_entropy)
    assert len(entropy), 224
    assert int(entropy, 2), int_entropy
    err_msg = "Negative entropy: "
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_entropy(-1 * int_entropy)

    bytes_entropy = int_entropy.to_bytes(27, byteorder="big")
    err_msg = "Wrong number of bits: "
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_entropy(bytes_entropy, 214)
    entropy = binstr_from_entropy(bytes_entropy, 216)
    assert entropy, binstr_entropy1
    err_msg = "Wrong number of bits: "
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_entropy(bytes_entropy, 224)

    invalid_entropy = tuple()
    err_msg = "Entropy must be binary 0/1 string, bytes-like, or int; not 'tuple'"
    with pytest.raises(TypeError, match=err_msg):
        binstr_from_entropy(invalid_entropy)


def test_randbinstr():
    bits = 256
    dice_base = 20
    bits_per_roll = math.floor(math.log2(dice_base))
    base = 2 ** bits_per_roll
    roll_number = math.ceil(bits / bits_per_roll)

    rolls = [base for _ in range(roll_number)]
    binstr = randbinstr(bits, dice_base, rolls, False, False, False)
    assert binstr, "1" * 256

    rolls = [base for _ in range(2 * roll_number)]
    binstr = randbinstr(bits, dice_base, rolls, False, False, False)
    assert binstr, "1" * 256

    rolls = [1 for _ in range(roll_number)]
    binstr = randbinstr(bits, dice_base, rolls, False, False, False)
    assert binstr, "0" * 256

    rolls = [1 for _ in range(2 * roll_number)]
    binstr = randbinstr(bits, dice_base, rolls, False, False, False)
    assert binstr, "0" * 256

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    binstr = randbinstr(bits, dice_base, rolls)
    assert len(binstr), 256
    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    binstr2 = randbinstr(bits, dice_base, rolls)
    assert len(binstr2), 256
    assert binstr != binstr2

    binstr = randbinstr(bits)
    assert len(binstr), 256
    binstr2 = randbinstr(bits)
    assert len(binstr2), 256
    assert binstr != binstr2

    # goes through bit lenght reduction before hashing
    rolls = [base for _ in range(roll_number + 1)]
    binstr = randbinstr(bits, dice_base, rolls)

    err_msg = "Wrong number of bits: "
    with pytest.raises(ValueError, match=err_msg):
        randbinstr(bits - 1, dice_base, rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number - 2)]
    err_msg = "Too few rolls in the usable "  # [1-16] range, missing 2 rolls
    with pytest.raises(ValueError, match=err_msg):
        randbinstr(bits, dice_base, rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    rolls[1] = base + 1
    err_msg = "Too few rolls in the usable "  # [1-16] range, missing 1 rolls
    with pytest.raises(ValueError, match=err_msg):
        randbinstr(bits, dice_base, rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    rolls[1] = dice_base + 1
    err_msg = "Invalid roll: "  # 21 is not in [1-20]
    with pytest.raises(ValueError, match=err_msg):
        randbinstr(bits, dice_base, rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    err_msg = "Invalid dice base "  # (1): must be >= 2
    with pytest.raises(ValueError, match=err_msg):
        randbinstr(bits, 1, rolls)
