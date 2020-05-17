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
    _bits,
    binstr_from_rolls,
    binstr_from_int,
    binstr_from_str,
    binstr_from_bytes,
)


def test_indexes():
    for entropy in ("0", "00000000000"):
        indexes = _indexes_from_entropy(entropy, 2048)
        assert indexes == [0]
    entropy = "000000000000"
    indexes = _indexes_from_entropy(entropy, 2048)
    assert indexes == [0, 0]

    test_indexes = [
        [1268, 535, 810, 685, 433, 811, 1385, 1790, 421, 570, 567, 1313],
        [0, 0, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 0],
        [0, 0, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 0],
    ]
    for indx in test_indexes:
        entropy = _entropy_from_indexes(indx, 2048)
        indexes = _indexes_from_entropy(entropy, 2048)
        assert indexes == indx


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

    max_bits = max(_bits)

    entr = "10" + "11111111" * (max_bits // 8)
    binary_number = bin(int(entr, 2))
    assert binstr_from_entropy(binary_number) == binstr_from_entropy(entr[:-2])

    # entr integer has its leftmost bit set to 0
    entr = 1 << max_bits - 1
    binstr_entropy = binstr_from_entropy(entr)
    assert len(binstr_entropy) == max_bits

    # entr integer has its leftmost bit set to 1
    entr = 1 << max_bits
    binstr_entropy = binstr_from_entropy(entr)
    assert len(binstr_entropy) == max_bits

    exp_int_entropy = entr >> 1
    entr = int(binstr_entropy, 2)
    assert entr == exp_int_entropy

    i = secrets.randbits(255)
    i_bytes = i.to_bytes(32, "big")
    binstr = binstr_from_int(i)
    assert int(binstr, 2) == i
    assert len(binstr) == 256

    assert binstr_from_str(binstr) == binstr
    assert binstr_from_str(hex(i).upper()) == binstr
    assert binstr_from_str(bin(i).upper()) == binstr
    assert binstr_from_str(i_bytes.hex()) == binstr

    assert binstr_from_bytes(i_bytes) == binstr
    assert binstr_from_bytes(i_bytes.hex()) == binstr

    binstr2 = binstr_from_int(i, 255)
    assert int(binstr2, 2) == i
    assert len(binstr2) == 255
    assert binstr_from_str("0" + binstr2) == binstr
    binstr2 = binstr_from_str(binstr, 128)
    assert len(binstr2) == 128
    assert binstr2 == binstr[:128]


def test_exceptions():
    binstr_entropy216 = "00011010" * 27  # 216 bits
    binstr_entropy214 = binstr_entropy216[:-2]  # 214 bits

    entropy = binstr_from_entropy(binstr_entropy214, 214)
    assert entropy == binstr_entropy214

    # 214 is not in [128, 160, 192, 224, 256, 512]
    err_msg = "Wrong number of bits: "
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_entropy(binstr_entropy214)

    # 214 is not in [216]
    err_msg = "Wrong number of bits: "
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_entropy(binstr_entropy214, 216)

    int_entropy211 = int(binstr_entropy214, 2)  # 211 bits
    assert int_entropy211.bit_length() == 211

    entropy = binstr_from_entropy(int_entropy211, 214)
    assert entropy == binstr_entropy214

    entropy = binstr_from_entropy(int_entropy211, 256)
    assert len(entropy) == 256
    assert int(entropy, 2) == int_entropy211

    entropy = binstr_from_entropy(int_entropy211)
    assert len(entropy) == 224
    assert int(entropy, 2) == int_entropy211

    err_msg = "Negative entropy: "
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_entropy(-1 * int_entropy211)

    bytes_entropy216 = int_entropy211.to_bytes(27, byteorder="big")
    entropy = binstr_from_entropy(bytes_entropy216, 214)
    assert entropy == binstr_entropy214

    entropy = binstr_from_entropy(bytes_entropy216, 216)
    assert entropy != binstr_entropy216

    err_msg = "Wrong number of bits: "
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_entropy(bytes_entropy216, 224)

    invalid_entropy = tuple()
    err_msg = "Entropy must be binary 0/1 string, bytes, or int; not 'tuple'"
    with pytest.raises(TypeError, match=err_msg):
        binstr_from_entropy(invalid_entropy)

    err_msg = "Entropy must be an int, not "
    with pytest.raises(TypeError, match=err_msg):
        binstr_from_int("not an int")

    err_msg = "Entropy must be a str, not "
    with pytest.raises(TypeError, match=err_msg):
        binstr_from_str(3)


def test_binstr_from_rolls():
    bits = 256
    dice_base = 20
    bits_per_roll = math.floor(math.log2(dice_base))
    base = 2 ** bits_per_roll
    roll_number = math.ceil(bits / bits_per_roll)

    rolls = [base for _ in range(roll_number)]
    binstr = binstr_from_rolls(bits, dice_base, rolls)
    assert binstr == "1" * 256

    rolls = [base for _ in range(2 * roll_number)]
    binstr = binstr_from_rolls(bits, dice_base, rolls)
    assert binstr == "1" * 256

    rolls = [1 for _ in range(roll_number)]
    binstr = binstr_from_rolls(bits, dice_base, rolls)
    assert binstr == "0" * 256

    rolls = [1 for _ in range(2 * roll_number)]
    binstr = binstr_from_rolls(bits, dice_base, rolls)
    assert binstr == "0" * 256

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    binstr = binstr_from_rolls(bits, dice_base, rolls)
    assert len(binstr) == 256

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    binstr2 = binstr_from_rolls(bits, dice_base, rolls)
    assert len(binstr2) == 256
    assert binstr != binstr2

    binstr = binstr_from_rolls(bits - 1, dice_base, rolls)
    assert len(binstr) == bits - 1

    rolls = [base for _ in range(roll_number + 1)]
    binstr = binstr_from_rolls(bits + 1, dice_base, rolls)
    assert len(binstr) == bits + 1

    rolls = [base for _ in range(roll_number + 1)]
    binstr_rolls = binstr_from_rolls(bits, dice_base, rolls)
    binstr = randbinstr(bits, binstr_rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number - 2)]
    err_msg = "Too few rolls in the usable "  # [1-16] range, missing 2 rolls
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_rolls(bits, dice_base, rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    rolls[1] = base + 1
    err_msg = "Too few rolls in the usable "  # [1-16] range, missing 1 rolls
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_rolls(bits, dice_base, rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    rolls[1] = dice_base + 1
    err_msg = "Invalid roll: "  # 21 is not in [1-20]
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_rolls(bits, dice_base, rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    err_msg = "Invalid dice base: "
    with pytest.raises(ValueError, match=err_msg):
        binstr_from_rolls(bits, 1, rolls)


def test_randbinstr():
    for hash in (True, False):
        bits = 256
        binstr = randbinstr(bits, hash=hash)
        assert len(binstr) == bits
        binstr2 = randbinstr(bits, hash=hash)
        assert len(binstr2) == bits
        assert binstr != binstr2

        bits = 512
        binstr = randbinstr(bits, hash=hash)
        assert len(binstr) == bits
        binstr2 = randbinstr(bits, binstr, hash=hash)
        assert len(binstr2) == bits
        assert binstr != binstr2

        binstr2 = randbinstr(256, binstr, hash=hash)
        assert len(binstr2) == 256

    binstr = randbinstr(1024, hash=False)
    assert len(binstr) == 1024
    err_msg = "Too many bits required: "
    with pytest.raises(ValueError, match=err_msg):
        randbinstr(1024)
