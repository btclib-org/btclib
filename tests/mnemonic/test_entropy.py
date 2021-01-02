#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.entropy` module."

import math
import secrets
from io import StringIO
from typing import List

import pytest

from btclib.exceptions import BTClibValueError
from btclib.mnemonic.entropy import (
    _bits,
    bin_str_entropy_from_bytes,
    bin_str_entropy_from_entropy,
    bin_str_entropy_from_int,
    bin_str_entropy_from_random,
    bin_str_entropy_from_rolls,
    bin_str_entropy_from_str,
    bin_str_entropy_from_wordlist_indexes,
    bytes_entropy_from_str,
    collect_rolls,
    wordlist_indexes_from_bin_str_entropy,
)


def test_indexes() -> None:
    for entropy in ("0", "00000000000"):
        indexes = wordlist_indexes_from_bin_str_entropy(entropy, 2048)
        assert indexes == [0]
    entropy = "000000000000"
    indexes = wordlist_indexes_from_bin_str_entropy(entropy, 2048)
    assert indexes == [0, 0]

    test_vector = [
        [1268, 535, 810, 685, 433, 811, 1385, 1790, 421, 570, 567, 1313],
        [0, 0, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 0],
        [0, 0, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 2047, 0],
    ]
    for indx in test_vector:
        entropy = bin_str_entropy_from_wordlist_indexes(indx, 2048)
        indexes = wordlist_indexes_from_bin_str_entropy(entropy, 2048)
        assert indexes == indx


def test_conversions() -> None:

    test_vectors = [
        "10101011" * 32,
        "00101011" * 32,
        "00000000" + "10101011" * 31,
    ]

    for raw in test_vectors:
        assert bin_str_entropy_from_str(raw) == raw
        i = int(raw, 2)
        assert bin_str_entropy_from_int(i) == raw
        assert bin_str_entropy_from_int(bin(i).upper()) == raw
        assert bin_str_entropy_from_int(hex(i).upper()) == raw
        b = i.to_bytes(32, byteorder="big", signed=False)
        assert bin_str_entropy_from_bytes(b) == raw
        assert bin_str_entropy_from_bytes(b.hex()) == raw

        assert bin_str_entropy_from_entropy(raw) == raw
        assert bin_str_entropy_from_entropy(i) == raw
        assert bin_str_entropy_from_entropy(b) == raw

    max_bits = max(_bits)

    raw = "10" + "11111111" * (max_bits // 8)
    assert bin_str_entropy_from_entropy(raw) == bin_str_entropy_from_entropy(raw[:-2])

    # entr integer has its leftmost bit set to 0
    i = 1 << max_bits - 1
    bin_str_entropy = bin_str_entropy_from_entropy(i)
    assert len(bin_str_entropy) == max_bits

    # entr integer has its leftmost bit set to 1
    i = 1 << max_bits
    bin_str_entropy = bin_str_entropy_from_entropy(i)
    assert len(bin_str_entropy) == max_bits

    exp_i = i >> 1
    i = int(bin_str_entropy, 2)
    assert i == exp_i

    i = secrets.randbits(255)
    raw = bin_str_entropy_from_int(i)
    assert int(raw, 2) == i
    assert len(raw) == 256

    assert bin_str_entropy_from_str(raw) == raw
    assert bin_str_entropy_from_int(hex(i).upper()) == raw

    b = i.to_bytes(32, byteorder="big", signed=False)
    assert bin_str_entropy_from_bytes(b) == raw

    raw2 = bin_str_entropy_from_int(i, 255)
    assert int(raw2, 2) == i
    assert len(raw2) == 255
    assert bin_str_entropy_from_str("0" + raw2) == raw
    raw2 = bin_str_entropy_from_str(raw, 128)
    assert len(raw2) == 128
    assert raw2 == raw[:128]


def test_exceptions() -> None:
    bin_str_entropy216 = "00011010" * 27  # 216 bits
    bin_str_entropy214 = bin_str_entropy216[:-2]  # 214 bits

    entropy = bin_str_entropy_from_entropy(bin_str_entropy214, 214)
    assert entropy == bin_str_entropy214

    # 214 is not in [128, 160, 192, 224, 256, 512]
    err_msg = "invalid number of bits: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_entropy(bin_str_entropy214)

    # 214 is not in [216]
    err_msg = "invalid number of bits: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_entropy(bin_str_entropy214, 216)

    int_entropy211 = int(bin_str_entropy214, 2)  # 211 bits
    assert int_entropy211.bit_length() == 211

    entropy = bin_str_entropy_from_entropy(int_entropy211, 214)
    assert entropy == bin_str_entropy214

    entropy = bin_str_entropy_from_entropy(int_entropy211, 256)
    assert len(entropy) == 256
    assert int(entropy, 2) == int_entropy211

    entropy = bin_str_entropy_from_entropy(int_entropy211)
    assert len(entropy) == 224
    assert int(entropy, 2) == int_entropy211

    err_msg = "Negative entropy: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_entropy(-1 * int_entropy211)

    bytes_entropy216 = int_entropy211.to_bytes(27, byteorder="big", signed=False)
    entropy = bin_str_entropy_from_entropy(bytes_entropy216, 214)
    assert entropy == bin_str_entropy214

    entropy = bin_str_entropy_from_entropy(bytes_entropy216, 216)
    assert entropy != bin_str_entropy216

    err_msg = "invalid number of bits: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_entropy(bytes_entropy216, 224)

    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_entropy(tuple())  # type: ignore

    with pytest.raises(ValueError):
        bin_str_entropy_from_int("not an int")  # type: ignore

    with pytest.raises(TypeError):
        bin_str_entropy_from_str(3)  # type: ignore

    err_msg = "invalid number of bits: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy = "01" * 65  # 130 bits
        bytes_entropy_from_str(bin_str_entropy)


inputs: List[StringIO] = []
# 2 input failures, then automatic rolls with default D6
inputs.append(StringIO("3\npluto\na\n"))
# D120, then 43 automatic rolls
inputs.append(StringIO("a120\n"))
# D120, one input failure, then 43 (implausible but valid) non-automatic rolls
inputs.append(StringIO("120\npluto\n" + "64\n" * 43))


def test_collect_rolls(monkeypatch):

    bits = 256
    for i, sides in enumerate((6, 120, 120)):
        monkeypatch.setattr("sys.stdin", inputs[i])
        dice_sides, dice_rolls = collect_rolls(bits)
        assert dice_sides == sides
        bits_per_roll = math.floor(math.log2(sides))
        base = 2 ** bits_per_roll
        for roll in dice_rolls:
            assert 0 < roll <= base
        min_roll_number = math.ceil(bits / bits_per_roll)
        assert len(dice_rolls) == min_roll_number


def test_bin_str_entropy_from_rolls() -> None:
    bits = 256
    dice_base = 20
    bits_per_roll = math.floor(math.log2(dice_base))
    base = 2 ** bits_per_roll
    roll_number = math.ceil(bits / bits_per_roll)

    rolls = [base for _ in range(roll_number)]
    bin_str = bin_str_entropy_from_rolls(bits, dice_base, rolls)
    assert bin_str == "1" * 256

    rolls = [base for _ in range(2 * roll_number)]
    bin_str = bin_str_entropy_from_rolls(bits, dice_base, rolls)
    assert bin_str == "1" * 256

    rolls = [1 for _ in range(roll_number)]
    bin_str = bin_str_entropy_from_rolls(bits, dice_base, rolls)
    assert bin_str == "0" * 256

    rolls = [1 for _ in range(2 * roll_number)]
    bin_str = bin_str_entropy_from_rolls(bits, dice_base, rolls)
    assert bin_str == "0" * 256

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    bin_str = bin_str_entropy_from_rolls(bits, dice_base, rolls)
    assert len(bin_str) == 256

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    bin_str2 = bin_str_entropy_from_rolls(bits, dice_base, rolls)
    assert len(bin_str2) == 256
    assert bin_str != bin_str2

    bin_str = bin_str_entropy_from_rolls(bits - 1, dice_base, rolls)
    assert len(bin_str) == bits - 1

    rolls = [base for _ in range(roll_number + 1)]
    bin_str = bin_str_entropy_from_rolls(bits + 1, dice_base, rolls)
    assert len(bin_str) == bits + 1

    rolls = [base for _ in range(roll_number + 1)]
    bin_str_rolls = bin_str_entropy_from_rolls(bits, dice_base, rolls)
    bin_str = bin_str_entropy_from_random(bits, bin_str_rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number - 2)]
    err_msg = "Too few rolls in the usable "  # [1-16] range, missing 2 rolls
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_rolls(bits, dice_base, rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    rolls[1] = base + 1
    err_msg = "Too few rolls in the usable "  # [1-16] range, missing 1 rolls
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_rolls(bits, dice_base, rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    rolls[1] = dice_base + 1
    err_msg = "invalid roll: "  # 21 is not in [1-20]
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_rolls(bits, dice_base, rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    err_msg = "invalid dice base: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_rolls(bits, 1, rolls)


def test_bin_str_entropy_from_random() -> None:
    for to_be_hashed in (True, False):
        bits = 256
        bin_str = bin_str_entropy_from_random(bits, to_be_hashed=to_be_hashed)
        assert len(bin_str) == bits
        bin_str2 = bin_str_entropy_from_random(bits, "", to_be_hashed=to_be_hashed)
        assert len(bin_str2) == bits
        assert bin_str != bin_str2
        bin_str2 = bin_str_entropy_from_random(bits, to_be_hashed=to_be_hashed)
        assert len(bin_str2) == bits
        assert bin_str != bin_str2
        bin_str2 = bin_str_entropy_from_random(bits, "", to_be_hashed=to_be_hashed)
        assert len(bin_str2) == bits
        assert bin_str != bin_str2

        bits = 512
        bin_str = bin_str_entropy_from_random(bits, to_be_hashed=to_be_hashed)
        assert len(bin_str) == bits
        bin_str2 = bin_str_entropy_from_random(bits, bin_str, to_be_hashed=to_be_hashed)
        assert len(bin_str2) == bits
        assert bin_str != bin_str2

        bin_str2 = bin_str_entropy_from_random(256, bin_str, to_be_hashed=to_be_hashed)
        assert len(bin_str2) == 256

    bin_str = bin_str_entropy_from_random(1024, to_be_hashed=False)
    assert len(bin_str) == 1024
    err_msg = "Too many bits required: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_random(1024)
