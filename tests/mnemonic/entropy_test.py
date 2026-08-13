# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.entropy` module."""

import math
import secrets
from io import StringIO

import pytest

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.mnemonic import (
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
from btclib.mnemonic.entropy import _bits, _bits_per_digit


def test_indexes() -> None:
    """Round-trip wordlist indexes through the binary string entropy."""
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
    for expected in test_vector:
        entropy = bin_str_entropy_from_wordlist_indexes(expected, 2048)
        indexes = wordlist_indexes_from_bin_str_entropy(entropy, 2048)
        assert indexes == expected


def test_indexes_round_trip_a_base_that_is_not_a_power_of_two() -> None:
    """2048 is a power of two, where `+`, `|` and `^` all agree; 1626 is not.

    Electrum's Portuguese wordlist is the base the module's own comment
    names: 13 words hold 139 bits, not the 130 that `bits_per_digit *
    nwords` would claim, and only a base like this -- not 2048 -- makes
    `entropy * base + index` differ from the same expression with `|` or
    `^` for a generic index. The value itself, not the decoder's own
    leading-zero padding for a base that is not a power of two, is what
    ties the length to the accumulation.
    """
    indexes = list(range(1, 14))
    value = 0
    for index in indexes:
        value = value * 1626 + index
    entropy = bin_str_entropy_from_wordlist_indexes(indexes, 1626)
    assert len(entropy) == 139
    assert int(entropy, 2) == value


def test_conversions() -> None:
    """Round-trip entropy across its str, int and bytes forms."""
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

    # a decimal string starting with "0" and a digit below "b": "01" sorts
    # below "0b", so `== "0b"` weakened to `<=` reads a plain decimal as
    # binary too -- "010" is 10 in decimal and 2 read as binary
    assert bin_str_entropy_from_int("010", 4) == "1010"
    # neither prefixed nor a valid plain decimal: `int("ab")` raises, so
    # `== "0x"` weakened to `>=` is what a string of only letters tells
    # apart -- "ab" sorts above "0x" and parses as hex (171) where the
    # unweakened check falls through to `int("ab")` and raises instead
    with pytest.raises(ValueError, match="invalid literal for int"):
        bin_str_entropy_from_int("ab", 8)

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
    assert bin_str_entropy_from_str(f"0{raw2}") == raw
    raw2 = bin_str_entropy_from_str(raw, 128)
    assert len(raw2) == 128
    assert raw2 == raw[:128]


def test_exceptions() -> None:
    """Refuse invalid bit counts, negative entropy, non-entropy types."""
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

    err_msg = "negative entropy: "
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
        bin_str_entropy_from_entropy(())  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        bin_str_entropy_from_int("not an int")

    with pytest.raises(TypeError):
        bin_str_entropy_from_str(3)  # type: ignore[arg-type]

    err_msg = "invalid number of bits: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy = "01" * 65  # 130 bits
        bytes_entropy_from_str(bin_str_entropy)


# 2 input failures, then automatic rolls with default D6
inputs = [StringIO("3\npluto\na\n")]
# D120, then 43 automatic rolls
inputs.append(StringIO("a120\n"))
# D120, one input failure, then 43 (implausible but valid) non-automatic rolls
inputs.append(StringIO("120\npluto\n" + "64\n" * 43))


def test_collect_rolls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Check the interactive roll collection over three stdin scripts."""
    bits = 256
    for i, sides in enumerate((6, 120, 120)):
        monkeypatch.setattr("sys.stdin", inputs[i])
        dice_sides, dice_rolls = collect_rolls(bits)
        assert dice_sides == sides
        bits_per_roll = math.floor(math.log2(sides))
        base = 2**bits_per_roll
        for roll in dice_rolls:
            assert 0 < roll <= base
        min_roll_number = math.ceil(bits / bits_per_roll)
        assert len(dice_rolls) == min_roll_number

        # the automated vector's 43 rolls, not the range check above, is
        # what tells `1 + secrets.randbelow(dice_sides)` from an operator
        # collapsing it to a constant (`**` makes every roll 1): the range
        # check alone cannot see that every roll is the same one value
        if i == 1:
            assert len(set(dice_rolls)) > 1


def test_collect_rolls_refuses_a_negative_or_a_short_roll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A negative roll is refused, and a roll under base is not base itself.

    D30's base is 16 (2**4, the highest power of 2 below 30), so 5 is a
    usable roll and not the boundary -- `0 < roll <= base` weakened to
    `0 != roll <= base` would accept `-1` (nonzero, and `-1 <= 16`), and
    weakened to `0 < roll == base` would refuse every usable roll that is
    not 16 itself, which the D120 vectors above never exercise: every one
    of their manual rolls is 64, D120's own base.
    """
    monkeypatch.setattr("sys.stdin", StringIO("30\n-1\n0\n5\n"))
    dice_sides, dice_rolls = collect_rolls(4)
    assert dice_sides == 30
    assert dice_rolls == [5]


@pytest.mark.parametrize("sides", [8, 48])
def test_collect_rolls_accepts_dice_sides_this_module_lists(
    sides: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """8 and 48 are two of `valid_dice_sides` no other test asks for.

    A `NumberReplacer` mutant of either entry survives on the D6/D120
    vectors above alone: nothing else in this suite ever offers 8 or 48
    for the `while dice_sides not in valid_dice_sides` loop to accept.
    """
    monkeypatch.setattr("sys.stdin", StringIO(f"{sides}\n1\n"))
    dice_sides, dice_rolls = collect_rolls(1)
    assert dice_sides == sides
    assert dice_rolls == [1]


def test_collect_rolls_prompt_names_the_roll_and_the_total(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The prompt counts from 1, and nothing but a human reads it.

    `i + 1` is arithmetic no assertion in this file reaches through
    `collect_rolls`' return value -- the prompt is printed and discarded
    by `input()`, not part of what the function hands back -- so it
    survived mutated eight different ways until captured here.
    """
    monkeypatch.setattr("sys.stdin", StringIO("4\n1\n1\n"))
    collect_rolls(4)
    out = capsys.readouterr().out
    assert "roll #1/2: " in out
    assert "roll #2/2: " in out


def test_collect_rolls_prompt_lists_the_dice_sides(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The dice-sides prompt names every side this module accepts.

    `f'{valid_dice_sides}'[:-1]` drops the tuple's closing paren so the
    line can add the automation note before it; `[:-0]` is `[:0]`, empty,
    and nothing but this test reads what `input()` printed and threw away.
    """
    monkeypatch.setattr("sys.stdin", StringIO("4\n1\n"))
    collect_rolls(2)
    out = capsys.readouterr().out
    assert "dice sides (4, 6, 8, 12, 20, 24, 30, 48, 60, 120" in out


def test_bin_str_entropy_from_rolls() -> None:
    """Check the roll-to-bits conversion, its bounds and its refusals."""
    bits = 256
    dice_base = 20
    bits_per_roll = math.floor(math.log2(dice_base))
    base = 2**bits_per_roll
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
    err_msg = "too few rolls in the usable "  # [1-16] range, missing 2 rolls
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_rolls(bits, dice_base, rolls)

    rolls = [secrets.randbelow(base) + 1 for _ in range(roll_number)]
    rolls[1] = base + 1
    err_msg = "too few rolls in the usable "  # [1-16] range, missing 1 rolls
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

    # the boundary itself, not 1: `< 2` weakened to `<= 2` still refuses
    # 1 and would also refuse 2, the smallest base the function accepts
    assert bin_str_entropy_from_rolls(4, 2, [1, 2, 1, 2], shuffle=False) == "0101"


@pytest.mark.parametrize("base", [2, 3, 6, 20, 1024, 1626, 2048, 2**48, 2**49])
def test_the_bits_a_digit_holds_are_counted_exactly(base: int) -> None:
    """The integer floor(log2), against the float it replaces.

    Both spellings agree over every base a word-list or a die plausibly
    has, which is what makes the difference easy to miss; the case below
    is where they part.
    """
    assert _bits_per_digit(base) == math.floor(math.log2(base))


def test_a_die_of_2_49_minus_one_faces_does_not_gain_a_bit() -> None:
    """Where `math.floor(math.log2(x))` stops being exact.

    At 2**49 - 1 the float rounds up to 49, so the usable range would
    become [1-2**49] -- larger than the die -- and a roll the die does
    not have would be counted as carrying 49 bits. The integer spelling
    answers 48, so the same rolls are the shortfall they are.
    """
    sides = 2**49 - 1
    assert math.floor(math.log2(sides)) == 49
    assert _bits_per_digit(sides) == 48

    base = 2**48
    rolls = [base + 1] * math.ceil(128 / 48)
    err_msg = "too few rolls in the usable "
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_rolls(128, sides, rolls)

    usable = [base] * math.ceil(128 / 48)
    assert len(bin_str_entropy_from_rolls(128, sides, usable, shuffle=False)) == 128


def test_a_dice_base_that_is_not_an_integer() -> None:
    """A float used to work by accident, `math.log2` taking one.

    `bit_length` does not, so the refusal is explicit rather than an
    AttributeError from inside the bit accounting.
    """
    err_msg = "invalid dice base type: float"
    with pytest.raises(BTClibTypeError, match=err_msg):
        bin_str_entropy_from_rolls(4, 2.0, [1, 2, 1, 2])  # type: ignore[arg-type]

    # a bool is not another spelling of the number one either
    err_msg = "invalid dice base type: bool"
    with pytest.raises(BTClibTypeError, match=err_msg):
        # no `type: ignore` here, and that is the point: `bool` is an
        # `int` to the type checker, so only this refusal catches it
        bin_str_entropy_from_rolls(4, True, [1, 2, 1, 2])


def test_bin_str_entropy_from_random() -> None:
    """Check the random entropy source, its mixing and its bit cap."""
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
    err_msg = "too many bits required: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_random(1024)

    # the cap itself: sha512's 512-bit digest, one bit over is refused and
    # the bit at it is not -- 1024 above is well past either side of a
    # cap computed one digest_size wider than it should be
    assert len(bin_str_entropy_from_random(512)) == 512
    with pytest.raises(BTClibValueError, match=err_msg):
        bin_str_entropy_from_random(513)
