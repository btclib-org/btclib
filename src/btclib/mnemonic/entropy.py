# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Entropy conversion functions.

Depending on the function, input entropy can be expressed as raw (i.e.
binary 0/1 string), bytes, or integer and their equivalent
representations.

Leading zeros in raw or bytes entropy are never considered redundant
padding.

Output entropy is always raw.
"""

from __future__ import annotations

import math
import secrets
from collections.abc import Iterable, Sequence
from hashlib import sha512

from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import assert_type, bytes_from_octets, is_integer

__all__ = [
    "BinStr",
    "Entropy",
    "OneOrMoreInt",
    "bin_str_entropy_from_bytes",
    "bin_str_entropy_from_entropy",
    "bin_str_entropy_from_int",
    "bin_str_entropy_from_random",
    "bin_str_entropy_from_rolls",
    "bin_str_entropy_from_str",
    "bin_str_entropy_from_wordlist_indexes",
    "bytes_entropy_from_str",
    "collect_rolls",
    "wordlist_indexes_from_bin_str_entropy",
]

_bits = 128, 160, 192, 224, 256, 512

# the main internal representation of entropy is binary 0/1 string
BinStr = str
# but int or bytes are fine too
Entropy = BinStr | int | bytes


def _bits_per_digit(base: int) -> int:
    """Return the whole bits one digit of that base holds, floor(log2).

    In integer arithmetic, where `math.floor(math.log2(base))` is the
    obvious spelling and is the one that is wrong at the edge: the float
    stops being exact at 2**49 - 1, where `log2` rounds up to 49 and the
    caller then reads one bit more per digit than the base holds -- a
    roll a die does not have, counted as usable.

        math.floor(math.log2(2**49 - 1))  # 49
        (2**49 - 1).bit_length() - 1      # 48

    `bin_str_entropy_from_wordlist_indexes` computes its own width the
    same integer way, and `bip85.rolls_from_root_key` computes the
    complementary ceiling as `(sides - 1).bit_length()`.
    """
    return base.bit_length() - 1


def _int_from_bin_str(entropy: BinStr) -> int:
    """Return the number a binary 0/1 string spells, or refuse the string.

    `int(x, 2)` answers what is no binary string with the bare
    ValueError "invalid literal for int() with base 2", which names
    neither the parameter nor this library, and what is no string at all
    with a bare TypeError.

    Neither message carries the value, and neither does this one: raw
    entropy is seed material, and every error in this module says a
    length or a count and never the digits (issue #137).
    """
    try:
        return int(entropy, 2)
    except TypeError as e:
        err_msg = f"invalid entropy type: {type(entropy).__name__}"
        raise BTClibTypeError(err_msg) from e
    except ValueError as e:
        raise BTClibValueError("invalid entropy: not a binary 0/1 string") from e


def wordlist_indexes_from_bin_str_entropy(entropy: BinStr, base: int) -> list[int]:
    """Return the digit indexes for the provided raw entropy.

    Return the list of integer indexes into a digit set, usually a
    language word-list, for the provided raw (i.e. binary 0/1 string)
    entropy; leading zeros are not considered redundant padding.
    """
    bits = len(entropy)
    int_entropy = _int_from_bin_str(entropy)
    indexes = []
    while int_entropy:
        int_entropy, index = divmod(int_entropy, base)
        indexes.append(index)

    # do not lose leading zeros entropy
    bits_per_digit = _bits_per_digit(base)
    nwords = math.ceil(bits / bits_per_digit)
    indexes += [0] * (nwords - len(indexes))

    return list(reversed(indexes))


def bin_str_entropy_from_wordlist_indexes(indexes: Sequence[int], base: int) -> BinStr:
    """Return the raw entropy from a list of word-list indexes.

    Return the raw (i.e. binary 0/1 string) entropy from the provided
    list of integer indexes into a given language word-list.

    An index the word list has no word for is refused rather than
    carried: base-`base` arithmetic accepts any number as a digit, so
    2048 in a 2048-word list is not an error but a carry into the digit
    above it -- entropy nothing spells, out of a function whose whole
    job is to say what a mnemonic means.
    """
    entropy = 0
    for index in indexes:
        if not is_integer(index):
            raise BTClibTypeError(f"invalid index type: {type(index).__name__}")
        if not 0 <= index < base:
            raise BTClibValueError(f"invalid index: {index}, not in [0, {base})")
        entropy = entropy * base + index

    binentropy = f"{entropy:b}"

    # do not lose leading zeros entropy. The width is that of the largest
    # value the digits can spell, in integer arithmetic: for a base that
    # is a power of two that is `_bits_per_digit` times the digit count,
    # and for electrum's 1626-word Portuguese -- 10.667 bits a word -- it
    # is the 139 bits thirteen words hold rather than the 130 that
    # rounding down claims
    bits = (base ** len(indexes) - 1).bit_length()
    return binentropy.zfill(bits)


OneOrMoreInt = int | Iterable[int]


def bin_str_entropy_from_entropy(entr: Entropy, bits: OneOrMoreInt = _bits) -> BinStr:
    """Return raw entropy from the input entropy.

    Input entropy can be expressed as:

    - raw (i.e. binary 0/1 string) entropy
    - bytes (no hex-string, as they would conflict with
      raw entropy representation)
    - integer (int, no string starting with "0b"/"0x")

    In the case of raw entropy and bytes,
    entropy is never padded to satisfy the bit-size requirement;
    instead,
    integer entropy is front-padded with zeros digits
    as much as necessary to satisfy the bit-size requirement.

    In all cases if more bits than required are provided,
    the leftmost ones are retained.

    Default bit-sizes are 128, 160, 192, 224, 256, or 512 bits.
    """
    if isinstance(entr, str):
        return bin_str_entropy_from_str(entr, bits)
    if isinstance(entr, int):
        return bin_str_entropy_from_int(entr, bits)
    # must be bytes-like
    return bin_str_entropy_from_bytes(entr, bits)


def bin_str_entropy_from_bytes(
    bytes_entropy: Octets, bits: OneOrMoreInt = _bits
) -> BinStr:
    """Return raw entropy from the input Octets entropy.

    Input entropy can be expressed as hex-string or bytes; it is never
    padded to satisfy the bit-size requirement.

    If more bits than required are provided, the leftmost ones are
    retained.

    Default bit-sizes are 128, 160, 192, 224, 256, or 512 bits.
    """
    bytes_entropy = bytes_from_octets(bytes_entropy)

    # if a single int, make it a tuple
    if isinstance(bits, int):
        bits = (bits,)
    # ascending unique sorting of allowed bits
    bits = sorted(set(bits))

    n_bits = len(bytes_entropy) * 8
    n_bits = min(n_bits, bits[-1])

    if n_bits not in bits:
        err_msg = f"invalid number of bits: {n_bits} instead of {bits}"
        raise BTClibValueError(err_msg)

    int_entropy = int.from_bytes(bytes_entropy, byteorder="big", signed=False)
    # only the leftmost bits will be retained
    return bin_str_entropy_from_int(int_entropy, n_bits)


def bytes_entropy_from_str(bin_str_entropy: BinStr) -> bytes:
    """Return the binary-string entropy as bytes, left-padded to whole ones."""
    n_bits = len(bin_str_entropy)
    if n_bits not in _bits:
        err_msg = f"invalid number of bits: {n_bits} instead of {_bits}"
        raise BTClibValueError(err_msg)
    nbytes = (n_bits + 7) // 8
    int_entropy = _int_from_bin_str(bin_str_entropy)
    return int_entropy.to_bytes(nbytes, byteorder="big", signed=False)


def bin_str_entropy_from_int(
    int_entropy: int | str, bits: OneOrMoreInt = _bits
) -> BinStr:
    """Return raw entropy from the input integer entropy.

    Input entropy can be expressed as int or string starting with
    "0x"/"0b"; it is front-padded with zeros digits as much as necessary
    to satisfy the bit-size requirement.

    If more bits than required are provided, the leftmost ones are
    retained.

    Default bit-sizes are 128, 160, 192, 224, 256, or 512 bits.
    """
    if isinstance(int_entropy, str):
        int_entropy = int_entropy.strip().lower()
        if int_entropy[:2] == "0b":
            int_entropy = _int_from_bin_str(int_entropy)
        else:
            # the two `int` readings left, and the same bare ValueError
            # out of both: "invalid literal for int() with base 16",
            # naming neither the parameter nor this library -- and
            # carrying the digits, which the message here does not
            base = 16 if int_entropy[:2] == "0x" else 10
            try:
                int_entropy = int(int_entropy, base)
            except ValueError as e:
                err_msg = f"invalid entropy: not a base {base} number"
                raise BTClibValueError(err_msg) from e

    if int_entropy < 0:
        raise BTClibValueError(f"negative entropy: {int_entropy}")

    # if a single int, make it a tuple
    if isinstance(bits, int):
        bits = (bits,)
    # ascending unique sorting of allowed bits
    bits = sorted(set(bits))

    # convert to binary string
    bin_str = f"{int_entropy:b}"
    n_bits = len(bin_str)
    if n_bits > bits[-1]:
        # only the leftmost bits are retained
        return bin_str[: bits[-1]]

    # pad up to the next allowed bit length
    n_bits = next(v for v in bits if v >= n_bits)
    return bin_str.zfill(n_bits)


def bin_str_entropy_from_str(str_entropy: str, bits: OneOrMoreInt = _bits) -> BinStr:
    """Return raw entropy from the input raw entropy.

    Input entropy must be expressed as raw entropy; it is never padded
    to satisfy the bit-size requirement.

    If more bits than required are provided, the leftmost ones are
    retained.

    Default bit-sizes are 128, 160, 192, 224, 256, or 512 bits.
    """
    _int_from_bin_str(str_entropy)

    # if a single int, make it a tuple
    if isinstance(bits, int):
        bits = (bits,)
    # ascending unique sorting of allowed bits
    bits = sorted(set(bits))

    n_bits = len(str_entropy)
    if n_bits > bits[-1]:
        # only the leftmost bits are retained
        return str_entropy[: bits[-1]]
    if n_bits not in bits:
        err_msg = f"invalid number of bits: {n_bits} instead of {bits}"
        raise BTClibValueError(err_msg)
    return str_entropy


def collect_rolls(bits: int) -> tuple[int, list[int]]:
    """Prompt for dice rolls until they carry `bits` of entropy.

    Interactive on purpose, input() and print() being its interface:
    the caller gets (dice sides, the rolls that count). Rolls beyond
    a power of two are discarded and asked again, carrying no whole
    bits.

    The automated mode rolls with `secrets`, and must keep doing so.
    `bip85.rolls_from_root_key` derives rolls as well, and derives them
    reproducibly from a root key -- which is what the entropy of a seed
    that does not exist yet must never be.
    """
    automate = False
    dice_sides = 0
    valid_dice_sides = (4, 6, 8, 12, 20, 24, 30, 48, 60, 120)
    while dice_sides not in valid_dice_sides:
        msg = f"dice sides {f'{valid_dice_sides}'[:-1]}"
        msg += "; prefix with 'a' to automate rolls, hit enter for 'a6'): "
        dice_sides_str = input(msg)
        dice_sides_str = dice_sides_str.lower()
        if dice_sides_str in {"", "a"}:
            automate = True
            dice_sides = 6
        else:
            automate = False
            if dice_sides_str.startswith("a"):
                automate = True
                dice_sides_str = dice_sides_str[1:]
            try:
                dice_sides = int(dice_sides_str)
            except ValueError:
                dice_sides = 0

    bits_per_roll = _bits_per_digit(dice_sides)
    base = 2**bits_per_roll
    if not automate:
        print(f"rolls are used only if in 1..{base}")

    rolls: list[int] = []
    min_roll_number = math.ceil(bits / bits_per_roll)
    for i in range(min_roll_number):
        roll = 0
        while not 0 < roll <= base:
            try:
                if automate:
                    roll_str = str(1 + secrets.randbelow(dice_sides))
                else:
                    roll_str = input(f"roll #{i + 1}/{min_roll_number}: ")
                roll = int(roll_str)
            except ValueError:
                roll = 0
        rolls.append(roll)
    print(f"collected {min_roll_number} usable D{dice_sides} rolls")

    return dice_sides, rolls


def bin_str_entropy_from_rolls(
    bits: int, dice_sides: int, rolls: list[int], shuffle: bool = True
) -> BinStr:
    """Return raw entropy from the input dice rolls.

    Dice rolls are represented by integers in the [1-dice_sides] range;
    there must be enough rolls to satisfy the bit-size requirement.

    Only rolls having value in the [1-base] range are used, with base
    being the highest power of 2 that is lower than the dice_sides (e.g.
    for a traditional D6 dice, only rolls having value in [1-4] are
    used; for a D20 dice, only rolls having value in [1-16] are used;
    etc.). Rolls can also be shuffled.

    If more bits than required are provided, the leftmost ones are
    retained.

    This reads dice into entropy; `bip85.rolls_from_root_key` writes
    rolls out of entropy, which is the opposite direction and not an
    inverse. It numbers a die's faces from zero and draws again for a
    trial the die has no face for, where this reads them from one and
    keeps only the rolls below the largest power of two -- so rolls
    carried from there to a wallet that reads dice are shifted by one,
    by whoever carries them.
    """
    # `_bits_per_digit` below takes `base.bit_length()`, which a float
    # has no method named, so a caller passing 6.0 would hear a bare
    # AttributeError rather than this module's own message
    if not is_integer(dice_sides):
        err_msg = f"invalid dice base type: {type(dice_sides).__name__}"
        raise BTClibTypeError(err_msg)
    assert_type(shuffle, bool, "shuffle")
    if dice_sides < 2:
        raise BTClibValueError(f"invalid dice base: {dice_sides}, must be >= 2")
    bits_per_roll = _bits_per_digit(dice_sides)
    # used base
    base = 2**bits_per_roll

    if shuffle:
        secrets.SystemRandom().shuffle(rolls)

    min_roll_number = math.ceil(bits / bits_per_roll)
    i = 0
    for roll in rolls:
        # reject invalid rolls not in [1-dice_sides]
        if not 0 < roll <= dice_sides:
            msg = f"invalid roll: {roll} is not in [1-{dice_sides}]"
            raise BTClibValueError(msg)

        # collect only usable rolls in [1-base]
        if 0 < roll <= base:
            i *= base
            i += roll - 1
            min_roll_number -= 1
    if min_roll_number > 0:
        msg = f"too few rolls in the usable [1-{base}] range"
        msg += f", missing {min_roll_number} rolls"
        raise BTClibValueError(msg)

    return bin_str_entropy_from_int(i, bits)


def bin_str_entropy_from_random(
    bits: int, entropy: BinStr | None = None, to_be_hashed: bool = True
) -> BinStr:
    """Return CSPRNG raw entropy XOR-ed with input raw entropy.

    The input raw entropy is used as initialization value;
    if not provided, then entropy is generated with the system
    cryptographically strong pseudo-random number generator (CSPRNG).

    Then, this entropy is:

    - XOR-ed with CSPRNG system entropy
    - possibly hashed (if requested)
    """
    assert_type(to_be_hashed, bool, "to_be_hashed")

    if entropy is None or not entropy:
        i = secrets.randbits(bits)
    else:
        if len(entropy) > bits:
            # only the leftmost bits are retained
            entropy = entropy[:bits]
        i = _int_from_bin_str(entropy)

    # XOR the current entropy with CSPRNG system entropy
    i ^= secrets.randbits(bits)

    # hash the current entropy
    if to_be_hashed:
        hf = sha512()
        max_bits = hf.digest_size * 8
        if bits > max_bits:
            err_msg = f"too many bits required: {bits}, max is {max_bits}"
            raise BTClibValueError(err_msg)
        n_bytes = math.ceil(i.bit_length() / 8)
        h512 = sha512(i.to_bytes(n_bytes, byteorder="big", signed=False)).digest()
        i = int.from_bytes(h512, byteorder="big", signed=False)

    return bin_str_entropy_from_int(i, bits)
