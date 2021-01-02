#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Entropy conversion functions.

Depending on the function, input entropy can be expressed
as raw (i.e. binary 0/1 string), bytes, or integer
and their equivalent representations.

Leading zeros in raw or bytes entropy
are never considered redundant padding.

Output entropy is always raw.
"""

import math
import secrets
from hashlib import sha512
from typing import Iterable, List, Optional, Tuple, Union

from btclib.alias import Octets
from btclib.exceptions import BTClibValueError
from btclib.utils import bytes_from_octets

_bits = 128, 160, 192, 224, 256, 512

# the main internal representation of entropy is binary 0/1 string
BinStr = str
# but int or bytes are fine too
Entropy = Union[BinStr, int, bytes]


def wordlist_indexes_from_bin_str_entropy(entropy: BinStr, base: int) -> List[int]:
    """Return the digit indexes for the provided raw entropy.

    Return the list of integer indexes into a digit set,
    usually a language word-list,
    for the provided raw (i.e. binary 0/1 string) entropy;
    leading zeros are not considered redundant padding.
    """

    # entropy = bin_str_entropy_from_entropy(entropy)
    bits = len(entropy)
    int_entropy = int(entropy, 2)
    indexes = []
    while int_entropy:
        int_entropy, index = divmod(int_entropy, base)
        indexes.append(index)

    # do not lose leading zeros entropy
    bits_per_digit = int(math.log(base, 2))
    nwords = math.ceil(bits / bits_per_digit)
    indexes += [0] * (nwords - len(indexes))

    return list(reversed(indexes))


def bin_str_entropy_from_wordlist_indexes(indexes: List[int], base: int) -> BinStr:
    """Return the raw entropy from a list of word-list indexes.

    Return the raw (i.e. binary 0/1 string) entropy
    from the provided list of integer indexes into
    a given language word-list.
    """

    entropy = 0
    for index in indexes:
        entropy = entropy * base + index

    binentropy = bin(entropy)[2:]  # remove '0b'

    # do not lose leading zeros entropy
    bits_per_digit = int(math.log(base, 2))
    bits = len(indexes) * bits_per_digit
    binentropy = binentropy.zfill(bits)

    return binentropy


OneOrMoreInt = Union[int, Iterable[int]]


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

    Input entropy can be expressed as hex-string or bytes;
    it is never padded to satisfy the bit-size requirement.

    If more bits than required are provided,
    the leftmost ones are retained.

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
    n_bits = len(bin_str_entropy)
    if n_bits not in _bits:
        err_msg = f"invalid number of bits: {n_bits} instead of {_bits}"
        raise BTClibValueError(err_msg)
    nbytes = (n_bits + 7) // 8
    int_entropy = int(bin_str_entropy, 2)
    return int_entropy.to_bytes(nbytes, byteorder="big", signed=False)


def bin_str_entropy_from_int(
    int_entropy: Union[int, str], bits: OneOrMoreInt = _bits
) -> BinStr:
    """Return raw entropy from the input integer entropy.

    Input entropy can be expressed as int
    or string starting with "0x"/"0b";
    it is front-padded with zeros digits
    as much as necessary to satisfy the bit-size requirement.

    If more bits than required are provided,
    the leftmost ones are retained.

    Default bit-sizes are 128, 160, 192, 224, 256, or 512 bits.
    """

    if isinstance(int_entropy, str):
        int_entropy = int_entropy.strip().lower()
        if int_entropy[:2] == "0b":
            int_entropy = int(int_entropy, 2)
        elif int_entropy[:2] == "0x":
            int_entropy = int(int_entropy, 16)
        else:
            int_entropy = int(int_entropy)

    if int_entropy < 0:
        raise BTClibValueError(f"Negative entropy: {int_entropy}")

    # if a single int, make it a tuple
    if isinstance(bits, int):
        bits = (bits,)
    # ascending unique sorting of allowed bits
    bits = sorted(set(bits))

    # convert to binary string and remove leading '0b'
    bin_str = bin(int_entropy)[2:]
    n_bits = len(bin_str)
    if n_bits > bits[-1]:
        # only the leftmost bits are retained
        return bin_str[: bits[-1]]

    # pad up to the next allowed bit length
    n_bits = next(v for v in bits if v >= n_bits)
    return bin_str.zfill(n_bits)


def bin_str_entropy_from_str(str_entropy: str, bits: OneOrMoreInt = _bits) -> BinStr:
    """Return raw entropy from the input raw entropy.

    Input entropy must be expressed as raw entropy;
    it is never padded to satisfy the bit-size requirement.

    If more bits than required are provided,
    the leftmost ones are retained.

    Default bit-sizes are 128, 160, 192, 224, 256, or 512 bits.
    """

    int(str_entropy, 2)

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


def collect_rolls(bits: int) -> Tuple[int, List[int]]:

    automate = False
    dice_sides = 0
    _dice_sides = (4, 6, 8, 12, 20, 24, 30, 48, 60, 120)
    while dice_sides not in _dice_sides:
        msg = "dice sides " + f"{_dice_sides}"[:-1]
        msg += "; prefix with 'a' to automate rolls, hit enter for 'a6'): "
        dice_sides_str = input(msg)
        dice_sides_str = dice_sides_str.lower()
        if dice_sides_str in ["", "a"]:
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

    bits_per_roll = math.floor(math.log2(dice_sides))
    base = 2 ** bits_per_roll
    if not automate:
        print(f"rolls are used only if in 1..{base}")

    rolls: List[int] = []
    min_roll_number = math.ceil(bits / bits_per_roll)
    for i in range(min_roll_number):
        roll = 0
        while not 0 < roll <= base:
            try:
                if automate:
                    roll_str = str(1 + secrets.randbelow(dice_sides))
                else:
                    roll_str = input(f"roll #{i+1}/{min_roll_number}: ")
                roll = int(roll_str)
            except ValueError:
                roll = 0
        rolls.append(roll)
    print(f"collected {min_roll_number} usable D{dice_sides} rolls")

    return dice_sides, rolls


def bin_str_entropy_from_rolls(
    bits: int, dice_sides: int, rolls: List[int], shuffle: bool = True
) -> BinStr:
    """Return raw entropy from the input dice rolls.

    Dice rolls are represented by integers in the [1-dice_sides] range;
    there must be enough rolls to satisfy the bit-size requirement.

    Only rolls having value in the [1-base] range are used,
    with base being the highest power of 2 that is lower than the
    dice_sides (e.g. for a traditional D6 dice, only rolls having value
    in [1-4] are used; for a D20 dice, only rolls having value in
    [1-16] are used; etc.). Rolls can also be shuffled.

    If more bits than required are provided,
    the leftmost ones are retained.
    """

    if dice_sides < 2:
        raise BTClibValueError(f"invalid dice base: {dice_sides}, must be >= 2")
    bits_per_roll = math.floor(math.log2(dice_sides))
    # used base
    base = 2 ** bits_per_roll

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
        msg = f"Too few rolls in the usable [1-{base}] range"
        msg += f", missing {min_roll_number} rolls"
        raise BTClibValueError(msg)

    return bin_str_entropy_from_int(i, bits)


def bin_str_entropy_from_random(
    bits: int, entropy: Optional[BinStr] = None, to_be_hashed: bool = True
) -> BinStr:
    """Return CSPRNG raw entropy XOR-ed with input raw entropy.

    The input raw entropy is used as initialization value;
    if not provided, then entropy is generated with the system
    cryptographically strong pseudo-random number generator (CSPRNG).

    Then, this entropy is:

    - XOR-ed with CSPRNG system entropy
    - possibly hashed (if requested)
    """

    if entropy is None or entropy == "":
        i = secrets.randbits(bits)
    else:
        if len(entropy) > bits:
            # only the leftmost bits are retained
            entropy = entropy[:bits]
        i = int(entropy, 2)

    # XOR the current entropy with CSPRNG system entropy
    i ^= secrets.randbits(bits)

    # hash the current entropy
    if to_be_hashed:
        hf = sha512()
        max_bits = hf.digest_size * 8
        if bits > max_bits:
            err_msg = f"Too many bits required: {bits}, max is {max_bits}"
            raise BTClibValueError(err_msg)
        n_bytes = math.ceil(i.bit_length() / 8)
        h512 = sha512(i.to_bytes(n_bytes, byteorder="big", signed=False)).digest()
        i = int.from_bytes(h512, byteorder="big", signed=False)

    return bin_str_entropy_from_int(i, bits)
