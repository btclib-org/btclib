#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
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

from .alias import BinStr, Entropy, Octets
from .utils import bytes_from_octets

_bits = 128, 160, 192, 224, 256, 512
_dice_sides = (4, 6, 8, 12, 20, 24, 30, 48, 60, 120)


def _indexes_from_entropy(entropy: BinStr, base: int) -> List[int]:
    """Return the digit indexes for the provided raw entropy.

    Return the list of integer indexes into a digit set,
    usually a language word-list,
    for the provided raw (i.e. binary 0/1 string) entropy;
    leading zeros are not considered redundant padding.
    """

    bits = len(entropy)
    int_entropy = int(entropy, 2)
    indexes = []
    while int_entropy:
        int_entropy, index = divmod(int_entropy, base)
        indexes.append(index)

    # do not lose leading zeros entropy
    bits_per_digit = int(math.log(base, 2))
    nwords = math.ceil(bits / bits_per_digit)
    while len(indexes) < nwords:
        indexes.append(0)

    return list(reversed(indexes))


def _entropy_from_indexes(indexes: List[int], base: int) -> BinStr:
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


def binstr_from_entropy(entr: Entropy, bits: OneOrMoreInt = _bits) -> BinStr:
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
        return binstr_from_binstr(entr, bits)
    elif isinstance(entr, bytes):
        return binstr_from_bytes(entr, bits)
    elif isinstance(entr, int):
        return binstr_from_int(entr, bits)

    m = "Entropy must be raw binary 0/1 string, bytes, or int; "
    m += f"not '{type(entr).__name__}'"
    raise TypeError(m)


def binstr_from_bytes(bytes_entropy: Octets, bits: OneOrMoreInt = _bits) -> BinStr:
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
    if n_bits > bits[-1]:
        n_bits = bits[-1]

    if n_bits not in bits:
        m = f"Wrong number of bits: {n_bits} instead of {bits}"
        raise ValueError(m)

    int_entropy = int.from_bytes(bytes_entropy, "big")
    # only the leftmost bits will be retained
    return binstr_from_int(int_entropy, n_bits)


def binstr_from_int(int_entropy: Union[int, str], bits: OneOrMoreInt = _bits) -> BinStr:
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

    if not isinstance(int_entropy, int):
        m = "Entropy must be an int, not "
        m += f"{type(int_entropy).__name__}"
        raise TypeError(m)

    if int_entropy < 0:
        raise ValueError(f"Negative entropy: {int_entropy}")

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
    n_bits = next(v for i, v in enumerate(bits) if v >= n_bits)
    return bin_str.zfill(n_bits)


def binstr_from_binstr(str_entropy: str, bits: OneOrMoreInt = _bits) -> BinStr:
    """Return raw entropy from the input raw entropy.

    Input entropy must be expressed as raw entropy;
    it is never padded to satisfy the bit-size requirement.

    If more bits than required are provided,
    the leftmost ones are retained.

    Default bit-sizes are 128, 160, 192, 224, 256, or 512 bits.
    """

    if not isinstance(str_entropy, str):
        m = "Entropy must be a str, not "
        m += f"{type(str_entropy).__name__}"
        raise TypeError(m)
        # check if it is a valid binary string

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
        m = f"Wrong number of bits: {n_bits} instead of {bits}"
        raise ValueError(m)
    return str_entropy


def collect_rolls(bits: int) -> Tuple[int, List[int]]:

    dice_sides = 0
    while dice_sides not in _dice_sides:
        automate = False
        msg = f"{_dice_sides}"
        msg = "dice sides " + msg[:-1]
        msg += "; prefix with 'a' to automate rolls, hit enter for 'a6'): "
        dice_sides_str = input(msg)
        dice_sides_str = dice_sides_str.lower()
        if dice_sides_str in ["", "a"]:
            automate = True
            dice_sides = 6
        else:
            if dice_sides_str.startswith("a"):
                automate = True
                dice_sides_str = dice_sides_str[1:]
            try:
                dice_sides = int(dice_sides_str)
            except Exception:
                dice_sides = 0

    bits_per_roll = math.floor(math.log2(dice_sides))
    base = 2 ** bits_per_roll
    if not automate:
        print(f"rolls are used only if in 1..{base}")

    rolls: List[int] = []
    min_roll_number = math.ceil(bits / bits_per_roll)
    for i in range(min_roll_number):
        x = 0
        while x < 1 or x > base:
            try:
                if automate:
                    x_str = str(1 + secrets.randbelow(dice_sides))
                else:
                    x_str = input(f"roll #{i+1}/{min_roll_number}: ")
                x = int(x_str)
            except Exception:
                x = 0
        rolls.append(x)
    print(f"collected {min_roll_number} usable D{dice_sides} rolls")

    return dice_sides, rolls


def binstr_from_rolls(
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
        raise ValueError(f"invalid dice base: {dice_sides}, must be >= 2")
    bits_per_roll = math.floor(math.log2(dice_sides))
    # used base
    base = 2 ** bits_per_roll

    if shuffle:
        secrets.SystemRandom().shuffle(rolls)

    min_roll_number = math.ceil(bits / bits_per_roll)
    i = 0
    for r in rolls:
        # collect only usable rolls in [1-base)]
        if 0 < r and r <= base:
            i *= base
            i += r - 1
            min_roll_number -= 1
        # reject invalid rolls not in [1-dice_sides)]
        elif r < 1 or r > dice_sides:
            msg = f"invalid roll: {r} is not in [1-{dice_sides}]"
            raise ValueError(msg)
    if min_roll_number > 0:
        msg = f"Too few rolls in the usable [1-{base}] range, missing {min_roll_number} rolls"
        raise ValueError(msg)

    return binstr_from_int(i, bits)


def randbinstr(
    bits: int, entropy: Optional[BinStr] = None, hash: bool = True
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
    if hash:
        hf = sha512()
        max_bits = hf.digest_size * 8
        if bits > max_bits:
            m = f"Too many bits required: {bits}, max is {max_bits}"
            raise ValueError(m)
        n_bytes = math.ceil(i.bit_length() / 8)
        h512 = sha512(i.to_bytes(n_bytes, byteorder="big")).digest()
        i = int.from_bytes(h512, byteorder="big")

    return binstr_from_int(i, bits)
