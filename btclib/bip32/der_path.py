#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""BIP32 derivation path and key origin.

A BIP 32 derivation path can be represented as:

- "m/44h/0'/1H/0/10" or "44h/0'/1H/0/10" string
- sequence of integer indexes (even a single int)
- bytes (multiples of 4-bytes index)
"""

from __future__ import annotations

from collections.abc import Sequence

from btclib.alias import Octets
from btclib.exceptions import BTClibValueError

# default hardening symbol among the possible ones: "h", "H", "'"
_HARDENING = "h"

# the offset a hardened index carries: BIP32 splits the 2**32 indexes in
# half at 2**31, so an index is hardened when it reaches this value, and
# what a path spells before the hardening symbol is what is left under it.
# The symbol and the offset are one fact in its two spellings, which is
# why they sit together -- and why bip32, mnemonic.electrum and bip44
# import this rather than write the literal again: a hardened test is the
# same test wherever it appears, and a literal repeated is a set of places
# to read before believing they agree
_HARDENED_OFFSET = 0x80000000


def int_from_index_str(s: str) -> int:
    """Return one path step as its index: "0h" is 0x80000000.

    Any of the three hardening symbols is read; an index at or above
    the hardened offset must be spelled with one, not as the number.
    """
    s.strip().lower()
    hardened = False
    if s[-1] in ("'", "h"):
        s = s[:-1]
        hardened = True

    index = int(s)
    if not 0 <= index < _HARDENED_OFFSET:
        raise BTClibValueError(f"invalid index: {index}")
    return index + (_HARDENED_OFFSET if hardened else 0)


def str_from_index_int(i: int, hardening: str = _HARDENING) -> str:
    """Return one index as a path step, the chosen symbol for hardened."""
    if hardening not in ("'", "h", "H"):
        raise BTClibValueError(f"invalid hardening symbol: {hardening}")
    if not 0 <= i <= 0xFFFFFFFF:
        raise BTClibValueError(f"invalid index: {i}")
    if i < _HARDENED_OFFSET:
        return str(i)
    return str(i - _HARDENED_OFFSET) + hardening


def _indexes_from_der_path_str(der_path: str, skip_m: bool = True) -> list[int]:
    steps = [x.strip().lower() for x in der_path.split("/")]
    if skip_m and steps[0] == "m":
        steps = steps[1:]

    indexes = [int_from_index_str(s) for s in steps if s != ""]

    if len(indexes) > 255:
        err_msg = f"depth greater than 255: {len(indexes)}"
        raise BTClibValueError(err_msg)
    return indexes


DerPath = str | Sequence[int] | int | bytes


def indexes_from_der_path(der_path: DerPath) -> list[int]:
    """Return the path as a list of indexes, whatever spelling it came in.

    The DerPath spellings of the module docstring are all read: a
    string with or without the leading m, a single int, the 4-byte
    little-endian concatenation, or any iterable of ints.
    """
    if isinstance(der_path, str):
        return _indexes_from_der_path_str(der_path)

    if isinstance(der_path, int):
        return [der_path]

    if isinstance(der_path, bytes):
        if len(der_path) % 4 != 0:
            err_msg = f"index are not a multiple of 4-bytes: {len(der_path)}"
            raise BTClibValueError(err_msg)
        return [
            int.from_bytes(der_path[n : n + 4], byteorder="little", signed=False)
            for n in range(0, len(der_path), 4)
        ]

    # an iterable of int
    return [int(i) for i in der_path]


def _str_from_der_path(der_path: DerPath, hardening: str = _HARDENING) -> str:
    indexes = indexes_from_der_path(der_path)
    return "/".join(str_from_index_int(i, hardening) for i in indexes)


def str_from_der_path(
    der_path: DerPath,
    master_fingerprint: Octets | None = None,
    hardening: str = _HARDENING,
) -> str:
    """Return the path as text, led by m or by the master fingerprint.

    With a fingerprint this is the key-origin spelling a descriptor
    brackets; without, the m/ path BIP32 writes.
    """
    result = _str_from_der_path(der_path, hardening)
    if master_fingerprint:
        if isinstance(master_fingerprint, str):
            first_element = master_fingerprint.strip()
        else:
            first_element = master_fingerprint.hex()
        if len(first_element) != 8:
            err_msg = f"invalid master fingerprint length: {first_element}"
            raise BTClibValueError(err_msg)
    else:
        first_element = "m"

    return first_element + (f"/{result}" if result else "")


def bytes_from_der_path(der_path: DerPath) -> bytes:
    """Return the path as bytes: each index in 4 bytes, little-endian."""
    indexes = indexes_from_der_path(der_path)
    result = [i.to_bytes(4, byteorder="little", signed=False) for i in indexes]
    return b"".join(result)
