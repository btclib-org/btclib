#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
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

from typing import List, Sequence, Union

from btclib.alias import Octets
from btclib.exceptions import BTClibValueError

# default hardening symbol among the possible ones: "h", "H", "'"
_HARDENING = "h"


def int_from_index_str(s: str) -> int:

    s.strip().lower()
    hardened = False
    if s[-1] in ("'", "h"):
        s = s[:-1]
        hardened = True

    index = int(s)
    if not 0 <= index < 0x80000000:
        raise BTClibValueError(f"invalid index: {index}")
    return index + (0x80000000 if hardened else 0)


def str_from_index_int(i: int, hardening: str = _HARDENING) -> str:

    if hardening not in ("'", "h", "H"):
        raise BTClibValueError(f"invalid hardening symbol: {hardening}")
    if not 0 <= i <= 0xFFFFFFFF:
        raise BTClibValueError(f"invalid index: {i}")
    if i < 0x80000000:
        return str(i)
    return str(i - 0x80000000) + hardening


def _indexes_from_bip32_path_str(der_path: str, skip_m: bool = True) -> List[int]:

    steps = [x.strip().lower() for x in der_path.split("/")]
    if skip_m and steps[0] == "m":
        steps = steps[1:]

    indexes = [int_from_index_str(s) for s in steps if s != ""]

    if len(indexes) > 255:
        err_msg = f"depth greater than 255: {len(indexes)}"
        raise BTClibValueError(err_msg)
    return indexes


BIP32DerPath = Union[str, Sequence[int], int, bytes]


# FIXME bip32_path should be der_path, BIP32DerPath DerPath, etc
def indexes_from_bip32_path(der_path: BIP32DerPath) -> List[int]:

    if isinstance(der_path, str):
        return _indexes_from_bip32_path_str(der_path)

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

    # Iterable[int]
    return [int(i) for i in der_path]


def _str_from_bip32_path(der_path: BIP32DerPath, hardening: str = _HARDENING) -> str:
    indexes = indexes_from_bip32_path(der_path)
    return "/".join(str_from_index_int(i, hardening) for i in indexes)


def str_from_bip32_path(
    der_path: BIP32DerPath,
    master_fingerprint: Octets = None,
    hardening: str = _HARDENING,
) -> str:
    result = _str_from_bip32_path(der_path, hardening)
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

    return first_element + ("/" + result if result else "")


def bytes_from_bip32_path(der_path: BIP32DerPath) -> bytes:
    indexes = indexes_from_bip32_path(der_path)
    result = [i.to_bytes(4, byteorder="little", signed=False) for i in indexes]
    return b"".join(result)
