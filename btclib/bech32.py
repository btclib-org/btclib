#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Bech32(m) encoding and decoding functions.

**The codec.** This module is bech32 and bech32m themselves, with no bitcoin
in them: data in, a checksummed string out, and nothing that knows what a
witness program is. What gives it meaning is btclib.b32 -- p2wpkh, p2wsh,
p2tr, the witness version and the network prefixes -- and the rule between
the two is that direction: b32 imports bech32, never the other way round.
`base58` and `b58` are the same pair for the base58 address encoding.

BIP173: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

This implementation of bech32 is originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

* the reference's single segwit_addr.py file is split in two: the codec
  here, the bitcoin semantics in b32.py
* type annotated Python3
* avoided returning (None, None), throwing Exceptions instead
* no 90-character string limit, a bitcoin address bound that b32
  enforces instead
* detailed error messages
* interface mimics the native Python3 base64 interface, i.e.
  it supports encoding bytes-like objects to ASCII bytes,
  and decoding ASCII bytes-like objects or ASCII strings to bytes.
"""

from __future__ import annotations

from collections.abc import Iterable

from btclib.alias import String
from btclib.exceptions import BTClibValueError

__all__ = [
    "decode",
    "encode",
]

_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_1_CONST = 1
_BECH32_M_CONST = 0x2BC830A3


def _polymod(values: Iterable[int]) -> int:
    """Return the bech32 checksum."""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _create_checksum(hrp: str, data: list[int], m: int) -> list[int]:
    """Compute the checksum values given HRP and data."""
    values = _hrp_expand(hrp) + data
    polymod = _polymod([*values, 0, 0, 0, 0, 0, 0]) ^ m
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _m_from_wit_ver(data: list[int]) -> int:
    if not data:
        raise BTClibValueError("empty data in bech32 address")
    wit_ver = data[0]
    return _BECH32_1_CONST if wit_ver == 0 else _BECH32_M_CONST


def _verify_checksum(hrp: str, data: list[int], m: int) -> bool:
    """Verify a checksum given HRP and converted data characters."""
    return _polymod(_hrp_expand(hrp) + data) == m


def _decode(bech: String) -> tuple[str, list[int], list[int]]:
    """Determine a bech32 string HRP, data and checksum."""
    if isinstance(bech, bytes):
        # bech32 is an ascii encoding, so a byte outside it is an
        # invalid character like any other and gets the same answer:
        # a UnicodeDecodeError let out would fly past every caller
        # written to catch BTClibValueError
        try:
            bech = bech.decode("ascii")
        except UnicodeDecodeError as e:
            raise BTClibValueError(f"non-ascii character in bech32 string: {e}") from e

    # no 90-character limit here: that bound belongs to bitcoin
    # addresses and not to bech32, which the Lightning Network uses
    # without it. The deferral is carried out rather than merely
    # intended -- b32.witness_from_address enforces it, and the module
    # docstring there lists it among the rules b32 adds on top

    pos = bech.rfind("1")  # find the separator between hrp and data
    if pos == -1:
        raise BTClibValueError(f"no separator character: {bech}")
    if pos == 0:
        raise BTClibValueError(f"empty HRP: {bech}")
    if pos + 7 > len(bech):
        raise BTClibValueError(f"too short checksum: {bech}")

    if not all(47 < ord(x) < 123 for x in bech[:pos]):
        raise BTClibValueError(f"HRP character out of range: {bech}")
    if bech.lower() != bech and bech.upper() != bech:
        raise BTClibValueError(f"mixed case: {bech}")

    bech = bech.lower()
    hrp = bech[:pos]

    if any(x not in _ALPHABET for x in bech[-6:]):
        raise BTClibValueError(f"invalid character in checksum: {bech}")
    if any(x not in _ALPHABET for x in bech[pos + 1 :]):
        raise BTClibValueError(f"invalid data character: {bech}")
    data = [_ALPHABET.find(x) for x in bech[pos + 1 :]]

    return hrp, data[:-6], data[-6:]


def decode(bech: String, m: int | None = None) -> tuple[str, list[int]]:
    """Return (hrp, data) from a bech32 string, verifying its checksum.

    `m` picks bech32 or bech32m; None reads it off the first data
    value, the witness version choosing the constant per BIP350.
    """
    hrp, data, checksum = _decode(bech)
    m = _m_from_wit_ver(data) if m is None else m
    if _verify_checksum(hrp, data + checksum, m):
        return hrp, data
    raise BTClibValueError(f"invalid checksum: {bech!r}")


def encode(hrp: str, data: list[int], m: int | None = None) -> bytes:
    """Compute a bech32 string given HRP and data values."""
    m = _m_from_wit_ver(data) if m is None else m
    combined = data + _create_checksum(hrp, data, m)
    s = f"{hrp}1" + "".join(_ALPHABET[d] for d in combined)
    return s.encode("ascii")
