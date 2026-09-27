# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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
* the checksum's inner loop is a 32-entry table of tap combinations,
  the same taps selected by a lookup rather than by five conditional
  XORs per character
* detailed error messages
* interface mimics the native Python3 base64 interface, i.e.
  it supports encoding bytes-like objects to ASCII bytes,
  and decoding ASCII bytes-like objects or ASCII strings to bytes.
"""

from __future__ import annotations

from collections.abc import Iterable
from functools import reduce
from operator import xor

from btclib.alias import String
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import is_integer, str_from_string

__all__ = [
    "BECH32_1_CONST",
    "BECH32_M_CONST",
    "decode",
    "encode",
]

_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# the `m` that `encode` and `decode` take: BIP173's bech32 and BIP350's
# bech32m, which differ in this constant alone. Exported for a caller
# whose first 5-bit digit is not a witness version -- a silent payment
# address, a BIP85 nsec -- and which has to say which of the two it means,
# `None` reading the choice off that digit
BECH32_1_CONST = 1
BECH32_M_CONST = 0x2BC830A3

# BIP173's five generator constants, and the XOR of the ones each 5-bit
# selection picks. What a step of _polymod applies depends on nothing but
# the top five bits of chk, of which there are 32, so the table computed
# once here is the whole of the reference's inner loop -- five shifts,
# five masks and five conditional XORs per input character. Bitcoin
# Core's PolyMod unrolls those five lines instead of tabulating them,
# which is what C makes cheap and Python does not
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_TAPS = [
    reduce(xor, [g for i, g in enumerate(_GENERATOR) if top >> i & 1], 0)
    for top in range(32)
]

# a digit for every character, built once: `x not in _ALPHABET` and
# `_ALPHABET.find(x)` were each a scan of all 32 characters. -1 rather
# than None keeps a lookup a plain int and doubles as the validity
# check, since a digit is never negative; lowercase-only because
# `_decode` already lowers `bech` before reaching the lookup
_INDEX_OF = {c: i for i, c in enumerate(_ALPHABET)}


def _hrp_in_range(text: str) -> bool:
    """Whether every character of `text` is in BIP173's HRP range.

    "a value in the range [33-126]", shared between `_decode`'s check on
    `text[:pos]` and `encode`'s on the HRP it is given, so the bound
    lives in one place. 33 and 126 are the boundary themselves ("!" and
    "~"); a weakened `<=` at either end would accept 32 (" ") or 127
    (DEL).
    """
    return all(32 < ord(x) < 127 for x in text)


def _polymod(values: Iterable[int]) -> int:
    """Return the bech32 checksum."""
    chk = 1
    for value in values:
        chk = (chk & 0x1FFFFFF) << 5 ^ value ^ _TAPS[chk >> 25]
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
    return BECH32_1_CONST if wit_ver == 0 else BECH32_M_CONST


def _verify_checksum(hrp: str, data: list[int], m: int) -> bool:
    """Verify a checksum given HRP and converted data characters."""
    return _polymod(_hrp_expand(hrp) + data) == m


def _decode(bech: String) -> tuple[str, list[int], list[int]]:
    """Determine a bech32 string HRP, data and checksum."""
    # bech32 is an ascii encoding, so a byte outside it is an invalid
    # character like any other, and what is neither text nor bytes is
    # refused here rather than reaching `rfind` as a missing method
    text = str_from_string(bech, "bech32 string")

    # no 90-character limit here: that bound belongs to bitcoin
    # addresses and not to bech32, which the Lightning Network uses
    # without it. The deferral is carried out rather than merely
    # intended -- b32.witness_from_address enforces it, and the module
    # docstring there lists it among the rules b32 adds on top

    # no refusal quotes `text`: what reaches an address decoder can be a
    # private key pasted in the wrong field, and an exception message is
    # what ends up in a log
    pos = text.rfind("1")  # find the separator between hrp and data
    if pos == -1:
        raise BTClibValueError("no separator character")
    if pos == 0:
        raise BTClibValueError("empty HRP")
    if pos + 7 > len(text):
        raise BTClibValueError("too short checksum")

    if not _hrp_in_range(text[:pos]):
        raise BTClibValueError("HRP character out of range")
    if text.lower() != text and text.upper() != text:
        raise BTClibValueError("mixed case")

    text = text.lower()
    hrp = text[:pos]

    indices = [_INDEX_OF.get(x, -1) for x in text[pos + 1 :]]
    if -1 in indices[-6:]:
        raise BTClibValueError("invalid character in checksum")
    if -1 in indices:
        raise BTClibValueError("invalid data character")
    data = indices

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
    raise BTClibValueError("invalid checksum")


def encode(hrp: str, data: list[int], m: int | None = None) -> bytes:
    """Compute a bech32 string given HRP and data values.

    The HRP is checked against the rule `_decode` applies to it:
    non-empty, ASCII, every character in BIP173's [33-126] range -- an
    `f"{hrp}1"` given anything else silently formats it rather than
    raising, a non-str hrp included, which is why the type is checked
    too rather than left to that formatting. Case is narrower than
    `_decode`'s: `_decode` accepts an all-uppercase string, but every
    data digit here comes from `_ALPHABET`, which is lowercase only, so
    an all-uppercase HRP combined with any data digit that is a letter
    writes a string `decode` refuses as mixed case -- the very defect
    this check exists to catch. Requiring the HRP itself lowercase,
    rather than merely single-case, is what makes the guarantee hold for
    every `data` rather than only for the calls that happen to carry no
    letter.

    Every value is one 5-bit digit, and each is checked rather than left
    to the alphabet lookup to fail: ``_ALPHABET[-1]`` is "l" and
    ``_ALPHABET[-32]`` is "q", Python indexing from the end, so a
    negative digit writes a *different address* and says nothing at all.
    A digit above 31 at least raises, and raises `IndexError`; a float
    raises `TypeError`. Neither is caught by the `except
    BTClibValueError` this library invites.

    The pair of checks walks the digits a second time, which is a
    fraction of what encoding them costs and a smaller fraction of the
    key derivation that produced them -- an address is encoded once,
    never in an inner loop.
    """
    if not isinstance(hrp, str):
        raise BTClibTypeError(f"invalid HRP type: {type(hrp).__name__}")
    if not hrp:
        raise BTClibValueError("empty HRP")
    if not _hrp_in_range(hrp):
        raise BTClibValueError(f"HRP character out of range: {hrp}")
    if hrp != hrp.lower():
        raise BTClibValueError(f"HRP is not lowercase: {hrp}")

    for d in data:
        if not is_integer(d):
            raise BTClibTypeError(f"invalid 5-bit value type: {type(d).__name__}")
        if not 0 <= d < 32:
            raise BTClibValueError(f"invalid 5-bit value: {d}")
    m = _m_from_wit_ver(data) if m is None else m
    combined = data + _create_checksum(hrp, data, m)
    s = f"{hrp}1" + "".join(_ALPHABET[d] for d in combined)
    return s.encode("ascii")
