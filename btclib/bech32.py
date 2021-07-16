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

# Copyright (C) 2019-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.


"""Bech32 encoding and decoding functions.

BIP173: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

This implementation of bech32 is originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

* splitted the original segwit_addr.py file in bech32.py and segwitaddress.py
* type annotated python3
* avoided returning (None, None), throwing Exceptions instead
* removed the 90-chars limit for bech32 string, enforced by segwitaddr instead
* detailed error messages
* interface mimics the native python3 base64 interface, i.e.
  it supports encoding bytes-like objects to ASCII bytes,
  and decoding ASCII bytes-like objects or ASCII strings to bytes.
"""


from typing import Iterable, List, Tuple

from btclib.alias import String
from btclib.exceptions import BTClibValueError

_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_M = 1  # 0x2bc830a3


def _polymod(values: Iterable[int]) -> int:
    "Internal function that computes the bech32 checksum."
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> List[int]:
    "Expand the HRP into values for checksum computation."
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _create_checksum(hrp: str, data: List[int]) -> List[int]:
    "Compute the checksum values given HRP and data."
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ _M
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def b32encode(hrp: str, data: List[int]) -> bytes:
    "Compute a bech32 string given HRP and data values."
    combined = data + _create_checksum(hrp, data)
    s = hrp + "1" + "".join(_ALPHABET[d] for d in combined)
    return s.encode("ascii")


def _verify_checksum(hrp: str, data: List[int]) -> bool:
    "Verify a checksum given HRP and converted data characters."
    return _polymod(_hrp_expand(hrp) + data) == _M


def b32decode(bech: String) -> Tuple[str, List[int]]:
    "Validate a bech32 string, and determine HRP and data."

    if isinstance(bech, str):
        bech = bech.strip()

    if isinstance(bech, bytes):
        bech = bech.decode("ascii")

    if not all(47 < ord(x) < 123 for x in bech):
        raise BTClibValueError(f"ASCII character outside [48-122]: {bech}")
    if bech.lower() != bech and bech.upper() != bech:
        raise BTClibValueError(f"mixed case: {bech}")
    bech = bech.lower()

    # it is fine to limit bech32 _bitcoin_addresses_ at 90 chars,
    # but it should be enforced when working with addresses,
    # not here at bech32 level.
    # e.g. Lightning Network uses bech32 without such limitation
    # if len(bech) > 90:
    #     raise BTClibValueError(f"Bech32 string length ({len(bech)}) > 90")

    pos = bech.rfind("1")  # find the separator between hrp and data
    if pos == -1:
        raise BTClibValueError(f"missing HRP: {bech}")
    if pos == 0:
        raise BTClibValueError(f"empty HRP: {bech}")
    if pos + 7 > len(bech):
        raise BTClibValueError(f"too short checksum: {bech}")

    hrp = bech[:pos]

    if any(x not in _ALPHABET for x in bech[pos + 1 :]):
        raise BTClibValueError(f"invalid data characters: {bech}")
    data = [_ALPHABET.find(x) for x in bech[pos + 1 :]]

    if _verify_checksum(hrp, data):
        return hrp, data[:-6]
    raise BTClibValueError(f"invalid checksum: {bech}")
