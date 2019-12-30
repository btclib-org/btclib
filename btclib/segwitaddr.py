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

# Copyright (C) 2019-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.


"""SegWit address implementation.

This implementation of Bech32 is originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

* splitted the original segwit_addr.py file in bech32.py and segwitaddr.py
* type annotated python3
* avoided returning None or (None, None), throwing ValueError instead
"""

from . import bech32
from typing import Tuple, Iterable, List


def _convertbits(data: Iterable[int], frombits: int,
                 tobits: int, pad: bool = True) -> List[int]:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("failure")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("failure")
    return ret


def decode(hrp: str, addr: str) -> Tuple[int, List[int]]:
    """Decode a segwit address."""
    hrpgot, data = bech32.decode(addr)
    if hrpgot != hrp:
        raise ValueError("failure")
    decoded = _convertbits(data[1:], 5, 8, False)
    if len(decoded) < 2 or len(decoded) > 40:
        raise ValueError("failure")
    if data[0] > 16:
        raise ValueError("failure")
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        raise ValueError("failure")
    return data[0], decoded


def encode(hrp: str, witver: int, witprog: Iterable[int]) -> str:
    """Encode a segwit address."""
    ret = bech32.encode(hrp, [witver] + _convertbits(witprog, 8, 5))
    _, _ = decode(hrp, ret)
    return ret
