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
* detailed error messages and exteded safety checks
* check that Bech32 addresses are not longer than 90 characters
  (as this is not enforced by bech32.encode)
"""


from typing import Tuple, Iterable, List
from . import bech32


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


def scriptpubkey(witness_version: int, witness_program: List[int]) -> bytes:
    """Construct a SegWit scriptPubKey for a given witness.
    
    The scriptPubKey is the witness version
    (OP_0 for version 0, OP_1 for version 1, etc.)
    followed by the canonical push of the witness program
    (i.e. program lenght + program).

    E.g. for P2WPKH, where the program is a 20-byte keyhash,
    the scriptPubkey is 0x0014{20-byte keyhash}
    """

    l = len(witness_program)
    if witness_version == 0:
        if l != 20 and l != 32:
            raise ValueError(f"{l}-bytes witness program: must be 20 or 32")
    elif witness_version > 16 or witness_version < 0:
        msg = f"witness version ({witness_version}) not in [0, 16]"
        raise ValueError(msg)
    else:
        if l < 2 or l > 40:
            raise ValueError(f"{l}-bytes witness program: must be in [2,40]")

    # start with witness version
    # OP_0 is encoded as 0x00, but OP_1 through OP_16 are encoded as 0x51 though 0x60
    script_pubkey = [witness_version + 0x50 if witness_version else 0]
    
    # follow with the canonical push of the witness program
    script_pubkey += [len(witness_program)]
    script_pubkey += witness_program

    return bytes(script_pubkey)


def decode(hrp: str, addr: str) -> Tuple[int, List[int]]:
    """Decode a segwit address."""

    # the following check was 
    if len(addr) > 90:
        raise ValueError(f"Bech32 address length ({len(addr)}) > 90")

    hrpgot, data = bech32.decode(addr)
    if hrpgot != hrp:
        raise ValueError("failure")

    witness_program = _convertbits(data[1:], 5, 8, False)
    l = len(witness_program)
    if l < 2 or l > 40:
        raise ValueError(f"{l}-bytes witness program: must be in [2, 40]")

    witness_version = data[0]
    if witness_version > 16 or witness_version < 0:
        msg = f"witness version ({witness_version}) not in [0, 16]"
        raise ValueError(msg)
    if witness_version == 0 and l != 20 and l != 32:
        raise ValueError(f"{l}-bytes witness program: must be 20 or 32")
    
    return witness_version, witness_program


def encode(hrp: str, witver: int, witprog: Iterable[int]) -> str:
    """Encode a segwit address."""
    ret = bech32.encode(hrp, [witver] + _convertbits(witprog, 8, 5))
    _, _ = decode(hrp, ret)
    return ret
