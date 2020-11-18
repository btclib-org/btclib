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


"""SegWit address functions.

Some of these functions were originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

* moved bech32 stuff into bech32.py
* type annotated python3
* avoided returning None or (None, None), throwing Exceptions instead
* detailed error messages and exteded safety checks
* check that bech32 addresses are not longer than 90 characters
  (as this is not enforced by bech32.b32decode anymore)
"""


from typing import Iterable, List, Optional, Tuple

from .alias import Octets, Script, String
from .bech32 import b32decode, b32encode
from .exceptions import BTClibValueError
from .hashes import hash160_from_key, hash256_from_script
from .network import NETWORKS, network_from_key_value
from .to_pubkey import Key
from .utils import bytes_from_octets

# 0. bech32 facilities


def _convertbits(
    data: Iterable[int], frombits: int, tobits: int, pad: bool = True
) -> List[int]:
    "General power-of-2 base conversion."
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise BTClibValueError(f"invalid value in _convertbits: {value}")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits:
        raise BTClibValueError("zero padding of more than 4 bits in 8-to-5 conversion")
    elif (acc << (tobits - bits)) & maxv:
        raise BTClibValueError("non-zero padding in 8-to-5 conversion")

    return ret


def _check_witness(witvers: int, witprog: bytes):
    length = len(witprog)
    if witvers == 0:
        if length not in (20, 32):
            err_msg = "invalid witness program length for witness version zero: "
            err_msg += f"{length} instead of 20 or 32"
            raise BTClibValueError(err_msg)
    elif witvers < 0 or witvers > 16:
        err_msg = "invalid witness version: "
        err_msg += f"{witvers} not in 0..16"
        raise BTClibValueError(err_msg)
    else:
        if length < 2 or length > 40:
            err_msg = "invalid witness program length for witness version zero: "
            err_msg += f"{length}, not in 2..40"
            raise BTClibValueError(err_msg)


# 1. Hash/WitnessProgram from pubkey/script_pubkey
# imported from the hashes module

# 2. bech32 address from WitnessProgram and vice versa


def _b32address_from_witness(hrp: str, wv: int, wp: Octets) -> bytes:
    wp = bytes_from_octets(wp)
    _check_witness(wv, wp)
    return b32encode(hrp, [wv] + _convertbits(wp, 8, 5))


def b32address_from_witness(wv: int, wp: Octets, network: str = "mainnet") -> bytes:
    "Encode a bech32 native SegWit address from the witness."

    hrp = NETWORKS[network].p2w
    return _b32address_from_witness(hrp, wv, wp)


def witness_from_b32address(b32addr: String) -> Tuple[int, bytes, str, bool]:
    "Return the witness from a bech32 native SegWit address."

    if isinstance(b32addr, str):
        b32addr = b32addr.strip()

    # the following check was originally in b32decode
    # but it does not pertain there
    if len(b32addr) > 90:
        raise BTClibValueError(f"invalid bech32 address length: {len(b32addr)} > 90")

    hrp, data = b32decode(b32addr)

    # check that it is a known SegWit address type
    network = network_from_key_value("p2w", hrp)

    if len(data) == 0:
        raise BTClibValueError(f"empty data in bech32 address: {b32addr!r}")

    witvers = data[0]
    witprog = _convertbits(data[1:], 5, 8, False)
    _check_witness(witvers, bytes(witprog))

    is_script_hash = witvers != 0 or len(witprog) != 20
    return witvers, bytes(witprog), network, is_script_hash


# 1.+2. = 3. bech32 address from pubkey/script_pubkey


def p2wpkh(key: Key, network: Optional[str] = None) -> bytes:
    "Return the p2wpkh bech32 address corresponding to a public key."
    compressed = True  # needed to force check on pubkey
    h160, network = hash160_from_key(key, network, compressed)
    return b32address_from_witness(0, h160, network)


def p2wsh(script_pubkey: Script, network: str = "mainnet") -> bytes:
    "Return the p2wsh bech32 address corresponding to a script_pubkey."
    h256 = hash256_from_script(script_pubkey)
    return b32address_from_witness(0, h256, network)
