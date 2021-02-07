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

from btclib.alias import Octets, String
from btclib.bech32 import b32decode, b32encode
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160_from_key
from btclib.network import NETWORKS, network_from_key_value
from btclib.to_pub_key import Key
from btclib.utils import bytes_from_octets, sha256

# 0. bech32 facilities


def has_segwit_prefix(addr: String) -> bool:

    str_addr = addr.strip().lower() if isinstance(addr, str) else addr.decode("ascii")
    return any(str_addr.startswith(NETWORKS[net].hrp + "1") for net in NETWORKS)


def power_of_2_base_conversion(
    data: Iterable[int], from_bits: int, to_bits: int, pad: bool = True
) -> List[int]:
    "Convert a power-of-two digit sequence to another power-of-two base."
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            raise BTClibValueError(f"invalid value: {value}")
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)

    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits:
        err_msg = f"zero padding of more than {from_bits-1} bits"
        err_msg += f" in {from_bits}-to-{to_bits} conversion"
        raise BTClibValueError(err_msg)
    elif (acc << (to_bits - bits)) & maxv:
        err_msg = f"non-zero padding in {from_bits}-to-{to_bits} conversion"
        raise BTClibValueError(err_msg)

    return ret


def check_witness(wit_ver: int, wit_prg: Octets) -> bytes:

    if not 0 <= int(wit_ver) < 17:
        err_msg = "invalid witness version: "
        err_msg += f"{wit_ver} not in 0..16"
        raise BTClibValueError(err_msg)

    if wit_ver == 0:
        return bytes_from_octets(wit_prg, (20, 32))

    return bytes_from_octets(wit_prg, list(range(2, 41)))


# 1. Hash/WitnessProgram from pub_key/script_pub_key
# imported from the hashes module

# 2. bech32 address from WitnessProgram and vice versa


def _address_from_witness(wit_ver: int, wit_prg: Octets, hrp: str) -> str:
    wit_prg = check_witness(wit_ver, wit_prg)
    bytes_ = b32encode(hrp, [wit_ver] + power_of_2_base_conversion(wit_prg, 8, 5))
    return bytes_.decode("ascii")


def address_from_witness(
    wit_ver: int, wit_prg: Octets, network: str = "mainnet"
) -> str:
    "Encode a bech32 native SegWit address from the witness."

    hrp = NETWORKS[network].hrp
    return _address_from_witness(wit_ver, wit_prg, hrp)


def witness_from_address(b32addr: String) -> Tuple[int, bytes, str]:
    "Return the witness from a bech32 native SegWit address."

    if isinstance(b32addr, str):
        b32addr = b32addr.strip()

    # the following check was originally in b32decode
    # but it does not pertain there
    if len(b32addr) > 90:
        raise BTClibValueError(f"invalid bech32 address length: {len(b32addr)} > 90")

    hrp, data = b32decode(b32addr)

    # check that it is a known SegWit address type
    network = network_from_key_value("hrp", hrp)
    if network is None:
        raise BTClibValueError(f"invalid hrp: {hrp}")

    if len(data) == 0:
        raise BTClibValueError(f"empty data in bech32 address: {b32addr!r}")

    wit_ver = data[0]
    wit_prg = bytes(power_of_2_base_conversion(data[1:], 5, 8, False))
    return wit_ver, check_witness(wit_ver, wit_prg), network


# 1.+2. = 3. bech32 address from pub_key/script_pub_key


def p2wpkh(key: Key, network: Optional[str] = None) -> str:
    "Return the p2wpkh bech32 address corresponding to a public key."
    compressed = True  # needed to force check on pub_key
    h160, network = hash160_from_key(key, network, compressed)
    return address_from_witness(0, h160, network)


def p2wsh(script_pub_key: Octets, network: str = "mainnet") -> str:
    "Return the p2wsh bech32 address corresponding to a script_pub_key."
    h256 = sha256(script_pub_key)
    return address_from_witness(0, h256, network)
