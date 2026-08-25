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
"""Segwit address functions.

**The bitcoin semantics.** p2wpkh, p2wsh and p2tr addresses: the witness
version, the human-readable part of each network, and the length rules a
witness program has to satisfy.

The encoding itself is btclib.bech32, which knows nothing about bitcoin, and
the rule between the two is that direction: this module imports bech32, never
the other way round. `base58` and `b58` are the same pair for the base58
address encoding.

The whole surface is exported, the two facilities below the addresses
included: `power_of_2_base_conversion` is the `convertbits` of the
reference implementation, which a caller reading or writing a witness
program in five-bit groups needs as much as this module does, and
`bytes_from_witness_program` is BIP141's length rule, which `btclib.b58`
asks for the p2sh-wrapped forms.

Some of these functions are originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

* type annotated Python3
* avoided returning None or (None, None), throwing Exceptions instead
* detailed error messages and extended safety checks
* check that bech32 addresses are not longer than 90 characters,
  a bound bech32.decode deliberately leaves to this module
"""

from __future__ import annotations

from collections.abc import Iterable

from btclib.alias import Octets, String
from btclib.bech32 import decode, encode
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.network import NETWORKS, network_from_key_value, network_from_name
from btclib.to_pub_key import Key, pub_keyinfo_from_key
from btclib.utils import assert_type, bytes_from_octets, str_from_string

__all__ = [
    "address_from_witness",
    "bytes_from_witness_program",
    "is_segwit_prefixed",
    "p2tr",
    "p2wpkh",
    "p2wsh",
    "power_of_2_base_conversion",
    "witness_from_address",
]

# 0. bech32 facilities


def is_segwit_prefixed(addr: String) -> bool:
    """Answer whether the string starts as a bech32 address of any network.

    The prefix alone -- hrp and the 1 separator -- is read; whether the
    rest decodes is witness_from_address's answer.
    """
    str_addr = str_from_string(addr, "address").strip().lower()
    return any(str_addr.startswith(f"{net.hrp}1") for net in NETWORKS.values())


def power_of_2_base_conversion(
    data: Iterable[int], from_bits: int, to_bits: int, pad: bool = True
) -> list[int]:
    """Convert a power-of-two digit sequence to another power-of-two base."""
    assert_type(pad, bool, "pad")

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
        err_msg = f"zero padding of more than {from_bits - 1} bits"
        err_msg += f" in {from_bits}-to-{to_bits} conversion"
        raise BTClibValueError(err_msg)
    elif (acc << (to_bits - bits)) & maxv:
        err_msg = f"non-zero padding in {from_bits}-to-{to_bits} conversion"
        raise BTClibValueError(err_msg)

    return ret


def bytes_from_witness_program(wit_ver: int, wit_prg: Octets) -> bytes:
    """Return the witness program, refusing what BIP141 does not define.

    A version outside 0..16, a program outside 2..40 bytes, or a v0
    program that is neither 20 nor 32 bytes is refused.
    """
    if not 0 <= wit_ver < 17:
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
    wit_prg = bytes_from_witness_program(wit_ver, wit_prg)
    data = [wit_ver, *power_of_2_base_conversion(wit_prg, 8, 5)]
    bytes_ = encode(hrp, data)
    return bytes_.decode("ascii")


def address_from_witness(
    wit_ver: int, wit_prg: Octets, network: str = "mainnet"
) -> str:
    """Encode a bech32 native segwit address from the witness."""
    hrp = network_from_name(network).hrp
    return _address_from_witness(wit_ver, wit_prg, hrp)


def witness_from_address(b32addr: String) -> tuple[int, bytes, str]:
    """Return the witness from a bech32 native segwit address.

    The returned data structure is: version, program, network.
    """
    # the coercion before the length, which is a fact about characters:
    # `len` of what is neither text nor bytes is a TypeError about a
    # builtin, where the codec below would have named the argument
    addr = str_from_string(b32addr, "address").strip()

    # the 90-character bound is address semantics, deliberately not
    # enforced by the bech32 codec (Lightning strings exceed it)
    if len(addr) > 90:
        raise BTClibValueError(f"invalid bech32 address length: {len(addr)} > 90")

    hrp, data = decode(addr)

    wit_ver = data[0]
    wit_prog = bytes(power_of_2_base_conversion(data[1:], 5, 8, False))
    wit_prog = bytes_from_witness_program(wit_ver, wit_prog)

    # check that it is a known segwit address type
    network = network_from_key_value("hrp", hrp)
    if network is None:
        raise BTClibValueError(f"invalid hrp: {hrp}")

    return wit_ver, wit_prog, network


# 1.+2. = 3. bech32 address from pub_key/script_pub_key


def p2wpkh(key: Key, network: str | None = None) -> str:
    """Return the p2wpkh bech32 address corresponding to a public key."""
    pub_key, network = pub_keyinfo_from_key(key, network, compressed=True)
    return address_from_witness(0, hash160(pub_key), network)


def p2wsh(script_pub_key: Octets, network: str = "mainnet") -> str:
    """Return the p2wsh bech32 address corresponding to a script_pub_key."""
    h256 = sha256(script_pub_key)
    return address_from_witness(0, h256, network)


def p2tr(output_key: Octets, network: str = "mainnet") -> str:
    """Return the p2tr bech32 address corresponding to a taproot output key."""
    return address_from_witness(1, output_key, network)
