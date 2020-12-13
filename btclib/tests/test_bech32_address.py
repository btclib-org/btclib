#!/usr/bin/env python3

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


"""Tests for the `btclib.bech32_address` module.

Some of these tests are originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

- splitted the original tests.py file in test_bech32.py
  and test_bech32_address.py
- checked for raised exceptions instead of assertIsNone
"""

from typing import List, Tuple

import pytest

from btclib import script
from btclib.base58_address import p2wpkh_p2sh, p2wsh_p2sh
from btclib.bech32_address import (
    _convertbits,
    bech32_address_from_witness,
    p2wpkh,
    p2wsh,
    witness_from_bech32_address,
)
from btclib.exceptions import BTClibValueError
from btclib.sec_point import bytes_from_point, point_from_octets
from btclib.utils import hash160, sha256


def test_valid_address() -> None:
    """Test whether valid addresses decode to the correct output"""

    valid_bc_addresses: List[Tuple[str, str]] = [
        (
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        (
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
            "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        ("BC1SW50QA3JX3S", "6002751e"),
        (
            "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
            "5210751e76e8199196d454941c45d1b3a323",
        ),
        (
            " bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",  # extra leading space
            "5210751e76e8199196d454941c45d1b3a323",
        ),
    ]
    valid_tb_addresses: List[Tuple[str, str]] = [
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ),
        (
            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
    ]

    for address, hexscript in valid_bc_addresses + valid_tb_addresses:
        w_ver, w_prg, network, _ = witness_from_bech32_address(address)
        addr = bech32_address_from_witness(w_ver, w_prg, network)
        assert address.lower().strip() == addr

        w_ver, w_prg, network, _ = witness_from_bech32_address(
            address.strip().encode("ascii")
        )
        addr = bech32_address_from_witness(w_ver, w_prg, network)
        assert address.lower().strip() == addr

        script_pub_key: List[script.ScriptToken] = [w_ver, w_prg]
        assert script.serialize(script_pub_key).hex() == hexscript


def test_invalid_address() -> None:
    """Test whether invalid addresses fail to decode"""

    invalid_addresses: List[Tuple[str, str]] = [
        (
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
            "invalid value for network keyword 'p2w': ",
        ),
        (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            "invalid checksum in bech32 string: ",
        ),
        ("BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", "invalid witness version: "),
        ("bc1rw5uspcuh", "invalid witness program length for witness v0: "),
        (
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "invalid witness program length for witness v0: ",
        ),
        (
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "invalid witness program length for witness v0: ",
        ),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            "mixed case in bech32 string: ",
        ),
        (
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
            "zero padding of more than 4 bits in 8-to-5 conversion",
        ),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            "non-zero padding in 8-to-5 conversion",
        ),
        ("bc1gmk9yu", "empty data in bech32 address: "),
        (
            "bc1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqv0jstn5",
            "invalid bech32 address length: ",
        ),
    ]

    for address, err_msg in invalid_addresses:
        with pytest.raises(BTClibValueError, match=err_msg):
            witness_from_bech32_address(address)


def test_invalid_address_enc() -> None:
    """Test whether address encoding fails on invalid input"""

    invalid_address_enc: List[Tuple[str, int, int, str]] = [
        ("MAINNET", 0, 20, "'MAINNET'"),
        ("mainnet", 0, 21, "invalid witness program length for witness v0: "),
        ("mainnet", 17, 32, "invalid witness version: "),
        ("mainnet", 1, 1, "invalid witness program length for witness v0: "),
        ("mainnet", 16, 41, "invalid witness program length for witness v0: "),
    ]

    network, version, length, err_msg = invalid_address_enc[0]
    with pytest.raises(KeyError, match=err_msg):
        bech32_address_from_witness(version, "00" * length, network)

    for network, version, length, err_msg in invalid_address_enc[1:]:
        with pytest.raises(BTClibValueError, match=err_msg):
            bech32_address_from_witness(version, "00" * length, network)


def test_bech32_address_from_witness() -> None:

    # self-consistency
    addr = "bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck"
    w_ver, w_prg, network, _ = witness_from_bech32_address(addr)
    assert bech32_address_from_witness(w_ver, w_prg, network) == addr

    wp_ints = list(w_prg)
    wp_ints[0] = -1
    with pytest.raises(BTClibValueError, match="invalid value in _convertbits: "):
        _convertbits(wp_ints, 8, 5)


def test_p2wpkh_p2sh() -> None:
    # https://matthewdowney.github.io/create-segwit-address.html
    pub = " 03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
    address = p2wpkh_p2sh(pub)
    assert address == "36NvZTcMsMowbt78wPzJaHHWaNiyR73Y4g"
    address = p2wpkh_p2sh(pub, "testnet")
    assert address == "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"

    # http://bitcoinscri.pt/pages/segwit_p2sh_p2wpkh
    pub = "02 f118cc409775419a931c57664d0c19c405e856ac0ee2f0e2a4137d8250531128"
    address = p2wpkh_p2sh(pub)
    assert address == "3Mwz6cg8Fz81B7ukexK8u8EVAW2yymgWNd"


def test_p2wpkh() -> None:

    # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    # leading/trailing spaces should be tolerated
    pub = " 02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert addr == p2wpkh(pub)
    addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    assert addr == p2wpkh(pub, "testnet")

    # http://bitcoinscri.pt/pages/segwit_native_p2wpkh
    pub = "02 530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69261b42def7"
    addr = "bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck"
    assert addr == p2wpkh(pub)

    _, w_prg, _, _ = witness_from_bech32_address(addr)
    assert bytes(w_prg) == hash160(pub)

    uncompr_pub = bytes_from_point(point_from_octets(pub), compressed=False)
    err_msg = "not a private or compressed public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        p2wpkh(uncompr_pub)
    with pytest.raises(BTClibValueError, match=err_msg):
        p2wpkh(pub + "00")

    err_msg = "invalid witness program length for witness v0: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bech32_address_from_witness(0, hash160(pub) + b"\x00")


def test_hash_from_bech32() -> None:
    network = "testnet"
    w_ver = 0
    w_prg = 20 * b"\x05"
    addr = bech32_address_from_witness(w_ver, w_prg, network)
    _, wp2, n_2, _ = witness_from_bech32_address(addr)
    assert n_2 == network
    assert wp2 == w_prg

    # witness program length (21) is not 20 or 32
    addr = "tb1qq5zs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5mpvsef"
    err_msg = "invalid witness program length for witness v0: "
    with pytest.raises(BTClibValueError, match=err_msg):
        witness_from_bech32_address(addr)


def test_p2wsh_p2sh() -> None:

    # leading/trailing spaces should be tolerated
    pub = " 02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    script_pub_key: List[script.ScriptToken] = [pub, "OP_CHECKSIG"]
    witness_script_bytes = script.serialize(script_pub_key)
    p2wsh_p2sh(witness_script_bytes)
    p2wsh_p2sh(witness_script_bytes, "testnet")


def test_p2wsh() -> None:

    # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    pub = "02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    script_pub_key: List[script.ScriptToken] = [pub, "OP_CHECKSIG"]
    witness_script_bytes = script.serialize(script_pub_key)

    addr = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
    assert addr == p2wsh(witness_script_bytes, "testnet")
    _, w_prg, _, _ = witness_from_bech32_address(addr)
    assert bytes(w_prg) == sha256(witness_script_bytes)

    addr = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
    assert addr == p2wsh(witness_script_bytes)
    _, w_prg, _, _ = witness_from_bech32_address(addr)
    assert bytes(w_prg) == sha256(witness_script_bytes)

    assert witness_from_bech32_address(addr)[1] == sha256(witness_script_bytes)

    err_msg = "invalid witness program length for witness v0: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bech32_address_from_witness(0, witness_script_bytes)
