# Copyright (C) The btclib developers
#
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
"""Tests for the `btclib.b32` module.

Some of these tests are originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

- split the original tests.py file in bech32_test.py
  and b32_test.py
- checked for raised exceptions instead of assertIsNone
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib import b32, b58
from btclib.alias import ScriptList
from btclib.curves import bytes_from_point, point_from_octets
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.script import op_int, output_pubkey, serialize


def test_has_segwit_prefix() -> None:
    """Verify bc1 addresses are told from base58 ones, str or bytes."""
    addr = b"bc1q0hy024867ednvuhy9en4dggflt5w9unw4ztl5a"
    assert b32.has_segwit_prefix(addr)
    assert b32.has_segwit_prefix(addr.decode("ascii"))
    addr = b"1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    assert not b32.has_segwit_prefix(addr)
    assert not b32.has_segwit_prefix(addr.decode("ascii"))


def test_valid_address() -> None:
    """Test whether valid addresses decode to the correct output."""
    valid_bc_addresses = [
        (
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
            "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        (
            "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
            "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        ("BC1SW50QGDZ25J", "6002751e"),
        (
            "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
            "5210751e76e8199196d454941c45d1b3a323",
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
    ]
    valid_tb_addresses = [
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ),
        (
            "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
            "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
        (
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        ),
    ]

    for address, hexscript in valid_bc_addresses + valid_tb_addresses:
        addr = b32.address_from_witness(*b32.witness_from_address(address))
        assert address.lower().strip() == addr

        wit_ver, wit_prg, network = b32.witness_from_address(
            address.strip().encode("ascii")
        )
        assert addr == b32.address_from_witness(wit_ver, wit_prg, network)

        script_pub_key: ScriptList = [op_int(wit_ver), wit_prg]
        assert serialize(script_pub_key).hex() == hexscript


def test_invalid_address() -> None:
    """Test whether invalid addresses fail to decode."""
    invalid_addresses = [
        ("tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", "invalid hrp: "),
        (
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            "invalid hrp: ",
        ),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "invalid checksum: "),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            "invalid checksum: ",
        ),
        (
            "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
            "invalid checksum: ",
        ),
        (
            "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
            "invalid checksum: ",
        ),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", "invalid checksum: "),
        (
            "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
            "invalid checksum: ",
        ),
        (
            "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
            "invalid character in checksum",
        ),
        (
            "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
            "invalid witness version: ",
        ),
        ("BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", "invalid checksum: "),
        ("bc1pw5dgrnzv", "invalid size: "),
        ("bc1rw5uspcuh", "invalid checksum: "),
        (
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "invalid checksum: ",
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
            "invalid size: ",
        ),
        ("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", "invalid size: "),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            "mixed case: ",
        ),
        (
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
            "mixed case: ",
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            "zero padding of more than 4 bits in 5-to-8 conversion",
        ),
        (
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
            "invalid checksum: ",
        ),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            "non-zero padding in 5-to-8 conversion",
        ),
        (
            "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
            "non-zero padding in 5-to-8 conversion",
        ),
        ("bc1gmk9yu", "empty data in bech32 address"),
        (
            "bc1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqv0jstn5",
            "invalid bech32 address length: ",
        ),
    ]

    for address, err_msg in invalid_addresses:
        with pytest.raises(BTClibValueError, match=err_msg):
            b32.witness_from_address(address)


def test_invalid_address_enc() -> None:
    """Test whether address encoding fails on invalid input."""
    invalid_address_enc = [
        ("MAINNET", 0, 20, "'MAINNET'"),
        ("mainnet", 0, 21, "invalid size: "),
        ("mainnet", 17, 32, "invalid witness version: "),
        ("mainnet", 1, 1, "invalid size: "),
        ("mainnet", 16, 41, "invalid size: "),
    ]

    network, wit_ver, length, err_msg = invalid_address_enc[0]
    with pytest.raises(KeyError, match=err_msg):
        b32.address_from_witness(wit_ver, "0A" * length, network)

    for network, wit_ver, length, err_msg in invalid_address_enc[1:]:
        with pytest.raises(BTClibValueError, match=err_msg):
            b32.address_from_witness(wit_ver, "0A" * length, network)


def test_address_witness() -> None:
    """Round-trip v0 witnesses; refuse a bad size or conversion value."""
    wit_ver = 0
    wit_prg = 20 * b"\x05"
    for net in ("mainnet", "testnet"):
        addr = b32.address_from_witness(wit_ver, wit_prg, net)
        assert (wit_ver, wit_prg, net) == b32.witness_from_address(addr)

    wit_ver = 0
    wit_prg = 32 * b"\x05"
    for net in ("mainnet", "testnet"):
        addr = b32.address_from_witness(wit_ver, wit_prg, net)
        assert (wit_ver, wit_prg, net) == b32.witness_from_address(addr)

    addr = "bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck"

    assert b32.address_from_witness(*b32.witness_from_address(addr)) == addr

    wit_prg_ints = list(wit_prg)
    wit_prg_ints[0] = -1
    with pytest.raises(BTClibValueError, match="invalid value: "):
        b32.power_of_2_base_conversion(wit_prg_ints, 8, 5)

    addr = "tb1qq5zs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5mpvsef"
    err_msg = "invalid size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        b32.witness_from_address(addr)


def test_p2wpkh_p2sh() -> None:
    """Reproduce published p2wpkh-p2sh addresses, testnet included."""
    # https://matthewdowney.github.io/create-segwit-address.html
    pub = " 03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
    address = b58.p2wpkh_p2sh(pub)
    assert address == "36NvZTcMsMowbt78wPzJaHHWaNiyR73Y4g"
    address = b58.p2wpkh_p2sh(pub, "testnet")
    assert address == "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2"

    # http://bitcoinscri.pt/pages/segwit_p2sh_p2wpkh
    pub = "02 f118cc409775419a931c57664d0c19c405e856ac0ee2f0e2a4137d8250531128"
    address = b58.p2wpkh_p2sh(pub)
    assert address == "3Mwz6cg8Fz81B7ukexK8u8EVAW2yymgWNd"


def test_p2wpkh() -> None:
    """Reproduce BIP173's p2wpkh examples; refuse uncompressed keys."""
    # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    # leading/trailing spaces should be tolerated
    pub = " 02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert addr == b32.p2wpkh(pub)
    addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    assert addr == b32.p2wpkh(pub, "testnet")

    # http://bitcoinscri.pt/pages/segwit_native_p2wpkh
    pub = "02 530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69261b42def7"
    addr = "bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck"
    assert addr == b32.p2wpkh(pub)

    _, wit_prg, _ = b32.witness_from_address(addr)
    assert wit_prg == hash160(pub)

    uncompr_pub = bytes_from_point(point_from_octets(pub), compressed=False)
    err_msg = "not a private or compressed public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        b32.p2wpkh(uncompr_pub)
    with pytest.raises(BTClibValueError, match=err_msg):
        b32.p2wpkh(f"{pub}0A")

    err_msg = "invalid size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        b32.address_from_witness(0, hash160(pub) + b"\x00")


def test_p2wsh_p2sh() -> None:
    """Build p2wsh-p2sh addresses from a script with spaced-out keys."""
    # leading/trailing spaces should be tolerated
    pub = " 02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    script_pub_key: ScriptList = [pub, "OP_CHECKSIG"]
    witness_script_bytes = serialize(script_pub_key)
    b58.p2wsh_p2sh(witness_script_bytes)
    b58.p2wsh_p2sh(witness_script_bytes, "testnet")


def test_p2wsh() -> None:
    """Reproduce BIP173's p2wsh addresses; the program is the sha256."""
    # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    pub = "02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    script_pub_key: ScriptList = [pub, "OP_CHECKSIG"]
    witness_script_bytes = serialize(script_pub_key)

    addr = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
    assert addr == b32.p2wsh(witness_script_bytes, "testnet")
    _, wit_prg, _ = b32.witness_from_address(addr)
    assert wit_prg == sha256(witness_script_bytes)

    addr = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
    assert addr == b32.p2wsh(witness_script_bytes)
    _, wit_prg, _ = b32.witness_from_address(addr)
    assert wit_prg == sha256(witness_script_bytes)

    err_msg = "invalid size: "
    with pytest.raises(BTClibValueError, match=err_msg):
        b32.address_from_witness(0, witness_script_bytes)


def test_p2tr() -> None:
    """Verify a p2tr address decodes back to its taproot output key."""
    key = 1
    pub_key = output_pubkey(key)[0]
    addr = b32.p2tr(pub_key)
    _, wit_prg, _ = b32.witness_from_address(addr)

    assert wit_prg == pub_key


# the three networks a bech32 address round-trips through, which is more
# than the base58 addresses of b58_test.py manage: the hrp tells these
# three apart where the version bytes of testnet and regtest do not.
# Signet and testnet4 are left out because they are the case the hrp
# does *not* tell apart -- both are "tb", testnet's, so an address built
# for either reads back as testnet and the round trip below would fail
# on the name rather than on the encoding it is testing (issue #207)
NETWORK = st.sampled_from(["mainnet", "testnet", "regtest"])


@given(
    wit_ver=st.integers(min_value=1, max_value=16),
    wit_prg=st.binary(min_size=2, max_size=40),
    network=NETWORK,
)
def test_round_trip_witness(wit_ver: int, wit_prg: bytes, network: str) -> None:
    """The witness of an address is the witness it was built from.

    The 8-to-5 bit conversion in the middle is the part worth generating
    input for: it pads, and the padding has to be zero and has to be
    dropped again, which a program length that is not a multiple of 5
    bits is what exercises.
    """
    address = b32.address_from_witness(wit_ver, wit_prg, network)
    assert b32.witness_from_address(address) == (wit_ver, wit_prg, network)


@given(
    wit_prg=st.integers(min_value=0, max_value=1).flatmap(
        lambda i: st.binary(min_size=(20, 32)[i], max_size=(20, 32)[i])
    ),
    network=NETWORK,
)
def test_round_trip_witness_v0(wit_prg: bytes, network: str) -> None:
    """Version 0 takes a 20-byte or a 32-byte program, and nothing else."""
    address = b32.address_from_witness(0, wit_prg, network)
    assert b32.witness_from_address(address) == (0, wit_prg, network)


@given(
    wit_ver=st.integers(min_value=0, max_value=16),
    wit_prg=st.binary(min_size=2, max_size=40),
    position=st.integers(min_value=0),
    value=st.integers(min_value=0, max_value=31),
)
def test_a_changed_character_is_not_an_address(
    wit_ver: int, wit_prg: bytes, position: int, value: int
) -> None:
    """A typo in an address is caught, not paid to a stranger."""
    if wit_ver == 0 and len(wit_prg) not in (20, 32):
        return
    address = b32.address_from_witness(wit_ver, wit_prg)
    # the hrp is left alone: changing it makes a different address
    body = address[len("bc1") :]
    i = position % len(body)
    mutated = body[:i] + "qpzry9x8gf2tvdw0s3jn54khce6mua7l"[value] + body[i + 1 :]
    if mutated == body:
        return
    with pytest.raises(BTClibValueError):
        b32.witness_from_address(f"bc1{mutated}")
