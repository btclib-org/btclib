# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the decoders given a `Network` rather than looking one up.

`b58.h160_from_address`, `b32.witness_from_address`,
`network.network_from_xkeyversion`, `b58.prv_key_data_from_wif` and the
two `from_address` constructors take an optional `network`. Given one,
they accept only its prefixes, hrp and versions. The first three return
the Network itself. The other three build an object whose `network` is a
name, or a Network NETWORKS does not hold: this file takes such a Network
through each of them and back through the encoders and json.
"""

from __future__ import annotations

import copy
import dataclasses
import json

import pytest

from btclib import b32, b58
from btclib.base58 import encode as b58encode
from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    InvalidPrvKeyError,
)
from btclib.hashes import hash160
from btclib.key import PrvKeyData, PubKeyData
from btclib.network import NETWORKS, Network, network_from_xkeyversion
from btclib.script import ScriptPubKey
from btclib.tx import TxOut

H160 = bytes(range(20))


def _other_chain() -> Network:
    """Return a made-up chain's Network, none of whose prefixes NETWORKS has."""
    dict_ = NETWORKS["mainnet"].to_dict() | {
        "genesis_block": "11" * 32,
        "wif": "b0",
        "p2pkh": "30",
        "p2sh": "32",
        "hrp": "xyz",
        "bip32_prv": "019d9cfe",
        "bip32_pub": "019da462",
        "slip132_p2wpkh_prv": "0aaa0001",
        "slip132_p2wpkh_pub": "0aaa0002",
        "slip132_p2wpkh_p2sh_prv": "0aaa0003",
        "slip132_p2wpkh_p2sh_pub": "0aaa0004",
        "slip132_p2wsh_prv": "0aaa0005",
        "slip132_p2wsh_pub": "0aaa0006",
        "slip132_p2wsh_p2sh_prv": "0aaa0007",
        "slip132_p2wsh_p2sh_pub": "0aaa0008",
    }
    return Network.from_dict(dict_)


OTHER = _other_chain()


def test_the_other_chain_is_not_in_networks() -> None:
    """The made-up Network equals no NETWORKS entry, the premise of the rest.

    Nor does any NETWORKS entry hold one of its prefixes, hrp or versions.
    """
    assert all(net != OTHER for net in NETWORKS.values())
    for field, value in OTHER.to_dict().items():
        if field not in {"curve", "network_type", "consensus"}:
            assert all(
                getattr(net, field) != getattr(OTHER, field)
                for net in NETWORKS.values()
            ), (field, value)


def test_h160_from_address() -> None:
    """Decode the other chain's base58 addresses, and refuse mainnet's."""
    for script_type, prefix in (("p2pkh", OTHER.p2pkh), ("p2sh", OTHER.p2sh)):
        addr = b58encode(prefix + H160).decode("ascii")
        assert b58.h160_from_address(addr, OTHER) == (script_type, H160, OTHER)
        with pytest.raises(BTClibValueError, match="invalid base58 address prefix"):
            b58.h160_from_address(addr)

    mainnet_addr = b58.address_from_h160("p2pkh", H160, "mainnet")
    with pytest.raises(BTClibValueError, match="invalid base58 address prefix"):
        b58.h160_from_address(mainnet_addr, OTHER)
    # the name, where no network is given
    assert b58.h160_from_address(mainnet_addr) == ("p2pkh", H160, "mainnet")


def test_witness_from_address() -> None:
    """Decode the other chain's bech32 address, and refuse mainnet's."""
    addr = b32._address_from_witness(0, H160, OTHER.hrp)
    assert b32.witness_from_address(addr, OTHER) == (0, H160, OTHER)
    with pytest.raises(BTClibValueError, match="invalid hrp: xyz"):
        b32.witness_from_address(addr)

    mainnet_addr = b32.address_from_witness(0, H160, "mainnet")
    with pytest.raises(BTClibValueError, match="invalid hrp: bc"):
        b32.witness_from_address(mainnet_addr, OTHER)


def test_network_from_xkeyversion() -> None:
    """Accept the other chain's xkey versions, and refuse mainnet's."""
    for version in (OTHER.bip32_prv, OTHER.bip32_pub, OTHER.slip132_p2wpkh_prv):
        assert network_from_xkeyversion(version, OTHER) is OTHER
        with pytest.raises(BTClibValueError, match="unknown xkey version"):
            network_from_xkeyversion(version)

    mainnet = NETWORKS["mainnet"]
    for version in (mainnet.bip32_prv, mainnet.slip132_p2wpkh_prv):
        with pytest.raises(BTClibValueError, match="not a version of the network"):
            network_from_xkeyversion(version, OTHER)
    # SLIP132's versions are the network's too
    assert network_from_xkeyversion(mainnet.slip132_p2wsh_pub, mainnet) is mainnet


def test_prv_key_data_from_wif() -> None:
    """Take the name of a NETWORKS entry given, and keep a Network it lacks."""
    wif = b58.wif_from_prv_key(1, "testnet")
    # the prefix testnet and signet share answers testnet on its own
    assert b58.prv_key_data_from_wif(wif).network == "testnet"
    assert b58.prv_key_data_from_wif(wif, NETWORKS["signet"]).network == "signet"
    with pytest.raises(InvalidPrvKeyError, match="not a mainnet wif"):
        b58.prv_key_data_from_wif(wif, NETWORKS["mainnet"])

    other_wif = b58.wif_from_prv_key(1, OTHER)
    assert other_wif == b58encode(OTHER.wif + (1).to_bytes(32, "big") + b"\x01").decode(
        "ascii"
    )
    key = b58.prv_key_data_from_wif(other_wif, OTHER)
    assert key == PrvKeyData(1, OTHER)
    assert key.network is OTHER
    assert key.curve == OTHER.curve
    assert b58.wif_from_prv_key(key.q, key.network, key.compressed) == other_wif
    # no WIF prefix of NETWORKS is this one, so no network can be found
    with pytest.raises(BTClibValueError, match="not a WIF"):
        b58.prv_key_data_from_wif(other_wif)
    with pytest.raises(InvalidPrvKeyError, match="not a given network's wif"):
        b58.prv_key_data_from_wif(wif, OTHER)


def test_from_address() -> None:
    """Keep a NETWORKS entry's name, and a Network NETWORKS lacks."""
    signet = NETWORKS["signet"]
    for addr in (
        b32.address_from_witness(0, H160, "testnet"),
        b58.address_from_h160("p2sh", H160, "testnet"),
    ):
        assert ScriptPubKey.from_address(addr).network == "testnet"
        script_pub_key = ScriptPubKey.from_address(addr, signet)
        assert script_pub_key.network == "signet"
        assert script_pub_key.address == addr
        tx_out = TxOut.from_address(1, addr, signet)
        assert tx_out.script_pub_key.network == "signet"

    for addr in (
        b32.address_from_witness(0, H160, "mainnet"),
        b58.address_from_h160("p2pkh", H160, "mainnet"),
    ):
        with pytest.raises(BTClibValueError, match="invalid"):
            ScriptPubKey.from_address(addr, signet)

    for addr in (
        b32._address_from_witness(0, H160, OTHER.hrp),
        b58encode(OTHER.p2pkh + H160).decode("ascii"),
        b58encode(OTHER.p2sh + H160).decode("ascii"),
    ):
        script_pub_key = ScriptPubKey.from_address(addr, OTHER)
        assert script_pub_key.network is OTHER
        assert script_pub_key.address == addr
        tx_out = TxOut.from_address(1, addr, OTHER)
        assert tx_out.script_pub_key == script_pub_key
        assert tx_out.script_pub_key.network is OTHER
        # equal and hashed alike by script and network type, as ever
        assert hash(script_pub_key) == hash(ScriptPubKey(script_pub_key.script))
        assert script_pub_key == ScriptPubKey(script_pub_key.script)
        assert script_pub_key != ScriptPubKey(script_pub_key.script, "testnet")
        with pytest.raises(BTClibValueError, match="invalid"):
            ScriptPubKey.from_address(addr)


def test_the_encoders_take_the_other_chain() -> None:
    """Encode with a Network NETWORKS lacks, and read the address back."""
    key = PubKeyData(b"\x02" + bytes(range(1, 33)), OTHER, check_validity=False)
    assert key.network is OTHER
    key.assert_valid()
    assert b58.p2pkh(key) == b58encode(OTHER.p2pkh + hash160(key.sec)).decode("ascii")
    assert b32.p2wpkh(key).startswith("xyz1")
    assert b58.p2wpkh_p2sh(key) == b58.address_from_h160(
        "p2sh", hash160(b"\x00\x14" + hash160(key.sec)), OTHER
    )
    assert b58.p2sh(b"\x51", OTHER) == b58.address_from_h160(
        "p2sh", hash160(b"\x51"), OTHER
    )
    assert b32.p2wsh(b"\x51", OTHER).startswith("xyz1")
    assert b32.p2tr(bytes(32), OTHER).startswith("xyz1")
    assert b58.p2wsh_p2sh(b"\x51", OTHER) == b58.p2sh(
        b"\x00\x20" + b32._v0_witness_program_from_script(b"\x51"), OTHER
    )
    for ctor, arg in (
        (ScriptPubKey.p2sh, b"\x51"),
        (ScriptPubKey.p2wsh, b"\x51"),
    ):
        assert ctor(arg, OTHER).network is OTHER
    internal = PrvKeyData(1, OTHER).pub
    assert internal.network is OTHER
    assert ScriptPubKey.p2tr(internal, None, OTHER).network is OTHER
    assert ScriptPubKey.p2wpkh(key).network is OTHER
    assert ScriptPubKey.p2pkh(key).addresses == [ScriptPubKey.p2pkh(key).address]


def test_the_name_of_a_networks_entry_is_kept_for_a_Network() -> None:
    """A Network equal to an entry is that entry's name, in every class."""
    sec = b"\x02" + bytes(range(1, 33))
    for name, net in NETWORKS.items():
        assert PubKeyData(sec, net).network == name
        assert PubKeyData(sec, net) == PubKeyData(sec, name)
        assert hash(PubKeyData(sec, net)) == hash(PubKeyData(sec, name))
        assert PrvKeyData(1, net).network == name
        assert ScriptPubKey(b"", net).network == name
    # not the Network of the made-up chain
    assert PubKeyData(sec, OTHER) != PubKeyData(sec, "mainnet")
    assert hash(PubKeyData(sec, OTHER)) == hash(PubKeyData(sec, OTHER))


def test_a_Network_is_not_shown_by_the_private_key_repr() -> None:
    """A private key's repr names a network only by a name it knows."""
    assert repr(PrvKeyData(1, "signet")) == (
        "PrvKeyData(q=..., network='signet', compressed=True)"
    )
    assert (
        repr(PrvKeyData(1, OTHER)) == "PrvKeyData(q=..., network=..., compressed=True)"
    )


def test_a_Network_is_not_shown_by_the_mixed_networks_error() -> None:
    """A p2ms with keys of two networks names a Network without its repr."""
    mainnet_key = PubKeyData(b"\x02" + bytes(range(1, 33)))
    other_key = PubKeyData(mainnet_key.sec, OTHER)
    with pytest.raises(BTClibValueError) as excinfo:
        ScriptPubKey.p2ms(1, [mainnet_key, other_key])
    assert str(excinfo.value) == "mixed networks in m-of-n: mainnet and a given network"
    with pytest.raises(BTClibValueError) as excinfo:
        ScriptPubKey.p2ms(1, [other_key, mainnet_key])
    assert str(excinfo.value) == "mixed networks in m-of-n: a given network and mainnet"
    # two Networks NETWORKS does not hold
    third_key = PubKeyData(mainnet_key.sec, dataclasses.replace(OTHER, hrp="xyw"))
    with pytest.raises(BTClibValueError) as excinfo:
        ScriptPubKey.p2ms(1, [other_key, third_key])
    assert str(excinfo.value) == "mixed networks in m-of-n: two given networks"


def test_the_other_chain_is_written_as_json_and_read_back() -> None:
    """A TxOut on a Network NETWORKS lacks round-trips through json."""
    addr = b32._address_from_witness(0, H160, OTHER.hrp)
    tx_out = TxOut.from_address(1, addr, OTHER)
    dict_ = json.loads(json.dumps(tx_out.to_dict()))
    assert dict_["network"] == OTHER.to_dict()
    assert dict_["addresses"] == [addr]
    back = TxOut.from_dict(dict_)
    assert back == tx_out
    assert back.script_pub_key.network == OTHER
    # a name is written as it always was
    named = TxOut.from_address(1, b32.address_from_witness(0, H160, "signet"))
    assert named.to_dict()["network"] == "testnet"
    assert TxOut.from_dict(named.to_dict()) == named


def test_a_network_json_cannot_name_is_refused() -> None:
    """Refuse json that would be read back as another network, or as none."""
    addr = b32._address_from_witness(0, H160, OTHER.hrp)
    # a consensus row the tables lack
    unnamed = copy.copy(OTHER)
    row = dataclasses.replace(OTHER.consensus, name="made-up")
    object.__setattr__(unnamed, "consensus", row)
    # a row of the tables' name, with other contents
    other_row = dataclasses.replace(
        OTHER.consensus,
        subsidy_halving_interval=OTHER.consensus.subsidy_halving_interval + 1,
    )
    imposter = copy.copy(OTHER)
    object.__setattr__(imposter, "consensus", other_row)
    for net in (unnamed, imposter):
        tx_out = TxOut.from_address(1, addr, net)
        assert tx_out.script_pub_key.network is net
        with pytest.raises(BTClibValueError, match="cannot be written as json"):
            tx_out.to_dict()


def test_what_is_not_a_valid_network_is_refused() -> None:
    """Refuse a name where a Network goes, and a Network built unchecked."""
    addr = b58.address_from_h160("p2pkh", H160, "mainnet")
    with pytest.raises(BTClibTypeError, match="invalid network type: str"):
        b58.h160_from_address(addr, "mainnet")  # type: ignore[call-overload]

    invalid = Network.from_dict(
        NETWORKS["mainnet"].to_dict() | {"network_type": "neither"},
        check_validity=False,
    )
    with pytest.raises(BTClibValueError, match="invalid network type: 'neither'"):
        b32.witness_from_address(b32.address_from_witness(0, H160), invalid)


def test_a_field_refuses_what_is_not_a_valid_network() -> None:
    """Refuse an invalid Network and a wrong type in each class's field."""
    invalid = Network.from_dict(
        NETWORKS["mainnet"].to_dict() | {"network_type": "neither"},
        check_validity=False,
    )
    sec = b"\x02" + bytes(range(1, 33))
    for build in (
        lambda **kw: PubKeyData(sec, invalid, **kw),
        lambda **kw: PrvKeyData(1, invalid, **kw),
        lambda **kw: ScriptPubKey(b"", invalid, **kw),
    ):
        with pytest.raises(BTClibValueError, match="invalid network type: 'neither'"):
            build()
        # built unchecked, asked afterwards
        with pytest.raises(BTClibValueError, match="invalid network type: 'neither'"):
            build(check_validity=False).assert_valid()

    with pytest.raises(BTClibTypeError, match="invalid network type: int"):
        PubKeyData(sec, 5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid network type: int"):
        PrvKeyData(1, 5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="not a network name"):
        ScriptPubKey(b"", 5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid network type: str"):
        ScriptPubKey.from_address("bc1", "mainnet")  # type: ignore[arg-type]


def test_a_base58_address_that_starts_as_the_hrp_is_base58() -> None:
    """A base58 address may start with the hrp and a 1, in any case.

    With Litecoin's values, a p2pkh address can start `ltc1` in some case,
    and is not bech32.
    """
    ltc = Network.from_dict(
        OTHER.to_dict() | {"hrp": "ltc", "p2pkh": "30", "p2sh": "32"}
    )
    assert all(net != ltc for net in NETWORKS.values())
    addr = "LTC1yevHviBXvxyg3NYQDZaZiPnAHjjUoi"
    assert b58.h160_from_address(addr, ltc)[0] == "p2pkh"
    script_pub_key = ScriptPubKey.from_address(addr, ltc)
    assert script_pub_key.network is ltc
    assert script_pub_key.address == addr
    assert TxOut.from_address(1, addr, ltc).script_pub_key == script_pub_key
    # a bech32 address of the network is still bech32
    bech32_addr = b32._address_from_witness(0, H160, "ltc")
    assert ScriptPubKey.from_address(bech32_addr, ltc).address == bech32_addr
    # read as neither: a mixed-case string cannot be bech32, so base58's
    # refusal is the answer
    with pytest.raises(BTClibValueError, match="invalid characters"):
        ScriptPubKey.from_address("ltc1" + addr[4:], ltc)
    # a Bitcoin bech32 address is refused by hrp
    with pytest.raises(BTClibValueError, match="invalid hrp: bc"):
        ScriptPubKey.from_address(b32.address_from_witness(0, H160), ltc)
    # a bech32 address of the network with a bad checksum
    mistyped = bech32_addr[:-1] + ("q" if bech32_addr[-1] != "q" else "p")
    with pytest.raises(BTClibValueError, match="invalid checksum"):
        ScriptPubKey.from_address(mistyped, ltc)


def test_a_base58_address_that_starts_as_a_bitcoin_hrp_is_base58() -> None:
    """A `bc1` start, in any case, does not make an address bech32."""
    net = Network.from_dict(OTHER.to_dict() | {"p2pkh": "19", "p2sh": "55"})
    assert all(n != net for n in NETWORKS.values())
    for addr, script_type in (
        ("BC1j9zy8bvJEamhRteoDZPqgh6KEpWZHBe", "p2pkh"),
        ("bc15CqfrE5JqxmVYAA1CoCWXLVLSxigT7d", "p2sh"),
    ):
        assert b58.h160_from_address(addr, net)[0] == script_type
        script_pub_key = ScriptPubKey.from_address(addr, net)
        assert script_pub_key.network is net
        assert script_pub_key.address == addr
        assert TxOut.from_address(1, addr, net).script_pub_key == script_pub_key
        # without a network it is read as it always was
        with pytest.raises(BTClibValueError):
            ScriptPubKey.from_address(addr)


def test_a_mistyped_base58_address_that_starts_as_a_bitcoin_hrp() -> None:
    """The error is base58's checksum, not a mixed-case one from bech32."""
    net = Network.from_dict(OTHER.to_dict() | {"p2pkh": "19", "p2sh": "55"})
    addr = "BC1j9zy8bvJEamhRteoDZPqgh6KEpWZHBe"
    with pytest.raises(BTClibValueError, match="invalid checksum"):
        ScriptPubKey.from_address(addr[:-1] + "A", net)
