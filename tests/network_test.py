# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.network` module."""

from dataclasses import fields
from typing import Any, get_args

import pytest

from btclib.alias import NetworkField, NetworkName
from btclib.curves.curve import CURVES
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import (
    NETWORKS,
    Network,
    curve_from_xkeyversion,
    network_from_key_value,
    network_from_name,
    network_from_xkeyversion,
    network_type_from_key_value,
    network_type_from_network,
    network_type_from_xkeyversion,
    networks_from_key_value,
    networks_from_xkeyversion,
    xprvversions_from_network,
    xpubversion_from_xprvversion,
    xpubversions_from_network,
)
from tests import replace_unchecked
from tests.conftest import JsonGolden


def test_bad_network() -> None:
    """Refuse a Network whose genesis block is not 32 bytes."""
    with pytest.raises(BTClibValueError, match="invalid genesis_block length: "):
        Network(
            curve=CURVES["secp256k1"],
            genesis_block="000000000019d6689c08",  # too short
            wif=b"\x80",
            p2pkh=b"\x00",
            p2sh=b"\x05",
            hrp="bc",
            bip32_prv="0488ade4",
            bip32_pub="0488b21e",
            slip132_p2wpkh_prv="04b2430c",
            slip132_p2wpkh_pub="04b24746",
            slip132_p2wpkh_p2sh_prv="049d7878",
            slip132_p2wpkh_p2sh_pub="049d7cb2",
            slip132_p2wsh_prv="02aa7a99",
            slip132_p2wsh_pub="02aa7ed3",
            slip132_p2wsh_p2sh_prv="0295b005",
            slip132_p2wsh_p2sh_pub="0295b43f",
        )


def test_curve_from_xkeyversion() -> None:
    """Verify curve, network and type lookups for every xkey version."""
    for net_str, net in NETWORKS.items():
        all_versions = xpubversions_from_network(net_str)
        all_versions += xprvversions_from_network(net_str)
        for version in all_versions:
            # four of the five networks carry testnet's version bytes, so
            # the singular lookup answers with testnet, the oldest of
            # them: the contract issue #207 documents, and the right
            # network to re-encode with, all four agreeing on every
            # version prefix
            expected = "mainnet" if net_str == "mainnet" else "testnet"
            assert expected == network_from_xkeyversion(version)
            assert net.curve == curve_from_xkeyversion(version)
            # what the version bytes *can* say, and cannot get wrong
            assert net.network_type == network_type_from_xkeyversion(version)


def test_the_xpub_version_paired_with_an_xprv_one() -> None:
    """What neutering re-labels a key with: same network, same script type.

    The pairing is by position within a network -- bip32_prv with
    bip32_pub, and so on for the four SLIP132 pairs -- which is what
    `xprvversions_from_network` and `xpubversions_from_network` spell out,
    one network at a time. Four networks share testnet's versions, so a
    shared xprv version answers with the shared xpub version, the same
    bytes for all four.
    """
    for name in NETWORKS:
        prv_versions = xprvversions_from_network(name)
        pub_versions = xpubversions_from_network(name)
        for prv, pub in zip(prv_versions, pub_versions, strict=True):
            assert xpubversion_from_xprvversion(prv) == pub


def test_only_an_xprv_version_has_a_paired_xpub_one() -> None:
    """Keyed by the private versions, so a public one is not a key at all.

    Which is the refusal that matters: `xpubversion_from_xprvversion` of
    an xpub version would otherwise have to invent an answer for a key
    that is already public, where neutering is what this serves.
    """
    with pytest.raises(BTClibValueError, match="unknown xprv version: 0x0488b21e"):
        xpubversion_from_xprvversion(NETWORKS["mainnet"].bip32_pub)
    with pytest.raises(BTClibValueError, match="unknown xprv version: 0xdeadbeef"):
        xpubversion_from_xprvversion(bytes.fromhex("deadbeef"))


def test_space_and_caps() -> None:
    """Verify network names are stripped and lowercased before lookup."""
    net = " MainNet "
    assert xpubversions_from_network(net), f"unknown network: {net}"

    # a BTClibValueError and not the bare KeyError of an unguarded
    # NETWORKS[...]: a LookupError is not caught by an `except
    # BTClibValueError` written against this library (issue #744)
    with pytest.raises(BTClibValueError, match="unknown network"):
        net = " MainNet2 "
        xpubversions_from_network(net)

    with pytest.raises(BTClibValueError, match="unknown network"):
        xprvversions_from_network("nosuchnet")

    with pytest.raises(BTClibTypeError, match="not a network name"):
        xpubversions_from_network(42)  # type: ignore[arg-type]


def test_numbers_of_networks() -> None:
    """Verify the registry holds the five built-in networks."""
    assert len(NETWORKS) == 5


def test_the_catalogue_is_read_only() -> None:
    """Adding a network is refused, which is what the tables below rest on.

    `networks_from_xkeyversion` and the two version sets are built once
    from `NETWORKS`, so an entry added afterwards would be in the
    catalogue and in none of them -- the disagreement issue 683 recorded,
    where the scan found a registered network and the frozen lists did
    not. A `Network` is an encoding table and every field of one is the
    same for every deployment of that network, so there is nothing left
    for a caller to register: a custom signet differs in its p2p magic,
    which identifies a node and is `bitcoin_core_rpc`'s.
    """
    mutable: Any = NETWORKS
    with pytest.raises(TypeError, match="does not support item assignment"):
        mutable["custom-signet"] = NETWORKS["signet"]
    with pytest.raises(AttributeError):
        mutable.pop("signet")

    # a mapping is what the library asks of it, and all of it
    assert NETWORKS["mainnet"].hrp == "bc"
    assert "mainnet" in NETWORKS
    assert set(NETWORKS) == set(get_args(NetworkName))


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
    """Round-trip every Network through its dict and golden json."""
    for network_name, net in NETWORKS.items():
        assert net == Network.from_dict(net.to_dict())

        json_golden(f"{network_name}.json", net.to_dict())


def test_the_test_networks_differ_from_testnet_in_the_genesis_block() -> None:
    """Signet and testnet4 reuse everything of testnet but the chain.

    The wif, p2pkh, p2sh, hrp and bip32 version bytes are testnet's,
    which is the whole reason the reverse lookups have an ambiguity to
    answer for; what a network of its own buys them is a genesis block --
    and, outside this table, a p2p magic, which identifies a *node* and
    lives in `bitcoin_core_rpc` with the rest of what Core reports.
    """
    testnet = NETWORKS["testnet"].to_dict()
    for name in ("signet", "testnet4", "regtest"):
        differing = {
            key
            for key, value in NETWORKS[name].to_dict().items()
            if testnet[key] != value
        }
        expected = {"genesis_block"}
        if name == "regtest":
            expected.add("hrp")  # bcrt, where signet and testnet4 are tb
        assert differing == expected, name

    assert NETWORKS["signet"].hrp == "tb"
    assert NETWORKS["testnet4"].hrp == "tb"
    # every network is a distinct chain, and the genesis block says so
    genesis = {net.genesis_block for net in NETWORKS.values()}
    assert len(genesis) == len(NETWORKS)


# Bitcoin Core's `getblockhash 0` on each chain, which is the authority
# for this field: a genesis block is a constant nothing here computes,
# so a wrong one is wrong quietly. Mainnet's is checked once more, in
# tests/block/block_test.py, against the vendored block 1 whose
# previous_block_hash it is; every other network's is checked only here.
# Every network is named, without exception -- naming only some is how
# regtest came to hold its hash byte-reversed with the suite green
# (issue #1203), and the assertion below fails if a network is added
# here without its genesis.
_GENESIS_BLOCKS: dict[NetworkName, str] = {
    "mainnet": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    "testnet": "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
    "testnet4": "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
    "signet": "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
    "regtest": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
}


def test_genesis_block_of_every_network() -> None:
    """Pin the genesis block of every network, leaving none unpinned.

    Covering the whole table, rather than the networks a reader happens
    to name, is the point: a byte-reversed hash is still thirty-two
    well-formed bytes carrying a plausible run of zeros, so no other
    check in this file can tell it from the real one. Only the value can.
    """
    assert set(_GENESIS_BLOCKS) == set(NETWORKS)
    for name, expected in _GENESIS_BLOCKS.items():
        assert NETWORKS[name].genesis_block.hex() == expected, name


# the prefix fields, i.e. every field a reverse lookup is asked about:
# the two chain-identity fields and the curve are not prefixes, and no
# lookup in this library keys on them
_PREFIX_FIELDS: tuple[NetworkField, ...] = (
    "wif",
    "p2pkh",
    "p2sh",
    "hrp",
    "bip32_prv",
    "bip32_pub",
    "slip132_p2wpkh_prv",
    "slip132_p2wpkh_pub",
    "slip132_p2wpkh_p2sh_prv",
    "slip132_p2wpkh_p2sh_pub",
    "slip132_p2wsh_prv",
    "slip132_p2wsh_pub",
    "slip132_p2wsh_p2sh_prv",
    "slip132_p2wsh_p2sh_pub",
)


def test_no_prefix_crosses_the_main_test_boundary() -> None:
    """The invariant the network type rests on, checked rather than assumed.

    A network *name* cannot be recovered from a prefix -- four networks
    share one set of them -- but "main or test" always can, and only
    because no test network prefix equals a mainnet prefix. Every field
    against every field, not field against same field: the type would be
    just as wrong if testnet's p2sh were mainnet's p2pkh, since a caller
    asks the lookups one field at a time and a collision anywhere makes
    an answer of "main" reachable from test bytes.
    """
    mainnet_prefixes = {getattr(NETWORKS["mainnet"], f) for f in _PREFIX_FIELDS}
    for name, net in NETWORKS.items():
        if net.network_type == "main":
            assert name == "mainnet"
            continue
        for field in _PREFIX_FIELDS:
            assert getattr(net, field) not in mainnet_prefixes, (name, field)

    # so mainnet is the only network of its type, and the four test
    # networks are the rest: the shape the type is a name for
    types = [net.network_type for net in NETWORKS.values()]
    assert types.count("main") == 1
    assert types.count("test") == len(NETWORKS) - 1


def test_the_three_lookups_answer_one_question_each() -> None:
    """Candidates, canonical name, type -- and how they relate."""
    # the shared test prefixes: four candidates on the base58 fields,
    # three on the hrp, regtest's bcrt being its own
    assert networks_from_key_value("wif", b"\xef") == [
        "testnet",
        "regtest",
        "signet",
        "testnet4",
    ]
    assert networks_from_key_value("hrp", "tb") == ["testnet", "signet", "testnet4"]
    assert networks_from_key_value("hrp", "bcrt") == ["regtest"]
    assert networks_from_key_value("hrp", "bc") == ["mainnet"]

    # the singular lookup is the [0] of the plural one, everywhere
    for field in _PREFIX_FIELDS:
        for net in NETWORKS.values():
            prefix = getattr(net, field)
            candidates = networks_from_key_value(field, prefix)
            assert candidates
            assert network_from_key_value(field, prefix) == candidates[0]
            # and the type is one answer for all the candidates, which is
            # what makes taking the first of them sound
            assert len({NETWORKS[c].network_type for c in candidates}) == 1
            assert network_type_from_key_value(field, prefix) == net.network_type

    # unknown bytes: None from both, and an empty list rather than a raise
    assert networks_from_key_value("hrp", "nosuchhrp") == []
    assert network_from_key_value("hrp", "nosuchhrp") is None
    assert network_type_from_key_value("hrp", "nosuchhrp") is None


def test_the_three_xkeyversion_lookups() -> None:
    """Verify the xkeyversion lookups and their unknown-version errors."""
    for name, net in NETWORKS.items():
        for version in xprvversions_from_network(name) + xpubversions_from_network(
            name
        ):
            candidates = networks_from_xkeyversion(version)
            assert network_from_xkeyversion(version) == candidates[0]
            assert network_type_from_xkeyversion(version) == net.network_type
            expected = (
                ["mainnet"]
                if name == "mainnet"
                else [
                    "testnet",
                    "regtest",
                    "signet",
                    "testnet4",
                ]
            )
            assert candidates == expected

    # an unknown version: a BTClibValueError, which is a ValueError, so a
    # caller catching the bare ValueError still catches it
    assert networks_from_xkeyversion(b"\x00\x00\x00\x00") == []
    with pytest.raises(BTClibValueError, match="unknown xkey version: 0x00000000"):
        network_from_xkeyversion(b"\x00\x00\x00\x00")
    with pytest.raises(ValueError, match="unknown xkey version"):
        network_type_from_xkeyversion(b"\xff\xff\xff\xff")


def test_network_type_from_network() -> None:
    """Verify the name-to-type mapping, mainnet alone being main."""
    assert network_type_from_network() == "main"
    assert network_type_from_network("mainnet") == "main"
    # the same space-and-caps tolerance as xpubversions_from_network
    assert network_type_from_network(" MainNet ") == "main"
    for name in ("testnet", "regtest", "signet", "testnet4"):
        assert network_type_from_network(name) == "test"
    with pytest.raises(BTClibValueError, match="unknown network"):
        network_type_from_network("nosuchnet")


def test_the_network_type_default_is_test() -> None:
    """A Network built without one is a test network, not the real chain.

    `from_dict` is where it matters, a dict serialized before the field
    existed having no `network_type` to read: the safe direction for what
    is missing is "test", a forgotten field being no reason to claim the
    real chain.
    """
    mainnet = NETWORKS["mainnet"].to_dict()
    del mainnet["network_type"]
    assert Network.from_dict(mainnet).network_type == "test"

    # every field of mainnet, so nothing but the default is at work here
    assert Network.from_dict(mainnet).p2pkh == NETWORKS["mainnet"].p2pkh

    with pytest.raises(BTClibValueError, match="invalid network type: 'mainnet'"):
        # the type is not a network name, and the json is what says it
        Network.from_dict({**NETWORKS["mainnet"].to_dict(), "network_type": "mainnet"})


def test_a_non_str_hrp_is_a_type_error() -> None:
    """The hrp is the human-readable part of an address, so it is a str.

    Every other field goes through bytes_from_octets, which refuses what
    is not convertible; the hrp is stored as given, so assert_valid is
    where a bytes hrp -- the plausible mistake, every neighbouring field
    being bytes -- is caught.
    """
    mainnet = NETWORKS["mainnet"].to_dict()
    with pytest.raises(BTClibTypeError, match="invalid hrp type: bytes"):
        Network.from_dict({**mainnet, "hrp": b"bc"})
    with pytest.raises(BTClibTypeError, match="invalid hrp type: int"):
        Network.from_dict({**mainnet, "hrp": 0})


def test_the_literal_vocabularies_name_the_data() -> None:
    """NetworkField is every field of Network, NetworkName every network.

    Neither can be checked by mypy against what it names: one is
    resolved with getattr, the other is a dict key, and both are
    Literals precisely so that nothing of them exists at run time
    (issue #216). So the equality is asserted here rather than left to
    drift. Half of the second one mypy does cover, network.py annotating
    with NetworkName the tuple of names it loads; a member no file loads
    is the other half, and this is what sees it.
    """
    assert set(get_args(NetworkField)) == {field.name for field in fields(Network)}
    assert set(get_args(NetworkName)) == set(NETWORKS)


def test_a_network_name_no_network_has_is_refused() -> None:
    """`network_from_name` is the one place a name becomes a Network.

    A BTClibValueError and not the bare KeyError of `NETWORKS[name]`:
    KeyError is a LookupError, so a caller filtering bad input with an
    `except BTClibValueError` -- which is what this library's own
    docstrings tell it to write -- did not catch it (issue #744). The
    message names the five, a typo being the case it exists for.
    """
    for name in NETWORKS:
        assert network_from_name(name) is NETWORKS[name]
    # the tolerance issue #216 decided to keep
    assert network_from_name(" MainNet ") is NETWORKS["mainnet"]
    assert network_from_name() is NETWORKS["mainnet"]

    with pytest.raises(BTClibValueError, match="unknown network"):
        network_from_name("nosuchnet")
    with pytest.raises(BTClibValueError, match="mainnet"):
        network_from_name("")
    with pytest.raises(BTClibTypeError, match="not a network name"):
        network_from_name(42)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="not a network name"):
        network_from_name(None)  # type: ignore[arg-type]


def test_a_field_no_network_has_is_refused_rather_than_scanned_for() -> None:
    """A misspelled field name is not the fact that no network carries it.

    `getattr` raised AttributeError, and answering `[]` instead would have
    been worse: `alias.py` claimed that was the behaviour -- "a misspelled
    field name matches no network, so the lookup answers None" -- which
    would make a typo read as a statement about the prefix (issue #744).
    """
    err_msg = "unknown network field"
    for key in ("nosuchfield", "", "Curve", "datadir"):
        with pytest.raises(BTClibValueError, match=err_msg):
            networks_from_key_value(key, b"\x00")  # type: ignore[arg-type]
        with pytest.raises(BTClibValueError, match=err_msg):
            network_from_key_value(key, b"\x00")  # type: ignore[arg-type]
        with pytest.raises(BTClibValueError, match=err_msg):
            network_type_from_key_value(key, b"\x00")  # type: ignore[arg-type]

    # every field of the dataclass is one, which is the set the run-time
    # check is built from and the one NetworkField names for mypy
    for field in fields(Network):
        assert networks_from_key_value(field.name, object()) == []  # type: ignore[arg-type]


def test_the_flag_still_switches_the_check_off() -> None:
    """Verify check_validity=False builds a network and writes its dict.

    Every network above is built checked -- every one in `NETWORKS` and
    the ones the refusals raise on -- so both `if check_validity:` lines
    ran one way only. A genesis block of the wrong length is the
    invalidity to carry: `to_dict` writes it as hex whatever its width,
    where a curve of another name would not survive the lookup the dict
    is read back through.
    """
    invalid = replace_unchecked(NETWORKS["mainnet"], genesis_block=b"\x00")

    assert invalid.to_dict(check_validity=False)["genesis_block"] == "00"
    err_msg = "invalid genesis_block length: 1 bytes instead of 32"
    with pytest.raises(BTClibValueError, match=err_msg):
        invalid.to_dict()
