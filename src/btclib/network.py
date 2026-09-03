# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Network dataclass, NETWORKS, and the lookups over them.

What this module exports is the dataclass, the catalogue, the three
questions asked of a key-value pair and the three asked of an extended-key
version, plus the two version sets a caller matches against.

**A Network is an encoding table, and NETWORKS is fixed at import.** The
fields are the prefixes and version bytes a network spells its keys and
addresses with, plus the genesis block; every one of them is the same for
every deployment of that network, so there is nothing here for a caller to
register and the catalogue is a read-only mapping.

What *is* per
deployment -- a custom signet's p2p magic, which its challenge determines
-- is a fact about a node rather than about an encoding, and lives where
the node is spoken to: `bitcoin_core_rpc.magic_from_signet_challenge`, and
`BitcoinCoreFetcher(..., signet_challenge=...)` for the check it feeds.
Fixed at import is what lets the reverse lookups below be tables built
once: a network registered afterwards would be found by a scan and missed
by a precomputed index, which is the disagreement issue 683 recorded.

The one field that is not an encoding is `consensus`, and it is a
reference rather than a copy: `btclib.consensus.CONSENSUS_PARAMS` holds
the rules each of these networks validates by, this module holds the
spellings a chain's keys and addresses are written in, and a `Network`
carries the row so that the two tables cannot disagree about which
networks exist. That module imports nothing of btclib, so reading an
activation height costs no import of this one, which is the direction
that decides where the table lives.

`datadir` stays out, and this is where that decision is recorded: it is
where this package keeps the five json files loaded at the bottom of this
file, so it answers a question about the installation and not one about a
network, and the only code that reads it is the loop it is written for --
`btclib.curves.curve` has a `datadir` of its own for its own catalogues.
It is still `btclib.network.datadir` for a caller who wants the path.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from types import MappingProxyType
from typing import Any

from btclib.alias import NetworkField, NetworkName, NetworkType, Octets
from btclib.consensus import CONSENSUS_PARAMS, ConsensusParams
from btclib.curves import Curve
from btclib.curves.curve import CURVES, _assert_valid_ec
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import assert_type, bytes_from_octets, fields_from_json_object

__all__ = [
    "NETWORKS",
    "XPRV_VERSIONS_ALL",
    "XPUB_VERSIONS_ALL",
    "Network",
    "curve_from_xkeyversion",
    "network_from_key_value",
    "network_from_name",
    "network_from_xkeyversion",
    "network_type_from_key_value",
    "network_type_from_network",
    "network_type_from_xkeyversion",
    "networks_from_key_value",
    "networks_from_xkeyversion",
    "xprvversions_from_network",
    "xpubversion_from_xprvversion",
    "xpubversions_from_network",
]

_KEY_SIZE: list[tuple[NetworkField, int]] = [
    ("genesis_block", 32),
    ("wif", 1),
    ("p2pkh", 1),
    ("p2sh", 1),
    ("bip32_prv", 4),
    ("bip32_pub", 4),
    ("slip132_p2wpkh_prv", 4),
    ("slip132_p2wpkh_pub", 4),
    ("slip132_p2wpkh_p2sh_prv", 4),
    ("slip132_p2wpkh_p2sh_pub", 4),
    ("slip132_p2wsh_prv", 4),
    ("slip132_p2wsh_pub", 4),
    ("slip132_p2wsh_p2sh_prv", 4),
    ("slip132_p2wsh_p2sh_pub", 4),
]


def _curve_from_name(name: Any) -> Curve:
    """Return the curve `to_dict` names, refusing what names none.

    `CURVES[...]` alone answers an unknown name with a `KeyError`, which
    is neither a `BTClibException` nor a `ValueError`, and an unhashable
    one with a `TypeError` about dict keys -- the field `from_dict` reads
    before the constructor, so `assert_valid` never sees either.
    """
    assert_type(name, str, "curve name")
    if name not in CURVES:
        raise BTClibValueError(f"unknown curve: {name}")
    return CURVES[name]


def _consensus_from_name(name: Any) -> ConsensusParams:
    """Return the consensus row a name names, refusing what names none.

    `_curve_from_name` above, for the other table a network dict points
    at, and refusing for the same two reasons: `CONSENSUS_PARAMS[...]`
    answers an unknown name with a `KeyError` and an unhashable one with
    a `TypeError` about dict keys, neither of which this library tells a
    caller to catch.
    """
    assert_type(name, str, "consensus name")
    if name not in CONSENSUS_PARAMS:
        raise BTClibValueError(f"unknown consensus parameters: {name}")
    return CONSENSUS_PARAMS[name]


@dataclass(frozen=True)
class Network:
    """The encoding table of one network: prefixes, versions, genesis.

    What tells a mainnet spelling from a test one -- wif and address
    prefixes, the bech32 hrp, the BIP32 and SLIP132 version bytes --
    plus the genesis block hash and the consensus row of the chain those
    spell keys for. No consensus parameter is written out here, `consensus`
    being a reference to `btclib.consensus`'s own table; and no p2p one at
    all: the message start belongs to the code that speaks to a node,
    `bitcoin_core_rpc.magic_from_chain` being where it is, because a
    custom signet's is a function of its challenge and therefore not a
    field any table can hold. NETWORKS holds the built-in instances, and
    the ``*_from_network`` and ``*_from_xkeyversion`` functions below
    are the lookups.
    """

    curve: Curve

    # "main" or "test": see NetworkType in alias.py for why this is the
    # one question the version bytes can still answer, and the three
    # network_type_from_* functions below for the answering
    network_type: NetworkType

    # the rules this chain validates by, one of btclib.consensus's rows.
    # A field and not a lookup keyed on something else: a Network carries
    # no name of its own, and a caller building one for a chain this
    # library does not ship has a row to hand it
    consensus: ConsensusParams

    genesis_block: bytes

    # base58 wif starts with 'K' or 'L' if compressed else '5'
    wif: bytes

    # base58 address starts with '1'
    p2pkh: bytes
    # base58 address starts with '3'
    p2sh: bytes

    # bech32_address starts with 'bc1'
    hrp: str

    # slip132 "m / 44h / 0h" p2pkh or p2sh
    bip32_prv: bytes  # xprv
    bip32_pub: bytes  # xpub

    # slip132 "m / 49h / 0h" p2wpkh-p2sh (i.e., p2sh-wrapped p2wpkh)
    slip132_p2wpkh_p2sh_prv: bytes  # yprv
    slip132_p2wpkh_p2sh_pub: bytes  # ypub

    # slip132 "m / 49h / 0h" p2wsh-p2sh (i.e., p2sh-wrapped p2wsh)
    slip132_p2wsh_p2sh_prv: bytes  # Yprv
    slip132_p2wsh_p2sh_pub: bytes  # Ypub

    # slip132 "m / 84h / 0h" p2wpkh
    slip132_p2wpkh_prv: bytes  # zprv
    slip132_p2wpkh_pub: bytes  # zpub

    # slip132 "m / 84h / 0h" p2wsh
    slip132_p2wsh_prv: bytes  # Zprv
    slip132_p2wsh_pub: bytes  # Zpub

    def __init__(
        self,
        curve: Curve,
        genesis_block: Octets,
        wif: Octets,
        p2pkh: Octets,
        p2sh: Octets,
        hrp: str,
        bip32_prv: Octets,
        bip32_pub: Octets,
        slip132_p2wpkh_prv: Octets,
        slip132_p2wpkh_pub: Octets,
        slip132_p2wpkh_p2sh_prv: Octets,
        slip132_p2wpkh_p2sh_pub: Octets,
        slip132_p2wsh_prv: Octets,
        slip132_p2wsh_pub: Octets,
        slip132_p2wsh_p2sh_prv: Octets,
        slip132_p2wsh_p2sh_pub: Octets,
        # last and defaulted, where the field is declared second: it is
        # the one field that is not bytes to be spelled out, and "test" is
        # the safe direction for a default. Defaulting to "main" would let
        # a forgotten argument claim a made-up chain is the real one
        network_type: NetworkType = "test",
        *,
        # keyword-only and required, where network_type is positional and
        # defaulted: no row is the safe answer for a network nobody named,
        # the way "test" is the safe network type, so this is asked for
        # rather than guessed
        consensus: ConsensusParams,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "curve", curve)
        object.__setattr__(self, "network_type", network_type)
        object.__setattr__(self, "consensus", consensus)
        object.__setattr__(self, "genesis_block", bytes_from_octets(genesis_block))

        object.__setattr__(self, "wif", bytes_from_octets(wif))

        object.__setattr__(self, "p2pkh", bytes_from_octets(p2pkh))
        object.__setattr__(self, "p2sh", bytes_from_octets(p2sh))

        object.__setattr__(self, "hrp", hrp)

        object.__setattr__(self, "bip32_prv", bytes_from_octets(bip32_prv))
        object.__setattr__(self, "bip32_pub", bytes_from_octets(bip32_pub))

        object.__setattr__(
            self, "slip132_p2wpkh_prv", bytes_from_octets(slip132_p2wpkh_prv)
        )
        object.__setattr__(
            self, "slip132_p2wpkh_pub", bytes_from_octets(slip132_p2wpkh_pub)
        )

        object.__setattr__(
            self, "slip132_p2wpkh_p2sh_prv", bytes_from_octets(slip132_p2wpkh_p2sh_prv)
        )
        object.__setattr__(
            self, "slip132_p2wpkh_p2sh_pub", bytes_from_octets(slip132_p2wpkh_p2sh_pub)
        )

        object.__setattr__(
            self, "slip132_p2wsh_prv", bytes_from_octets(slip132_p2wsh_prv)
        )
        object.__setattr__(
            self, "slip132_p2wsh_pub", bytes_from_octets(slip132_p2wsh_pub)
        )

        object.__setattr__(
            self, "slip132_p2wsh_p2sh_prv", bytes_from_octets(slip132_p2wsh_p2sh_prv)
        )
        object.__setattr__(
            self, "slip132_p2wsh_p2sh_pub", bytes_from_octets(slip132_p2wsh_p2sh_pub)
        )

        if check_validity:
            self.assert_valid()

    def to_dict(self, *, check_validity: bool = True) -> dict[str, str | None]:
        """Return the network as a dict of hex strings and names."""
        if check_validity:
            self.assert_valid()

        return {
            "curve": self.curve.name,
            "network_type": self.network_type,
            # the row's name and not its fields: this dict is the network's
            # own spellings, and the consensus parameters are written once,
            # where they are transcribed
            "consensus": self.consensus.name,
            "genesis_block": self.genesis_block.hex(),
            "wif": self.wif.hex(),
            "p2pkh": self.p2pkh.hex(),
            "p2sh": self.p2sh.hex(),
            "hrp": self.hrp,
            "bip32_prv": self.bip32_prv.hex(),
            "bip32_pub": self.bip32_pub.hex(),
            "slip132_p2wpkh_prv": self.slip132_p2wpkh_prv.hex(),
            "slip132_p2wpkh_pub": self.slip132_p2wpkh_pub.hex(),
            "slip132_p2wpkh_p2sh_prv": self.slip132_p2wpkh_p2sh_prv.hex(),
            "slip132_p2wpkh_p2sh_pub": self.slip132_p2wpkh_p2sh_pub.hex(),
            "slip132_p2wsh_prv": self.slip132_p2wsh_prv.hex(),
            "slip132_p2wsh_pub": self.slip132_p2wsh_pub.hex(),
            "slip132_p2wsh_p2sh_prv": self.slip132_p2wsh_p2sh_prv.hex(),
            "slip132_p2wsh_p2sh_pub": self.slip132_p2wsh_p2sh_pub.hex(),
        }

    @classmethod
    def from_dict(
        cls: type[Network], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> Network:
        """Build a Network from the dict shape to_dict writes."""
        dict_ = fields_from_json_object(dict_, "network")
        return cls(
            _curve_from_name(dict_["curve"]),
            dict_["genesis_block"],
            dict_["wif"],
            dict_["p2pkh"],
            dict_["p2sh"],
            dict_["hrp"],
            dict_["bip32_prv"],
            dict_["bip32_pub"],
            dict_["slip132_p2wpkh_prv"],
            dict_["slip132_p2wpkh_pub"],
            dict_["slip132_p2wpkh_p2sh_prv"],
            dict_["slip132_p2wpkh_p2sh_pub"],
            dict_["slip132_p2wsh_prv"],
            dict_["slip132_p2wsh_pub"],
            dict_["slip132_p2wsh_p2sh_prv"],
            dict_["slip132_p2wsh_p2sh_pub"],
            # .get, alone among these keys: a dict serialized before the
            # field existed still loads, as a test network
            dict_.get("network_type", "test"),
            consensus=_consensus_from_name(dict_["consensus"]),
            check_validity=check_validity,
        )

    def assert_valid(self) -> None:
        """Refuse a field of the wrong type, size, or network_type value."""
        # the curve is what every key of this network lives on, and it is
        # read for its own fields wherever the network is: `curve.name`
        # goes into to_dict, and `network_from_name(net).curve` is what
        # the key converters compare an `ec` against. Same check as the
        # one in front of those, `curve._assert_valid_ec`
        _assert_valid_ec(self.curve)

        # the hrp is the human-readable part of every bech32 address of this
        # network, so it has to be a str. An isinstance check, because
        # str(self.hrp) would check nothing: str() accepts every object
        # there is. The bytes() calls below are the same guard for the
        # bytes fields, TypeError being what they raise for a field
        # rebound to something else
        assert_type(self.hrp, str, "hrp")

        # the row a dict points at is resolved by from_dict, so what this
        # catches is a Network built in code with something else in the
        # field -- and every reader of it below expects the dataclass
        assert_type(self.consensus, ConsensusParams, "consensus")

        # NetworkType is a Literal, which is a mypy fact and not a runtime
        # one: from_dict takes whatever the json says, so this is the only
        # place a third network type can be refused
        if self.network_type not in {"main", "test"}:
            err_msg = f"invalid network type: {self.network_type!r}"
            raise BTClibValueError(err_msg)

        for key, size in _KEY_SIZE:
            value = bytes(getattr(self, key))
            if len(value) != size:
                err_msg = f"invalid {key} length: "
                err_msg += f"{len(value)} bytes"
                err_msg += f" instead of {size}"
                raise BTClibValueError(err_msg)


datadir = Path(__file__).parent / "_data"
# order matters, and it is the order of the reverse lookups below: the
# first network holding a version prefix is the one they answer with, so
# testnet, the oldest, answers for the four networks that share its
# prefixes, and appending a newer network cannot change any answer.
# mainnet first, then the test networks oldest to newest -- signet.json
# and testnet4.json differ from testnet.json in the genesis block, and in
# nothing else.
#
# Annotated, where inference would widen it to tuple[str, ...]: this is
# what ties NetworkName to the data it names, a sixth file loaded here
# without a sixth member there being a mypy error
_network_names: tuple[NetworkName, ...] = (
    "mainnet",
    "testnet",
    "regtest",
    "signet",
    "testnet4",
)
# the loop's own names are underscored: a for target and a with target are
# module globals like any other, so `net`, `filename` and the open file
# would be three names of this module that no caller has any use for
_networks: dict[str, Network] = {}
for _net in _network_names:
    _filename = datadir / f"{_net}.json"
    with _filename.open(encoding="ascii") as _network_file:
        _networks[_net] = Network.from_dict(json.load(_network_file))

# the networks btclib ships, by name. A mapping and not a dict, because the
# tables below are built from it once and an entry added afterwards would be
# in the catalogue and in none of them. `NETWORKS[name]`, `name in
# NETWORKS`, `.items()` and `.values()` are what this library and its
# callers do with it, and all four are what a mapping is
NETWORKS: Mapping[str, Network] = MappingProxyType(_networks)

# what a `key: NetworkField` may name, off the dataclass rather than off
# alias.NetworkField's Literal: the Literal is what mypy holds a caller
# to, and this is the same vocabulary at run time, for the callers mypy
# never sees. network_test.py asserts the two are the same set
_NETWORK_FIELDS = frozenset(field.name for field in fields(Network))


# Everything below is derived from NETWORKS, in one pass over it, because
# every one of these questions is "which network carries these bytes" asked
# from a different side -- and a second pass is a second thing to go stale.
# Insertion order is the order above, so the first candidate of a shared
# prefix is the oldest network holding it.
_XPRV_VERSIONS: dict[str, tuple[bytes, ...]] = {}
_XPUB_VERSIONS: dict[str, tuple[bytes, ...]] = {}
_NETWORKS_FROM_XKEYVERSION: dict[bytes, tuple[str, ...]] = {}
# the sibling of an xprv version: what neutering re-labels a key with,
# looked up rather than found by position in the two sets below
_XPUB_VERSION_FROM_XPRV_VERSION: dict[bytes, bytes] = {}

for _name, _network in _networks.items():
    # the five kinds of xkey -- BIP32's and SLIP132's four -- in one order
    # for both halves: what pairs a prv version with its pub is this
    # pairing, and nothing about where either lands in the sets below
    _prv_versions = (
        _network.bip32_prv,
        _network.slip132_p2wsh_p2sh_prv,
        _network.slip132_p2wpkh_p2sh_prv,
        _network.slip132_p2wpkh_prv,
        _network.slip132_p2wsh_prv,
    )
    _pub_versions = (
        _network.bip32_pub,
        _network.slip132_p2wsh_p2sh_pub,
        _network.slip132_p2wpkh_p2sh_pub,
        _network.slip132_p2wpkh_pub,
        _network.slip132_p2wsh_pub,
    )
    _XPRV_VERSIONS[_name] = _prv_versions
    _XPUB_VERSIONS[_name] = _pub_versions
    for _prv, _pub in zip(_prv_versions, _pub_versions, strict=True):
        # setdefault, not assignment: the four test networks carry one set
        # of versions between them, so testnet -- first of the four -- is
        # what a shared version keeps answering
        _XPUB_VERSION_FROM_XPRV_VERSION.setdefault(_prv, _pub)
    # dict.fromkeys and not the concatenation itself: a network naming
    # itself twice for one version is what a prv version equal to a pub
    # one would produce, and this is exact without a condition that the
    # shipped data never takes
    for _version in dict.fromkeys(_prv_versions + _pub_versions):
        _NETWORKS_FROM_XKEYVERSION[_version] = (
            *_NETWORKS_FROM_XKEYVERSION.get(_version, ()),
            _name,
        )

# every xkey version this library knows, private and public. Sets, because
# each answers one question -- is this a private version, is this a public
# one -- and the four test networks carry one set of versions between them,
# so a list of them was four fifths repetition in an order that meant
# nothing. `xpubversion_from_xprvversion` is the pairing the parallel lists
# were also used for, and `xprvversions_from_network` the versions of one
# network
XPRV_VERSIONS_ALL = frozenset(_XPUB_VERSION_FROM_XPRV_VERSION)
XPUB_VERSIONS_ALL = frozenset(_XPUB_VERSION_FROM_XPRV_VERSION.values())


# Three questions, three functions, and one answer underneath each trio --
# because "which networks carry these bytes" is the only fact here and it
# belongs in one place. Which of the three to reach for:
#
# - networks_from_*: every candidate, oldest first. The whole truth, for
#   a caller that wants to show it or count it
# - network_from_*: the oldest candidate. The right answer for byte-level
#   work -- re-encoding an address, reading a curve, finding the sibling
#   version of an xprv -- because every candidate agrees on those bytes.
#   It is not an answer to "which chain is this"
# - network_type_from_*: "main" or "test". The honest answer to "is this
#   the real thing", and the one this module recommends: unlike the
#   singular name it cannot be wrong, no prefix crossing that boundary
#
# What none of them is is a substitute for the forward check, which is
# what a caller who *knows* the chain should use: a version among
# xprvversions_from_network(net), a prefix equal to NETWORKS[net].wif.
# That check is exact for all five networks, and issue #207 records the
# WIF path having got this wrong by comparing reverse-lookup names.
def networks_from_key_value(
    key: NetworkField, prefix: str | bytes | Curve
) -> list[str]:
    """Return every network with the (key, value) pair, oldest first.

    The list is the ordinal the singular lookups below hide: [0] is the
    canonical answer, [n] the nth network sharing those bytes -- and its
    length says how many there are, which is what "testnet" alone could
    never say. Mostly it holds the four test networks (one set of
    prefixes between them) or exactly one (mainnet's bytes, and
    regtest's bcrt hrp, are unique).

    A scan where the xkey-version trio is a table, and not for want of a
    key: `prefix` is whatever a caller passes, so a dict would answer an
    unhashable one with a TypeError where the comparison answers "no
    network carries this". Five networks and one `getattr` each is what
    that costs.

    A `key` that names no field of Network is refused rather than scanned
    for: `getattr` would raise `AttributeError`, which is neither a
    `ValueError` nor something a caller of this library is told to catch,
    and answering `[]` instead -- "no network carries this prefix" -- would
    be worse, a typo in a field name reading as a fact about the prefix.
    """
    if key not in _NETWORK_FIELDS:
        err_msg = f"unknown network field: '{key}'"
        err_msg += f"; it must be one of {sorted(_NETWORK_FIELDS)}"
        raise BTClibValueError(err_msg)
    return [
        network_str
        for network_str, network in NETWORKS.items()
        if getattr(network, key) == prefix
    ]


def network_from_key_value(
    key: NetworkField, prefix: str | bytes | Curve
) -> str | None:
    """Return the oldest network with the (key, value) pair, else None.

    Oldest, i.e. 'testnet' for the prefixes testnet, regtest, signet and
    testnet4 share, 'regtest' for the bcrt hrp that is regtest's alone,
    'mainnet' for mainnet's. That is the network to encode *with*: the
    candidates differ in the genesis block, which no encoding here reads,
    so the bytes it yields are right for all of them.
    It is not an answer to "which chain is this": use
    network_type_from_key_value for what the prefix does say, or
    networks_from_key_value for the candidates.
    """
    networks = networks_from_key_value(key, prefix)
    return networks[0] if networks else None


def network_type_from_key_value(
    key: NetworkField, prefix: str | bytes | Curve
) -> NetworkType | None:
    """Return "main" or "test" from a (key, value) pair, None if unknown.

    Unambiguous where the network name is not: no prefix of a test
    network equals a mainnet prefix, on any field, so every candidate
    has the same type and the first one speaks for all.
    """
    networks = networks_from_key_value(key, prefix)
    return NETWORKS[networks[0]].network_type if networks else None


def _validated_network_name(network: str) -> str:
    """Return the name of a network, normalized, or refuse it.

    `strip().lower()` is the tolerance issue #216 decided to keep, and the
    reason `alias.NetworkName` is not the annotation of a `network`
    parameter: the set accepted is wider than the five spellings it
    names.
    """
    if not isinstance(network, str):
        raise BTClibTypeError(f"not a network name: {network!r}")
    name = network.strip().lower()
    if name not in NETWORKS:
        err_msg = f"unknown network: '{network}'"
        err_msg += f"; it must be one of {sorted(NETWORKS)}"
        raise BTClibValueError(err_msg)
    return name


def network_from_name(network: str = "mainnet") -> Network:
    """Return the Network a name names, in any case and spaced how it likes.

    The one place a `network: str` becomes a `Network`, and what every
    caller of a network name should reach for rather than indexing
    `NETWORKS` itself: a name no network has is refused here, where
    `NETWORKS[network]` answers a bare `KeyError`. That matters beyond
    tidiness, `KeyError` being a `LookupError` -- so no `except
    BTClibValueError` written against this library catches it, and a
    caller filtering bad input sees an exception nothing told it to
    expect.

    `NETWORKS` stays exported for a caller iterating the five, which is a
    different question from resolving one name.
    """
    return NETWORKS[_validated_network_name(network)]


def network_type_from_network(network: str = "mainnet") -> NetworkType:
    """Return the "main"/"test" type of a network name."""
    return network_from_name(network).network_type


def xpubversions_from_network(network: str = "mainnet") -> list[bytes]:
    """Return every xpub version of the network, BIP32 and SLIP132.

    A fresh list off the table built at import, so that a caller sorting
    or trimming the answer is not editing the table every other lookup
    reads.
    """
    return list(_XPUB_VERSIONS[_validated_network_name(network)])


def xprvversions_from_network(network: str = "mainnet") -> list[bytes]:
    """Return every xprv version of the network, BIP32 and SLIP132."""
    return list(_XPRV_VERSIONS[_validated_network_name(network)])


def xpubversion_from_xprvversion(xprvversion: bytes) -> bytes:
    """Return the xpub version paired with an xprv version.

    The same network and the same script type: xprv to xpub, yprv to ypub,
    Zprv to Zpub. What neutering re-labels a key with, and the one
    question here a version *pair* answers rather than a version alone --
    which is why it is a table and not two positions in the sets above.
    """
    if xprvversion not in _XPUB_VERSION_FROM_XPRV_VERSION:
        err_msg = f"unknown xprv version: 0x{xprvversion.hex()}"
        raise BTClibValueError(err_msg)
    return _XPUB_VERSION_FROM_XPRV_VERSION[xprvversion]


def networks_from_xkeyversion(xkeyversion: bytes) -> list[str]:
    """Return every network with the xkey version prefix, oldest first.

    One lookup, where asking each network in turn rebuilt two version
    lists per network asked -- issue 683 measured what that cost the
    address path, and the table it answers from is why NETWORKS is fixed
    at import.
    """
    return list(_NETWORKS_FROM_XKEYVERSION.get(xkeyversion, ()))


def network_from_xkeyversion(xkeyversion: bytes) -> str:
    """Return the oldest network with the xkey version prefix.

    'testnet' for a testnet, regtest, signet or testnet4 version, those
    four being the same bytes: the network to derive and re-encode
    *with*, since all four agree on every version prefix. It is not an
    answer to "which chain is this" -- network_type_from_xkeyversion is
    what a prefix can answer, networks_from_xkeyversion the candidates.
    """
    networks = networks_from_xkeyversion(xkeyversion)
    if not networks:
        # BTClibValueError subclasses ValueError, so an `except
        # ValueError` caller catches this too
        err_msg = f"unknown xkey version: 0x{xkeyversion.hex()}"
        raise BTClibValueError(err_msg)
    return networks[0]


def network_type_from_xkeyversion(xkeyversion: bytes) -> NetworkType:
    """Return "main" or "test" from an xkey version prefix.

    Unambiguous where the network name is not: no test network version
    equals a mainnet one, so an xprv is either the real thing or not.
    """
    return NETWORKS[network_from_xkeyversion(xkeyversion)].network_type


def curve_from_xkeyversion(xkeyversion: bytes) -> Curve:
    """Return the curve of the network the version bytes belong to."""
    network = network_from_xkeyversion(xkeyversion)
    return NETWORKS[network].curve
