# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the per-network consensus table.

`CONSENSUS_PARAMS` is a transcription, so what a test can do for it is
say what it was transcribed from: `_CHAINPARAMS` below writes Core's
values out a second time, off the same lines of the same blob the module
cites, and the first test compares them field by field. A value edited in
one of the two places is then a failing test rather than a silent
agreement -- which is the whole of what a table copied from another
project can be held to, short of building that project.

Two of them are not restatements but derivations, and are the stronger
half. `pow_limit_bits` is compared against `bits_from_target` of Core's
own 32-byte `powLimit`, so the compact form is computed here rather than
read off the module; and `script_flags_at` is compared against Core's
`GetBlockScriptFlags` written out as a rule -- the three flags on for
every block, the four gated on a buried deployment, and the exception
looked up by hash -- rather than against a table of answers.

The blob is Bitcoin Core v31.1, `bitcoin/bitcoin@9be056a8a7`. A tag and
not a branch tip, so the line numbers beside each row cannot move under
the citation; `src/btclib/consensus.py` says why that release.
"""

from __future__ import annotations

from dataclasses import fields
from typing import Any

import pytest

from btclib.block.proof_of_work import bits_from_target
from btclib.consensus import CONSENSUS_PARAMS, ConsensusParams
from btclib.exceptions import BTClibTypeError
from btclib.network import NETWORKS
from btclib.script.engine.flags import NO_FLAGS, ScriptFlag

# Core's own `powLimit`, the 32 bytes `uint256{"..."}` spells, per
# network. The module stores the compact form of each; that this is what
# it is the compact form *of* is what the derivation below asks
_POW_LIMIT = {
    "mainnet": "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "testnet": "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "regtest": "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "signet": "00000377ae000000000000000000000000000000000000000000000000000000",
    "testnet4": "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

# src/kernel/chainparams.cpp, at the tag above: the class of each chain
# type, read at the lines the module's own rows cite. `bip30_exceptions`
# is src/validation.cpp's `IsBIP30Repeat` instead, which is where Core
# hardcodes the pair rather than keeping it in the params struct
_CHAINPARAMS: dict[str, dict[str, Any]] = {
    "mainnet": {
        "subsidy_halving_interval": 210000,
        "bip34_height": 227931,
        "bip66_height": 363725,
        "bip65_height": 388381,
        "csv_height": 419328,
        "segwit_height": 481824,
        "pow_allow_min_difficulty_blocks": False,
        "enforce_bip94": False,
        "pow_no_retargeting": False,
        "minimum_chain_work": int(
            "0000000000000000000000000000000000000001128750f82f4c366153a3a030", 16
        ),
        "bip30_exceptions": (
            (
                91842,
                bytes.fromhex(
                    "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
                ),
            ),
            (
                91880,
                bytes.fromhex(
                    "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
                ),
            ),
        ),
        "script_flag_exceptions": (
            (
                bytes.fromhex(
                    "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
                ),
                (),
            ),
            (
                bytes.fromhex(
                    "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
                ),
                ("P2SH", "WITNESS"),
            ),
        ),
    },
    "testnet": {
        "subsidy_halving_interval": 210000,
        "bip34_height": 21111,
        "bip66_height": 330776,
        "bip65_height": 581885,
        "csv_height": 770112,
        "segwit_height": 834624,
        "pow_allow_min_difficulty_blocks": True,
        "enforce_bip94": False,
        "pow_no_retargeting": False,
        "minimum_chain_work": int(
            "0000000000000000000000000000000000000000000017dde1c649f3708d14b6", 16
        ),
        "bip30_exceptions": (),
        "script_flag_exceptions": (
            (
                bytes.fromhex(
                    "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"
                ),
                (),
            ),
        ),
    },
    "regtest": {
        "subsidy_halving_interval": 150,
        "bip34_height": 1,
        "bip66_height": 1,
        "bip65_height": 1,
        "csv_height": 1,
        # zero, alone among the five buried deployments and alone among
        # the networks: segwit binds on regtest from the genesis block
        "segwit_height": 0,
        "pow_allow_min_difficulty_blocks": True,
        # `opts.enforce_bip94` at chainparams.cpp:579, and the option's
        # own default is false at chainparams.h:154: what a regtest node
        # runs with, `-test=bip94` not being passed
        "enforce_bip94": False,
        "pow_no_retargeting": True,
        # `uint256{}`, which is no work at all: a chain mined for a test
        # never leaves initial block download on this comparison
        "minimum_chain_work": 0,
        "bip30_exceptions": (),
        "script_flag_exceptions": (),
    },
    "signet": {
        "subsidy_halving_interval": 210000,
        "bip34_height": 1,
        "bip66_height": 1,
        "bip65_height": 1,
        "csv_height": 1,
        "segwit_height": 1,
        "pow_allow_min_difficulty_blocks": False,
        "enforce_bip94": False,
        "pow_no_retargeting": False,
        # the default signet's, which chainparams assigns above the class
        # body's own block: a custom challenge gets `uint256{}` instead
        "minimum_chain_work": int(
            "00000000000000000000000000000000000000000000000000000b463ea0a4b8", 16
        ),
        "bip30_exceptions": (),
        "script_flag_exceptions": (),
    },
    "testnet4": {
        "subsidy_halving_interval": 210000,
        "bip34_height": 1,
        "bip66_height": 1,
        "bip65_height": 1,
        "csv_height": 1,
        "segwit_height": 1,
        "pow_allow_min_difficulty_blocks": True,
        # true on testnet4 alone, the chain BIP94 was written for
        "enforce_bip94": True,
        "pow_no_retargeting": False,
        "minimum_chain_work": int(
            "0000000000000000000000000000000000000000000009a0fe15d0177d086304", 16
        ),
        "bip30_exceptions": (),
        "script_flag_exceptions": (),
    },
}

# Core's GetBlockScriptFlags, as the rule rather than as an answer: the
# three it turns on for every block of every chain, and the four it asks
# a buried deployment about, each named by the field holding the height
_ALWAYS_ON = ScriptFlag.P2SH | ScriptFlag.WITNESS | ScriptFlag.TAPROOT
_GATED = (
    ("bip66_height", ScriptFlag.DERSIG),
    ("bip65_height", ScriptFlag.CHECKLOCKTIMEVERIFY),
    ("csv_height", ScriptFlag.CHECKSEQUENCEVERIFY),
    ("segwit_height", ScriptFlag.NULLDUMMY),
)


def test_the_transcription_covers_every_field_a_row_has() -> None:
    """Every field of a row is one `_CHAINPARAMS` holds to Core's value.

    The test below walks `_CHAINPARAMS`, so a field added to
    `ConsensusParams` and left out of the table above runs no assertion
    rather than failing one -- which is the defect this has the shape of,
    and it is how a field arrives: beside the others, in the dataclass
    first.

    Two fields are held elsewhere and are named here rather than left to
    be noticed: `name` has nothing in Core to compare against, being
    btclib's own key into `CONSENSUS_PARAMS`, and
    `test_the_table_answers_for_the_networks_the_encodings_name` holds
    it; `pow_limit_bits` is derived from `_POW_LIMIT` rather than
    restated, which is the stronger check and is why it is not in the
    table above.
    """
    held_elsewhere = {"name", "pow_limit_bits"}
    assert {f.name for f in fields(ConsensusParams)} == {
        *held_elsewhere,
        *_CHAINPARAMS["mainnet"],
    }
    assert set(_POW_LIMIT) == set(_CHAINPARAMS)
    for network, transcribed in _CHAINPARAMS.items():
        assert set(transcribed) == set(_CHAINPARAMS["mainnet"]), network


@pytest.mark.parametrize("network", sorted(_CHAINPARAMS))
def test_every_field_is_the_one_core_carries(network: str) -> None:
    """Compare each field of a row with the transcription above."""
    row = CONSENSUS_PARAMS[network]
    for field, expected in _CHAINPARAMS[network].items():
        assert getattr(row, field) == expected, (network, field)


@pytest.mark.parametrize("network", sorted(_POW_LIMIT))
def test_the_pow_limit_is_the_compact_form_of_cores_own(network: str) -> None:
    """Derive `pow_limit_bits` from Core's 32-byte powLimit.

    The compact form rounds down, so this is not a round trip and cannot
    be written as one: `target_from_bits` of the answer is below Core's
    value for every network but signet. What the encoding preserves is
    the comparison, the next target the compact form can express above
    the rounded one being already above Core's own limit.
    """
    core_limit = bytes.fromhex(_POW_LIMIT[network])
    assert CONSENSUS_PARAMS[network].pow_limit_bits == bits_from_target(core_limit)


def test_the_table_answers_for_the_networks_the_encodings_name() -> None:
    """Every network of NETWORKS has a row, and carries that row.

    The two tables are keyed by the same names on purpose: a network
    reachable from one and not the other is what having a single
    `consensus` field on `Network` is there to make impossible.
    """
    assert set(CONSENSUS_PARAMS) == set(NETWORKS)
    for name, row in CONSENSUS_PARAMS.items():
        assert row.name == name
        assert NETWORKS[name].consensus is row


def test_the_table_is_read_only() -> None:
    """Refuse a row assigned into the catalogue after import.

    `NETWORKS` is fixed at import for the reason its own module gives,
    and every `Network` in it holds one of these rows: a row replaced
    here afterwards would answer in this table and nowhere else.
    """
    mutable: Any = CONSENSUS_PARAMS
    with pytest.raises(TypeError, match="does not support item assignment"):
        mutable["mainnet"] = CONSENSUS_PARAMS["regtest"]


def test_a_row_is_hashable_as_the_network_holding_it_is() -> None:
    """Verify a row can be a dict key, which `Network` needs it to be."""
    assert len(set(CONSENSUS_PARAMS.values())) == len(CONSENSUS_PARAMS)
    assert hash(NETWORKS["mainnet"]) == hash(NETWORKS["mainnet"])


@pytest.mark.parametrize("network", sorted(_CHAINPARAMS))
def test_script_flags_at_is_cores_get_block_script_flags(network: str) -> None:
    """Answer each activation height and its neighbours as Core does.

    Every height at which the answer can change is asked about, and the
    one below it: the four buried deployments' own heights, and zero,
    which is where segwit binds on regtest and no rule binds anywhere
    else.
    """
    row = CONSENSUS_PARAMS[network]
    heights = {0}
    for field, _ in _GATED:
        at = getattr(row, field)
        heights |= {at - 1, at, at + 1}
    for height in sorted(h for h in heights if h >= 0):
        expected = _ALWAYS_ON
        for field, flag in _GATED:
            if height >= getattr(row, field):
                expected |= flag
        assert row.script_flags_at(height) == expected, (network, height)


def test_taproot_is_on_from_the_genesis_block_of_every_chain() -> None:
    """Verify no height gates P2SH, segwit v0 or taproot.

    Core turns the three on for every block and names the blocks that
    fail them one by one, so a table of activation heights has no row
    for taproot to be wrong about -- which is the value btclib-node's
    own copy records as a date rather than a height.
    """
    for row in CONSENSUS_PARAMS.values():
        assert row.script_flags_at(0) & ScriptFlag.TAPROOT
        assert row.script_flags_at(0) & ScriptFlag.P2SH
        assert row.script_flags_at(0) & ScriptFlag.WITNESS


def test_an_exception_block_is_answered_by_its_hash() -> None:
    """Replace the default flags with the exception's, and gate the rest.

    Core's `GetBlockScriptFlags` assigns the entry it finds over the
    three defaults and then adds the height-gated rules on top, so an
    exception block high enough on the chain is not checked with no rule
    at all.
    """
    mainnet = CONSENSUS_PARAMS["mainnet"]
    bip16_block, taproot_block = (h for h, _ in mainnet.script_flag_exceptions)

    # the BIP16 exception sits below every gated height, so nothing is
    # added back and the block is checked with no rule at all
    assert mainnet.script_flags_at(170_060, bip16_block) == NO_FLAGS
    # the taproot exception sits above all four, so the entry's own two
    # flags come back with the four gated ones on top -- and without the
    # taproot flag the block fails
    at_taproot = mainnet.script_flags_at(709_632, taproot_block)
    assert not at_taproot & ScriptFlag.TAPROOT
    assert at_taproot & ScriptFlag.NULLDUMMY
    assert at_taproot & ScriptFlag.P2SH


def test_a_hash_that_is_not_an_exception_changes_nothing() -> None:
    """Answer the same for an ordinary block as for no hash at all.

    Both halves: a chain with exceptions to scan through, and one with
    none to scan at all.
    """
    ordinary = bytes(32)
    for name in ("mainnet", "regtest"):
        row = CONSENSUS_PARAMS[name]
        assert row.script_flags_at(500_000, ordinary) == row.script_flags_at(500_000)

    # and the hex spelling of a hash is an Octets like any other
    mainnet = CONSENSUS_PARAMS["mainnet"]
    bip16_block = mainnet.script_flag_exceptions[0][0]
    assert mainnet.script_flags_at(170_060, bip16_block.hex()) == NO_FLAGS


@pytest.mark.parametrize("height", ["227931", 227931.0, True, None])
def test_script_flags_at_refuses_a_height_that_is_not_one(height: Any) -> None:
    """Refuse a height that is not an integer, a bool included.

    `btclib.exceptions` is imported inside the method for the reason the
    module docstring gives, so this is also what says that import runs.
    """
    with pytest.raises(BTClibTypeError, match="invalid height type"):
        CONSENSUS_PARAMS["mainnet"].script_flags_at(height)


def test_a_row_can_be_built_for_a_chain_this_library_does_not_ship() -> None:
    """Build a row of one's own, which a custom signet needs.

    `Network` takes the row as a required keyword argument rather than
    defaulting it, so a caller with a chain of their own supplies both
    halves; nothing here validates it, the module docstring saying why.
    """
    custom = ConsensusParams(
        name="custom-signet",
        subsidy_halving_interval=210_000,
        bip34_height=1,
        bip66_height=1,
        bip65_height=1,
        csv_height=1,
        segwit_height=1,
        pow_limit_bits=CONSENSUS_PARAMS["signet"].pow_limit_bits,
        pow_allow_min_difficulty_blocks=False,
        enforce_bip94=False,
        pow_no_retargeting=False,
        minimum_chain_work=0,
        bip30_exceptions=(),
        script_flag_exceptions=(),
    )
    assert custom.script_flags_at(1) == CONSENSUS_PARAMS["signet"].script_flags_at(1)
    assert custom != CONSENSUS_PARAMS["signet"]
