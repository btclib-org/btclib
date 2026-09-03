# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.block.genesis` module.

Every network's built genesis is checked against the hash `NETWORKS`
already carries for it -- ISS 1602's own "done when" -- and against the
block `Block.assert_valid` accepts at that network's own easiest target,
never mainnet's default.
"""

from __future__ import annotations

import pytest

from btclib.block.genesis import genesis_block
from btclib.exceptions import BTClibValueError
from btclib.network import NETWORKS


@pytest.mark.parametrize("name", sorted(NETWORKS))
def test_genesis_block_reproduces_the_networks_own_hash(name: str) -> None:
    """The built block's header hash matches Network.genesis_block."""
    block = genesis_block(name)
    assert block.header.hash == NETWORKS[name].genesis_block


@pytest.mark.parametrize("name", sorted(NETWORKS))
def test_genesis_block_is_valid_at_its_own_pow_limit(name: str) -> None:
    """assert_valid, at the network's own bits, raises nothing.

    genesis_block already calls this before returning; the point of
    calling it again here is that a network whose regtest-or-signet-grade
    bits were checked against mainnet's default would fail it, so this is
    where a caller who reads the test rather than the source sees why
    `pow_limit_bits` is not left at its default.
    """
    block = genesis_block(name)
    block.assert_valid(NETWORKS[name].consensus.pow_limit_bits)


def test_genesis_block_defaults_to_mainnet() -> None:
    """No argument is the same block as the explicit name."""
    assert genesis_block() == genesis_block("mainnet")


def test_genesis_block_has_one_coinbase_and_no_witness() -> None:
    """The genesis coinbase spends nothing and carries no witness.

    Predating BIP141 as much as it predates BIP34, so build_block adds no
    witness commitment -- the same shape
    test_build_block_adds_no_commitment_without_a_witness checks for an
    ordinary block.
    """
    block = genesis_block("mainnet")
    assert len(block.transactions) == 1
    assert block.transactions[0].is_coinbase
    assert not block.transactions[0].is_segwit


def test_genesis_block_testnet4_differs_from_the_other_four() -> None:
    """testnet4's coinbase is not the mainnet one under a later timestamp.

    The issue that opened this module said every network shared the
    mainnet coinbase; true of four of the five, and corrected here rather
    than repeated -- bitcoin/bitcoin@9be056a8a7's kernel/chainparams.cpp
    gives testnet4 its own message and an output script that pays to
    thirty-three zero bytes rather than to Satoshi's pubkey.
    """
    mainnet_coinbase = genesis_block("mainnet").transactions[0]
    testnet4_coinbase = genesis_block("testnet4").transactions[0]
    assert mainnet_coinbase.vin[0].script_sig != testnet4_coinbase.vin[0].script_sig
    assert (
        mainnet_coinbase.vout[0].script_pub_key
        != testnet4_coinbase.vout[0].script_pub_key
    )
    # and every network still pays the same height-zero subsidy
    assert mainnet_coinbase.vout[0].value == testnet4_coinbase.vout[0].value


def test_genesis_block_refuses_an_unknown_network() -> None:
    """The same refusal network_from_name gives, not a bare KeyError."""
    with pytest.raises(BTClibValueError, match="unknown network"):
        genesis_block("not-a-network")
