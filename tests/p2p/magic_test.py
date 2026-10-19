# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.magic` module.

`_CORE` is `pchMessageStart` as `src/kernel/chainparams.cpp` writes it at
Bitcoin Core v31.1, the tag the module cites. The `bitcoin-core-rpc`
package keeps a copy of the same table and the same derivation, and the
tests below compare btclib's answers with that copy as well.
"""

from __future__ import annotations

import bitcoin_core_rpc
import pytest

import btclib.p2p
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import NETWORKS
from btclib.p2p.magic import (
    DEFAULT_SIGNET_CHALLENGE,
    magic_from_network,
    magic_from_signet_challenge,
)

_CORE = {
    "mainnet": bytes([0xF9, 0xBE, 0xB4, 0xD9]),
    "testnet": bytes([0x0B, 0x11, 0x09, 0x07]),
    "testnet4": bytes([0x1C, 0x16, 0x3F, 0x28]),
    "regtest": bytes([0xFA, 0xBF, 0xB5, 0xDA]),
}


def test_every_network_has_core_s_message_start() -> None:
    """Each network answers Core's value, and the rpc package's copy."""
    assert set(NETWORKS) == {*_CORE, "signet"}
    for network, magic in _CORE.items():
        assert magic_from_network(network) == magic
    for network in NETWORKS:
        chain = bitcoin_core_rpc.chain_from_network(network)
        assert magic_from_network(network) == bitcoin_core_rpc.magic_from_chain(chain)


def test_the_default_signet_challenge_derives_the_signet_entry() -> None:
    """The table's signet entry is the derivation of the default challenge."""
    default = magic_from_signet_challenge(DEFAULT_SIGNET_CHALLENGE)
    assert default == magic_from_network("signet")
    assert DEFAULT_SIGNET_CHALLENGE.hex() == bitcoin_core_rpc.DEFAULT_SIGNET_CHALLENGE


@pytest.mark.parametrize(
    "challenge",
    [
        # OP_1: anyone may mine
        "51",
        DEFAULT_SIGNET_CHALLENGE.hex(),
        # 253 octets, the first length CompactSize writes in three octets
        "6a" * 253,
    ],
)
def test_a_custom_signet_s_message_start(challenge: str) -> None:
    """Hex and octets answer alike, and as the rpc package's derivation."""
    magic = magic_from_signet_challenge(challenge)
    assert len(magic) == 4
    assert magic == magic_from_signet_challenge(bytes.fromhex(challenge))
    assert magic == bitcoin_core_rpc.magic_from_signet_challenge(challenge)
    if challenge != DEFAULT_SIGNET_CHALLENGE.hex():
        assert magic != magic_from_network("signet")


def test_the_empty_challenge_is_derived_as_core_derives_it() -> None:
    """Core parses an empty `-signetchallenge` as an empty script.

    The serialization is then the single CompactSize octet `00`.
    """
    assert magic_from_signet_challenge("") == bytes.fromhex("1406e058")


def test_a_challenge_that_is_no_octets_is_refused() -> None:
    """Refused by `bytes_from_octets`, with btclib's exceptions."""
    with pytest.raises(BTClibValueError):
        magic_from_signet_challenge("5")
    with pytest.raises(BTClibTypeError):
        magic_from_signet_challenge(81)  # type: ignore[arg-type]


def test_a_network_name_is_taken_as_every_other_one_is() -> None:
    """The whitespace-and-case tolerance issue #216 decided to keep."""
    assert magic_from_network("  MainNet ") == magic_from_network("mainnet")
    assert magic_from_network() == magic_from_network("mainnet")


def test_a_core_chain_name_is_not_a_network_name() -> None:
    """Core says "main" where btclib says "mainnet", and "main" is refused.

    A value that is no name at all is refused too, as a `BTClibTypeError`.
    """
    with pytest.raises(BTClibValueError, match="unknown network"):
        magic_from_network("main")
    with pytest.raises(BTClibTypeError, match="not a network name"):
        magic_from_network(1.5)  # type: ignore[arg-type]


def test_the_package_publishes_both_functions() -> None:
    """`btclib.p2p` re-exports the module's two functions."""
    assert btclib.p2p.magic_from_network is magic_from_network
    assert btclib.p2p.magic_from_signet_challenge is magic_from_signet_challenge
