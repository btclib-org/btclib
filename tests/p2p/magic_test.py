# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.magic` module.

The table is not btclib's, so what is tested here is not the table: the
`bitcoin-core-rpc` package holds `pchMessageStart` per chain and tests it
against Core. What is btclib's is the vocabulary and the exceptions --
`NETWORKS` is keyed by BIP network names where the package takes Core's
chain names -- and that is the whole of what `magic_from_network` adds.

The function is imported from `btclib.p2p.magic` and not from the package,
which publishes it through `__getattr__`: that spelling is `Callable[...,
bytes]` to mypy, so a call with a wrong type would be a call nothing
checks. The package spelling is asserted to be the same object instead.
`magic_from_chain` and `magic_from_signet_challenge` are the `bitcoin-core-rpc`
package's, imported from it.

The walk over `NETWORKS` below is the other half: nothing at run time
re-checks that every btclib network is a chain Core has, so this is where
that stops being true visibly rather than at a caller.
"""

from __future__ import annotations

import bitcoin_core_rpc
import pytest
from bitcoin_core_rpc import magic_from_chain, magic_from_signet_challenge

import btclib.p2p
import btclib.p2p.magic
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import NETWORKS
from btclib.p2p.magic import magic_from_network


def test_the_module_publishes_the_one_function_it_defines() -> None:
    """The two Core-vocabulary functions are not btclib's to publish.

    `bitcoin_core_rpc.magic_from_chain` is what a caller with a chain name
    imports, and a second spelling of it here would be a surface btclib does
    not own.
    """
    assert btclib.p2p.magic.__all__ == ["magic_from_network"]
    assert not hasattr(btclib.p2p, "magic_from_chain")


def test_every_network_of_the_catalogue_has_a_message_start() -> None:
    """`NETWORKS`' keys are btclib's vocabulary, and each answers."""
    for network in NETWORKS:
        magic = magic_from_network(network)
        assert len(magic) == 4
        assert magic == magic_from_chain(bitcoin_core_rpc.chain_from_network(network))

    assert magic_from_network("mainnet") == bytes.fromhex("f9beb4d9")


def test_a_network_name_is_not_a_chain_name() -> None:
    """The bridge is what this function is, and the reason it exists.

    Core says "main" where btclib says "mainnet", so a caller passing a
    `NETWORKS` key straight to `magic_from_chain` is told its network is
    unknown -- and one passing a chain name to `magic_from_network` is
    told the same, in the other direction. Both are refused rather than
    guessed at.
    """
    with pytest.raises(BTClibValueError, match="unknown network"):
        magic_from_network("main")
    with pytest.raises(bitcoin_core_rpc.BtcRpcValueError):
        magic_from_chain("mainnet")


def test_a_network_name_is_taken_as_every_other_one_is() -> None:
    """The whitespace-and-case tolerance issue #216 decided to keep.

    `network.validated_network_name` is the one converter, so a name
    that works anywhere else in the library works here; the default is
    mainnet, as it is for `network_from_name`.
    """
    assert magic_from_network("  MainNet ") == magic_from_network("mainnet")
    assert magic_from_network() == magic_from_network("mainnet")


def test_what_leaves_a_btclib_name_is_a_btclib_exception() -> None:
    """The one line of translation this module is, and its limit.

    `magic_from_network` is btclib's function, so its refusal is
    `btclib.exceptions`'. The two aliases beside it are the package's own
    functions under btclib's name, so theirs stay the package's -- the
    same split `btclib_wallet.fetch.transport` documents for the transport it
    re-exports.
    """
    with pytest.raises(BTClibValueError, match="unknown network") as refusal:
        magic_from_network("nosuchnet")

    # not the package's class, which an `except BTClibException` would
    # not catch, and it names what was passed
    assert not isinstance(refusal.value, bitcoin_core_rpc.BtcRpcValueError)
    assert "nosuchnet" in str(refusal.value)

    # and the type rule beside the value one, which is the converter's
    with pytest.raises(BTClibTypeError, match="not a network name"):
        magic_from_network(1.5)  # type: ignore[arg-type]


def test_the_default_signet_challenge_derives_the_tabulated_magic() -> None:
    """A signet is named by its challenge, which is why no field holds it.

    The one property that makes the `Network` field impossible rather
    than merely inconvenient: two signets report the same chain and are
    different networks, so the message start of one of them is not a
    fact any table keyed by name can carry.
    """
    default = magic_from_signet_challenge(bitcoin_core_rpc.DEFAULT_SIGNET_CHALLENGE)
    assert default == magic_from_network("signet")

    other = magic_from_signet_challenge("51")  # OP_1: anyone may mine
    assert len(other) == 4
    assert other != default


def test_the_package_publishes_the_function_without_importing_it() -> None:
    """PEP 562 here, as in `src/btclib/script/__init__.py`, and why.

    Reaching `bitcoin_core_rpc` brings `urllib.request`, `ssl` and
    `socket` with it, and a codec has no use for any of them --
    `tests/imports_test.py` is where that cost is measured. What is left
    to check is the publication itself: the name reachable off the
    package, offered to a prompt, and nothing else answered.
    """
    assert "magic_from_network" in btclib.p2p.__all__
    assert btclib.p2p.magic_from_network is btclib.p2p.magic.magic_from_network

    assert set(btclib.p2p.__all__) <= set(dir(btclib.p2p))
    with pytest.raises(AttributeError, match="has no attribute 'magic_from_networks'"):
        _ = btclib.p2p.magic_from_networks
