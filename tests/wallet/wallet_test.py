# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the vocabulary every `btclib.wallet` class answers to.

One account, three wallets over it, and one set of assertions run against
all three: the ledger of what has been handed out, `next_address` walking
a branch, `position_of` taking every spelling of an output, and the bounds
of a position. What each computes an address *from* is its own module's
test; this one is about the words being the same words, which is what a
caller who does not know which kind of wallet it has depends on.

The three are the same account wherever they can be -- the key wallet and
the descriptor wallet derive the very same BIP84 addresses, which is
asserted below -- and the script wallet is a 2-of-3 p2wsh of the same
seed's keys, there being no key-hash wallet for it to agree with.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from btclib.bip32 import bip32
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script.script_pub_key import ScriptPubKey
from btclib.wallet import (
    BIP32KeyWallet,
    DescriptorWallet,
    KeyGroup,
    RangedWallet,
    ScriptWallet,
)

# the "abandon abandon ... about" seed, whose master key BIP84 publishes
# as its rootpriv
_ROOT = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
_ACCOUNT = "m/84h/0h/0h"
_FINGERPRINT = "73c5da0a"

# an address of nobody's wallet here: BIP173's own p2wsh vector
_ELSEWHERE = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"


def _multisig_xpubs() -> list[str]:
    """Three account xpubs of the seed, for the script wallet's quorum."""
    return [
        bip32.xpub_from_xprv(bip32.derive(_ROOT, f"m/48h/0h/{i}h")) for i in range(3)
    ]


def key_wallet() -> BIP32KeyWallet:
    """Return the BIP84 account, as an extended key."""
    return BIP32KeyWallet(_ROOT, _ACCOUNT)


def descriptor_wallet() -> DescriptorWallet:
    """Return the same account, as the ``wpkh()`` pair of its chains."""
    return DescriptorWallet.from_account(_ROOT, _ACCOUNT, _FINGERPRINT)


def script_wallet() -> ScriptWallet:
    """Return a 2-of-3 p2wsh of the seed, which no descriptor states."""
    return ScriptWallet([KeyGroup(2, _multisig_xpubs())], order="derived")


WALLETS: list[Callable[[], RangedWallet]] = [
    key_wallet,
    descriptor_wallet,
    script_wallet,
]

BUILDERS = pytest.mark.parametrize("build", WALLETS, ids=lambda build: build.__name__)


@BUILDERS
def test_the_ledger_holds_what_was_handed_out(
    build: Callable[[], RangedWallet],
) -> None:
    """A wallet remembers the positions it was asked for, and only those.

    Idempotent, and in the order it was asked: a wallet is a function of
    its source rather than a generator with a position, so the same
    position twice is one entry.
    """
    wallet = build()
    assert not len(wallet)
    assert not wallet.addresses

    first = wallet.address(0, 0)
    assert wallet.address(0, 0) == first
    assert len(wallet) == 1
    assert first in wallet
    assert wallet.addresses == (first,)

    change = wallet.address(1, 2)
    assert list(wallet.addresses) == [first, change]
    info = wallet.address_info(change)
    assert (info.address, info.branch, info.index) == (change, 1, 2)
    assert info.script_type == wallet.script_type

    # an address of the wallet's own chains, not asked for yet, is a miss:
    # the ledger is what has been issued and not what could be
    unissued = build().address(0, 9)
    assert unissued not in wallet
    for address in (unissued, _ELSEWHERE):
        with pytest.raises(BTClibValueError, match="address not in the wallet"):
            wallet.address_info(address)


@BUILDERS
def test_next_address_is_one_past_the_top_of_a_branch(
    build: Callable[[], RangedWallet],
) -> None:
    """And each branch counts on its own, as BIP44's two chains do."""
    wallet = build()
    assert wallet.next_address() == wallet.address(0, 0)
    assert wallet.next_address() == wallet.address(0, 1)
    assert wallet.next_address(1) == wallet.address(1, 0)

    wallet.address(0, 7)
    assert wallet.next_address() == wallet.address(0, 8)
    assert wallet.next_address(1) == wallet.address(1, 1)


@BUILDERS
def test_position_of_takes_every_spelling_of_an_output(
    build: Callable[[], RangedWallet],
) -> None:
    """The output as a ScriptPubKey, as bytes, as hex, or as its address.

    One question -- "is this output mine" -- and the answer is the whole
    script compared at each position, which is why the address is read
    for the script it encodes rather than matched as text.
    """
    wallet = build()
    script_pub_key = wallet.script_pub_key(1, 3)
    for named in (
        script_pub_key,
        script_pub_key.script,
        script_pub_key.script.hex(),
        script_pub_key.address,
    ):
        assert wallet.position_of(named, 4) == (1, 3)

    # bounded by last_index, both ends included, and the bound is the
    # caller's gap limit rather than a policy of the wallet's
    assert wallet.position_of(script_pub_key, 2) is None
    # and somebody else's output is not this wallet's, which is the answer
    # a caller acts on
    assert wallet.position_of(ScriptPubKey.from_address(_ELSEWHERE), 2) is None
    # asking does not hand anything out: position_of records nothing
    assert not len(wallet)


@BUILDERS
def test_position_of_refuses_what_names_no_output(
    build: Callable[[], RangedWallet],
) -> None:
    """None means "not this wallet's", so a bad argument cannot mean it."""
    wallet = build()
    with pytest.raises(BTClibTypeError, match="invalid script_pub_key type"):
        wallet.position_of(None)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="empty script_pub_key"):
        wallet.position_of("")
    with pytest.raises(BTClibValueError, match="neither a script nor an address"):
        wallet.position_of("not an address")


@BUILDERS
def test_a_position_outside_the_wallet_is_refused(
    build: Callable[[], RangedWallet],
) -> None:
    """The branch against `branches`, and the index for its sign.

    Every method that takes a position asks, `redeem_script` and
    `witness_script` included: a pre-image of a position the wallet has
    no output at is not `b""`, it is a mistake.
    """
    wallet = build()
    assert wallet.branches == (0, 1)
    for method in (
        wallet.address,
        wallet.script_pub_key,
        wallet.redeem_script,
        wallet.witness_script,
    ):
        with pytest.raises(
            BTClibValueError, match=r"invalid branch: 2 not in \(0, 1\)"
        ):
            method(2, 0)
        with pytest.raises(BTClibValueError, match="invalid index: -1"):
            method(0, -1)


@BUILDERS
def test_every_wallet_answers_whether_it_can_sign(
    build: Callable[[], RangedWallet],
) -> None:
    """`is_watch_only` is asked of all three, whatever the source is."""
    assert isinstance(build().is_watch_only, bool)


def test_the_key_wallet_and_the_descriptor_wallet_are_one_account() -> None:
    """Two ways to hold a BIP84 account, and one set of addresses.

    Which is what makes the vocabulary worth having: a caller that
    switched from one to the other would be watching the same chain.
    """
    keys = key_wallet()
    descriptors = descriptor_wallet()
    assert keys.script_type == descriptors.script_type == "p2wpkh"
    for branch in (0, 1):
        for index in (0, 1, 5):
            assert keys.address(branch, index) == descriptors.address(branch, index)
            assert keys.script_pub_key(branch, index) == descriptors.script_pub_key(
                branch, index
            )


def test_only_a_key_wallet_records_one_derivation_path() -> None:
    """`der_path` is one path, and two of the three have no single one.

    A quorum has a path per key, which a psbt key origin records and an
    `AddressInfo` field cannot; a descriptor holds its paths inside the
    key expressions. Both answer "" rather than one of the paths.
    """
    keys = key_wallet()
    assert keys.address_info(keys.address(1, 4)).der_path == "m/84h/0h/0h/1/4"
    for build in (descriptor_wallet, script_wallet):
        wallet = build()
        assert not wallet.address_info(wallet.address(1, 4)).der_path


def test_an_address_of_a_bech32_spelling_is_found_however_it_is_written() -> None:
    """Which is `Wallet.__contains__` and the lookup under it."""
    wallet = script_wallet()
    address = wallet.address(0, 0)
    for spelling in (address.upper(), f"  {address}  ", address.encode("ascii")):
        assert spelling in wallet
        assert wallet.address_info(spelling).address == address
