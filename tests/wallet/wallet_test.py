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
from typing_extensions import override

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
    """The output named any way it can be named.

    As a ScriptPubKey, as octets however held, or as its address. One
    question -- "is this output mine" -- and the answer is the whole
    script compared at each position, which is why the address is read
    for the script it encodes rather than matched as text.

    The buffers are here because the answer used to depend on how the
    caller held the octets, which is the one thing it must not depend on:
    a script as a bytearray or a memoryview was refused outright, with
    "invalid script_pub_key type", where the same octets as bytes
    answered (issue #1238). An address is a `str` here and not octets --
    its own bytes are read as a script, which is what they are.
    """
    wallet = build()
    script_pub_key = wallet.script_pub_key(1, 3)
    for named in (
        script_pub_key,
        script_pub_key.script,
        script_pub_key.script.hex(),
        script_pub_key.address,
        bytearray(script_pub_key.script),
        memoryview(script_pub_key.script),
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
    """Which is `Wallet.__contains__` and the lookup under it.

    Held however a caller holds it, `String` naming the buffers too.
    Neither used to reach the lookup at all: `_address_str` promises a
    `str` and returned what it was given, so a bytearray arrived at the
    dict of handed-out addresses and raised `TypeError: cannot use
    'bytearray' as a dict key`, and a memoryview did not get that far --
    a bare `AttributeError` on the `strip` it does not have. Two Python
    errors for a supported spelling, neither of them this library's
    (issue #1238).
    """
    wallet = script_wallet()
    address = wallet.address(0, 0)
    octets = address.encode("ascii")
    for spelling in (
        address.upper(),
        f"  {address}  ",
        octets,
        bytearray(octets),
        memoryview(octets),
    ):
        assert spelling in wallet
        assert wallet.address_info(spelling).address == address


@BUILDERS
def test_every_position_argument_defaults_to_the_first_receiving_address(
    build: Callable[[], RangedWallet],
) -> None:
    """Branch 0 and index 0, which is what "the" address of a wallet means.

    Each of these takes the pair and nothing called them without it, so
    the defaults were free to name any position -- the change chain
    included, which is the address a caller would then have somebody else
    pay. The neighbours are asserted different afterwards, an equality
    against a position that answers the same everywhere being no
    assertion at all.
    """
    wallet = build()
    assert wallet.address() == wallet.address(0, 0)
    assert wallet.script_pub_key() == wallet.script_pub_key(0, 0)
    assert wallet.redeem_script() == wallet.redeem_script(0, 0)
    assert wallet.witness_script() == wallet.witness_script(0, 0)

    assert wallet.script_pub_key(0, 0) != wallet.script_pub_key(0, 1)
    assert wallet.script_pub_key(0, 0) != wallet.script_pub_key(1, 0)


@BUILDERS
def test_position_of_searches_up_to_last_index_inclusive(
    build: Callable[[], RangedWallet],
) -> None:
    """`last_index` is the last index searched, not the first one left out.

    The output at exactly that index is the case that says which, and
    the index below it is what says the search is bounded at all: a
    walk one short of its own bound answers None for an output the
    wallet holds, which is the answer a caller reads as "somebody
    else's".
    """
    wallet = build()
    script_pub_key = wallet.script_pub_key(0, 3)
    assert wallet.position_of(script_pub_key, last_index=3) == (0, 3)
    assert wallet.position_of(script_pub_key, last_index=2) is None


@BUILDERS
def test_a_span_is_what_a_branch_derives_from_an_index_on(
    build: Callable[[], RangedWallet],
) -> None:
    """A list of addresses read back against the wallet said to derive it.

    Written however the caller holds them, as `position_of` takes them,
    and asking hands nothing out: a span on disk is checked against the
    wallet, not issued by it.
    """
    wallet = build()
    span = [build().address(1, index) for index in range(3, 8)]
    wallet.assert_derives(span, 1, 3)
    wallet.assert_derives([ScriptPubKey.from_address(a) for a in span], 1, 3)
    wallet.assert_derives(span[:1], 1, 3)
    assert not len(wallet)


@BUILDERS
def test_a_span_filed_at_the_wrong_position_is_refused(
    build: Callable[[], RangedWallet],
) -> None:
    """Shifted by one, on the other chain, or holding somebody else's output.

    The three accidents that write a whitelist nobody re-derived, and
    each is named by the position that disagrees rather than by the
    span as a whole. An empty span is refused before any of them: there
    is nothing there to be right about.
    """
    wallet = build()
    span = [build().address(1, index) for index in range(3, 8)]

    with pytest.raises(BTClibValueError, match="no addresses to check"):
        wallet.assert_derives([], 1, 3)
    with pytest.raises(BTClibValueError, match="not what 1/2 derives"):
        wallet.assert_derives(span, 1, 2)
    with pytest.raises(BTClibValueError, match="not what 0/3 derives"):
        wallet.assert_derives(span, 0, 3)

    span[2] = _ELSEWHERE
    with pytest.raises(BTClibValueError, match="not what 1/5 derives"):
        wallet.assert_derives(span, 1, 3)


def test_a_span_of_one_output_repeated_is_no_span() -> None:
    """Refuse a branch that derives the same output at every position.

    The one accident the comparison above cannot see: a script that
    ignores its index derives one address everywhere, so every entry of
    the span is "what that position derives" and the file is that address
    a hundred times. No wallet here can be built that way -- a
    `ScriptWallet` with no `KeyGroup` in its template is refused, and a
    descriptor that is not ranged has no script past index 0 -- but
    `RangedWallet` is what a caller subclasses, and `_script_pub_key` is
    theirs to write.
    """

    class OneOutput(RangedWallet):
        """A wallet paying to the same anyone-can-spend script everywhere."""

        @property
        @override
        def is_watch_only(self) -> bool:
            return True

        @property
        @override
        def branches(self) -> tuple[int, ...]:
            return (0,)

        @override
        def _script_pub_key(self, branch: int, index: int) -> ScriptPubKey:
            return ScriptPubKey(b"\x51")

    wallet = OneOutput()
    assert wallet.is_watch_only
    wallet.assert_derives([b"\x51"], 0, 0)
    with pytest.raises(BTClibValueError, match="derives one output twice"):
        wallet.assert_derives([b"\x51"] * 3, 0, 0)


def test_a_wallet_that_names_no_branches_is_not_a_wallet() -> None:
    """`branches` is abstract, and a subclass leaving it out cannot be built.

    Three abstract members, and a test that builds a subclass implementing
    all of them says nothing about any one of them: what makes this an
    assertion is that the class below implements the other two, so the
    TypeError names the one it left out. `position_of` searches whatever
    this answers, so a wallet without it would search nothing and answer
    that every output is somebody else's.
    """

    class Branchless(RangedWallet):
        """A wallet with an output at every position and no chains."""

        @property
        @override
        def is_watch_only(self) -> bool:
            return True

        @override
        def _script_pub_key(self, branch: int, index: int) -> ScriptPubKey:
            return ScriptPubKey(b"\x51")

    with pytest.raises(TypeError, match="branches"):
        Branchless()  # type: ignore[abstract]

    # the same class with the chains it was missing, which is what says the
    # refusal above was about that member and not about the other two
    class OneBranch(Branchless):
        """The same wallet, on the receiving chain alone."""

        @property
        @override
        def branches(self) -> tuple[int, ...]:
            return (0,)

    wallet = OneBranch()
    assert wallet.is_watch_only
    assert wallet.script_pub_key(0, 0).script == b"\x51"
    assert wallet.position_of(b"\x51") == (0, 0)
