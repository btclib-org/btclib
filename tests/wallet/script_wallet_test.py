# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.wallet.script_wallet` module.

The script a template writes is asserted against the same script built by
hand -- `derive_from_account`, a sort, `op_int`, `script.serialize` --
because those four calls are what a caller had to write before this class
existed, and what it must keep answering. The deployed wallet that made
the case for it is pinned in `tests/descriptors/custody_wallet_test.py`,
against the mainnet addresses it holds coins at.
"""

from __future__ import annotations

import pytest

from btclib.alias import Command
from btclib.bip32 import bip32
from btclib.bip32.bip32 import BIP32KeyData, derive_from_account
from btclib.exceptions import BTClibValueError
from btclib.script import script
from btclib.script.script import op_int
from btclib.script.script_pub_key import ScriptPubKey
from btclib.wallet import KeyGroup, ScriptWallet

# the "abandon abandon ... about" seed, and three account keys of it that
# no wallet elsewhere in the suite uses as a quorum
_ROOT = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
_ACCOUNTS = [f"m/48h/0h/{i}h" for i in range(3)]
_XPRVS = [bip32.derive(_ROOT, account) for account in _ACCOUNTS]
_XPUBS = [bip32.xpub_from_xprv(xprv) for xprv in _XPRVS]

# the timelock of the example in the module docstring, spelled the way the
# wallets that need this class spell it: a push, OP_CSV, OP_DROP
_TIMELOCK: list[Command] = ["9000", "OP_CHECKSEQUENCEVERIFY", "OP_DROP"]


def _derived(xpub: str, branch: int, index: int) -> bytes:
    """Return the public key of a position, the four-primitive way."""
    return BIP32KeyData.b58decode(derive_from_account(xpub, branch, index)).key


def _quorum(
    threshold: int, xpubs: list[str], branch: int, index: int, sort: bool = False
) -> list[Command]:
    """Return `k <key>... n OP_CHECKMULTISIG`, by hand."""
    keys = [_derived(xpub, branch, index) for xpub in xpubs]
    if sort:
        keys.sort()
    return [op_int(threshold), *keys, op_int(len(keys)), "OP_CHECKMULTISIG"]


def test_a_template_is_the_commands_with_the_groups_among_them() -> None:
    """The script is what `script.serialize` would write, group expanded.

    Which is the claim the class exists for: the four calls a caller wrote
    by hand are still what comes out, and the template is only where they
    are written down.
    """
    template: list[Command | KeyGroup] = [
        "OP_IF",
        KeyGroup(2, _XPUBS),
        "OP_ELSE",
        *_TIMELOCK,
        KeyGroup(1, _XPUBS[:1]),
        "OP_ENDIF",
    ]
    wallet = ScriptWallet(template, "p2wsh")
    assert wallet.template == tuple(template)

    for branch, index in ((0, 0), (1, 7)):
        by_hand = script.serialize(
            [
                "OP_IF",
                *_quorum(2, _XPUBS, branch, index),
                "OP_ELSE",
                *_TIMELOCK,
                *_quorum(1, _XPUBS[:1], branch, index),
                "OP_ENDIF",
            ]
        )
        assert wallet.witness_script(branch, index) == by_hand
        assert wallet.script_pub_key(branch, index) == ScriptPubKey.p2wsh(by_hand)
        assert wallet.address(branch, index) == ScriptPubKey.p2wsh(by_hand).address


@pytest.mark.parametrize("branch", [0, 1])
@pytest.mark.parametrize("index", [0, 1, 13])
def test_the_derived_order_is_remade_at_every_position(branch: int, index: int) -> None:
    """BIP67 on the derived keys, which no ranged descriptor can state.

    The order is a property of the position and not of the wallet, so the
    script has to be built at the position to know it -- and the keys of
    two indices of one quorum can come out the other way round.
    """
    wallet = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh", "derived")
    assert wallet.witness_script(branch, index) == script.serialize(
        _quorum(2, _XPUBS, branch, index, sort=True)
    )


def test_the_account_order_is_applied_once_and_derived_afterwards() -> None:
    """Which is the order a fixed ``multi()`` states, and it is not the same.

    The two BIP67 readings answer different scripts at the same position:
    sorting the account keys and sorting what they derive to are the same
    operation on different bytes, and a wallet has to say which it means.
    """
    by_account = sorted(_XPUBS, key=lambda xpub: BIP32KeyData.b58decode(xpub).key)
    wallet = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh", "account")
    for index in (0, 4):
        assert wallet.witness_script(0, index) == script.serialize(
            _quorum(2, by_account, 0, index)
        )

    derived = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh", "derived")
    assert derived.witness_script(0, 0) != wallet.witness_script(0, 0)
    # and declaration order is a third answer, which is the default
    declared = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh")
    assert declared.witness_script(0, 0) == script.serialize(_quorum(2, _XPUBS, 0, 0))


def test_a_sort_key_orders_by_something_that_is_not_a_byte_order() -> None:
    """The deployed case: account xpubs sorted case-insensitively.

    Neither a byte order nor a BIP, and a wallet holding coins does it, so
    the sort is a strategy with a key function rather than a constant.
    """
    by_lower_case = sorted(_XPUBS, key=str.lower)
    wallet = ScriptWallet(
        [KeyGroup(2, _XPUBS)],
        "p2wsh",
        "account",
        sort_key=lambda xkey: xkey.b58encode().lower(),
    )
    assert wallet.witness_script(0, 0) == script.serialize(
        _quorum(2, by_lower_case, 0, 0)
    )

    # and the same key function on the derived keys, which sorts what the
    # script carries rather than what it came from
    on_derived = ScriptWallet(
        [KeyGroup(2, _XPUBS)], "p2wsh", "derived", sort_key=bytes.hex
    )
    assert on_derived.witness_script(0, 0) == script.serialize(
        _quorum(2, _XPUBS, 0, 0, sort=True)
    )


def test_a_sort_key_with_no_sort_is_refused() -> None:
    """Two arguments that contradict each other, rather than one ignored."""
    with pytest.raises(BTClibValueError, match='sort_key with order "none"'):
        ScriptWallet([KeyGroup(1, _XPUBS[:1])], "p2wsh", sort_key=bytes.hex)


@pytest.mark.parametrize(
    "script_type, address_prefix",
    [("p2wsh", "bc1q"), ("p2sh", "3"), ("p2sh-p2wsh", "3")],
)
def test_the_three_ways_a_script_becomes_an_output(
    script_type: str, address_prefix: str
) -> None:
    """And the two pre-images each of them commits to.

    A p2sh pushes the script itself, a p2wsh commits to it in the witness,
    and the wrapped form has both -- the redeem script being the witness
    program, which is what the input pushes, and not the script that
    program commits to.
    """
    group = KeyGroup(2, _XPUBS)
    wallet = ScriptWallet([group], script_type)  # type: ignore[arg-type]
    template_script = script.serialize(_quorum(2, _XPUBS, 0, 0))
    assert wallet.address(0, 0).startswith(address_prefix)

    if script_type == "p2sh":
        assert wallet.redeem_script(0, 0) == template_script
        assert not wallet.witness_script(0, 0)
    elif script_type == "p2wsh":
        assert not wallet.redeem_script(0, 0)
        assert wallet.witness_script(0, 0) == template_script
        assert wallet.script_pub_key(0, 0) == ScriptPubKey.p2wsh(template_script)
    else:
        assert wallet.witness_script(0, 0) == template_script
        assert wallet.redeem_script(0, 0) == ScriptPubKey.p2wsh(template_script).script
        assert wallet.script_pub_key(0, 0) == ScriptPubKey.p2sh(
            ScriptPubKey.p2wsh(template_script).script
        )


def test_an_unknown_script_type_or_order_is_refused() -> None:
    """The two vocabularies, checked for the caller who runs no mypy."""
    group = KeyGroup(1, _XPUBS[:1])
    with pytest.raises(BTClibValueError, match="unknown script type: p2pkh"):
        ScriptWallet([group], "p2pkh")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="unknown key order: sorted"):
        ScriptWallet([group], "p2wsh", "sorted")  # type: ignore[arg-type]


def test_a_template_with_no_key_group_is_not_a_wallet() -> None:
    """One script is not a range of them, and `script.serialize` writes it."""
    with pytest.raises(BTClibValueError, match="no KeyGroup in the template"):
        ScriptWallet(["OP_1"], "p2wsh")


def test_a_quorum_is_bounded_by_what_op_int_spells() -> None:
    """1 to 16 keys, and a threshold no larger than the count."""
    with pytest.raises(BTClibValueError, match="invalid n in 1-of-0"):
        KeyGroup(1, [])
    with pytest.raises(BTClibValueError, match="invalid n in 1-of-17"):
        KeyGroup(1, _XPUBS[:1] * 17)
    with pytest.raises(BTClibValueError, match="invalid threshold in 4-of-3"):
        KeyGroup(4, _XPUBS)
    with pytest.raises(BTClibValueError, match="invalid threshold in 0-of-3"):
        KeyGroup(0, _XPUBS)
    # a group takes any spelling of an extended key, decoded or not
    assert (
        KeyGroup(1, [BIP32KeyData.b58decode(_XPUBS[0])]).keys
        == KeyGroup(1, _XPUBS[:1]).keys
    )
    assert repr(KeyGroup(2, _XPUBS)) == "KeyGroup(2, 3 keys)"


def test_a_script_too_long_for_the_output_it_would_pay() -> None:
    """A p2sh redeem script is pushed, so the push limit bounds it.

    Refused at construction rather than at the address, and the size is
    the size at every index: a derived public key is 33 bytes wherever it
    came from, so a script that fits at one position fits at all of them.
    """
    sixteen = KeyGroup(16, _XPUBS[:1] * 16)
    assert ScriptWallet([sixteen], "p2wsh").address(0, 0)
    with pytest.raises(BTClibValueError, match="invalid script length: 5[0-9][0-9]"):
        ScriptWallet([sixteen], "p2sh")


def test_a_key_of_another_network_cannot_be_in_the_quorum() -> None:
    """The template is built at construction, which is where this shows."""
    with pytest.raises(BTClibValueError, match="not a private or public key"):
        ScriptWallet([KeyGroup(1, _XPUBS[:1])], "p2wsh", network="testnet")


def test_an_xprv_in_a_quorum_is_what_makes_a_wallet_not_watch_only() -> None:
    """And what goes into the script is the public key either way."""
    watching = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh", "derived")
    assert watching.is_watch_only

    signing = ScriptWallet([KeyGroup(2, _XPRVS)], "p2wsh", "derived")
    assert not signing.is_watch_only
    # the private spelling is never what the script carries: the two
    # wallets are the same wallet, and the same addresses
    assert signing.address(0, 0) == watching.address(0, 0)
    # nor does the account order read the private key: sorting by
    # BIP32KeyData.key would order the xprvs by material the xpubs do not
    # have, and answer two different scripts for one wallet
    assert ScriptWallet([KeyGroup(2, _XPRVS)], "p2wsh", "account").address(
        0, 0
    ) == ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh", "account").address(0, 0)


def test_the_derivation_bounds_are_bip32s_own() -> None:
    """The two branches BIP44 defines, and an index that fits in a level."""
    wallet = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh", "derived")
    assert wallet.branches == (0, 1)
    with pytest.raises(BTClibValueError, match="invalid address index"):
        wallet.address(0, 0x10000)
