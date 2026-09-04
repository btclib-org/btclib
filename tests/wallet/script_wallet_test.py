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

The psbt half is asserted the same way: the key paths against the account
path with the two derived levels appended, which is the path a signer
walks, and the pre-images against `redeem_script` and `witness_script`.

`descriptor()` too: the expression is written out by hand from the keys
the quorum names, and what the lift produces has to be that text -- so a
change of spelling is a failure here rather than a descriptor somebody
imports and finds derives something else. The same method against a
deployment, which is the authority the addresses give it, is in that
other module too.
"""

from __future__ import annotations

import pytest

from btclib.alias import Command
from btclib.bip32 import bip32, fingerprint
from btclib.bip32.bip32 import BIP32KeyData, derive_from_account
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.descriptors import KeyExpression, add_checksum, parse
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibValueError,
    NoDescriptorError,
)
from btclib.psbt.psbt import Psbt
from btclib.script import script
from btclib.script.script import op_int
from btclib.script.script_pub_key import ScriptPubKey
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from btclib.wallet import DescriptorWallet, KeyGroup, ScriptWallet
from btclib.wallet import script_wallet as script_wallet_module
from tests import replace_unchecked

# the "abandon abandon ... about" seed, and three account keys of it in an
# order that none of the sorts below answers: the account keys sort one
# way, their case-folded xpubs another, and what they derive to a third,
# so the script written at a position says which of the three wrote it.
# The first three accounts of the same seed -- which is the quorum
# `tests/wallet/wallet_test.py` builds -- would say nothing: they are
# already in the byte order of both their account keys and their xpubs, so
# a wallet that sorted by anything at all, the network beside the key
# included, would write the script a wallet that sorted by nothing writes
_ROOT = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
_ACCOUNTS = ["m/48h/0h/1h", "m/48h/0h/0h", "m/48h/0h/5h"]
_XPRVS = [bip32.derive(_ROOT, account) for account in _ACCOUNTS]
_XPUBS = [bip32.xpub_from_xprv(xprv) for xprv in _XPRVS]

# two more accounts of the same seed, for the tests that need a second
# quorum: a descriptor naming one key twice is refused as insane, so a
# combinator whose two branches share a key has no descriptor for a reason
# that is not the one under test
_RECOVERY = [
    bip32.xpub_from_xprv(bip32.derive(_ROOT, account))
    for account in ("m/48h/0h/7h", "m/48h/0h/9h")
]

# the timelock of the example in the module docstring, spelled the way the
# wallets that need this class spell it: a push, OP_CSV, OP_DROP
_TIMELOCK: list[Command] = ["9000", "OP_CHECKSEQUENCEVERIFY", "OP_DROP"]

# where those three accounts came from, which is what a psbt carries
# beside each key, and what a descriptor writes in front of it: the master
# fingerprint, which only the root key supplies, and the path down to the
# account
_FINGERPRINT = fingerprint(_ROOT)
_ORIGINS = [BIP32KeyOrigin(_FINGERPRINT, account) for account in _ACCOUNTS]

# the same 144 blocks as miniscript writes them, which is the whole
# difference between a wallet that has a descriptor and one that does not:
# `older(144)` compiles to the push and OP_CSV, and leaves the number on
# the stack for the fragment above it to consume
_MINISCRIPT_TIMELOCK: list[Command] = ["9000", "OP_CHECKSEQUENCEVERIFY"]


def _key_expression(xpub: str, branch: int, origins: bool = True) -> str:
    """Return the ranged KEY expression of an account key, as text.

    With the origin the group declared in front of it, where the wallet
    under test declared one: a key of a group given none is written as the
    xpub alone, which is what `origins=False` asks for here.
    """
    prefix = f"[{_ORIGINS[_XPUBS.index(xpub)].description}]" if origins else ""
    return f"{prefix}{xpub}/{branch}/*"


def _multi(
    threshold: int,
    xpubs: list[str],
    branch: int,
    name: str = "multi",
    origins: bool = True,
) -> str:
    """Return the BIP383 quorum of some account keys, written out."""
    keys = ",".join(_key_expression(xpub, branch, origins) for xpub in xpubs)
    return f"{name}({threshold},{keys})"


def _derived(xpub: str, branch: int, index: int) -> bytes:
    """Return the public key of a position, the four-primitive way."""
    return BIP32KeyData.b58decode(derive_from_account(xpub, branch, index)).key


def _quorum(
    threshold: int,
    xpubs: list[str],
    branch: int,
    index: int,
    sort: bool = False,
    verify: bool = False,
) -> list[Command]:
    """Return `k <key>... n OP_CHECKMULTISIG[VERIFY]`, by hand."""
    keys = [_derived(xpub, branch, index) for xpub in xpubs]
    if sort:
        keys.sort()
    opcode = "OP_CHECKMULTISIGVERIFY" if verify else "OP_CHECKMULTISIG"
    return [op_int(threshold), *keys, op_int(len(keys)), opcode]


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
    # the sort is a reorder over this quorum, which is what makes the
    # equality below an assertion about the order rather than about the
    # keys: over a quorum already in account order every sort writes the
    # same script, and so does no sort at all
    assert by_account != _XPUBS
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
    assert declared.witness_script(0, 0) != wallet.witness_script(0, 0)
    assert declared.witness_script(0, 0) != derived.witness_script(0, 0)


def test_a_sort_key_orders_by_something_that_is_not_a_byte_order() -> None:
    """The deployed case: account xpubs sorted case-insensitively.

    Neither a byte order nor a BIP, and a wallet holding coins does it, so
    the sort is a strategy with a key function rather than a constant.
    """
    by_lower_case = sorted(_XPUBS, key=str.lower)
    # a third order, and that is the whole of what makes the assertion
    # below about the key function: it is not the declaration order, so a
    # sort ran, and it is not the account keys' byte order either, so the
    # sort that ran is this one and not the default
    assert by_lower_case != _XPUBS
    assert by_lower_case != sorted(
        _XPUBS, key=lambda xpub: BIP32KeyData.b58decode(xpub).key
    )
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
    # and below zero, which a window asserted at 0 alone lets through: the
    # floor is a quorum of one and not "not zero"
    with pytest.raises(BTClibValueError, match="invalid threshold in -1-of-3"):
        KeyGroup(-1, _XPUBS)
    # a group takes any spelling of an extended key, decoded or not
    assert (
        KeyGroup(1, [BIP32KeyData.b58decode(_XPUBS[0])]).keys
        == KeyGroup(1, _XPUBS[:1]).keys
    )
    assert repr(KeyGroup(2, _XPUBS)) == "KeyGroup(2, 3 keys)"


def test_a_decoded_key_is_validated_too() -> None:
    """The rule of #684: an object is validated as a string is.

    `KeyGroup.__init__` mapped every key through `BIP32KeyData.b58decode`,
    which validates by default, but trusted an already-built
    `BIP32KeyData` in `keys` unasked.
    """
    bad = replace_unchecked(BIP32KeyData.b58decode(_XPUBS[0]), index=-1)
    err_msg = "invalid index: -1"
    with pytest.raises(BTClibValueError, match=err_msg):
        bad.assert_valid()
    with pytest.raises(BTClibValueError, match=err_msg):
        KeyGroup(1, [bad])


def test_verify_writes_checkmultisigverify_and_nothing_else() -> None:
    """The required-quorum form miniscript's `v:` wrapper compiles to.

    One opcode differs from the group's usual script, and `repr` says so.
    """
    assert repr(KeyGroup(2, _XPUBS, verify=True)) == "KeyGroup(2, 3 keys, verify=True)"

    template: list[Command | KeyGroup] = [
        KeyGroup(2, _XPUBS, verify=True),
        *_TIMELOCK,
        KeyGroup(1, _XPUBS[:1]),
    ]
    wallet = ScriptWallet(template, "p2wsh", "derived")
    for branch, index in ((0, 0), (1, 7)):
        by_hand = script.serialize(
            [
                *_quorum(2, _XPUBS, branch, index, sort=True, verify=True),
                *_TIMELOCK,
                *_quorum(1, _XPUBS[:1], branch, index),
            ]
        )
        assert wallet.witness_script(branch, index) == by_hand

    # verify=False is the default, and the only difference from the plain
    # group is the last opcode
    plain = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh", "derived")
    verified = ScriptWallet([KeyGroup(2, _XPUBS, verify=True)], "p2wsh", "derived")
    assert plain.witness_script(0, 0)[:-1] == verified.witness_script(0, 0)[:-1]
    assert plain.witness_script(0, 0)[-1] != verified.witness_script(0, 0)[-1]


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
    with pytest.raises(BTClibValueError, match="Not a testnet key: version "):
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
    # have, and answer two different scripts for one wallet -- these three
    # accounts sort one way by their private keys and the other by their
    # public ones, which is what leaves the equality below something to say
    assert sorted(range(3), key=lambda i: BIP32KeyData.b58decode(_XPRVS[i]).key) != (
        sorted(range(3), key=lambda i: BIP32KeyData.b58decode(_XPUBS[i]).key)
    )
    assert ScriptWallet([KeyGroup(2, _XPRVS)], "p2wsh", "account").address(
        0, 0
    ) == ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh", "account").address(0, 0)


def test_the_derivation_bounds_are_bip32s_own() -> None:
    """The two branches BIP44 defines, and an index that fits in a level."""
    wallet = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh", "derived")
    assert wallet.branches == (0, 1)
    with pytest.raises(BTClibValueError, match="invalid address index"):
        wallet.address(0, 0x10000)


def _psbt_spending(script_pub_key: ScriptPubKey) -> Psbt:
    """Return a psbt whose one input spends an output of that script."""
    prev_tx = Tx(
        vin=[TxIn(OutPoint(b"\x02" * 32, 0))], vout=[TxOut(1000, script_pub_key)]
    )
    psbt = Psbt.from_tx(
        Tx(vin=[TxIn(OutPoint(prev_tx.id, 0))], vout=[TxOut(900, script_pub_key)])
    )
    psbt.inputs[0].non_witness_utxo = prev_tx
    return psbt


def _derived_path(account: str, branch: int, index: int) -> str:
    """Return the path a signer walks to the key of a position.

    The account path, which is the origin the caller declared, with the
    two levels `derive_from_account` adds to it.
    """
    return f"{_FINGERPRINT.hex()}{account[1:]}/{branch}/{index}"


def test_the_updater_writes_the_pre_image_and_the_key_origins() -> None:
    """BIP174's Updater over a script no descriptor states.

    Which is what a signer needs of a position and what it cannot derive
    for itself: the script the output commits to, and the path down to
    each key in it. What is not written is what the wallet does not know
    -- the utxo, the sighash type, the signatures.
    """
    wallet = ScriptWallet([KeyGroup(2, _XPUBS, origins=_ORIGINS)], "p2wsh", "derived")
    psbt = _psbt_spending(wallet.script_pub_key(1, 2))

    psbt_in = wallet.update_psbt_input(psbt, 0, 1, 2).inputs[0]
    assert psbt_in.witness_script == wallet.witness_script(1, 2)
    # `b""` is not written: a native p2wsh has no redeem script, and the
    # field already holds the empty answer
    assert not psbt_in.redeem_script
    assert len(psbt_in.hd_key_paths) == len(_XPUBS)
    for xpub, account in zip(_XPUBS, _ACCOUNTS, strict=True):
        origin = psbt_in.hd_key_paths[_derived(xpub, 1, 2)]
        assert origin.description == _derived_path(account, 1, 2)
    assert not psbt_in.sig_hash_type
    assert not psbt_in.partial_sigs

    # the psbt handed in is left alone, the copy being what carries them
    assert not psbt.inputs[0].hd_key_paths
    assert not psbt.inputs[0].witness_script


def test_an_output_is_marked_only_where_the_whole_script_says_so() -> None:
    """The evidence for "this comes back to me" is the script itself.

    A reader derives it at the position given and compares it with what
    the output pays; a position that derives another script is refused
    rather than marked, which is `position_of` asked as a claim.
    """
    wallet = ScriptWallet([KeyGroup(2, _XPUBS, origins=_ORIGINS)], "p2wsh", "derived")
    psbt = _psbt_spending(wallet.script_pub_key(1, 2))

    psbt_out = wallet.update_psbt_output(psbt, 0, 1, 2).outputs[0]
    assert psbt_out.witness_script == wallet.witness_script(1, 2)
    # the same fields on either side of BIP174's two maps: what a script
    # and a key origin say does not depend on which of them holds it
    psbt_in = wallet.update_psbt_input(psbt, 0, 1, 2).inputs[0]
    assert psbt_out.hd_key_paths == psbt_in.hd_key_paths
    assert not psbt.outputs[0].hd_key_paths

    with pytest.raises(BTClibValueError, match="which is not the script"):
        wallet.update_psbt_output(psbt, 0, 1, 3)


def test_both_pre_images_of_a_wrapped_script_and_every_key_of_it() -> None:
    """A p2sh-p2wsh input pushes one and commits to the other.

    And the key paths are the template's own, quorum by quorum: an output
    is not a signing instruction, so the keys of the branch nobody is
    spending are in it too -- which is what lets a reader rebuild the
    whole script rather than the part a spend uses.
    """
    template: list[Command | KeyGroup] = [
        "OP_IF",
        KeyGroup(2, _XPUBS, origins=_ORIGINS),
        "OP_ELSE",
        *_TIMELOCK,
        KeyGroup(1, _XPUBS[:1], origins=_ORIGINS[:1]),
        "OP_ENDIF",
    ]
    wallet = ScriptWallet(template, "p2sh-p2wsh")
    psbt = _psbt_spending(wallet.script_pub_key())

    psbt_in = wallet.update_psbt_input(psbt, 0).inputs[0]
    assert psbt_in.redeem_script == wallet.redeem_script()
    assert psbt_in.witness_script == wallet.witness_script()
    # the recovery key is the first account again, and the mapping is
    # keyed by key: one entry per distinct key of the script, not per
    # appearance of one
    assert len(psbt_in.hd_key_paths) == len(_XPUBS)

    plain = ScriptWallet(template, "p2sh")
    psbt_in = plain.update_psbt_input(_psbt_spending(plain.script_pub_key()), 0).inputs[
        0
    ]
    assert psbt_in.redeem_script == plain.redeem_script()
    assert not psbt_in.witness_script


def test_the_account_order_does_not_move_an_origin_off_its_key() -> None:
    """The sort reorders the script, and the mapping is keyed by the key.

    `order="account"` sorts the keys of a group before deriving them, so
    the script carries them in an order the caller did not write. What
    would be wrong silently is a path under the key of another
    participant: a signer would derive a key it does not hold, or worse,
    the wrong key of one it does.
    """
    wallet = ScriptWallet([KeyGroup(2, _XPUBS, origins=_ORIGINS)], "p2wsh", "account")
    # the sort is a reorder over this quorum, which is what leaves the
    # assertion below something to say
    assert sorted(_XPUBS, key=lambda xpub: BIP32KeyData.b58decode(xpub).key) != _XPUBS

    psbt = _psbt_spending(wallet.script_pub_key())
    hd_key_paths = wallet.update_psbt_input(psbt, 0).inputs[0].hd_key_paths
    for xpub, account in zip(_XPUBS, _ACCOUNTS, strict=True):
        assert hd_key_paths[_derived(xpub, 0, 0)].description == _derived_path(
            account, 0, 0
        )


def test_a_group_given_no_origin_writes_no_key_path() -> None:
    """Which is a wallet that computes addresses and updates nothing else.

    An account key records neither the master fingerprint nor the path
    down to itself, so a caller who has neither has nothing to declare,
    and the psbt is short of exactly that field.
    """
    wallet = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh", "derived")
    psbt = _psbt_spending(wallet.script_pub_key())

    psbt_in = wallet.update_psbt_input(psbt, 0).inputs[0]
    assert psbt_in.witness_script == wallet.witness_script()
    assert not psbt_in.hd_key_paths

    # and one origin among several is one entry, the missing ones being
    # skipped rather than refused
    partial = ScriptWallet(
        [KeyGroup(2, _XPUBS, origins=[_ORIGINS[0], None, None])], "p2wsh", "derived"
    )
    psbt = _psbt_spending(partial.script_pub_key())
    assert len(partial.update_psbt_input(psbt, 0).inputs[0].hd_key_paths) == 1


def test_a_key_origin_is_checked_against_the_key_it_belongs_to() -> None:
    """The depth and the index, which are what an extended key records.

    The levels above cannot be checked -- nothing in the key names them --
    so what is refused is a path that does not end at this key: another
    length, or another index at the right depth. A master key is the one
    whose fingerprint is checkable, and it is checked.
    """
    with pytest.raises(BTClibValueError, match="2 levels for a key at depth 3"):
        KeyGroup(1, _XPUBS[:1], origins=[BIP32KeyOrigin(_FINGERPRINT, "m/48h/0h")])
    with pytest.raises(BTClibValueError, match="it ends at 0h, and the key's own"):
        KeyGroup(1, _XPUBS[:1], origins=[BIP32KeyOrigin(_FINGERPRINT, "m/48h/0h/0h")])
    with pytest.raises(BTClibValueError, match="own fingerprint is"):
        KeyGroup(1, [_ROOT], origins=[BIP32KeyOrigin("deadbeef", "m")])
    # the root key with its own origin is the empty path, and passes
    assert KeyGroup(1, [_ROOT], origins=[BIP32KeyOrigin(_FINGERPRINT, "m")]).origins

    with pytest.raises(BTClibValueError, match="2 origins for 3 keys"):
        KeyGroup(2, _XPUBS, origins=_ORIGINS[:2])
    # no origin at all is the default, and it is one None per key rather
    # than an empty tuple: the pairing is positional
    assert KeyGroup(2, _XPUBS).origins == (None,) * len(_XPUBS)


def test_the_updaters_refuse_a_position_or_a_psbt_index_they_have_not() -> None:
    """An IndexError out of a public method is not an answer.

    Nor is the input at the other end, which a negative index would
    quietly update instead.
    """
    wallet = ScriptWallet([KeyGroup(2, _XPUBS, origins=_ORIGINS)], "p2wsh", "derived")
    psbt = _psbt_spending(wallet.script_pub_key())

    with pytest.raises(BTClibValueError, match="invalid input index: 1"):
        wallet.update_psbt_input(psbt, 1)
    with pytest.raises(BTClibValueError, match="invalid input index: -1"):
        wallet.update_psbt_input(psbt, -1)
    with pytest.raises(BTClibValueError, match="invalid output index: 1"):
        wallet.update_psbt_output(psbt, 1)
    with pytest.raises(BTClibValueError, match="invalid output index: -1"):
        wallet.update_psbt_output(psbt, -1)
    for method in (wallet.update_psbt_input, wallet.update_psbt_output):
        with pytest.raises(BTClibValueError, match="invalid branch: 2"):
            method(psbt, 0, 2, 0)


@pytest.mark.parametrize("branch", [0, 1])
@pytest.mark.parametrize(
    "order, name",
    [("none", "multi"), ("account", "multi"), ("derived", "sortedmulti")],
)
def test_one_quorum_is_a_descriptor_in_every_order(
    order: str, name: str, branch: int
) -> None:
    """A template that is one group is BIP383's, per-index order included.

    Which is the one place `sortedmulti()` states the order a quorum is
    given after derivation: it is a descriptor function and not a
    miniscript fragment, so it says this and cannot say it inside a
    combinator. `multi()` states the other two orders by listing the keys
    in the order the script carries them, so the account sort shows up in
    the text and not only in the script.
    """
    group = KeyGroup(2, _XPUBS, origins=_ORIGINS)
    wallet = ScriptWallet([group], "p2wsh", order)  # type: ignore[arg-type]
    ordered = (
        sorted(_XPUBS, key=lambda xpub: BIP32KeyData.b58decode(xpub).key)
        if order == "account"
        else _XPUBS
    )
    descriptor = wallet.descriptor(branch)
    assert str(descriptor) == f"wsh({_multi(2, ordered, branch, name)})"
    assert descriptor.is_ranged
    # the addresses of the branch, which is what the descriptor is for and
    # what makes the equality above more than a claim about text
    assert [descriptor.address(i) for i in range(5)] == [
        wallet.address(branch, i) for i in range(5)
    ]
    # and the text is a descriptor to whoever reads it back, checksum and
    # all: what `descriptor()` returns is what `parse` answers for it
    assert parse(add_checksum(str(descriptor))) == descriptor


def test_the_lift_reads_the_script_and_puts_the_keys_back() -> None:
    """A shape no argument of this class names, out of the script itself.

    The timelocked spending path miniscript *does* state -- OP_CSV with no
    OP_DROP after it -- and the lift is what recognizes it: nothing here
    says `or_i`, `and_v` or `older`, the script says them and
    `miniscript.from_script` reads them.
    """
    template: list[Command | KeyGroup] = [
        "OP_IF",
        KeyGroup(2, _XPUBS, origins=_ORIGINS),
        "OP_ELSE",
        KeyGroup(2, _RECOVERY, verify=True),
        *_MINISCRIPT_TIMELOCK,
        "OP_ENDIF",
    ]
    wallet = ScriptWallet(template, "p2wsh")
    descriptor = wallet.descriptor(1, 8)
    recovery = _multi(2, _RECOVERY, 1, origins=False)
    assert str(descriptor) == (
        f"wsh(or_i({_multi(2, _XPUBS, 1)},and_v(v:{recovery},older(144))))"
    )
    # the recovery group declared no origin, so its keys are written
    # without one -- the same thing an empty `hd_key_paths` says, and a
    # descriptor BIP380 allows
    assert "[" not in recovery
    assert [descriptor.address(i) for i in range(8)] == [
        wallet.address(1, i) for i in range(8)
    ]
    # and the wallet of the pair of descriptors answers the same addresses
    # from the other source, which is the bridge this method is
    both = DescriptorWallet({b: wallet.descriptor(b) for b in wallet.branches})
    assert both.address(0, 3) == wallet.address(0, 3)
    assert both.position_of(wallet.script_pub_key(1, 5), 6) == (1, 5)


def test_a_key_the_wallet_does_not_derive_stays_the_key_it_is() -> None:
    """A literal push in the template is a fixed key in the descriptor.

    The honest answer rather than a refusal: BIP380 states a public key as
    the hex it is, so what comes out is ranged in the keys of the groups
    and fixed in the one the template wrote down -- which is exactly what
    the wallet computes at every index.
    """
    literal = _derived(_RECOVERY[0], 0, 0).hex()
    wallet = ScriptWallet(
        [literal, "OP_CHECKSIGVERIFY", KeyGroup(1, _XPUBS[:1], origins=_ORIGINS[:1])],
        "p2wsh",
    )
    descriptor = wallet.descriptor()
    assert str(descriptor) == (
        f"wsh(and_v(v:pk({literal}),{_multi(1, _XPUBS[:1], 0)}))"
    )
    assert [descriptor.address(i) for i in range(4)] == [
        wallet.address(0, i) for i in range(4)
    ]


@pytest.mark.parametrize(
    "script_type, text",
    [
        ("p2sh", "sh({})"),
        ("p2wsh", "wsh({})"),
        ("p2sh-p2wsh", "sh(wsh({}))"),
    ],
)
def test_a_quorum_has_a_descriptor_for_each_way_it_becomes_an_output(
    script_type: str, text: str
) -> None:
    """Including the legacy p2sh one, which no miniscript can be read in.

    `sh(sortedmulti(2,...))` is the pre-descriptor multisig wallet, and it
    is BIP381 wrapping BIP383 rather than a miniscript: the quorum is
    written from the groups, so the script type is the only thing that
    changes here.
    """
    group = KeyGroup(2, _XPUBS, origins=_ORIGINS)
    wallet = ScriptWallet([group], script_type, "derived")  # type: ignore[arg-type]
    descriptor = wallet.descriptor()
    assert str(descriptor) == text.format(_multi(2, _XPUBS, 0, "sortedmulti"))
    assert descriptor.address(3) == wallet.address(0, 3)


def test_an_xprv_in_a_quorum_is_not_written_into_the_descriptor() -> None:
    """A descriptor is text that gets logged, and `parse` neuters one too.

    The origins are looked up under the xpub for the same reason: it is
    the spelling the answer carries, whichever of the two the group was
    given.
    """
    signing = ScriptWallet([KeyGroup(2, _XPRVS, origins=_ORIGINS)], "p2wsh")
    watching = ScriptWallet([KeyGroup(2, _XPUBS, origins=_ORIGINS)], "p2wsh")
    assert not signing.is_watch_only
    assert signing.descriptor() == watching.descriptor()
    assert all(xprv not in str(signing.descriptor()) for xprv in _XPRVS)


def test_a_quorum_ordered_per_index_inside_a_combinator_has_no_descriptor() -> None:
    """The refusal the class exists for, and the one nothing can widen.

    `sortedmulti()` states the order of a quorum that is the whole script;
    inside a combinator BIP379 has no fragment that states it, so the
    order is a property of the index and no ranged expression covers it.
    """
    template: list[Command | KeyGroup] = [
        "OP_IF",
        KeyGroup(2, _XPUBS),
        "OP_ELSE",
        KeyGroup(2, _RECOVERY, verify=True),
        *_MINISCRIPT_TIMELOCK,
        "OP_ENDIF",
    ]
    wallet = ScriptWallet(template, "p2wsh", "derived")
    with pytest.raises(NoDescriptorError, match="sorted after derivation"):
        wallet.descriptor()
    # the very same template in the declared order does have one, which is
    # what leaves the refusal above about the order and nothing else
    declared = ScriptWallet(template, "p2wsh").descriptor()
    assert str(declared).startswith("wsh(or_i(multi(2,")


def test_a_script_no_miniscript_reads_has_no_descriptor() -> None:
    """`<n> OP_CSV OP_DROP` closes no fragment: the deployed spelling.

    The message is `from_script`'s own, this being a refusal about the
    script rather than one this class works out for itself.
    """
    template: list[Command | KeyGroup] = [
        "OP_IF",
        KeyGroup(2, _XPUBS),
        "OP_ELSE",
        *_TIMELOCK,
        KeyGroup(2, _RECOVERY),
        "OP_ENDIF",
    ]
    err_msg = "not a miniscript: op code 0x75 closes no fragment"
    with pytest.raises(NoDescriptorError, match=err_msg):
        ScriptWallet(template, "p2wsh").descriptor()


def test_a_legacy_script_that_is_not_a_bare_quorum_has_no_descriptor() -> None:
    """A p2sh miniscript is not a thing: P2WSH and tapscript are the two."""
    template: list[Command | KeyGroup] = [
        "OP_IF",
        KeyGroup(2, _XPUBS),
        "OP_ELSE",
        KeyGroup(1, _RECOVERY[:1]),
        "OP_ENDIF",
    ]
    with pytest.raises(NoDescriptorError, match="no legacy one"):
        ScriptWallet(template, "p2sh").descriptor()


def test_a_required_quorum_on_its_own_is_no_script_at_all() -> None:
    """An OP_CHECKMULTISIGVERIFY leaves nothing on the stack: a V, not a B.

    Which the lift is what says: a template of one group is BIP383's
    quorum, and `verify=True` is not that quorum -- so it falls through to
    `from_script`, where the type of the expression is the answer.
    """
    wallet = ScriptWallet([KeyGroup(2, _XPUBS, verify=True)], "p2wsh")
    with pytest.raises(NoDescriptorError, match="not a miniscript script"):
        wallet.descriptor()


def test_a_per_index_sort_that_is_not_bip67_is_stated_by_nothing() -> None:
    """``sortedmulti()`` is byte order on the derived keys, and only that.

    So the one quorum that has a descriptor in the plain per-index order
    stops having one as soon as the sort is the caller's own: the function
    would state a different order, and `multi()` cannot state this one
    either, it not being a property of the wallet. Refused whatever the
    key function computes -- one that happens to agree with byte order at
    every index is not something this could know, and a descriptor is
    right or it is not offered.
    """
    wallet = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh", "derived", sort_key=bytes.hex)
    with pytest.raises(NoDescriptorError, match="sorted after derivation"):
        wallet.descriptor()


def test_an_expression_no_descriptor_may_hold_has_no_descriptor() -> None:
    """Sane or refused, which is Bitcoin Core's rule for a descriptor.

    The lift reads the script and `parse` judges it, so a wallet whose two
    spending paths share a key is refused with the reason a descriptor is
    refused for -- not with a failure to read the script, which read fine.
    """
    template: list[Command | KeyGroup] = [
        "OP_IF",
        KeyGroup(2, _XPUBS),
        "OP_ELSE",
        KeyGroup(2, _XPUBS[:2], verify=True),
        *_MINISCRIPT_TIMELOCK,
        "OP_ENDIF",
    ]
    with pytest.raises(NoDescriptorError, match="it repeats a public key"):
        ScriptWallet(template, "p2wsh").descriptor()


def test_a_substitution_that_put_no_key_back_is_not_a_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lift that missed every key describes one script, and says so.

    Which is the first thing the confirmation asks, and it has to be
    asked before the comparison: a descriptor of one script has no index 1
    to compare at, so a caller would otherwise be told the index is out of
    range and left to work out why.
    """
    template: list[Command | KeyGroup] = [
        "OP_IF",
        KeyGroup(2, _XPUBS),
        "OP_ELSE",
        KeyGroup(2, _RECOVERY, verify=True),
        *_MINISCRIPT_TIMELOCK,
        "OP_ENDIF",
    ]
    # the quorum path writes the key expressions itself, so the lift is
    # only reached by a template a combinator makes of it
    monkeypatch.setattr(script_wallet_module, "_lifted", lambda node, expressions: node)
    with pytest.raises(BTClibRuntimeError, match="not a range"):
        ScriptWallet(template, "p2wsh").descriptor()


def test_a_lift_that_derives_something_else_is_not_handed_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The confirmation, on a substitution that is ranged and wrong.

    A key expression naming the other chain is the shape of the mistake
    this guards against: every key is put back, the descriptor is ranged,
    and what it derives is a wallet nobody has. The addresses are what
    tells the two apart, which is why they are compared rather than
    trusted.
    """

    def other_branch(
        self: ScriptWallet,
        key: BIP32KeyData,
        branch: int,
        origins: object,
    ) -> KeyExpression:
        return KeyExpression(xkey=key.b58encode(), der_path=(1 - branch,), wildcard=0)

    monkeypatch.setattr(ScriptWallet, "_key_expression", other_branch)
    wallet = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh")
    with pytest.raises(BTClibRuntimeError, match="where this wallet pays to"):
        wallet.descriptor()


def test_a_lift_is_confirmed_at_two_positions_or_the_call_is_refused() -> None:
    """One is index 0, which is where the expression was read: no evidence."""
    wallet = ScriptWallet([KeyGroup(2, _XPUBS)], "p2wsh")
    with pytest.raises(BTClibValueError, match="invalid checked_indexes: 1"):
        wallet.descriptor(0, 1)
    # and a branch this wallet has no chain at is refused as everywhere
    # else, the position being checked before anything is derived
    with pytest.raises(BTClibValueError, match="invalid branch: 2"):
        wallet.descriptor(2)
