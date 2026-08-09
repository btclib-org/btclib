# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.wallet.descriptor_wallet` module.

What a `DescriptorWallet` adds to a `Descriptor` is the branch, the ledger
and `position_of`; what it delegates is the rest. So these tests are about
the pairing -- the three ways the chains get their labels, and the
refusals a chain cannot be built from -- and about the delegation being
the descriptor's own answer at the position asked for, rather than a
second implementation of it.
"""

from __future__ import annotations

import pytest

from btclib.bip32 import bip32
from btclib.descriptors import add_checksum, parse
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.psbt.psbt import Psbt
from btclib.script.script_pub_key import ScriptPubKey
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from btclib.wallet import BIP32KeyWallet, DescriptorWallet

# the "abandon abandon ... about" seed and its BIP84 account, which is the
# account every other wallet test uses too
_ROOT = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
_ACCOUNT = "m/84h/0h/0h"
_FINGERPRINT = "73c5da0a"

# SLIP132's account xpub for purpose 44, which most of the tests below
# only need to be *an* account xpub, and the BIP84 one beside it, for the
# two that check a descriptor wallet against the key wallet of the very
# same account
_XPUB = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
_ACCOUNT_XPUB = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
_XPUB_OTHER = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"

# a p2wsh address of nobody's wallet here: BIP173's own vector
_ELSEWHERE = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"


def _descriptor(expression: str) -> str:
    """Return the expression with the checksum `parse` verifies."""
    return add_checksum(expression)


def test_the_chains_can_be_given_three_ways() -> None:
    """A mapping, a sequence, and one descriptor on its own.

    The sequence is the chains in order, which is what
    `descriptors.account_descriptors` returns and how BIP389 expands; the
    mapping is for a caller whose labels are not 0 and 1, and one
    descriptor alone is the wallet of a single chain -- what a caller
    watching only receiving addresses has, and not an error.
    """
    receive, change = (parse(_descriptor(f"wpkh({_XPUB}/{i}/*)")) for i in (0, 1))

    ordered = DescriptorWallet([receive, change])
    assert ordered.branches == (0, 1)

    labelled = DescriptorWallet({7: receive, 3: change})
    # sorted, so that `branches` is ascending whatever order they came in
    assert labelled.branches == (3, 7)
    assert labelled.descriptor(7) is receive

    alone = DescriptorWallet(receive)
    assert alone.branches == (0,)
    assert alone.address(0, 4) == ordered.address(0, 4)


def test_the_multipath_spelling_is_one_line_for_the_whole_wallet() -> None:
    """BIP389's ``<0;1>``, expanded positionally: element 0 is branch 0."""
    wallet = DescriptorWallet.from_descriptor(
        _descriptor(f"wpkh([{_FINGERPRINT}/84h/0h/0h]{_ACCOUNT_XPUB}/<0;1>/*)")
    )
    assert wallet.branches == (0, 1)
    assert wallet.is_ranged
    assert wallet.address(1, 0) == BIP32KeyWallet(_ROOT, _ACCOUNT).address(1, 0)

    # and a descriptor with no multipath step is a wallet of one chain
    single = DescriptorWallet.from_descriptor(_descriptor(f"wpkh({_XPUB}/0/*)"))
    assert single.branches == (0,)


def test_an_account_xpub_is_the_wallet_its_purpose_says() -> None:
    """`from_account` is `descriptors.account_descriptors`, as a wallet.

    Every argument is that function's, and the addresses are the ones the
    same account answers as a `BIP32KeyWallet`: the purpose selects the
    encoding in both.
    """
    keys = BIP32KeyWallet(_ROOT, "m/49h/0h/0h")
    wallet = DescriptorWallet.from_account(_ROOT, "m/49h/0h/0h", _FINGERPRINT)
    assert wallet.script_type == "p2sh"
    assert wallet.address(0, 0) == keys.address(0, 0)
    # the script type override is account_descriptors' own, and reaches it
    overridden = DescriptorWallet.from_account(
        _ROOT, "m/49h/0h/0h", _FINGERPRINT, "p2wpkh"
    )
    assert overridden.script_type == "p2wpkh"
    assert overridden.address(0, 0) == BIP32KeyWallet(
        _ROOT, "m/49h/0h/0h", "p2wpkh"
    ).address(0, 0)


def test_a_descriptor_string_is_not_a_descriptor() -> None:
    """The mistake a `Sequence` would otherwise read character by character."""
    err_msg = "a descriptor string is not a Descriptor"
    with pytest.raises(BTClibTypeError, match=err_msg):
        DescriptorWallet(f"wpkh({_XPUB}/0/*)")  # type: ignore[arg-type]


def test_a_wallet_has_at_least_one_chain() -> None:
    """No descriptor is not a wallet with nothing in it; it is nothing."""
    with pytest.raises(BTClibValueError, match="no descriptor"):
        DescriptorWallet([])
    with pytest.raises(BTClibValueError, match="no descriptor"):
        DescriptorWallet({})


def test_a_branch_is_a_label_and_labels_are_not_negative() -> None:
    """The one thing a chain label has to be, `position_of` walking them."""
    with pytest.raises(BTClibValueError, match="invalid branch: -1"):
        DescriptorWallet({-1: parse(_descriptor(f"wpkh({_XPUB}/0/*)"))})


def test_the_chains_must_be_of_one_network() -> None:
    """A wallet is on a chain, and a network is what a chain is."""
    mainnet = parse(_descriptor(f"wpkh({_XPUB}/0/*)"))
    testnet = parse(_descriptor(f"wpkh({_XPUB}/1/*)"), "testnet")
    err_msg = r"descriptors of different networks: \['mainnet', 'testnet'\]"
    with pytest.raises(BTClibValueError, match=err_msg):
        DescriptorWallet([mainnet, testnet])


def test_a_combo_is_four_addresses_at_one_position() -> None:
    """Which is not a wallet position, so the wallet refuses it.

    `Descriptor.script_pub_keys` is what answers for a ``combo()``, and
    the message says so: a position that meant four addresses would make
    `address(branch, index)` a lie.
    """
    combo = parse(_descriptor(f"combo({_XPUB}/0/*)"))
    with pytest.raises(BTClibValueError, match="combo\\(\\) at branch 0"):
        DescriptorWallet([combo])


def test_a_script_with_no_address_is_not_handed_out() -> None:
    """A ``pk()`` is a script and not an address, and says which it is.

    The wallet is built all the same -- `script_pub_key` and
    `position_of` answer for it -- and it is `address` that refuses,
    rather than handing out the "" a script with no address renders as.
    """
    wallet = DescriptorWallet(parse(_descriptor(f"pk({_XPUB}/0/*)")))
    assert wallet.script_type == "p2pk"
    assert wallet.script_pub_key(0, 3).script
    assert wallet.position_of(wallet.script_pub_key(0, 3), 4) == (0, 3)
    with pytest.raises(BTClibValueError, match="no address for the script at 0/3"):
        wallet.address(0, 3)


def test_a_wallet_that_is_not_ranged_has_one_position_per_chain() -> None:
    """`is_ranged` is the descriptors', and so is the bound it imposes."""
    address = _ELSEWHERE
    wallet = DescriptorWallet(parse(_descriptor(f"addr({address})")))
    assert not wallet.is_ranged
    assert wallet.address() == address
    assert wallet.position_of(address, 999) == (0, 0)
    err_msg = "not a ranged descriptor: no script at index 1"
    with pytest.raises(BTClibValueError, match=err_msg):
        wallet.address(0, 1)


def test_the_two_pre_images_are_the_wrapped_descriptors_own() -> None:
    """BIP174's redeem script and witness script, per position.

    Four shapes: a ``sh()`` has the first, a ``wsh()`` the second, a
    ``sh(wsh())`` both -- the wrapping showing up in the redeem script and
    nowhere else -- and a bare ``wpkh()`` neither.
    """
    multi = f"multi(1,{_XPUB}/0/*,{_XPUB_OTHER}/0/*)"
    sh = DescriptorWallet(parse(_descriptor(f"sh({multi})")))
    wsh = DescriptorWallet(parse(_descriptor(f"wsh({multi})")))
    sh_wsh = DescriptorWallet(parse(_descriptor(f"sh(wsh({multi}))")))
    wpkh = DescriptorWallet(parse(_descriptor(f"wpkh({_XPUB}/0/*)")))

    quorum = parse(_descriptor(multi)).redeem_script(3)
    assert sh.redeem_script(0, 3) == quorum
    assert not sh.witness_script(0, 3)

    assert wsh.witness_script(0, 3) == quorum
    assert not wsh.redeem_script(0, 3)

    assert sh_wsh.witness_script(0, 3) == quorum
    assert sh_wsh.redeem_script(0, 3) == ScriptPubKey.p2wsh(quorum).script

    assert not wpkh.redeem_script(0, 3)
    assert not wpkh.witness_script(0, 3)
    # a sh(wpkh()) has the p2wpkh program as its redeem script, which is
    # what the wrapped form pushes
    sh_wpkh = DescriptorWallet(parse(_descriptor(f"sh(wpkh({_XPUB}/0/*))")))
    assert (
        sh_wpkh.redeem_script(0, 3)
        == ScriptPubKey.p2wpkh(
            parse(_descriptor(f"wpkh({_XPUB}/0/*)"))
            .key_expressions[0]
            .sec(3, "mainnet")
        ).script
    )
    assert not sh_wpkh.witness_script(0, 3)


def test_position_of_is_index_of_per_chain() -> None:
    """The same whole-script comparison, asked of each chain in turn."""
    wallet = DescriptorWallet.from_account(_ROOT, _ACCOUNT, _FINGERPRINT)
    assert wallet.position_of(wallet.script_pub_key(1, 6), 9) == (1, 6)
    assert wallet.position_of(wallet.script_pub_key(1, 6), 5) is None
    assert wallet.position_of(_ELSEWHERE, 5) is None
    # the refusals are index_of's, which is what makes them one rule
    with pytest.raises(BTClibValueError, match="empty script_pub_key"):
        wallet.position_of("")


def test_the_hardened_steps_are_walked_with_the_private_keys() -> None:
    """`prv_keys` is what a descriptor takes and what makes a wallet sign.

    A parsed descriptor holds no private key -- `descriptors.parse` keeps
    the xpub of an xprv -- so that mapping is the only key material a
    wallet of descriptors can have, and `is_watch_only` reads it.
    """
    xprv = bip32.derive(_ROOT, _ACCOUNT)
    xpub = bip32.xpub_from_xprv(xprv)
    expression = f"wpkh([{_FINGERPRINT}/84h/0h/0h]{xpub}/0h/*)"

    # and the refusal is at construction, not at the first address: the
    # first thing a wallet does is derive one script, so a wallet that
    # could compute none of its own scripts is never built
    err_msg = "invalid hardened derivation from public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        DescriptorWallet.from_descriptor(_descriptor(expression))

    signing = DescriptorWallet.from_descriptor(
        _descriptor(expression), prv_keys={xpub: xprv}
    )
    assert not signing.is_watch_only
    assert signing.address(0, 0)


def test_satisfy_is_the_descriptors_own_at_the_position() -> None:
    """The spend of one position, assembled from the signatures handed in."""
    wallet = DescriptorWallet.from_account(_ROOT, _ACCOUNT, _FINGERPRINT)
    descriptor = wallet.descriptor(1)
    sec = descriptor.key_expressions[0].sec(2, "mainnet")
    signature = bytes.fromhex("3045") + b"\x01" * 69

    assert wallet.satisfy({sec: signature}, 1, 2) == descriptor.satisfy(
        {sec: signature}, 2
    )
    # and a position the wallet has no output at is refused before the
    # signatures are looked up under a key derived from it
    with pytest.raises(BTClibValueError, match="invalid branch: 2"):
        wallet.satisfy({sec: signature}, 2, 2)


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


def test_the_updaters_take_a_position_where_a_descriptor_takes_an_index() -> None:
    """Which is the whole of what the wallet adds to BIP174's Updater.

    A caller holding a psbt has a position -- the change output is
    `branch 1`, at whatever index the wallet handed out -- and the fields
    written are the descriptor's own.
    """
    wallet = DescriptorWallet.from_account(_ROOT, "m/49h/0h/0h", _FINGERPRINT)
    change = wallet.script_pub_key(1, 2)
    psbt = _psbt_spending(change)

    updated = wallet.update_psbt_input(psbt, 0, 1, 2)
    assert updated.inputs[0].redeem_script == wallet.redeem_script(1, 2)
    assert updated.inputs[0].hd_key_paths

    paid = wallet.update_psbt_output(psbt, 0, 1, 2)
    assert paid.outputs[0].redeem_script == wallet.redeem_script(1, 2)
    # the output half refuses unless the output being paid is the very
    # script the position derives, which is `position_of` as a claim
    with pytest.raises(BTClibValueError, match="which is not the script"):
        wallet.update_psbt_output(psbt, 0, 1, 3)
    for method in (wallet.update_psbt_input, wallet.update_psbt_output):
        with pytest.raises(BTClibValueError, match="invalid branch: 2"):
            method(psbt, 0, 2, 2)
