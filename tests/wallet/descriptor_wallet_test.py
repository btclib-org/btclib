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

The last four are about one output type rather than about the class, and
they are here because the answer to "does btclib need a taproot wallet" is
this file: a ``tr()`` with a script tree is the shape that makes a
`ScriptWallet` necessary for p2wsh -- two spending paths behind one
address, one of them timelocked -- and as a descriptor it needs no
template. What they pin is the whole of what that costs a caller: the
addresses of both chains, the tree being inside the output key,
`redeem_script` and `witness_script` answering `b""` because a p2tr output
has neither, and BIP371's psbt fields carrying the leaf scripts and the
tree in their place.
"""

from __future__ import annotations

import pytest

from btclib.bip32 import bip32
from btclib.descriptors import (
    Miniscript,
    MultiA,
    TrDescriptor,
    add_checksum,
    parse,
)
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.psbt.psbt import Psbt
from btclib.script import script
from btclib.script.script_pub_key import ScriptPubKey
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from btclib.utils import encode_num
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


# A taproot wallet of the same seed: an internal key that spends by the key
# path, and a script tree of two leaves -- a 2-of-2 that spends now, and a
# 2-of-2 that spends after a relative timelock. Five accounts of one seed,
# each key carrying its own origin, which is what a hardware signer reads.
_TAPROOT_ACCOUNTS = [f"m/86h/0h/{i}h" for i in range(5)]
_TAPROOT_XPUBS = [
    "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
    "xpub6BgBgsespWvEUBtu8NPpew4suu4JeuYz1ryQBqRKYk6BCN4p6nugJwXyBFjwPS93FTP4Rvkgqzhoy4ZysXh6f6jPWrjwbtG5PBzqPJghDkT",
    "xpub6BgBgsespWvEUNQvZj72AxG29hVzAPMDoKvBra591gqt3cLWTZx3y94qLb3tcT45XdxMjocQLz9M8zv2UtQdG7Tk8FXx4JdB4PRfoTfDcd5",
    "xpub6BgBgsespWvEWvvEW19QjiCZRXgy8ScjDH26BRXm2c4DRmt5apjJ1FyjQM6KzWajnXKwkERUzZ7BqC8evgb8LPsANycnVktLoFrXqjwQy7y",
    "xpub6BgBgsespWvEbyJV7d8VrTwxGSQpacvMT41jPU94mnuYF2DoxYgZ3kXyuthB2PibVsPQBxAxe3pVRkTki6qkyLJQc66g9F4jE7ZiJeVDuNU",
]

# 36 days, the timelock the wallet of #538 puts on its recovery path: the
# same design one output type further on
_RECOVERY_BLOCKS = 5184

# the first three addresses of each chain, as a regression net. The
# authority on taproot arithmetic is elsewhere -- BIP386 and BIP387's own
# vectors, in tests/descriptors/ -- and what these pin is that the wallet
# goes on composing it the same way at the same positions
_TAPROOT_ADDRESSES = {
    0: [
        "bc1pmxg54dnfx29hqud65z0scndw3ht75zsact939tjsfnwrqkn8wytsz2zcv2",
        "bc1p4866xnzdfrpf3gj0z8ym6u65s2jy9wxr5prqenrf5dtxemu4fs0qfgwmnh",
        "bc1pjdkna238d0egvedjtnhcxfk374tqjs2xf5sj86uajc6hsdw6yvmq2ec5yr",
    ],
    1: [
        "bc1pkygfwanlq4nppwclxr3uhtca84xt9hpq78wl5ynh2x0ccr48q35qupxhrj",
        "bc1p7m2rq2cs2g3rwsau7w55e3l098hytvdem45w2svfwd2lew7fredsr3jf7q",
        "bc1plj2d9x7tw80kk8nap6y3kg7gvvfah2eqs3lr4zh4x6jyg423gs6qqx735c",
    ],
}


def _taproot_key(i: int, step: str) -> str:
    """Return the i-th key expression, at a derivation step of its own."""
    return f"[{_FINGERPRINT}/86h/0h/{i}h]{_TAPROOT_XPUBS[i]}/{step}/*"


def _taproot_descriptor(step: str) -> str:
    """Return the ``tr()`` of the wallet, at one derivation step.

    `<0;1>` for the wallet of both chains, and `0` or `1` for the chain
    written on its own, which is what the multipath expansion is checked
    against below.
    """
    return _descriptor(
        f"tr({_taproot_key(0, step)},"
        f"{{multi_a(2,{_taproot_key(1, step)},{_taproot_key(2, step)}),"
        f"and_v(v:older({_RECOVERY_BLOCKS}),"
        f"multi_a(2,{_taproot_key(3, step)},{_taproot_key(4, step)}))}})"
    )


def _taproot_wallet() -> DescriptorWallet:
    """Return that wallet, both chains, from the one multipath line."""
    return DescriptorWallet.from_descriptor(_taproot_descriptor("<0;1>"))


def test_a_taproot_tree_is_a_wallet_with_nothing_added() -> None:
    """The output type `ScriptWallet` does not cover, because this does.

    A ``tr()`` with a script tree is a wallet of the shape that makes a
    `ScriptWallet` necessary for p2wsh -- two spending paths behind one
    address, one of them timelocked -- and here it is a descriptor, so it
    is a `DescriptorWallet` and needs no template: the addresses, the
    chains and `position_of` come out of the same three methods every
    other wallet answers.
    """
    wallet = _taproot_wallet()
    assert wallet.script_type == "p2tr"
    assert wallet.branches == (0, 1)
    assert wallet.is_ranged
    assert wallet.is_watch_only

    for branch, addresses in _TAPROOT_ADDRESSES.items():
        assert [
            wallet.address(branch, index) for index in range(len(addresses))
        ] == addresses
        # and the branch is the label of a chain, so it is the chain that
        # descriptor states on its own: the BIP389 expansion is positional
        single = parse(_taproot_descriptor(str(branch)))
        assert [single.address(index) for index in range(len(addresses))] == addresses


def test_the_leaves_are_in_the_output_key_and_reachable() -> None:
    """A tree changes the address, and the wallet hands the tree back.

    The first half is what makes `position_of` an answer about the whole
    wallet: an output key commits to the merkle root, so the same internal
    key with another tree is another address, and recognizing one's own
    output is recognizing the tree too.

    The second is where the vocabulary stops on purpose --
    `descriptor(branch)` is what a caller reads the leaves off, this class
    asking only the questions every wallet answers.
    """
    wallet = _taproot_wallet()
    key_path_only = parse(_descriptor(f"tr({_taproot_key(0, '0')})"))
    assert key_path_only.address() != wallet.address(0, 0)

    descriptor = wallet.descriptor(0)
    assert isinstance(descriptor, TrDescriptor)
    # a branch of two leaves, and not one leaf: `DescriptorTree` is either
    # a leaf, a pair of subtrees, or nothing at all
    tree = descriptor.tree
    assert isinstance(tree, tuple)
    assert isinstance(tree[0], MultiA)
    assert isinstance(tree[1], Miniscript)
    assert wallet.position_of(wallet.address(1, 2), 3) == (1, 2)


def test_a_taproot_wallet_has_neither_pre_image_of_a_v0_output() -> None:
    """`redeem_script` and `witness_script` are `b""`, and that is honest.

    They are BIP174's two version-0 fields, and a p2tr output has neither:
    what it commits to is a merkle root over leaves, each with its own
    control block. The psbt is where those travel, which is the test
    below, and `b""` here is "no such script" rather than "not
    implemented" -- the same answer a native p2wsh gives to
    `redeem_script`.
    """
    wallet = _taproot_wallet()
    for branch in (0, 1):
        assert not wallet.redeem_script(branch, 2)
        assert not wallet.witness_script(branch, 2)


def test_the_psbt_carries_what_the_two_pre_images_cannot() -> None:
    """BIP371's fields, filled by the descriptor at the wallet's position.

    The output half publishes the internal key and the whole tree, which
    is what lets a reader rebuild the output key and see that the money
    comes back; the input half publishes the leaf scripts and the merkle
    root, which is what a signer of one leaf needs. Both come from
    `Descriptor`, and what the wallet adds is that the position they are
    asked at is a `(branch, index)`.
    """
    wallet = _taproot_wallet()
    script_pub_key = wallet.script_pub_key(1, 2)
    psbt = _psbt_spending(script_pub_key)

    psbt_out = wallet.update_psbt_output(psbt, 0, 1, 2).outputs[0]
    assert psbt_out.taproot_internal_key
    assert len(psbt_out.taproot_tree) == 2
    # one origin per key of the wallet, the internal one included: it is
    # what a hardware signer matches its own fingerprint against
    assert len(psbt_out.taproot_hd_key_paths) == len(_TAPROOT_XPUBS)

    psbt_in = wallet.update_psbt_input(psbt, 0, 1, 2).inputs[0]
    assert psbt_in.taproot_internal_key == psbt_out.taproot_internal_key
    assert psbt_in.taproot_merkle_root
    # keyed by control block, and each value is the leaf script with its
    # version: 0xc0 is the tapscript BIP342 defines, and the only one a
    # descriptor can name
    assert len(psbt_in.taproot_leaf_scripts) == 2
    leaves = list(psbt_in.taproot_leaf_scripts.values())
    assert {version for _, version in leaves} == {0xC0}
    # and the timelocked leaf is there as the script it compiles to, which
    # is the pre-image the recovery path is spent with -- with the OP_VERIFY
    # that and_v(v:older(n),X) emits, and not the OP_DROP the wallet of #538
    # writes by hand, which is why that one has no descriptor at all
    timelock = script.serialize(
        [encode_num(_RECOVERY_BLOCKS).hex(), "OP_CHECKSEQUENCEVERIFY", "OP_VERIFY"]
    )
    assert sum(leaf_script.startswith(timelock) for leaf_script, _ in leaves) == 1
