# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `psbt_signer.SoftwareSigner`, the reference implementation.

The other test module of that file exercises the checks with doubles that
lie; this one runs the real thing end to end, which is what the signer is
for: a psbt built by btclib's own Updater, signed through the contract,
checked by `request_signatures` and finalized -- with no device and
nothing mocked, so a failure anywhere in that chain is a failure here.

The key is BIP84's published root, so the addresses the account exports
are the ones `tests/bip44_test.py` checks against the BIP.
"""

from __future__ import annotations

import pytest

from btclib.bip32.bip32 import BIP32KeyData, derive, xpub_from_xprv
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.core_import import account_import_requests
from btclib.descriptors import Descriptor, add_checksum
from btclib.exceptions import BTClibValueError
from btclib.psbt.psbt import Psbt, finalize
from btclib.psbt_signer import (
    AddressDisplay,
    MessageSigner,
    PsbtSigner,
    SignerCapabilities,
    SoftwareSigner,
    display_address,
    export_account,
    request_signatures,
    sign_message,
)
from btclib.script.engine import verify_transaction
from btclib.tx import OutPoint, Tx, TxIn, TxOut

# the "abandon abandon ... about" root of BIP39, which BIP84 publishes
XPRV_ROOT = (
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRR"
    "uL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
)


def spending(
    receive: Descriptor, change: Descriptor, index: int = 0
) -> tuple[Psbt, list[TxOut]]:
    """Return a psbt spending one address and paying change to another.

    The shape a wallet builds: an input of its own, a payment out, and
    change back. Both halves are updated from the descriptors, which is
    what makes the psbt one a signer can answer -- the input for the key
    origins it signs by, the output for the change a device recognizes.
    """
    prev_out = TxOut(100_000, receive.script_pub_key(index))
    prev_tx = Tx(vin=[TxIn(OutPoint(b"\x06" * 32, 0))], vout=[prev_out])
    tx = Tx(
        vin=[TxIn(OutPoint(prev_tx.id, 0))],
        vout=[
            TxOut(60_000, receive.script_pub_key(index + 1)),
            TxOut(39_000, change.script_pub_key(index)),
        ],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].non_witness_utxo = prev_tx
    psbt = receive.update_psbt_input(psbt, 0, index)
    psbt = change.update_psbt_output(psbt, 1, index)
    return psbt, [prev_out]


def test_the_software_signer_answers_every_protocol() -> None:
    """One class, the three contracts, and taproot among its capabilities."""
    signer = SoftwareSigner(XPRV_ROOT)
    assert isinstance(signer, PsbtSigner)
    assert isinstance(signer, AddressDisplay)
    assert isinstance(signer, MessageSigner)

    assert signer.capabilities() == SignerCapabilities(taproot=True, musig2=False)
    assert SoftwareSigner(XPRV_ROOT, musig2=True).capabilities().musig2
    assert not signer.is_watch_only
    assert signer.master_fingerprint().hex() == "73c5da0a"
    assert signer.xpub("m/84h/0h/0h") == xpub_from_xprv(
        derive(XPRV_ROOT, "m/84h/0h/0h")
    )

    # every spelling of a BIP32Key is one key: the b58 text, its bytes,
    # and the decoded object, held here as the text whichever came in
    decoded = BIP32KeyData.b58decode(XPRV_ROOT)
    for xkey in (decoded, XPRV_ROOT.encode("ascii")):
        assert SoftwareSigner(xkey).xpub("m/0") == signer.xpub("m/0")
    # and a key that is no key is refused where it was handed in
    with pytest.raises(BTClibValueError):
        SoftwareSigner("not a key")


@pytest.mark.parametrize("purpose", [44, 49, 84, 86])
def test_a_psbt_of_an_exported_account_is_signed_and_spends(purpose: int) -> None:
    """The whole flow, once per BIP44 encoding, and the engine is the oracle.

    Export the account, build a psbt of it, update both halves, send it
    through the contract, check what came back, finalize, and run the
    spend under btclib's own script engine. Every role BIP174 names is a
    btclib call and the last one is checked by executing it, so a
    signature made under the wrong sig_hash, a key origin that derives to
    another key or a witness assembled wrong all fail here.
    """
    signer = SoftwareSigner(XPRV_ROOT)
    receive, change = export_account(signer, f"m/{purpose}h/0h/0h")
    psbt, prevouts = spending(receive, change)

    signed = request_signatures(signer, psbt)
    assert signed != psbt

    final = finalize(signed)
    tx = final.tx
    tx.vin[0].script_sig = final.inputs[0].final_script_sig
    tx.vin[0].script_witness = final.inputs[0].final_script_witness
    verify_transaction(prevouts, tx)


def test_the_change_output_carries_what_a_device_reads() -> None:
    """What the signer is told about the output that comes back.

    The origin of the change key, under the same master fingerprint the
    signer answers with -- which is what lets a device show a payment and
    a change output differently -- and the script it was checked against
    before the claim was made.
    """
    signer = SoftwareSigner(XPRV_ROOT)
    receive, change = export_account(signer, "m/84h/0h/0h")
    psbt, _ = spending(receive, change, 5)

    psbt_out = psbt.outputs[1]
    ((pub_key, origin),) = psbt_out.hd_key_paths.items()
    assert pub_key == change.key_expressions[0].sec(5)
    assert origin.master_fingerprint == signer.master_fingerprint()
    assert origin.description == "73c5da0a/84h/0h/0h/1/5"
    # the payment is not the wallet's, so nothing was written on it
    assert not psbt.outputs[0].hd_key_paths


def test_the_signer_answers_for_its_own_keys_only() -> None:
    """A key at a path this signer cannot walk is somebody else's.

    Three ways for that, and each answers None rather than raising: an
    origin under another master fingerprint, a path this key cannot
    derive, and an input naming a public key the path does not lead to --
    which is the check a device makes too, a psbt being written by
    whoever sends it.
    """
    signer = SoftwareSigner(XPRV_ROOT)
    receive, change = export_account(signer, "m/84h/0h/0h")
    psbt, _ = spending(receive, change)
    origin = next(iter(psbt.inputs[0].hd_key_paths.values()))
    pub_key = next(iter(psbt.inputs[0].hd_key_paths))
    msg_hash = b"\x07" * 32

    assert signer.sign_ecdsa(pub_key, origin, msg_hash) is not None
    assert signer.sign_ecdsa(pub_key, None, msg_hash) is None

    # one stranger on each side of this signer's own fingerprint in byte
    # order -- 73c5da0a -- the question being whose master it is and not
    # which of the two sorts first
    for stranger_fingerprint in ("deadbeef", "0badcafe"):
        stranger = BIP32KeyOrigin(stranger_fingerprint, origin.der_path)
        assert signer.sign_ecdsa(pub_key, stranger, msg_hash) is None

    # a hardened step under an xpub, which no derivation can take
    watch_only = SoftwareSigner(xpub_from_xprv(derive(XPRV_ROOT, "m/84h/0h/0h")))
    hardened = BIP32KeyOrigin(watch_only.master_fingerprint(), "m/0h")
    assert watch_only.sign_ecdsa(pub_key, hardened, msg_hash) is None

    # the path walks, and leads to another key than the one named
    elsewhere = BIP32KeyOrigin(origin.master_fingerprint, "m/84h/0h/0h/0/9")
    assert signer.sign_ecdsa(pub_key, elsewhere, msg_hash) is None

    # the same three answers for a taproot candidate, whose key is the
    # x-only spelling of the same 33 bytes
    taproot = export_account(signer, "m/86h/0h/0h")[0]
    x_only = taproot.key_expressions[0].sec(0)[1:]
    tr_origin = BIP32KeyOrigin(signer.master_fingerprint(), "m/86h/0h/0h/0/0")
    assert signer.sign_schnorr(x_only, tr_origin, msg_hash, b"") is not None
    assert signer.sign_schnorr(x_only, None, msg_hash, b"") is None
    assert signer.sign_schnorr(x_only, elsewhere, msg_hash, b"") is None


def test_a_watch_only_signer_shows_and_derives_but_does_not_sign() -> None:
    """Watching is most of what a signer does, and it is not a broken state.

    An xpub answers the fingerprint, an unhardened path and an address to
    display; what it refuses is the two questions that need a key, and it
    says which of the two states it is in rather than answering "none of
    these keys are mine".

    What it also cannot answer is an *account*: every level of a BIP44
    account path is hardened, so no xpub can walk one, and a watch-only
    signer is therefore one that was handed the account key rather than
    one that derives it. The refusal is `bip32`'s own.
    """
    root_xpub = xpub_from_xprv(XPRV_ROOT)
    signer = SoftwareSigner(root_xpub)
    assert signer.is_watch_only
    assert signer.master_fingerprint() == SoftwareSigner(XPRV_ROOT).master_fingerprint()
    assert signer.xpub("m/0") == derive(root_xpub, "m/0")

    with pytest.raises(BTClibValueError, match="hardened derivation from public key"):
        export_account(signer, "m/84h/0h/0h")

    holder = SoftwareSigner(XPRV_ROOT)
    receive, change = export_account(holder, "m/84h/0h/0h")
    assert display_address(signer, receive, 2) == receive.address(2)
    # and the method's own default, which the function above always passes
    # explicitly: the first address of the chain is what "the" address of a
    # descriptor means
    assert signer.display_address(receive) == receive.address(0)

    psbt = spending(receive, change)[0]
    with pytest.raises(BTClibValueError, match="watch-only signer"):
        signer.sign_psbt(psbt)
    with pytest.raises(BTClibValueError, match="watch-only signer"):
        sign_message(signer, b"hello", "m/0/0", receive.address(0))


def test_a_closed_signer_answers_nothing() -> None:
    """There is nothing to release, so this exists for the contract.

    A caller that closes every signer it opens is one that works with a
    device too, and a closed signer raising is what makes that visible in
    a test rather than only against hardware. The fingerprint is the one
    answer left: it is what a caller selects a signer *by*, and it is a
    fact about the key rather than about the connection.
    """
    signer = SoftwareSigner(XPRV_ROOT)
    receive = export_account(signer, "m/84h/0h/0h")[0]
    signer.close()
    signer.close()

    assert signer.master_fingerprint().hex() == "73c5da0a"
    with pytest.raises(BTClibValueError, match="the signer is closed"):
        signer.xpub("m/0")
    with pytest.raises(BTClibValueError, match="the signer is closed"):
        signer.display_address(receive)
    with pytest.raises(BTClibValueError, match="the signer is closed"):
        signer.sign_message(b"hello", "m/0")


def test_a_message_signature_opens_to_the_address_asked_for() -> None:
    """The p2pkh address of the key at the path, which `bms` signs with."""
    signer = SoftwareSigner(XPRV_ROOT)
    der_path = "m/44h/0h/0h/0/0"
    address = export_account(signer, "m/44h/0h/0h")[0].address(0)

    assert sign_message(signer, b"hello", der_path, address)
    # the address of another key of the same signer: a signature that is
    # valid and opens to somebody else
    other = export_account(signer, "m/44h/0h/0h")[0].address(1)
    with pytest.raises(BTClibValueError):
        sign_message(signer, b"hello", der_path, other)


def test_the_account_a_signer_exports_is_the_one_core_imports() -> None:
    """The end of the pure half: two answers in, two rpc requests out.

    Nothing in this chain is about a device -- the signer is software and
    the node is not there -- which is the point: the requests a caller
    would send are built and checked without either.
    """
    signer = SoftwareSigner(XPRV_ROOT)
    receive, change = export_account(signer, "m/84h/0h/0h")
    requests = account_import_requests(receive, change, key_range=(0, 24))

    assert [request["desc"] for request in requests] == [
        add_checksum(str(receive)),
        add_checksum(str(change)),
    ]
    assert [request["internal"] for request in requests] == [False, True]
    assert all(request["range"] == [0, 24] for request in requests)


def test_a_signer_of_accounts_answers_for_the_master_it_names() -> None:
    """What a device that exported its accounts and kept its master leaves.

    The same flow as the whole-flow test above, signed by a signer that
    holds the account key alone: the origins a wallet writes name the
    master fingerprint, so the fingerprint is told rather than computed
    and the account path is what the remainder is derived from. Built on
    that account key the ordinary way, the signer answers the account's
    own fingerprint and therefore for no origin of this psbt.
    """
    account_path = "m/84h/0h/0h"
    account = derive(XPRV_ROOT, account_path)
    master = SoftwareSigner(XPRV_ROOT)
    signer = SoftwareSigner.from_accounts(
        master.master_fingerprint(), {account_path: account}
    )

    assert signer.master_fingerprint() == master.master_fingerprint()
    assert signer.xpub(account_path) == master.xpub(account_path)
    assert not signer.is_watch_only
    assert isinstance(signer, PsbtSigner)

    receive, change = export_account(signer, account_path)
    psbt, prevouts = spending(receive, change)
    signed = request_signatures(signer, psbt)
    assert signed != psbt

    final = finalize(signed)
    tx = final.tx
    tx.vin[0].script_sig = final.inputs[0].final_script_sig
    tx.vin[0].script_witness = final.inputs[0].final_script_witness
    verify_transaction(prevouts, tx)

    # the same key, built on the ordinary way: its own fingerprint is
    # four other bytes, and no origin of this psbt names them
    plain = SoftwareSigner(account)
    assert plain.master_fingerprint() != master.master_fingerprint()
    assert plain.sign_psbt(psbt) == psbt


def test_the_longest_account_prefixing_an_origin_answers() -> None:
    """Two accounts on one path, and the deeper one has less left to derive."""
    signer = SoftwareSigner.from_accounts(
        SoftwareSigner(XPRV_ROOT).master_fingerprint(),
        {
            "m/84h/0h": derive(XPRV_ROOT, "m/84h/0h"),
            "m/84h/0h/0h": derive(XPRV_ROOT, "m/84h/0h/0h"),
        },
    )
    # both could reach it; what matters is that the answer is the key the
    # path names, whichever account was walked to get there
    assert signer.xpub("m/84h/0h/0h/0/7") == xpub_from_xprv(
        derive(XPRV_ROOT, "m/84h/0h/0h/0/7")
    )
    # a path no account of it prefixes is a key it does not hold, and that
    # is a prefix and not an ordering: the second of these sorts above
    # both accounts where the first sorts below them, and neither is a
    # path either account can walk to
    for elsewhere in ("m/44h/0h/0h", "m/99h/0h/0h"):
        with pytest.raises(BTClibValueError, match="no key held for the path"):
            signer.xpub(elsewhere)


def test_a_signer_of_accounts_has_no_single_key() -> None:
    """`xkey` is the key a signer was built on, and there was none."""
    account_path = "m/84h/0h/0h"
    signer = SoftwareSigner.from_accounts(
        SoftwareSigner(XPRV_ROOT).master_fingerprint(),
        {account_path: derive(XPRV_ROOT, account_path)},
    )
    with pytest.raises(BTClibValueError, match="holds accounts, not one key"):
        _ = signer.xkey
    # built on one key, the property is that key, and the empty path
    # reaches it as any other account path reaches its own
    assert (
        SoftwareSigner(XPRV_ROOT).xkey == BIP32KeyData.b58decode(XPRV_ROOT).b58encode()
    )

    with pytest.raises(BTClibValueError, match="the signer would hold no key"):
        SoftwareSigner.from_accounts(b"\x00" * 4, {})


def test_an_account_paired_with_the_wrong_master_answers_for_nothing() -> None:
    """The fingerprint is a claim, and the public key is what checks it.

    Nothing in an extended key records the master it came from, so an
    account told the wrong one matches origins whose keys it does not
    hold. One derivation later the public key is not the one the psbt
    names, and the key is refused there rather than signed with.
    """
    account_path = "m/84h/0h/0h"
    honest = SoftwareSigner(XPRV_ROOT)
    receive, change = export_account(honest, account_path)
    psbt, _ = spending(receive, change)

    # another master's account, told this master's fingerprint
    other_root = derive(XPRV_ROOT, "m/9h")
    liar = SoftwareSigner.from_accounts(
        honest.master_fingerprint(), {account_path: derive(other_root, account_path)}
    )
    assert liar.sign_psbt(psbt) == psbt


def test_a_signer_of_watch_only_accounts_derives_but_does_not_sign() -> None:
    """Accounts exported as xpubs hold no key that signs."""
    account_path = "m/84h/0h/0h"
    account = xpub_from_xprv(derive(XPRV_ROOT, account_path))
    signer = SoftwareSigner.from_accounts(
        SoftwareSigner(XPRV_ROOT).master_fingerprint(), {account_path: account}
    )

    assert signer.is_watch_only
    assert signer.xpub(f"{account_path}/0/0") == xpub_from_xprv(
        derive(XPRV_ROOT, f"{account_path}/0/0")
    )
    # the account it was handed is what a watch-only signer cannot
    # derive for itself: every level of the path is hardened
    receive, change = export_account(SoftwareSigner(XPRV_ROOT), account_path)
    with pytest.raises(BTClibValueError, match="watch-only signer"):
        signer.sign_psbt(spending(receive, change)[0])
