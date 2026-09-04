# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.psbt_signer` module.

What is under test is the checking, so the signers here are doubles that
answer wrongly on purpose: a device that changes an amount, one that
shows another address, one that signs a message with the wrong key.
Nothing in this file is a reference implementation -- that is the
software signer of its own module -- and the honest double below is as
small as it can be while still producing a signature to be checked.
"""

from __future__ import annotations

from base64 import b64encode
from copy import deepcopy

import pytest
from typing_extensions import override

from btclib.alias import Octets
from btclib.bip32 import fingerprint
from btclib.bip32.bip32 import derive, rootxprv_from_seed, xpub_from_xprv
from btclib.bip32.der_path import DerPath
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.descriptors import (
    Descriptor,
    KeyExpression,
    TrDescriptor,
    WpkhDescriptor,
    parse,
    wallet_policy,
    wallet_policy_address,
)
from btclib.ecc import bms, dsa
from btclib.exceptions import BTClibValueError, SignerError
from btclib.hwi import HwiDevice
from btclib.key import PrvKeyData
from btclib.psbt.psbt import Psbt, sign
from btclib.psbt_signer import (
    AddressDisplay,
    MessageSigner,
    PsbtSigner,
    SignerCapabilities,
    SignerDecorator,
    WalletPolicyAddressDisplay,
    assert_public,
    display_address,
    display_policy_address,
    export_account,
    merge_devices,
    request_signatures,
    select_device,
    sign_message,
)
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from btclib.tx import OutPoint, Tx, TxIn, TxOut

# the "abandon abandon ... about" root of BIP39, which BIP84 publishes
XPRV_ROOT = (
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRR"
    "uL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
)
ACCOUNT = "m/84h/0h/0h"
# another extended key, for a musig() group of two
XPUB_OTHER = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"


class _KeyManager:
    """A `KeyManager` over one extended key: the honest half of a signer.

    Keys are answered by origin and not by public key, which is what a
    device does: it derives the path it is told and signs with what comes
    out, having no list of its own children to look one up in.
    """

    def __init__(self, xprv: str) -> None:
        self.xprv = xprv

    def _prv_key(self, origin: BIP32KeyOrigin | None) -> int | None:
        if origin is None or origin.master_fingerprint != fingerprint(self.xprv):
            return None
        return prv_keyinfo_from_prv_key(derive(self.xprv, origin.der_path))[0]

    def sign_ecdsa(
        self, pub_key: bytes, origin: BIP32KeyOrigin | None, msg_hash: bytes
    ) -> bytes | None:
        """Return the DER signature of the key at the origin, or None."""
        prv_key = self._prv_key(origin)
        if prv_key is None:
            return None
        return dsa.sign_(msg_hash, prv_key).serialize()

    def sign_schnorr(
        self,
        pub_key: bytes,
        origin: BIP32KeyOrigin | None,
        msg_hash: bytes,
        merkle_root: bytes,
    ) -> bytes | None:
        """Answer for no taproot key: this double signs ECDSA only."""
        return None

    def sign_schnorr_script_path(
        self,
        pub_key: bytes,
        origin: BIP32KeyOrigin | None,
        msg_hash: bytes,
        leaf_hash: bytes,
    ) -> bytes | None:
        """Answer for no leaf key either, for the same reason."""
        return None


class _Signer:
    """A `PsbtSigner` double holding one extended private key.

    `answer` is what it hands back instead of the psbt it signed, which is
    how a lying device is written here: every check `request_signatures`
    makes has a case, and each case is one field changed on the way home.
    """

    def __init__(self, xprv: str = XPRV_ROOT) -> None:
        self.xprv = xprv
        self.answer: Psbt | None = None
        self.closed = False

    @property
    def master_fingerprint(self) -> bytes:
        """Return the fingerprint of the key this signer holds."""
        return fingerprint(self.xprv)

    def xpub(self, der_path: DerPath) -> str:
        """Return the extended public key at the path."""
        return xpub_from_xprv(derive(self.xprv, der_path))

    def sign_psbt(self, psbt: Psbt) -> Psbt:
        """Return the psbt signed, or whatever `answer` was set to."""
        if self.answer is not None:
            return self.answer
        return sign(psbt, _KeyManager(self.xprv))[0]

    @property
    def capabilities(self) -> SignerCapabilities:
        """Return what this double can sign: no taproot, no musig2."""
        return SignerCapabilities()

    def close(self) -> None:
        """Record that it was closed, twice being no different from once."""
        self.closed = True


def account_psbt(signer: _Signer, index: int = 0) -> tuple[Psbt, Descriptor]:
    """Return a psbt spending the receiving address of a signer's account."""
    receive = export_account(signer, ACCOUNT)[0]
    script_pub_key = receive.script_pub_key(index)
    prev_tx = Tx(
        vin=[TxIn(OutPoint(b"\x04" * 32, 0))], vout=[TxOut(10_000, script_pub_key)]
    )
    psbt = Psbt.from_tx(
        Tx(vin=[TxIn(OutPoint(prev_tx.id, 0))], vout=[TxOut(9_000, script_pub_key)])
    )
    psbt.inputs[0].non_witness_utxo = prev_tx
    return receive.update_psbt_input(psbt, 0, index), receive


def test_the_protocols_are_what_a_signer_is_asked_for() -> None:
    """Runtime-checkable, so a caller asks rather than being told.

    Which is also why the optional operations are protocols and not flags
    on `SignerCapabilities`: a flag beside a method would be the same fact
    twice, and the two would disagree.
    """
    signer = _Signer()
    assert isinstance(signer, PsbtSigner)
    assert not isinstance(signer, AddressDisplay)
    assert not isinstance(signer, MessageSigner)
    assert not isinstance(signer, WalletPolicyAddressDisplay)

    assert signer.capabilities == SignerCapabilities(taproot=False, musig2=False)
    signer.close()
    signer.close()
    assert signer.closed


def test_a_signature_comes_back_checked_and_merged() -> None:
    """The psbt goes out, the answer is held to it, and the two combine.

    The request itself is left alone, so a caller can ask several signers
    with one psbt and combine the answers itself.
    """
    signer = _Signer()
    psbt, _ = account_psbt(signer)
    request = deepcopy(psbt)

    signed = request_signatures(signer, psbt)
    assert signed.inputs[0].partial_sigs
    assert psbt == request
    assert not request.inputs[0].partial_sigs


def test_an_answer_that_changed_anything_but_a_signature_is_refused() -> None:
    """`combine` would merge each of these without a word.

    It takes the union of what it is given and resolves a conflict by
    picking a side, so the check is what stands between a caller and an
    answer that rewrote the transaction it was asked to sign.
    """
    signer = _Signer()
    psbt, _ = account_psbt(signer)

    # the transaction itself: another amount, and the signature is of the
    # transaction that was sent rather than of this one
    tampered = sign(deepcopy(psbt), _KeyManager(signer.xprv))[0]
    tampered.outputs[0].amount = 1
    signer.answer = tampered
    with pytest.raises(BTClibValueError, match="the transaction being signed"):
        request_signatures(signer, psbt)

    # a field that is not a signature, added on the way home
    tampered = sign(deepcopy(psbt), _KeyManager(signer.xprv))[0]
    tampered.inputs[0].unknown = {b"\xfc\x01": b"vendor"}
    signer.answer = tampered
    with pytest.raises(BTClibValueError, match="unknown"):
        request_signatures(signer, psbt)

    # a signature that does not verify, which the validator checks before
    # anything is merged
    tampered = sign(deepcopy(psbt), _KeyManager(signer.xprv))[0]
    pub_key, signature = next(iter(tampered.inputs[0].partial_sigs.items()))
    tampered.inputs[0].partial_sigs[pub_key] = signature[:-2] + b"\x00\x01"
    signer.answer = tampered
    with pytest.raises(BTClibValueError, match="signature"):
        request_signatures(signer, psbt)


def test_a_signer_holding_none_of_the_keys_adds_nothing() -> None:
    """Which is not an error: an input somebody else signs is not this one's.

    Two ways to hold none of them, and both answer the same way. The psbt
    of another master key is one -- the origin names a fingerprint this
    signer is not -- and a taproot input is the other, this double being
    one whose capabilities say it cannot sign one. The answer passes the
    check and combines into a psbt that gained nothing, which is what a
    caller then sees.

    The taproot input carries a leaf as well as an internal key, both of
    them keys this signer derives: a taproot input is offered both of its
    paths, so both are questions this double has to answer None to.
    """
    signer = _Signer()
    stranger = _Signer(rootxprv_from_seed("000102030405060708090a0b0c0d0e0f"))
    psbt, _ = account_psbt(stranger)
    assert not request_signatures(signer, psbt).inputs[0].partial_sigs

    key = export_account(signer, "m/86h/0h/0h")[0].key_expressions[0]
    taproot = parse(f"tr({key},pk({key}))")
    script_pub_key = taproot.script_pub_key(0)
    prev_tx = Tx(
        vin=[TxIn(OutPoint(b"\x05" * 32, 0))], vout=[TxOut(10_000, script_pub_key)]
    )
    taproot_psbt = Psbt.from_tx(
        Tx(vin=[TxIn(OutPoint(prev_tx.id, 0))], vout=[TxOut(9_000, script_pub_key)])
    )
    taproot_psbt.inputs[0].witness_utxo = TxOut(10_000, script_pub_key)
    taproot_psbt = taproot.update_psbt_input(taproot_psbt, 0)

    assert not signer.capabilities.taproot
    signed = request_signatures(signer, taproot_psbt)
    assert not signed.inputs[0].taproot_key_spend_signature
    assert not signed.inputs[0].taproot_script_spend_signatures


def test_an_account_is_exported_from_two_answers() -> None:
    """The fingerprint and the xpub at the path, composed into the pair.

    And the pair is the one `descriptors.account_descriptors` builds from
    the same two facts, which is what says this is a composition rather
    than a second implementation.
    """
    signer = _Signer()
    receive, change = export_account(signer, ACCOUNT)

    assert str(receive).startswith("wpkh([73c5da0a/84h/0h/0h]")
    assert receive.key_expressions[0].der_path == (0,)
    assert change.key_expressions[0].der_path == (1,)
    assert receive.address(0) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    # the purpose selects the encoding, and an override is passed through
    assert str(export_account(signer, "m/44h/0h/0h")[0]).startswith("pkh(")
    assert str(export_account(signer, "m/48h/0h/0h", "p2wpkh")[0]).startswith("wpkh(")


def test_an_xpub_that_is_not_the_account_is_refused() -> None:
    """A signer answering with another key is caught where it can be.

    The depth and the index of the xpub say which account it is, and
    `account_descriptors` refuses one that is not the path's. What no
    check can see is an xpub of another *master* key at the right path:
    an extended key records nothing about where it came from, so the
    second, independent answer is what catches that -- an address the
    device shows for the same descriptor.
    """

    class _WrongAccount(_Signer):
        @override
        def xpub(self, der_path: DerPath) -> str:
            """Answer with the next account, whatever was asked."""
            return xpub_from_xprv(derive(self.xprv, "m/84h/0h/1h"))

    with pytest.raises(BTClibValueError, match="is not the path's 0h"):
        export_account(_WrongAccount(), ACCOUNT)


class _Display(_Signer):
    """A signer that shows an address, honestly unless told otherwise."""

    def __init__(self, shown: str | None = None) -> None:
        super().__init__()
        self.shown = shown

    def display_address(self, descriptor: Descriptor, index: int = 0) -> str:
        """Return the address, or the one this was built to lie with."""
        return self.shown if self.shown is not None else descriptor.address(index)


def test_a_displayed_address_is_compared_with_the_descriptor_s() -> None:
    """The screen is what a compromised host cannot rewrite.

    So the answer is compared with what the descriptor describes, and a
    caller that showed the user its own answer instead would have checked
    nothing at all.
    """
    signer = _Display()
    assert isinstance(signer, AddressDisplay)
    receive = export_account(signer, ACCOUNT)[0]

    assert display_address(signer, receive, 3) == receive.address(3)
    # and the index defaults to the first address of the chain, which is
    # what a caller asking for "the" address of a descriptor means
    assert display_address(signer, receive) == receive.address(0)

    # a lie on each side of the truth in byte order: what the check asks
    # is whether the two strings are the same string, where an ordering
    # would accept every address that sorts the right way
    truth = receive.address(3)
    below = "bc1q" + "0" * (len(truth) - 4)
    above = "bc1q" + "z" * (len(truth) - 4)
    assert below < truth < above
    for lie in (below, above):
        with pytest.raises(BTClibValueError, match="the signer displayed"):
            display_address(_Display(lie), receive, 3)


class _PolicyDisplay(_Signer):
    """A signer that shows a policy's address, honestly by default."""

    def __init__(
        self,
        template: str,
        key_info: tuple[KeyExpression, ...],
        shown: str | None = None,
    ) -> None:
        super().__init__()
        self.template = template
        self.key_info = key_info
        self.shown = shown

    def display_policy_address(
        self, registration: str, index: int = 0, multipath_index: int = 0
    ) -> str:
        """Return the address, or the one this was built to lie with."""
        if self.shown is not None:
            return self.shown
        return wallet_policy_address(
            self.template, self.key_info, index, multipath_index
        )


def test_a_registered_policy_s_address_is_compared_with_the_policy_s() -> None:
    """The same check `display_address` runs, over a BIP388 policy instead.

    `wallet_policy_address` computes what the policy describes at an
    index and a multipath index -- the second parameter a plain
    `Descriptor` and `AddressDisplay` have no room for, which is why this
    is a second protocol rather than a widened first one.
    """
    receive, change = export_account(_Signer(), ACCOUNT)
    template, key_info = wallet_policy(receive, change)
    display = _PolicyDisplay(template, key_info)
    assert isinstance(display, WalletPolicyAddressDisplay)

    expected = wallet_policy_address(template, key_info, 3, 1)
    assert display_policy_address(display, "cafe", template, key_info, 3, 1) == expected

    lying = _PolicyDisplay(template, key_info, "bc1q" + "0" * (len(expected) - 4))
    with pytest.raises(BTClibValueError, match="the signer displayed"):
        display_policy_address(lying, "cafe", template, key_info, 3, 1)


def test_a_descriptor_that_holds_a_private_key_is_not_sent() -> None:
    """Nothing `parse` returns can fail this, and a hand-built one can.

    `parse` neuters every xprv it reads, so the case is a `KeyExpression`
    built by hand -- which the fragment classes are public enough to allow
    -- and the moment before it goes to something outside the process is
    the moment to catch it.
    """
    assert_public(parse(f"wpkh({xpub_from_xprv(XPRV_ROOT)}/0/*)"))

    private = WpkhDescriptor(KeyExpression(xkey=XPRV_ROOT, der_path=(0,), wildcard=0))
    with pytest.raises(BTClibValueError, match="holds a private key"):
        assert_public(private)
    with pytest.raises(BTClibValueError, match="holds a private key"):
        display_address(_Display(), private)

    # a participant of a musig() is a key expression like any other, and
    # `key_expressions` answers with the aggregate rather than with them,
    # so the participants are walked here explicitly
    assert_public(parse(f"tr(musig({xpub_from_xprv(XPRV_ROOT)},{XPUB_OTHER}))"))
    smuggled = TrDescriptor(
        KeyExpression(
            participants=(
                KeyExpression(xkey=XPRV_ROOT),
                KeyExpression(xkey=XPUB_OTHER),
            )
        )
    )
    with pytest.raises(BTClibValueError, match="holds a private key"):
        assert_public(smuggled)


class _MessageSigner(_Signer):
    """A signer that signs a message, with the key at the path or another."""

    def __init__(self, der_path: DerPath | None = None) -> None:
        super().__init__()
        self.der_path = der_path

    def sign_message(self, message: Octets, der_path: DerPath) -> str:
        """Return the compact signature, by the key this was built with.

        Base64, which is how a signature travels and what `bms` reads
        back: the serialization is 65 bytes and no encoding of its own.
        """
        path = self.der_path if self.der_path is not None else der_path
        q, network, compressed = prv_keyinfo_from_prv_key(derive(self.xprv, path))
        prv_key = PrvKeyData(q, network, compressed)
        return b64encode(bms.sign(message, prv_key).serialize()).decode("ascii")


def test_a_signed_message_is_verified_against_the_address_asked_for() -> None:
    """Which address a caller means is a fact about the key it asked for.

    So the address is a parameter rather than something this works out,
    and what is checked is the one thing that matters: the signature opens
    to it.
    """
    signer = _MessageSigner()
    assert isinstance(signer, MessageSigner)
    der_path = "m/84h/0h/0h/0/0"
    address = export_account(signer, ACCOUNT)[0].address(0)

    signature = sign_message(signer, b"hello", der_path, address)
    assert bms.verify(b"hello", address, signature)

    # the same message signed with another key of the same device: a
    # signature that verifies, under an address nobody asked about
    elsewhere = _MessageSigner("m/84h/0h/0h/0/1")
    with pytest.raises(BTClibValueError):
        sign_message(elsewhere, b"hello", der_path, address)


def test_a_device_is_selected_by_fingerprint() -> None:
    """The one thing a caller does before it has a signer at all."""
    wanted = HwiDevice(type="ledger", model="nanos", path="a", fingerprint=b"\x01" * 4)
    other = HwiDevice(type="trezor", model="one", path="b", fingerprint=b"\x02" * 4)

    assert select_device([other, wanted], b"\x01" * 4) is wanted
    assert select_device([other, wanted], "01010101") is wanted

    with pytest.raises(SignerError, match="no device with fingerprint 03030303"):
        select_device([other, wanted], b"\x03" * 4)


def test_a_device_that_said_why_it_cannot_be_asked_is_not_selected() -> None:
    """Different news from "not there": this one is a device to unlock."""
    locked = HwiDevice(
        type="trezor",
        model="one",
        path="a",
        fingerprint=b"\x01" * 4,
        error="device is locked",
    )
    with pytest.raises(SignerError, match="cannot be used: device is locked"):
        select_device([locked], b"\x01" * 4)


def test_devices_of_several_sources_are_merged_in_the_caller_s_order() -> None:
    """Which source wins is the caller's to state, so order states it."""
    hardware = HwiDevice(
        type="ledger", model="nanos", path="a", fingerprint=b"\x01" * 4
    )
    software = HwiDevice(
        type="software", model="emulated", path="b", fingerprint=b"\x01" * 4
    )
    only_software = HwiDevice(
        type="software", model="emulated", path="c", fingerprint=b"\x02" * 4
    )

    merged = merge_devices([hardware], [software, only_software])
    assert merged == [hardware, only_software]
    assert merge_devices([software], [hardware]) == [software]
    assert merge_devices() == []


def test_a_device_with_no_fingerprint_yet_is_kept_by_the_merge() -> None:
    """There is no fingerprint to be a duplicate of, and it is plugged in."""
    locked = HwiDevice(type="trezor", model="one", path="a", error="locked")
    also_locked = HwiDevice(type="trezor", model="one", path="b", error="locked")

    assert merge_devices([locked], [also_locked]) == [locked, also_locked]


class _Counting(_Signer):
    """A signer that records the psbts it was asked to sign."""

    def __init__(self) -> None:
        super().__init__()
        self.requests: list[Psbt] = []

    @override
    def sign_psbt(self, psbt: Psbt) -> Psbt:
        """Record the request, then sign it as the double does."""
        self.requests.append(psbt)
        return super().sign_psbt(psbt)


class _Refusing(SignerDecorator):
    """A decorator with one rule: no output may pay more than a limit.

    The shape of every "sign, but only if" -- a whitelist, a spending
    cap, a prompt -- written here as the smallest rule that can refuse.
    """

    def __init__(self, signer: PsbtSigner, limit: int) -> None:
        super().__init__(signer)
        self.limit = limit

    @override
    def sign_psbt(self, psbt: Psbt) -> Psbt:
        """Sign, unless an output pays more than the limit allows."""
        for out in psbt.tx.vout:
            if out.value > self.limit:
                err_msg = f"{out.value} is over the {self.limit} limit"
                raise SignerError(err_msg)
        return super().sign_psbt(psbt)


def test_a_decorated_signer_answers_what_the_signer_underneath_answers() -> None:
    """Every method but the one a subclass is about, forwarded.

    A wrapper that answered `capabilities` for itself would tell a caller
    a taproot input cannot be signed by a signer that can, and one that
    forgot `close` would leave what the signer holds open after the
    caller closed it.
    """
    signer = _Signer()
    wrapped = SignerDecorator(signer)
    assert isinstance(wrapped, PsbtSigner)

    assert wrapped.master_fingerprint == signer.master_fingerprint
    assert wrapped.xpub(ACCOUNT) == signer.xpub(ACCOUNT)
    assert wrapped.capabilities == signer.capabilities

    psbt, _ = account_psbt(signer)
    assert wrapped.sign_psbt(deepcopy(psbt)) == signer.sign_psbt(deepcopy(psbt))

    wrapped.close()
    assert signer.closed


def test_a_rule_is_what_a_subclass_adds_and_the_only_thing_it_adds() -> None:
    """The psbt reaches the signer, or nothing does."""
    signer = _Counting()
    psbt, _ = account_psbt(signer)

    allowed = _Refusing(signer, 9_000)
    assert allowed.sign_psbt(deepcopy(psbt)).inputs[0].partial_sigs
    assert len(signer.requests) == 1

    asked = _Counting()
    refused = _Refusing(asked, 8_999)
    with pytest.raises(SignerError, match="9000 is over the 8999 limit"):
        refused.sign_psbt(deepcopy(psbt))
    # and the signer underneath was never asked, which is what a rule in
    # front of a device is for: a device that refuses is a device that
    # was shown the transaction
    assert not asked.requests


def test_wrapping_a_signer_does_not_hide_what_it_offers() -> None:
    """`isinstance` answers about the wrapped signer, either way.

    The optional protocols are how a caller asks whether an operation is
    there at all, so a wrapper that carried them would turn a signer that
    cannot show an address into one that fails when asked, and a wrapper
    that dropped them would turn one that can into one that cannot.
    """
    assert not isinstance(SignerDecorator(_Signer()), AddressDisplay)
    assert not isinstance(SignerDecorator(_Signer()), MessageSigner)
    assert not isinstance(SignerDecorator(_Signer()), WalletPolicyAddressDisplay)

    display = SignerDecorator(_Display())
    assert isinstance(display, AddressDisplay)
    receive = export_account(display, ACCOUNT)[0]
    assert display.display_address(receive, 3) == receive.address(3)

    receive, change = export_account(_Signer(), ACCOUNT)
    template, key_info = wallet_policy(receive, change)
    policy_display = SignerDecorator(_PolicyDisplay(template, key_info))
    assert isinstance(policy_display, WalletPolicyAddressDisplay)
    assert policy_display.display_policy_address("cafe", 3, 1) == wallet_policy_address(
        template, key_info, 3, 1
    )

    assert isinstance(SignerDecorator(_MessageSigner()), MessageSigner)


def test_a_decorator_carries_the_contract_and_not_the_adapter() -> None:
    """What the wrapper answers is the five methods and the two operations.

    An attribute of the signer that is not part of either -- a timeout, a
    path, whatever the adapter holds -- is read off `.signer`, which is
    what the caller passed in: a wrapper that forwarded everything would
    be answering for the wrong object, copying and pickling included.
    """
    signer = _Signer()
    wrapped = SignerDecorator(signer)
    assert wrapped.signer is signer
    assert wrapped.signer.xprv == XPRV_ROOT
    with pytest.raises(AttributeError):
        _ = wrapped.xprv  # type: ignore[attr-defined]


def test_a_subclass_that_writes_an_operation_keeps_it() -> None:
    """An operation written by a class is the subclass answering it itself.

    The wrapped signer's is bound on the instance, which would otherwise
    shadow it: a subclass overriding `display_address` -- to refuse it,
    to log it, to show something else -- has said what it means.
    """

    class _Silent(SignerDecorator):
        """A wrapper over a device whose screen is not to be used."""

        def display_address(self, descriptor: Descriptor, index: int = 0) -> str:
            """Refuse to ask the device to show anything."""
            err_msg = "this signer's screen is not to be used"
            raise SignerError(err_msg)

    silent = _Silent(_Display())
    assert isinstance(silent, AddressDisplay)
    receive = export_account(silent, ACCOUNT)[0]
    with pytest.raises(SignerError, match="screen is not to be used"):
        silent.display_address(receive)
