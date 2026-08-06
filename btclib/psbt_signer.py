# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The contract an external signer answers, and the checks on its answers.

A hardware wallet, a signing service, another process: something that
holds keys btclib does not have and answers questions about them. The
protocols here are what it implements; the functions beside them are what
a caller should run over its answers, and they are the point of the module
-- a protocol alone is an interface, and every one of these answers
arrives from outside and can be wrong.

This is **not** `psbt.sign`, which is the Signer role played over a
`KeyManager` btclib calls in-process: that one derives keys and signs, and
its answers are btclib's own. Here the psbt goes out and comes back
untrusted, so the two need different trust models and are two contracts.

What each function checks, which is what the caller would otherwise have
to remember:

- `request_signatures` holds the returned psbt to the one that was sent --
  `psbt.assert_signatures_only`, so nothing but signatures came back --
  and only then combines the two;
- `export_account` builds the descriptors of an account from the
  fingerprint and the xpub a signer answers with, and
  `descriptors.account_descriptors` is what refuses an xpub that is not
  the account the path names;
- `display_address` compares the address a device shows with the one the
  descriptor describes, which is the whole point of asking a device to
  show one;
- `sign_message` verifies the signature against the address the caller
  says it must open to.

Nothing here sends a private key anywhere, and nothing can: a `Descriptor`
holds no key that signs, `descriptors.parse` having neutered what it read,
and `assert_public` is what says so of one built by hand rather than
parsed. A psbt has no field for a private key at all.

Selecting *which* device answers, the transport it answers over, and the
timeouts and output limits a subprocess needs are the adapter's, not this
module's: this is the contract such an adapter implements (issue #381).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from btclib.alias import BIP44ScriptType, Octets, String
from btclib.bip32.bip32 import BIP32KeyData
from btclib.bip32.der_path import DerPath
from btclib.descriptors import Descriptor, account_descriptors
from btclib.ecc import bms
from btclib.exceptions import BTClibValueError
from btclib.psbt.psbt import Psbt, assert_signatures_only, combine

__all__ = [
    "AddressDisplay",
    "MessageSigner",
    "PsbtSigner",
    "SignerCapabilities",
    "assert_public",
    "display_address",
    "export_account",
    "request_signatures",
    "sign_message",
]


@dataclass(frozen=True)
class SignerCapabilities:
    """What a signer can be asked to sign, in the terms btclib acts on.

    Two flags and not a device matrix: which models support what is a
    table HWI maintains per vendor and per firmware version, and a library
    that copied it would be wrong the week after. What belongs in a
    contract is what a caller does differently on the answer, and there
    are two such facts -- a taproot input needs a signer that knows
    BIP341, and a MuSig2 session needs one that knows BIP327 and BIP373.

    Which *operations* a signer offers is not here either: that is what
    the optional protocols below say, and a caller asks with `isinstance`,
    both being runtime-checkable. A flag saying "I can display an address"
    beside a `display_address` method would be the same fact twice, and
    the two would disagree.
    """

    taproot: bool = False
    musig2: bool = False


@runtime_checkable
class PsbtSigner(Protocol):
    """What every external signer answers: keys, a signature, an end.

    The three questions a caller cannot answer for itself and one piece of
    housekeeping. Nothing here is about a device in particular -- a
    subprocess adapter, a signing service and a software signer implement
    the same four -- which is what makes it the boundary rather than a
    driver.
    """

    def master_fingerprint(self) -> bytes:
        """Return the four bytes identifying the master key, BIP32's own."""
        ...

    def xpub(self, der_path: DerPath) -> str:
        """Return the extended public key at a derivation path."""
        ...

    def sign_psbt(self, psbt: Psbt) -> Psbt:
        """Return the psbt with the signatures this signer can add.

        The answer is untrusted, whatever the transport: what a caller
        does with it is `request_signatures`, which holds it to the psbt
        that was sent before merging anything.
        """
        ...

    def capabilities(self) -> SignerCapabilities:
        """Return what this signer can be asked to sign."""
        ...

    def close(self) -> None:
        """Release whatever the signer holds: a handle, a process, a socket.

        Idempotent, so that a caller may close a signer it is not sure
        about; `contextlib.closing` is the customary way to run one.
        """
        ...


@runtime_checkable
class AddressDisplay(Protocol):
    """A signer that can show an address on a screen of its own.

    Optional, and separate from `PsbtSigner` for the reason the issue
    behind this module gives: a signer that cannot show anything is still
    a signer, and a caller asks with `isinstance` rather than being told.
    """

    def display_address(self, descriptor: Descriptor, index: int = 0) -> str:
        """Return the address the signer shows for a descriptor at an index."""
        ...


@runtime_checkable
class MessageSigner(Protocol):
    """A signer that can sign a message with a key it holds.

    Optional in the same way, and the message is not a transaction: what
    comes back is a BIP137 compact signature, which `sign_message` checks
    against the address the caller says it must open to.
    """

    def sign_message(self, message: Octets, der_path: DerPath) -> str:
        """Return the compact signature of a message, by the key at a path."""
        ...


def assert_public(descriptor: Descriptor) -> None:
    """Raise if any key of the descriptor is one that signs.

    Nothing `descriptors.parse` returns can fail this: it neuters every
    xprv it reads and hands the private spelling back to its caller. What
    this catches is a descriptor built by hand, which the fragment classes
    are public enough to allow -- and the moment before it is sent to
    something outside the process is the moment to catch it.
    """
    for key in descriptor.key_expressions:
        keys = [key.xkey] if key.xkey else []
        keys += [participant.xkey for participant in key.participants]
        for xkey in keys:
            if xkey and BIP32KeyData.b58decode(xkey).is_private:
                err_msg = "the descriptor holds a private key: it cannot be sent"
                raise BTClibValueError(err_msg)


def request_signatures(signer: PsbtSigner, psbt: Psbt) -> Psbt:
    """Return the psbt with what the signer added, checked and merged.

    Three steps and the middle one is why this exists: the psbt goes out,
    the answer is held to it -- everything that is not a signature comes
    back as it was sent, the signature fields may only have gained
    entries, and every signature that arrived verifies -- and only then
    are the two combined.

    Skipping that check is not a smaller version of this call: `combine`
    takes the union of what it is given and resolves a conflict by picking
    a side, so an answer that changed an amount, an outpoint or somebody
    else's signature would be merged in without a word.

    The psbt handed in is left alone, `combine` returning a copy of its
    own, so a caller can ask several signers with the same request and
    combine the answers itself.
    """
    returned = signer.sign_psbt(psbt)
    assert_signatures_only(psbt, returned)
    return combine([psbt, returned])


def export_account(
    signer: PsbtSigner,
    der_path: DerPath,
    script_type: BIP44ScriptType | None = None,
) -> tuple[Descriptor, Descriptor]:
    """Return the receive and change descriptors of an account of a signer.

    Two questions to the signer and one composition:
    `descriptors.account_descriptors` builds the pair from the master
    fingerprint and the xpub at the account path, and is what refuses an
    xpub that is not the account the path names -- its depth and its own
    index say which account it is, and a purpose the mapping does not know
    is refused rather than guessed.

    What cannot be checked here is that the xpub descends from that
    fingerprint at all: an extended key records nothing about where it
    came from, and a signer that answered with another key would need a
    second, independent path to be caught -- an address the device shows
    for the same descriptor, which is `display_address`.
    """
    return account_descriptors(
        signer.xpub(der_path), der_path, signer.master_fingerprint(), script_type
    )


def display_address(
    signer: AddressDisplay,
    descriptor: Descriptor,
    index: int = 0,
) -> str:
    """Return the address the signer shows, having checked it is the right one.

    The whole point of asking a device to display an address is that the
    screen is the one part of it a compromised host cannot rewrite -- so
    what the device says has to be compared with what the descriptor
    describes, and a caller that shows the user its own answer instead has
    checked nothing.

    The descriptor is checked to hold no key that signs before it is sent
    anywhere, which is `assert_public`.
    """
    assert_public(descriptor)
    expected = descriptor.address(index)
    shown = signer.display_address(descriptor, index)
    if shown != expected:
        err_msg = f"the signer displayed {shown}, where the descriptor describes"
        err_msg += f" {expected}"
        raise BTClibValueError(err_msg)
    return shown


def sign_message(
    signer: MessageSigner,
    message: Octets,
    der_path: DerPath,
    address: String,
) -> str:
    """Return the signature of a message, verified against an address.

    The address is a parameter and not something this works out: a BIP137
    signature carries a recovery flag that says which address type it is
    for, and which address a caller means is a fact about the key it asked
    for rather than about the signature that came back. What is checked is
    the one thing that matters -- the signature opens to that address --
    and `ecc.bms.assert_as_valid` is the check.
    """
    signature = signer.sign_message(message, der_path)
    bms.assert_as_valid(message, address, signature)
    return signature
