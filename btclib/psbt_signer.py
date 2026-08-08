# Copyright (c) The btclib developers
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

from base64 import b64encode
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from btclib.alias import BIP44ScriptType, Octets, String
from btclib.bip32.bip32 import BIP32Key, BIP32KeyData, derive, xpub_from_xprv
from btclib.bip32.der_path import DerPath, indexes_from_der_path, str_from_der_path
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.descriptors import Descriptor, account_descriptors
from btclib.ecc import bms, dsa, ssa
from btclib.exceptions import BTClibValueError
from btclib.psbt.psbt import Psbt, assert_signatures_only, combine, sign
from btclib.script.taproot import output_prvkey_from_merkle_root
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from btclib.to_pub_key import fingerprint, pub_keyinfo_from_key
from btclib.utils import bytes_from_octets

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "AddressDisplay",
    "MessageSigner",
    "PsbtSigner",
    "SignerCapabilities",
    "SoftwareSigner",
    "assert_public",
    "display_address",
    "export_account",
    "request_signatures",
    "sign_message",
]


def _b58_text(xkey: BIP32Key) -> str:
    """Return the b58 spelling of a key, whatever spelling came in."""
    if isinstance(xkey, BIP32KeyData):
        return xkey.b58encode()
    return BIP32KeyData.b58decode(xkey).b58encode()


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


class SoftwareSigner:
    """Keys in this process, at known paths, answering the contract above.

    The reference implementation of `PsbtSigner`, `AddressDisplay` and
    `MessageSigner`, and what makes the contract testable without
    hardware: a deterministic signer is a signer whose answers a test can
    predict, so every psbt shape the library builds can be signed end to
    end here before any device is involved.

    It is not a way to sign with a key you hold -- `psbt.sign` over a
    `KeyManager` is that, and this calls it. What this adds is the
    boundary: it answers only what the protocol asks, by deriving what it
    is told to derive, and it holds nothing about the caller. Which is why
    it is worth having beside a device rather than instead of one -- an
    adapter and this answer the same questions, so a caller can be
    developed against this and run against that.

    A key is answered for when the origin's fingerprint is this signer's
    and the path derives to the very public key the psbt names. That
    second half is the check a device makes too: a psbt saying "this key
    is at that path" is a psbt somebody else wrote, and signing with what
    the path derives to without looking would sign with a key the caller
    was not told about.

    One key or several is the same model: what is held is a key at a path
    from the master, and `SoftwareSigner(xkey)` is the case where that
    path is empty and the key *is* the master. `from_accounts` is the
    other case, where a device exported accounts and kept its master --
    the shape a psbt names, its key origins being a master fingerprint
    and a path from it.
    """

    def __init__(self, xkey: BIP32Key, *, musig2: bool = False) -> None:
        # held as the b58 text whatever came in, which is what `derive`
        # takes and what the two key answers below hand back: one spelling
        # inside, rather than a branch at every use. The round trip is
        # also what refuses a key that is no key, at construction rather
        # than at the first question asked
        key = _b58_text(xkey)
        self._musig2 = musig2
        self._fingerprint = fingerprint(key)
        # the empty path is the master itself: every origin descends from
        # it, so the lookup below finds this key for any of them
        self._keys: dict[tuple[int, ...], str] = {(): key}
        self._closed = False

    @classmethod
    def from_accounts(
        cls,
        master_fingerprint: Octets,
        accounts: Mapping[DerPath, BIP32Key],
        *,
        musig2: bool = False,
    ) -> SoftwareSigner:
        """Return a signer holding accounts, for the master they came from.

        What a device that exported its accounts leaves behind, and what
        `SoftwareSigner(xkey)` cannot express: the fingerprint a psbt
        names is the *master*'s, and an account key's own is a different
        four bytes, so a signer built on an account would answer for no
        origin the device's psbts carry.

        The fingerprint is therefore told rather than computed, and is a
        claim: nothing in an extended key records where it came from, so
        an account paired with the wrong master answers for origins whose
        keys it does not hold -- and the public key check refuses each of
        them, one derivation later.

        Each path is the account's own, from that master. An origin is
        answered by the account whose path is a prefix of it, the
        remainder being what is derived; where two accounts prefix the
        same origin the longer one answers, having less left to derive.
        Fingerprint, then prefix, then the public key: the three are what
        HWI's ledger driver matches on and what electrum's keystore tries
        first, which is the shape a psbt written by a wallet has.

        An origin naming an *account's* own fingerprint rather than the
        master's is the other thing a wallet writes, and it is
        `SoftwareSigner(account_xkey)`: a signer answers one fingerprint,
        `master_fingerprint` being a single question, so which of the two
        a psbt carries decides which constructor reads it.

        What is not done is electrum's third attempt, which ignores the
        fingerprint and tries the last few indexes against the public key
        anyway. It is a search for a key the psbt did not say is there,
        and a match found that way is a coincidence a signature would
        make binding.
        """
        if not accounts:
            raise BTClibValueError("no account: the signer would hold no key")
        signer = cls.__new__(cls)
        signer._musig2 = musig2
        signer._fingerprint = bytes_from_octets(master_fingerprint, 4)
        signer._keys = {
            tuple(indexes_from_der_path(path)): _b58_text(key)
            for path, key in accounts.items()
        }
        signer._closed = False
        return signer

    @property
    def xkey(self) -> str:
        """Return the key this signer was built on, where it was built on one.

        A signer holding accounts was built on none: there is no key of
        which the others are derivations, and answering one of them would
        be answering a key the caller did not ask about.
        """
        try:
            return self._keys[()]
        except KeyError:
            err_msg = "this signer holds accounts, not one key"
            raise BTClibValueError(err_msg) from None

    def _at(self, der_path: DerPath) -> str:
        """Return the key at a path from the master, derived from what is held.

        The account whose path is a prefix of the one asked for is the one
        that can reach it; the longest such account is the one with the
        least left to derive, and where the signer holds a master that
        account is the master.
        """
        indexes = tuple(indexes_from_der_path(der_path))
        candidates = [
            (len(path), key)
            for path, key in self._keys.items()
            if indexes[: len(path)] == path
        ]
        if not candidates:
            err_msg = f"no key held for the path {str_from_der_path(der_path)}"
            raise BTClibValueError(err_msg)
        depth, key = max(candidates)
        return derive(key, list(indexes[depth:])) if indexes[depth:] else key

    @property
    def is_watch_only(self) -> bool:
        """Answer whether this signer holds no key that signs."""
        return not any(
            BIP32KeyData.b58decode(key).is_private for key in self._keys.values()
        )

    def master_fingerprint(self) -> bytes:
        """Return the fingerprint of the key this signer was built on.

        The *master* fingerprint of the contract, which is this key's own
        and is therefore a claim only as true as the key handed in: a
        signer built on an account xpub answers that account's
        fingerprint, and a key origin naming it would send another signer
        looking for a master key nobody has.
        """
        return self._fingerprint

    def xpub(self, der_path: DerPath) -> str:
        """Return the extended public key at a path, neutered whatever it is.

        Public whether this signer holds a private key or not: what the
        contract asks for is an xpub, and answering an xprv would put a
        key that signs where a caller expects one that cannot.
        """
        self._assert_open()
        derived = self._at(der_path)
        if BIP32KeyData.b58decode(derived).is_private:
            return xpub_from_xprv(derived)
        return derived

    def sign_psbt(self, psbt: Psbt) -> Psbt:
        """Return the psbt with a signature for every key this one holds.

        `psbt.sign` over a `KeyManager` this class implements, which is
        the whole of it: the roles are btclib's already, and a reference
        signer that re-derived the sig_hash itself would be a second
        implementation to keep right.

        A watch-only signer raises rather than answering the psbt
        unchanged: "I hold none of these keys" and "I hold no key at all"
        are different answers, and only the first is a psbt somebody else
        can carry on with.
        """
        self._assert_open()
        if self.is_watch_only:
            raise BTClibValueError("watch-only signer: it holds no key that signs")
        return sign(psbt, self)[0]

    def capabilities(self) -> SignerCapabilities:
        """Return what this signer can be asked to sign.

        Taproot always: `psbt.sign` signs the key path, which is what a
        BIP341 output with no script tree is spent by. MuSig2 is a
        constructor argument and defaults to False, because the rounds of
        BIP373 are `psbt.musig2`'s and are played by a caller holding the
        secret nonce between them -- this signer signs in one call and
        cannot answer for a session it does not hold.
        """
        return SignerCapabilities(taproot=True, musig2=self._musig2)

    def close(self) -> None:
        """Mark the signer closed; there is nothing to release.

        A software signer holds no handle and no process, so this exists
        for the contract: a caller that closes every signer it opens is a
        caller that works with a device too. Asking a closed signer
        anything raises, which is what makes the difference visible in a
        test rather than only against hardware.
        """
        self._closed = True

    def _assert_open(self) -> None:
        """Refuse to answer once closed, as a device would."""
        if self._closed:
            raise BTClibValueError("the signer is closed")

    def display_address(self, descriptor: Descriptor, index: int = 0) -> str:
        """Return the address the descriptor describes, as a screen would.

        There is no screen here, so what this answers is what a device
        would show if it agreed -- which makes `display_address` above a
        check of the descriptor against itself when this signer is the
        one asked. That is what a reference implementation is for: the
        caller's flow runs unchanged, and the check that matters is the
        one made against a device that could have disagreed.
        """
        self._assert_open()
        return descriptor.address(index)

    def sign_message(self, message: Octets, der_path: DerPath) -> str:
        """Return the BIP137 compact signature of a message, base64.

        The address the signature opens to is the p2pkh one of the key at
        the path, which is what `ecc.bms` signs with by default and what
        a caller checks it against.
        """
        self._assert_open()
        if self.is_watch_only:
            raise BTClibValueError("watch-only signer: it holds no key that signs")
        prv_key = self._at(der_path)
        return b64encode(bms.sign(message, prv_key).serialize()).decode("ascii")

    def _prv_key(self, pub_key: bytes, origin: BIP32KeyOrigin | None) -> int | None:
        """Return the key at the origin, where it is one this signer holds.

        Three conditions and each is a refusal: an origin at all, whose
        fingerprint is this signer's, and whose path derives to the public
        key the psbt names. The last is what a device checks too -- a psbt
        is written by somebody else, and its claim about which key sits at
        which path is not evidence.

        The x-only spelling is accepted for the taproot candidates, whose
        `pub_key` is 32 bytes where an ECDSA one is 33.
        """
        if origin is None or origin.master_fingerprint != self._fingerprint:
            return None
        try:
            derived = self._at(origin.der_path)
        # a path this signer cannot walk is a key it does not hold: an
        # origin no account of it prefixes, a hardened step under an
        # xpub, or an index BIP32 refuses
        except BTClibValueError:
            return None
        sec = pub_keyinfo_from_key(derived)[0]
        if pub_key not in {sec, sec[1:]}:
            return None
        return prv_keyinfo_from_prv_key(derived)[0]

    def sign_ecdsa(
        self, pub_key: bytes, origin: BIP32KeyOrigin | None, msg_hash: bytes
    ) -> bytes | None:
        """Return the DER signature of msg_hash by pub_key, or None."""
        prv_key = self._prv_key(pub_key, origin)
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
        """Return the BIP340 signature of msg_hash by pub_key, or None.

        Tweaked by the merkle root before signing, which is the
        `KeyManager` contract: the signature has to be the *output* key's,
        and `sign` never holds what tweaking a private key needs.
        """
        prv_key = self._prv_key(pub_key, origin)
        if prv_key is None:
            return None
        tweaked = output_prvkey_from_merkle_root(prv_key, merkle_root)
        return ssa.sign_(msg_hash, tweaked).serialize()
