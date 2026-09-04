# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Check an implementation of `psbt_signer`'s contract, from outside it.

`psbt_signer` says what a signer answers; this says whether one does. A
protocol is a promise the type checker reads and nothing runs, so an
adapter that returns a five-byte fingerprint, or a psbt it edited, or an
xpub it derived from the wrong path, type-checks and is wrong at the
first spend.

btclib's own adapters are checked by btclib's tests, which is no help to
the caller writing the next one: an implementer outside this repository
had no way to ask the library whether their signer answers what callers
of it will assume. `assert_psbt_signer` is that question, and it takes any
`PsbtSigner` -- a command line adapter, an in-process driver, a signing
service, a signer that is not a device at all.

It is a function and not a test suite so that it belongs to no test
framework: call it from pytest, from unittest, from a script run against
the hardware on a bench. It raises on the first breach, with what was
expected and what came back, because the first breach is the one to fix
and a list of consequences of it is not more information.

What it checks is what a type cannot say. A method returning the wrong
type is what the implementer's own type checker reports, and repeating
that here would be a second, weaker copy of it; a fingerprint of the
wrong width, an xpub that is not one, a key answered privately, a
signature added to somebody else's input -- none of those are type
errors, and all of them type-check.

**What it does not check is whether the signatures are right.** That is
`request_signatures`, which holds an answer to the psbt that was sent and
verifies every signature that arrived -- the check that matters most is
the one a caller runs on every spend, not one a conformance pass runs
once. What this adds is the shape of the answers around it: the things
`request_signatures` assumes and does not restate.

Two of the checks need material only the caller has, and both are
optional. A signer holds keys at paths this module cannot guess, so
`der_path` is asked for rather than defaulted -- a wrong guess would
report a conforming signer as broken. And a psbt the signer can actually
sign is the only way to see it sign, so `signable` is what turns a shape
check into an end-to-end one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple, NoReturn

from btclib.bip32.bip32 import BIP32KeyData
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.exceptions import BTClibValueError
from btclib.psbt import Psbt
from btclib.psbt_signer import (
    AddressDisplay,
    MessageSigner,
    PsbtSigner,
    WalletPolicyAddressDisplay,
    request_signatures,
)
from btclib.script.script_pub_key import ScriptPubKey
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut

if TYPE_CHECKING:
    from btclib.bip32.der_path import DerPath

__all__ = [
    "OptionalProtocols",
    "assert_psbt_signer",
    "optional_protocols",
    "unsignable_psbt",
]

# a fingerprint is four bytes, BIP32's own, and every psbt key origin is
# written against that width
_FINGERPRINT_SIZE = 4

# the generator point of secp256k1, used as the key of the input no
# signer is meant to sign: a point on the curve is needed -- an output
# script is not built from arbitrary bytes -- and this one is the public
# key of a private key nobody chose and everybody knows, which is the
# property wanted of a key that must not be signed with
_SOMEBODY_ELSES_KEY = bytes.fromhex(
    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
)


def _fail(what: str) -> NoReturn:
    """Raise the one refusal this module makes, so it reads as one."""
    raise BTClibValueError(f"the signer breaks the contract: {what}")


def unsignable_psbt(fingerprint: bytes) -> Psbt:
    """Return a psbt of one input no signer of this fingerprint can sign.

    A p2wpkh whose key origin names somebody else's master, which is the
    shape of the psbt a caller sends to every signer it has and expects
    most of them to hand straight back. Built from the signer's own
    fingerprint with a bit flipped, so it is somebody else's for *this*
    signer whoever it is, and no caller has to supply a key to find out
    what the signer does with a psbt that is not its business.
    """
    other = bytes([fingerprint[0] ^ 0xFF, *fingerprint[1:]])
    script_pub_key = ScriptPubKey.p2wpkh(_SOMEBODY_ELSES_KEY)

    tx_in = TxIn(OutPoint(b"\xaa" * 32, 0))
    tx_out = TxOut(9_000, script_pub_key)
    psbt = Psbt.from_tx(Tx(version=2, lock_time=0, vin=[tx_in], vout=[tx_out]))
    # the fields are set on the input the psbt already holds rather than
    # on one built beside it: BIP370 keeps the outpoint on the input, so
    # an input replaced wholesale is an input naming nothing
    psbt_in = psbt.inputs[0]
    psbt_in.witness_utxo = TxOut(10_000, script_pub_key)
    psbt_in.hd_key_paths[_SOMEBODY_ELSES_KEY] = BIP32KeyOrigin(other, "m/84h/0h/0h/0/0")
    return psbt


def _check_fingerprint(signer: PsbtSigner) -> bytes:
    """Check the master fingerprint and return it, the rest needing it."""
    fingerprint = signer.master_fingerprint
    if len(fingerprint) != _FINGERPRINT_SIZE:
        _fail(f"master_fingerprint is {len(fingerprint)} bytes, not 4")
    if signer.master_fingerprint != fingerprint:
        _fail("master_fingerprint answered two different values")
    return fingerprint


def _check_capabilities(signer: PsbtSigner) -> None:
    """Check that what the signer says it can sign does not change.

    A caller reads this once and sends taproot inputs, or does not, for
    the rest of the session: a signer that answers differently the
    second time has already been acted on.
    """
    if signer.capabilities != signer.capabilities:
        _fail("capabilities answered two different values")


def _check_xpub(signer: PsbtSigner, der_path: DerPath) -> None:
    """Check the key at a path: public, parseable, and the same twice."""
    xpub = signer.xpub(der_path)
    try:
        key = BIP32KeyData.b58decode(xpub)
    except ValueError as e:
        _fail(f"xpub is not an extended key: {e}")
    if key.is_private:
        # the one answer that is not merely wrong: a signer that hands
        # out a key that signs has published the thing it exists to keep
        _fail("xpub answered a private key")
    if signer.xpub(der_path) != xpub:
        _fail("xpub answered two different keys for one path")


def _check_unsignable(signer: PsbtSigner, fingerprint: bytes) -> None:
    """Check what the signer does with a psbt that is not its business.

    Hand it back, having added nothing. Not an error: a caller sends one
    request to every signer it has, and a signer that raises rather than
    abstaining makes "this device holds no key here" indistinguishable
    from "this device failed", which is the distinction the caller needs
    in order to go on to the next one.
    """
    psbt = unsignable_psbt(fingerprint)
    answered = request_signatures(signer, psbt)
    added = [
        pub_key
        for psbt_in, answered_in in zip(psbt.inputs, answered.inputs, strict=True)
        for pub_key in answered_in.partial_sigs
        if pub_key not in psbt_in.partial_sigs
    ]
    if added:
        _fail("sign_psbt signed an input whose key origin names another master")


def _check_signable(signer: PsbtSigner, signable: Psbt) -> None:
    """Check that the signer signs what it was said to be able to sign."""
    answered = request_signatures(signer, signable)
    added = sum(
        len(answered_in.partial_sigs) - len(psbt_in.partial_sigs)
        for psbt_in, answered_in in zip(signable.inputs, answered.inputs, strict=True)
    )
    added += sum(
        len(answered_in.taproot_script_spend_signatures)
        - len(psbt_in.taproot_script_spend_signatures)
        + (answered_in.taproot_key_spend_signature is not None)
        - (psbt_in.taproot_key_spend_signature is not None)
        for psbt_in, answered_in in zip(signable.inputs, answered.inputs, strict=True)
    )
    if added <= 0:
        _fail("sign_psbt added no signature to a psbt it was said to sign")


def assert_psbt_signer(
    signer: object,
    *,
    der_path: DerPath | None = None,
    signable: object = None,
) -> None:
    """Check a signer against the contract, raising at the first breach.

    `der_path` is a path the signer holds a key at; without one the xpub
    checks are skipped, since a path guessed here would report a
    conforming signer as broken. `signable` is a psbt the signer can
    sign; without one the checks are of shape alone, and nothing sees it
    sign.

    Both it and the signer are typed `object` rather than what they have
    to be. A function whose subject is what a type cannot promise is one
    that has to be callable with what a type would have refused, and it
    says what arrived instead of the caller's type checker saying it
    first: an adapter written without one is exactly the caller this
    exists for.

    Closing is checked last and twice, `close` being documented as
    idempotent -- a caller closes a signer it is not sure about -- so the
    signer is spent when this returns.
    """
    if not isinstance(signer, PsbtSigner):
        _fail("it does not implement PsbtSigner")

    fingerprint = _check_fingerprint(signer)
    _check_capabilities(signer)
    if der_path is not None:
        _check_xpub(signer, der_path)
    _check_unsignable(signer, fingerprint)
    if signable is not None:
        if not isinstance(signable, Psbt):
            _fail(f"signable is {type(signable).__name__}, not a Psbt")
        _check_signable(signer, signable)

    signer.close()
    signer.close()


class OptionalProtocols(NamedTuple):
    """Answers to unrelated questions, which is a record and no sequence.

    A plain tuple is right for a sequence -- things of one kind whose
    count is the point, where an index is a position and means it.
    `displays_address`, `displays_policy_address` and `signs_message`
    answer questions that have nothing to do with each other, and how
    many of them there are is an accident of which optional protocols
    exist today. An index into a record is a position standing in for a
    name, and the name is what a caller reading `[1]` meant.

    The field names are an escape from that for a caller who reads them,
    not a guard: a caller who indexes rather than names a field reads
    the wrong answer the moment a protocol is inserted rather than
    appended.
    """

    displays_address: bool
    displays_policy_address: bool
    signs_message: bool


def optional_protocols(signer: object) -> OptionalProtocols:
    """Return which optional protocols the signer offers, as a caller asks.

    `isinstance` against the three runtime-checkable protocols, which is
    the whole of it: what `display_address`, `display_policy_address` and
    `sign_message` answer is checked by the functions of `psbt_signer`
    that call them, against the descriptor, the policy or the address the
    caller says the answer must match, and a conformance pass has none of
    that material.
    """
    return OptionalProtocols(
        isinstance(signer, AddressDisplay),
        isinstance(signer, WalletPolicyAddressDisplay),
        isinstance(signer, MessageSigner),
    )
