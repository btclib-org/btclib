# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A `PsbtSigner` over Bitcoin Core HWI's JSON command line.

https://github.com/bitcoin-core/HWI

HWI speaks to Trezor, Ledger, KeepKey, Digital Bitbox, Coldcard, BitBox02
and Jade over HID, USB, serial and emulator transports, and publishes a
JSON command line so that other software need not. This module is that
other software: it runs `hwi` as a subprocess and turns five of its
commands into the contract `btclib.psbt_signer` defines.

**Nothing is imported from hwilib, and nothing has to be installed for
btclib to work.** HWI declares `hidapi`, `libusb1`, `cbor2`, `pyserial`,
`noiseprotocol`, `protobuf` and vendor libraries, and a Python range
narrower than btclib's; a mandatory dependency on that is the thing issue
#381 rules out. What this module needs at runtime is an executable, named
by the caller and absent until a device is actually being used, so the
import costs `json` and `subprocess` and the tests run with no HWI at
all.

`enumerate_devices` is the one call that names no device; everything else
is `HwiSigner`, which is selected by fingerprint and passes `--fingerprint`
to every command it runs. That is issue #381's own rule, and the reason
selection is not optional: HWI's `--device-type` connects to "the first
device of this type enumerated", so two devices of one vendor make which
one signs a question of enumeration order.

The subprocess is bounded twice. `timeout` is how long a command may run
-- a device waiting for a button press is the ordinary case, so the
default is generous and a caller signing unattended should lower it --
and `max_output` is how much of its answer is accepted: HWI answers with
one json object, and a backend that sends megabytes is one whose output
is not read to the end. The timeout is what stops it in the meantime,
`subprocess.communicate` reading to EOF, so what the limit bounds is what
is parsed rather than what is buffered.

Failures come back as `exceptions.SignerError`, carrying HWI's own error
code where there is one: -14 is the user pressing the button that says
no, -3 is a cable, -9 is a model that will never do it. The one failure
that is not about a device -- the executable is not installed -- is the
`SignerNotFoundError` subclass, so that a caller which also offers
signers of other kinds can tell "no hardware here" from "the hardware
could not be reached" without matching on the text of a message.

## Wallet policies, and the multisig this cannot register

A Ledger will not display or sign a multisig it has not been shown
first. BIP388 wallet policies are how it is shown, and registration is a
one-time exchange ending in an HMAC the host keeps and replays on every
later call. `hwilib`'s ledger driver does that; `hwilib/_cli.py` does
not expose it, so this module cannot -- issue #381 delegates policy
registration to HWI on purpose, and the command line is where the
delegation stops. A caller with a Ledger multisig registers it out of
band, with HWI's Python API or Ledger's own tooling, and then this
module signs for it: the psbt path needs no policy, only the
registration does.

Whether btclib could grow it rather than route around it is one fact,
and it is not about the transport. A policy is a descriptor *template* --
`wsh(sortedmulti(2,@0/**,@1/**))` -- with the keys lifted out into a
vector beside it, which is a rewriting of what `descriptors` already
builds: the fragments a template may hold are BIP388's fixed set plus
miniscript inside `wsh()` in Ledger's app, and both halves of that are
read here now (issue #187). So the locking script with an `OP_IF` branch
and a `CHECKSEQUENCEVERIFY` in it that asked the question is expressible,
and what stands between a caller and a registered policy is the template
rewriting rather than the language or the transport.

Staying aligned with a project this does not import is two things, and
neither is a copy of it. `tests/hwi_test.py` writes out the surface used
-- the commands, the flags, the answer keys, the error codes -- and
`tests/_data/README.md` pins `hwilib/_cli.py` and `hwilib/errors.py` to
the revisions it was read from, so the monthly upstream re-check reports
a command line that moved. What that already caught: `signtx` answers
`signed` beside the psbt, which `sign_psbt` now holds the two strings to.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from btclib.alias import Octets
from btclib.bip32.der_path import DerPath, str_from_der_path
from btclib.descriptors import Descriptor, add_checksum, at_index
from btclib.exceptions import BTClibValueError, SignerError, SignerNotFoundError
from btclib.network import NETWORKS
from btclib.psbt.psbt import Psbt
from btclib.psbt_signer import SignerCapabilities
from btclib.utils import bytes_from_octets

__all__ = [
    "DEFAULT_MAX_OUTPUT",
    "DEFAULT_TIMEOUT",
    "NO_CAPABILITIES",
    "HwiDevice",
    "HwiSigner",
    "enumerate_devices",
]

# a button press is what a signing command waits for, so the bound is on
# a person and not on a computation: two minutes is long enough for a
# device that asks to confirm every output of a large transaction, and
# short enough that an unattended caller is not hung for an afternoon
DEFAULT_TIMEOUT = 120.0

# one json object, and the largest is a signed psbt: a megabyte is past
# any transaction standardness relays, and a backend that sends more is
# not one whose answer should be parsed to find out
DEFAULT_MAX_OUTPUT = 1 << 20

# what a caller that has not said gets: nothing supported, which is the
# honest default when the answer is not in any json HWI prints. A module
# global rather than a call in the signature, which is a mutable default
# in every language that has them and a ruff finding in this one
NO_CAPABILITIES = SignerCapabilities()

# btclib names five networks and HWI takes four chains: `--chain` is what
# decides the version bytes of the xpubs it answers with, so the mapping
# is what makes `account_descriptors` agree with the device about which
# chain the account is on. testnet4 has no HWI chain of its own
_HWI_CHAIN = {
    "mainnet": "main",
    "testnet": "test",
    "regtest": "regtest",
    "signet": "signet",
}


@dataclass(frozen=True)
class HwiDevice:
    """One entry of what `hwi enumerate` answers.

    `fingerprint` is None for a device that cannot be asked for one yet --
    a locked Trezor, a Ledger with no app open -- and `error` says why,
    with HWI's own `code` beside it. Such a device is enumerated on
    purpose: what a caller does about a locked device is unlock it, and a
    list that left it out would say it is not there.
    """

    type: str
    model: str
    path: str
    fingerprint: bytes | None = None
    needs_pin_sent: bool = False
    needs_passphrase_sent: bool = False
    error: str = ""
    code: int | None = None

    @property
    def is_usable(self) -> bool:
        """Answer whether the device answered a fingerprint and no error."""
        return self.fingerprint is not None and not self.error


def _executable(executable: str | Sequence[str]) -> list[str]:
    """Return the argv prefix that runs HWI, from a name or a whole argv.

    A sequence is what a caller passes for anything that is not a bare
    executable on the PATH -- `python -m hwilib`, an interpreter and a
    script, a wrapper with flags of its own -- and it is what the tests
    use to run a stand-in with no HWI installed.
    """
    return [executable] if isinstance(executable, str) else list(executable)


def _run(
    argv: list[str],
    *,
    timeout: float,
    max_output: int,
) -> Any:
    """Run HWI and return the json it answered, or raise what it failed with.

    Every failure is a `SignerError`: a backend that cannot be started, an
    answer that is not json, an answer past the limit, and the error
    object HWI itself returns. The last is the one carrying a code, which
    is why the others explicitly carry None -- "no number" is a fact about
    the exchange rather than a device that answered zero.
    """
    try:
        completed = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise SignerError(f"{argv[0]} timed out after {timeout} s") from e
    except FileNotFoundError as e:
        # the one failure that is not about a device: the command line is
        # not installed, which a caller offering signers of several kinds
        # reports differently from one it could not reach
        raise SignerNotFoundError(f"cannot run {argv[0]}: {e}") from e
    except OSError as e:
        raise SignerError(f"cannot run {argv[0]}: {e}") from e

    if len(completed.stdout) > max_output:
        err_msg = f"{argv[0]} answered more than {max_output} bytes"
        raise SignerError(err_msg)
    if not completed.stdout.strip():
        # a command that printed nothing has failed in its own way, and
        # stderr is where it said so: HWI prints a traceback there when it
        # cannot even build the parser
        message = completed.stderr.decode("utf-8", "replace").strip()
        raise SignerError(f"{argv[0]} answered nothing: {message or 'no output'}")

    try:
        answer = json.loads(completed.stdout)
    except json.JSONDecodeError as e:
        raise SignerError(f"{argv[0]} did not answer json: {e}") from e

    if isinstance(answer, dict) and "error" in answer:
        raise SignerError(str(answer["error"]), answer.get("code"))
    return answer


def _device(entry: dict[str, Any]) -> HwiDevice:
    """Return one enumerate entry as an `HwiDevice`, fingerprint decoded."""
    fingerprint = entry.get("fingerprint")
    return HwiDevice(
        type=str(entry.get("type", "")),
        model=str(entry.get("model", "")),
        path=str(entry.get("path", "")),
        fingerprint=None if fingerprint is None else bytes_from_octets(fingerprint, 4),
        needs_pin_sent=bool(entry.get("needs_pin_sent")),
        needs_passphrase_sent=bool(entry.get("needs_passphrase_sent")),
        error=str(entry.get("error", "")),
        code=entry.get("code"),
    )


def enumerate_devices(
    *,
    executable: str | Sequence[str] = "hwi",
    network: str = "mainnet",
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
    emulators: bool = False,
) -> list[HwiDevice]:
    """Return the devices HWI can see, the ones it cannot talk to included.

    `emulators` is HWI's own `--emulators`, off by default: an emulator is
    a device with no secure element and no owner, and enumerating one
    without being asked would make a test fixture look like a signer.
    """
    argv = [*_executable(executable), *_chain_args(network), "enumerate"]
    if emulators:
        argv.insert(-1, "--emulators")
    answer = _run(argv, timeout=timeout, max_output=max_output)
    if not isinstance(answer, list):
        raise SignerError(f"hwi enumerate did not answer a list: {answer!r}")
    return [_device(entry) for entry in answer]


def _chain_args(network: str) -> list[str]:
    """Return HWI's `--chain` flag for a btclib network name."""
    chain = _HWI_CHAIN.get(network)
    if chain is None:
        known = ", ".join(sorted(_HWI_CHAIN))
        raise BTClibValueError(f"no HWI chain for network {network}: not in ({known})")
    return ["--chain", chain]


class HwiSigner:
    """One device, selected by fingerprint, answering the signer contract.

    `btclib.psbt_signer`'s three protocols over five HWI commands:
    `getxpub`, `signtx`, `signmessage`, `displayaddress`, and `enumerate`
    for the selection. Everything a caller should check about the answers
    is checked by the functions of that module -- `request_signatures`,
    `display_address`, `sign_message` -- and not here: this is the
    transport, and a transport that also decided what to trust would be
    two things.

    The fingerprint is what a device is named by. Passing one selects it;
    passing none enumerates and refuses unless exactly one device is
    usable, because "the first one enumerated" is not a choice a library
    makes for a caller holding two.

    `capabilities` is the caller's word: HWI's JSON CLI does not report
    what a model supports, and the matrix that does is maintained per
    vendor and per firmware in HWI's own documentation. A default of
    nothing supported is the honest one, and a caller that knows its
    device says so.
    """

    def __init__(
        self,
        fingerprint: Octets | None = None,
        *,
        executable: str | Sequence[str] = "hwi",
        network: str = "mainnet",
        timeout: float = DEFAULT_TIMEOUT,
        max_output: int = DEFAULT_MAX_OUTPUT,
        emulators: bool = False,
        capabilities: SignerCapabilities = NO_CAPABILITIES,
    ) -> None:
        if network not in NETWORKS:
            raise BTClibValueError(f"unknown network: {network}")
        self.executable = _executable(executable)
        self.network = network
        self.timeout = timeout
        self.max_output = max_output
        self.emulators = emulators
        self._capabilities = capabilities
        self._fingerprint = (
            self._select() if fingerprint is None else bytes_from_octets(fingerprint, 4)
        )
        self._closed = False

    def _select(self) -> bytes:
        """Return the fingerprint of the one usable device, refusing two.

        A device that could not be asked for a fingerprint is not a
        candidate and is named in the refusal: "no device" and "one device,
        locked" are different things to be told, and the second is fixed by
        unlocking it rather than by plugging something in.
        """
        devices = enumerate_devices(
            executable=self.executable,
            network=self.network,
            timeout=self.timeout,
            max_output=self.max_output,
            emulators=self.emulators,
        )
        usable = [device for device in devices if device.is_usable]
        if len(usable) == 1:
            assert usable[0].fingerprint is not None  # noqa: S101
            return usable[0].fingerprint
        if not usable:
            unusable = ", ".join(
                f"{device.type} ({device.error or 'no fingerprint'})"
                for device in devices
            )
            err_msg = f"no usable device: {unusable}" if unusable else "no device"
            raise SignerError(err_msg)
        fingerprints = ", ".join(
            device.fingerprint.hex() for device in usable if device.fingerprint
        )
        err_msg = f"{len(usable)} usable devices ({fingerprints}):"
        err_msg += " name the one to use by its fingerprint"
        raise SignerError(err_msg)

    def _hwi(self, *args: str) -> Any:
        """Run one command against this device, by fingerprint."""
        if self._closed:
            raise SignerError("the signer is closed")
        argv = [
            *self.executable,
            *_chain_args(self.network),
            "--fingerprint",
            self._fingerprint.hex(),
            *args,
        ]
        return _run(argv, timeout=self.timeout, max_output=self.max_output)

    def _answer(self, command: list[str], field: str) -> str:
        """Return one string field of an answer, refusing one without it."""
        answer = self._hwi(*command)
        if not isinstance(answer, dict) or field not in answer:
            err_msg = f"hwi {command[0]} did not answer a {field}: {answer!r}"
            raise SignerError(err_msg)
        return str(answer[field])

    def master_fingerprint(self) -> bytes:
        """Return the fingerprint this signer was selected by.

        Not asked of the device again: it is what every command carries as
        `--fingerprint`, so HWI has refused to talk to a device answering
        anything else before any of them ran.
        """
        return self._fingerprint

    def xpub(self, der_path: DerPath) -> str:
        """Return the extended public key at a path: HWI's `getxpub`."""
        return self._answer(["getxpub", str_from_der_path(der_path)], "xpub")

    def sign_psbt(self, psbt: Psbt) -> Psbt:
        """Return what `hwi signtx` answered, parsed and otherwise untouched.

        Untouched deliberately: what the answer *contains* is checked
        against the psbt that was sent by
        `psbt_signer.request_signatures`, which is the caller of this and
        the one place that comparison belongs.

        What is checked here is the other thing, and only this layer can:
        `signtx` answers `signed` beside the psbt -- HWI computes it as
        "the base64 I return is not the base64 I was given" -- so the flag
        and the two strings have to agree. A device claiming it signed
        while handing back what it was sent, or denying it while handing
        back something else, has answered inconsistently, and the psbt is
        not the place that shows it: the comparison is over the very
        strings that crossed the boundary.

        A device that signed nothing is not an error and does not raise.
        One signer of an m-of-n answers for its own key and for no other,
        which is the same answer `psbt.sign` gives by adding nothing; what
        a caller compares is the psbt it gets back.
        """
        sent = psbt.b64encode()
        answer = self._hwi("signtx", sent)
        if not isinstance(answer, dict) or "psbt" not in answer:
            raise SignerError(f"hwi signtx did not answer a psbt: {answer!r}")
        returned = str(answer["psbt"])
        # absent from HWI before the flag existed, and a caller may be
        # running one of those: what is not answered is not checked
        signed = answer.get("signed")
        if signed is not None and bool(signed) != (returned != sent):
            err_msg = f"hwi signtx answered signed={signed!r} and a psbt that"
            err_msg += " was" if returned == sent else " was not"
            err_msg += " the one it was given"
            raise SignerError(err_msg)
        return Psbt.b64decode(returned)

    def sign_message(self, message: Octets, der_path: DerPath) -> str:
        """Return the compact signature of a message: HWI's `signmessage`.

        `Octets` as everywhere else in btclib, so a `str` is the hex of the
        message and bytes are the message: `ecc.bms` reads it that way and
        the two have to agree, a signature being verified here against
        what was signed there.

        What goes on the command line is text, HWI's `signmessage` taking
        a string and passing it to its own signer as one. The bytes are
        decoded as utf-8 for that, and a message that is not utf-8 is one
        this backend cannot be asked for -- which is a limit of the
        command line rather than of the device, and is said as such.
        """
        octets = bytes_from_octets(message)
        try:
            text = octets.decode("utf-8")
        except UnicodeDecodeError as e:
            err_msg = "hwi signmessage takes text on a command line:"
            err_msg += " this message is not utf-8"
            raise BTClibValueError(err_msg) from e
        return self._answer(
            ["signmessage", text, str_from_der_path(der_path)], "signature"
        )

    def display_address(self, descriptor: Descriptor, index: int = 0) -> str:
        """Return the address the device shows: HWI's `displayaddress`.

        The descriptor is sent with the index written into it rather than
        as the ranged one it may be: HWI derives a ranged descriptor at
        index 0 whatever was meant, so a caller asking for index 5 would
        be shown index 0 and told it was 5. `descriptors.at_index` is what
        names the one script, and `psbt_signer.display_address` is what
        then compares the answer with the address that descriptor
        describes.

        Checksummed, which is what HWI's `--desc` parser requires of
        anything it is given.
        """
        text = add_checksum(str(at_index(descriptor, index)))
        return self._answer(["displayaddress", "--desc", text], "address")

    def capabilities(self) -> SignerCapabilities:
        """Return what the caller said this device can be asked to sign."""
        return self._capabilities

    def close(self) -> None:
        """Refuse further commands; there is no connection to release.

        A subprocess per command is what a command line is, so nothing is
        held open between two of them and closing is a decision rather
        than a release. Making it refuse afterwards is what gives a caller
        the same shape as a signer that does hold something -- and
        `contextlib.closing` then works over either.
        """
        self._closed = True
