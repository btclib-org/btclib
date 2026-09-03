# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A `PsbtSigner` over Bitcoin Core HWI's JSON command line.

https://github.com/bitcoin-core/HWI

HWI speaks to Trezor, Ledger, KeepKey, Digital Bitbox, Coldcard, BitBox02
and Jade over HID, USB, serial and emulator transports, and publishes a
JSON command line so that other software need not. This module is that
other software: it runs `hwi` as a subprocess. Five of its commands
answer the contract `btclib.psbt_signer` defines; a sixth,
`registerdescriptor`, is wrapped beside them with no protocol of its own
to answer -- registering a policy is not a question `psbt_signer` asks.

**Nothing is imported from hwilib, and nothing has to be installed for
btclib to work.** HWI declares `hidapi`, `libusb1`, `cbor2`, `pyserial`,
`noiseprotocol`, `protobuf` and vendor libraries, and a Python range
narrower than btclib's; a mandatory dependency on that is the thing issue
#381 rules out. What this module needs at runtime is an executable, named
by the caller and absent until a device is actually being used, so the
import costs nothing outside the standard library and the tests run with
no HWI at all.

An optional extra importing `hwilib` beside this was weighed and refused
(#469), and the reason is that Python range: HWI declares `^3.9,<3.13`,
where this library supports 3.10 to 3.14 and pypy, so an extra nobody can
install on the two newest interpreters is a second and narrower support
matrix rather than an option. A subprocess has no such problem, the
executable living in an environment of its own. What a caller who does hold
an open `hwilib` device writes instead is a `psbt_signer.PsbtSigner` of
their own: that contract names an in-process driver as one of its shapes,
and it is met in the caller's environment rather than in this one.

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
is not read to the end. It bounds stdout and stderr separately, and it
bounds what is written rather than what is parsed: both streams go to
temporary files whose size is watched while the child runs, so a backend
past the limit is killed where it stands rather than read to EOF into
memory and measured afterwards.

Failures come back as `exceptions.SignerError`, carrying HWI's own error
code where there is one: -14 is the user pressing the button that says
no, -3 is a cable, -9 is a model that will never do it. The one failure
that is not about a device -- the executable is not installed -- is the
`SignerNotFoundError` subclass, so that a caller which also offers
signers of other kinds can tell "no hardware here" from "the hardware
could not be reached" without matching on the text of a message.
`is_available` is that one question asked *before* anything is run, which is
when a caller deciding what to offer at all has to have the answer: a
refusal is the right answer to a question that was asked, and the wrong
way to find out there was nothing to ask.

## Wallet policies, and the address `displayaddress` still cannot show

A Ledger will not display or sign a multisig it has not been shown
first. BIP388 wallet policies are how it is shown, and registration is a
one-time exchange ending in an HMAC the host keeps and replays on every
later call. `hwilib/_cli.py` exposes `registerdescriptor` for that
exchange, and `HwiSigner.register_descriptor` wraps it the way `getxpub`
and `signmessage` are wrapped: one request, one opaque answer, nothing
here to check it against.

No HWI release through 3.2.0 carries that subcommand -- it is on
`master` -- and `.github/workflows/integration-hwi.yml` installs 3.2.0,
so the weekly `integration-hwi` job runs a command line
`register_descriptor` cannot reach. Raising that workflow's
`HWI_VERSION` to the first release whose `hwilib/_cli.py` adds
`registerdescriptor` is what ends the wait, and what makes this paragraph
removable.

`displayaddress`'s BIP388 policy mode -- `--registration`, `--index`,
`--multipath-index` -- is not wrapped, and is on `master` rather than in
a release for the same reason `registerdescriptor` is.
`psbt_signer.display_address` exists to compare a device's screen with
the address a `Descriptor` computes, and
`descriptors.wallet_policy_address` is now that address for a policy
too: `descriptors.wallet_policy` builds the `@N` template and
key-information vector BIP388's own `/**` describes, from a receive and
a change `Descriptor` of one account -- `account_descriptors`' own pair
-- or the narrower `/*` form from one `Descriptor` alone, and
`wallet_policy_descriptor`/`wallet_policy_address` read either pair back
into the descriptor and the address the policy describes at an index.
What is still missing is the wiring, not the computation (issue #1588):
no method here takes `--registration`, `--index` or `--multipath-index`
and no protocol this library defines carries a multipath index for
`psbt_signer.display_address` to pass one through. A caller with a
registered policy still reads the address off the device's own screen;
that is what the screen is for, whether or not this module checks it
too.

Staying aligned with a project this does not import is two things, and
neither is a copy of it. `tests/hwi_test.py` writes out the surface used
-- the commands, the flags, the answer keys, the error codes -- and
`tests/_data/README.md` pins `hwilib/_cli.py` and `hwilib/errors.py` to
the revisions it was read from, so the weekly upstream re-check reports
a command line that moved. What that already caught: `signtx` answers
`signed` beside the psbt, which `sign_psbt` now holds the two strings to.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import IO, Any

from btclib.alias import Octets
from btclib.bip32.der_path import DerPath, str_from_der_path
from btclib.descriptors import Descriptor, add_checksum, at_index
from btclib.exceptions import BTClibValueError, SignerError, SignerNotFoundError
from btclib.network import NETWORKS
from btclib.psbt.psbt import Psbt
from btclib.psbt_signer import SignerCapabilities
from btclib.utils import assert_type, bytes_from_octets, is_integer

__all__ = [
    "DEFAULT_EXECUTABLE",
    "DEFAULT_MAX_OUTPUT",
    "DEFAULT_TIMEOUT",
    "NO_CAPABILITIES",
    "HwiDevice",
    "HwiSigner",
    "enumerate_devices",
    "is_available",
]

# the command HWI publishes, and the one name for it here: what
# `is_available` looks for on the PATH and what every command runs are the
# same string, so that "it is not installed" and "it is installed" cannot
# be answers about two different executables
DEFAULT_EXECUTABLE = "hwi"

# a button press is what a signing command waits for, so the bound is on
# a person and not on a computation: two minutes is long enough for a
# device that asks to confirm every output of a large transaction, and
# short enough that an unattended caller is not hung for an afternoon
DEFAULT_TIMEOUT = 120.0

# one json object, and the largest is a signed psbt: a megabyte is past
# any transaction standardness relays, and a backend that sends more is
# not one whose answer should be parsed to find out
DEFAULT_MAX_OUTPUT = 1 << 20

# the slice a wait is cut into, and so how far past `max_output` a stream
# may grow before the child is stopped: short enough that a flood is
# caught while it is still small, long enough that watching a device wait
# for a button press is not a busy loop
_POLL_INTERVAL = 0.05

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


def is_available(executable: str | Sequence[str] = DEFAULT_EXECUTABLE) -> bool:
    """Whether the command line this module runs is there to be run.

    Asked before running it, rather than read off a failure afterwards. A
    caller that offers signers of several kinds decides which to offer at
    all -- what devices to enumerate, whether to fall back to a software
    signer, what to put in front of a user -- and that decision comes
    before there is a device to ask about, so a refusal is not the shape
    of the answer: `enumerate_devices` on a host with no HWI raises
    `SignerNotFoundError`, which is the right answer to a question that
    was asked and the wrong way to find out that there was nothing to ask.

    What is looked for is argv[0] of what would be run, which is why this
    belongs here and not in the caller: an `executable` is a name on the
    PATH or a whole argv -- `["python", "-m", "hwilib"]`, a wrapper with
    flags of its own -- and which part of it has to be on the PATH is
    this module's own convention, `_executable`'s. A caller writing
    `shutil.which("hwi")` beside it writes the default name a second
    time and takes that convention as read.

    True is not a promise that a device will answer, or that what is on
    the PATH is HWI at all: it is that there is something to run, which
    is the half of it a caller cannot find out without running one.
    """
    return shutil.which(_executable(executable)[0]) is not None


def _watch(
    process: subprocess.Popen[bytes],
    streams: tuple[IO[bytes], IO[bytes]],
    *,
    timeout: float,
    max_output: int,
) -> bool:
    """Wait for the process, answering whether it ran out of time.

    It returns as soon as the child has exited, as soon as either stream
    is past the limit, or when the deadline is reached. Killing it is the
    caller's to do, that being what all three ways out have in common.
    """
    deadline = time.monotonic() + timeout
    while (left := deadline - time.monotonic()) > 0:
        try:
            process.wait(timeout=min(_POLL_INTERVAL, left))
        except subprocess.TimeoutExpired:
            if any(
                os.fstat(stream.fileno()).st_size > max_output for stream in streams
            ):
                return False
        else:
            return False
    return True


def _kill(process: subprocess.Popen[bytes]) -> None:
    """Kill the child and reap it; a child already reaped is left alone.

    `send_signal` is what does the leaving alone, doing nothing once the
    return code is in, so this needs no state of its own and can run on
    the way out of every path.
    """
    process.kill()
    process.wait()


def _read(stream: IO[bytes], limit: int) -> bytes:
    """Return at most `limit` bytes of what the child wrote to a stream."""
    stream.seek(0)
    return stream.read(limit)


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

    The two streams are temporary files rather than pipes, which is what
    lets the limit be enforced while the child is still running: a pipe
    has to be drained by whoever is also timing the child, and draining it
    is the buffering the limit is there to prevent. A file is written by
    the child alone, so the size is a question this process can ask
    between two waits, and one byte past the limit is read back whatever
    the child did afterwards.
    """
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            process = subprocess.Popen(argv, stdout=out, stderr=err)  # noqa: S603
        except FileNotFoundError as e:
            # the one failure that is not about a device: the command line
            # is not installed, which a caller offering signers of several
            # kinds reports differently from one it could not reach
            raise SignerNotFoundError(f"cannot run {argv[0]}: {e}") from e
        except OSError as e:
            raise SignerError(f"cannot run {argv[0]}: {e}") from e

        try:
            timed_out = _watch(
                process, (out, err), timeout=timeout, max_output=max_output
            )
        finally:
            _kill(process)

        if timed_out:
            raise SignerError(f"{argv[0]} timed out after {timeout} s")
        # one byte past the limit is all that has to be read to know the
        # limit was passed, and all that is read of a child that flooded
        stdout = _read(out, max_output + 1)
        stderr = _read(err, max_output + 1)

    if len(stdout) > max_output:
        err_msg = f"{argv[0]} answered more than {max_output} bytes"
        raise SignerError(err_msg)
    if len(stderr) > max_output:
        # the same limit and a separate one: stderr is diagnostics, so a
        # backend flooding it says nothing about the answer, and a backend
        # flooding it is still one this process will not hold in memory
        err_msg = f"{argv[0]} wrote more than {max_output} bytes to stderr"
        raise SignerError(err_msg)
    if not stdout.strip():
        # a command that printed nothing has failed in its own way, and
        # stderr is where it said so: HWI prints a traceback there when it
        # cannot even build the parser
        message = stderr.decode("utf-8", "replace").strip()
        raise SignerError(f"{argv[0]} answered nothing: {message or 'no output'}")

    try:
        answer = json.loads(stdout)
    except json.JSONDecodeError as e:
        raise SignerError(f"{argv[0]} did not answer json: {e}") from e

    if isinstance(answer, dict) and "error" in answer:
        raise SignerError(str(answer["error"]), answer.get("code"))
    return answer


def _fingerprint(entry: Mapping[str, Any]) -> bytes | None:
    """Return the four octets of an entry's fingerprint, or None for none.

    None is a device that cannot be asked for one yet, which `HwiDevice`
    documents; anything that is not four octets of hex is a device
    described by a backend that is not speaking HWI's protocol, and is
    the caller's `SignerError` rather than the `ValueError` `bytes.fromhex`
    raises from underneath the library.
    """
    fingerprint = entry.get("fingerprint")
    if fingerprint is None:
        return None
    try:
        return bytes_from_octets(fingerprint, 4)
    except (TypeError, ValueError) as e:
        err_msg = f"hwi enumerate answered an invalid fingerprint {fingerprint!r}: {e}"
        raise SignerError(err_msg) from e


def _code(entry: Mapping[str, Any]) -> int | None:
    """Return an entry's error code, refusing one that is not a number.

    `HwiDevice.code` is what a caller branches on -- -14 is the button
    that says no -- so a code is a number or there is none. `is_integer`
    and not `isinstance`, `True` being an `int` in this language and not
    an error code in any other.
    """
    code = entry.get("code")
    if code is None or is_integer(code):
        return code
    raise SignerError(f"hwi enumerate answered a code that is not a number: {code!r}")


def _device(entry: Any) -> HwiDevice:
    """Return one enumerate entry as an `HwiDevice`, its fields narrowed.

    `enumerate` is the one command whose answer is a list of objects
    rather than one object with a known field in it, so this is where a
    json nobody validated is read. What the entry can be wrong about is a
    `SignerError` like everything else the exchange can be wrong about: a
    caller catches one class, and an `AttributeError` from a string that
    stood where an object should have is not that class.

    The strings and the two flags are coerced rather than refused, which
    is the line drawn here: `str` and `bool` accept every object there
    is, and a model name that arrived as a number describes the device it
    describes. A fingerprint and a code are the two fields a caller acts
    on, and neither has a reading that is merely odd.
    """
    if not isinstance(entry, Mapping):
        raise SignerError(f"hwi enumerate did not answer a device: {entry!r}")
    return HwiDevice(
        type=str(entry.get("type", "")),
        model=str(entry.get("model", "")),
        path=str(entry.get("path", "")),
        fingerprint=_fingerprint(entry),
        needs_pin_sent=bool(entry.get("needs_pin_sent")),
        needs_passphrase_sent=bool(entry.get("needs_passphrase_sent")),
        error=str(entry.get("error", "")),
        code=_code(entry),
    )


def enumerate_devices(
    *,
    executable: str | Sequence[str] = DEFAULT_EXECUTABLE,
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
    assert_type(emulators, bool, "emulators")
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
    two things. `register_descriptor` is a sixth command with no protocol
    of its own; the module docstring's "Wallet policies" says why.

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
        executable: str | Sequence[str] = DEFAULT_EXECUTABLE,
        network: str = "mainnet",
        timeout: float = DEFAULT_TIMEOUT,
        max_output: int = DEFAULT_MAX_OUTPUT,
        emulators: bool = False,
        capabilities: SignerCapabilities = NO_CAPABILITIES,
    ) -> None:
        if network not in NETWORKS:
            raise BTClibValueError(f"unknown network: {network}")
        assert_type(emulators, bool, "emulators")
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

    @property
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

    def register_descriptor(self, name: str, descriptor: Descriptor) -> str:
        """Register a wallet policy with the device: HWI's `registerdescriptor`.

        A Ledger will not display or sign a multisig it has not been shown
        first (module docstring, "Wallet policies"); this is that showing.
        What comes back is opaque -- an HMAC on Ledger, nothing at all on a
        device that needs none -- and is the caller's to persist and pass
        back as `--registration` on a later `displayaddress`, which this
        module does not wrap: `descriptors.wallet_policy_address` computes
        what a device would show under that flag, but nothing here takes
        the registration, the index and the multipath index and passes
        them to `displayaddress` to compare it against.

        The descriptor goes out ranged, whole rather than at one index:
        registration is of the policy, and `displayaddress --index` is
        what later asks for one address of it.

        Checksummed, which is what HWI's parser requires of anything it is
        given, `--desc` included.

        No HWI release through 3.2.0 has `registerdescriptor` at all, so
        this needs a build of `master`; the module docstring's *Wallet
        policies* says what ends that.
        """
        assert_type(name, str, "name")
        text = add_checksum(str(descriptor))
        return self._answer(["registerdescriptor", name, text], "registration")

    @property
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
