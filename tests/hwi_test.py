# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.hwi` module, with no HWI installed.

The device is a stand-in: a Python script this module writes out, run as
`[sys.executable, script]`, which answers each command from a table the
test wrote into it. That is the whole point of a subprocess adapter being
testable -- HWI declares `hidapi`, `libusb1`, `cbor2`, `pyserial`,
`noiseprotocol`, `protobuf` and vendor libraries, and none of them has to
exist for these to run.

`[sys.executable, script]` rather than a shebang and a chmod: a shebang
is not how Windows runs anything, and the matrix has a Windows job.

What the stand-in answers is HWI's own shapes, read from its `_cli.py`
and `errors.py`: a list for `enumerate`, `{"xpub": …}`, `{"psbt": …,
"signed": …}`, `{"signature": …}`, `{"address": …}` for the rest, and
`{"error": …, "code": …}` for a failure. The signing answers are made by
`psbt_signer.SoftwareSigner`, so the psbt that comes back is one a real
device could have sent -- which is what lets the checks in `psbt_signer`
run over it here.

The tables below that transcription is written out in are the other half
of staying aligned with a project btclib does not import: they say what
btclib sends and reads, and `tests/_data/README.md` pins the two upstream
paths they were read from, so the weekly re-check reports a command line
that moved. The module cites, the README carries the revision -- the same
split every vendored vector here has.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from btclib.bip32 import fingerprint
from btclib.bip32.bip32 import derive, xpub_from_xprv
from btclib.descriptors import Descriptor, add_checksum, at_index, parse
from btclib.exceptions import BTClibValueError, SignerError, SignerNotFoundError
from btclib.hwi import (
    _HWI_CHAIN,
    DEFAULT_EXECUTABLE,
    DEFAULT_MAX_OUTPUT,
    DEFAULT_TIMEOUT,
    HwiDevice,
    HwiSigner,
    enumerate_devices,
    is_available,
)
from btclib.network import NETWORKS
from btclib.psbt.psbt import Psbt
from btclib.psbt_signer import (
    AddressDisplay,
    MessageSigner,
    PsbtSigner,
    SignerCapabilities,
    display_address,
    export_account,
    request_signatures,
    sign_message,
)
from btclib.tx import OutPoint, Tx, TxIn, TxOut

# the "abandon abandon ... about" root of BIP39, which BIP84 publishes
XPRV_ROOT = (
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRR"
    "uL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
)
FINGERPRINT = fingerprint(XPRV_ROOT).hex()

# what the stand-in prints for a command, before any test changes it: the
# device is the software signer of the same key, so every answer is one
# btclib can check rather than a fixture that only looks right
_STAND_IN = """
import json, pathlib, sys
from btclib.psbt.psbt import Psbt
from btclib.psbt_signer import SoftwareSigner

ANSWERS = json.loads({answers!r})
# what it was run with, for the tests that are about the argv itself
pathlib.Path(__file__).with_suffix(".argv.json").write_text(json.dumps(sys.argv[1:]))
signer = SoftwareSigner({xprv!r})
args = [arg for arg in sys.argv[1:]]
command = next(arg for arg in args if not arg.startswith("-") and arg not in
               ("main", "test", "regtest", "signet", {fingerprint!r}))

if command in ANSWERS:
    print(json.dumps(ANSWERS[command]))
elif command == "enumerate":
    print(json.dumps([{{"type": "stand-in", "model": "stand_in_simulator",
                        "path": "/dev/null", "fingerprint": {fingerprint!r}}}]))
elif command == "getxpub":
    print(json.dumps({{"xpub": signer.xpub(args[args.index("getxpub") + 1])}}))
elif command == "signtx":
    psbt = Psbt.b64decode(args[args.index("signtx") + 1])
    print(json.dumps({{"psbt": signer.sign_psbt(psbt).b64encode()}}))
elif command == "signmessage":
    i = args.index("signmessage")
    message = args[i + 1].encode("utf-8")
    print(json.dumps({{"signature": signer.sign_message(message, args[i + 2])}}))
elif command == "displayaddress":
    from btclib.descriptors import parse
    descriptor = parse(args[args.index("--desc") + 1])
    print(json.dumps({{"address": signer.display_address(descriptor)}}))
elif command == "registerdescriptor":
    print(json.dumps({{"registration": "deadbeef"}}))
else:
    print(json.dumps({{"error": "unknown command " + command, "code": -13}}))
"""


# The surface btclib depends on, transcribed from HWI's `_cli.py` and
# `errors.py`; `tests/_data/README.md` carries the revision each is
# pinned to, so the weekly upstream re-check reports a path that moved.
#
# Written out rather than derived from `btclib.hwi`: a table that read
# the adapter would agree with it by construction and say nothing. This
# is the other side of the comparison, and what it catches is btclib
# changing what it sends -- upstream changing what it takes is what the
# pin is for, and the two together are the whole of the alignment.
#
# Each command with the positional arguments it takes, in order.
HWI_COMMANDS = {
    "enumerate": (),
    "getxpub": ("path",),
    "signtx": ("psbt",),
    "signmessage": ("message", "path"),
    "displayaddress": (),
    "registerdescriptor": ("name", "descriptor"),
}

# the global flags, which HWI's parser takes before the command, and the
# per-command one btclib passes
HWI_GLOBAL_FLAGS = ("--chain", "--fingerprint", "--emulators")
HWI_COMMAND_FLAGS = {"displayaddress": ("--desc",)}

# what btclib reads out of each answer. `signed` is the second key of
# signtx, added in 2021 and absent from HWI's own docstring for it
HWI_ANSWER_KEYS = {
    "getxpub": ("xpub",),
    "signtx": ("psbt", "signed"),
    "signmessage": ("signature",),
    "displayaddress": ("address",),
    "registerdescriptor": ("registration",),
}

# the chains `--chain` takes, which is what decides the version bytes of
# every extended key HWI answers with. `btclib.hwi` sends a subset:
# `_HWI_CHAIN` says why btclib's testnet4 network goes out as `test`
HWI_CHAINS = ("main", "test", "signet", "regtest", "testnet4")

# every error code HWI defines, with the name it gives it: the numbers a
# caller acts on, and `exceptions.SignerError` carries them through
HWI_ERROR_CODES = {
    -1: "NO_DEVICE_TYPE",
    -2: "MISSING_ARGUMENTS",
    -3: "DEVICE_CONN_ERROR",
    -4: "UNKNOWN_DEVICE_TYPE",
    -5: "INVALID_TX",
    -6: "NO_PASSWORD",
    -7: "BAD_ARGUMENT",
    -8: "NOT_IMPLEMENTED",
    -9: "UNAVAILABLE_ACTION",
    -10: "DEVICE_ALREADY_INIT",
    -11: "DEVICE_ALREADY_UNLOCKED",
    -12: "DEVICE_NOT_READY",
    -13: "UNKNOWN_ERROR",
    -14: "ACTION_CANCELED",
    -15: "DEVICE_BUSY",
    -16: "NEED_TO_BE_ROOT",
    -17: "HELP_TEXT",
    -18: "DEVICE_NOT_INITIALIZED",
    -19: "INVALID_POLICY",
}


@pytest.fixture
def hwi(tmp_path: Path) -> list[str]:
    """Return the argv of a stand-in device answering HWI's own shapes."""
    return stand_in(tmp_path, {})


def stand_in(tmp_path: Path, answers: dict[str, object]) -> list[str]:
    """Return the argv of a stand-in answering `answers` for those commands.

    A command not in the mapping is answered by signing with the key: the
    canned ones are how a device that fails, lies or floods is written.
    """
    script = tmp_path / f"hwi_stand_in_{len(list(tmp_path.iterdir()))}.py"
    script.write_text(
        _STAND_IN.format(
            answers=json.dumps(answers), xprv=XPRV_ROOT, fingerprint=FINGERPRINT
        ),
        encoding="ascii",
    )
    return [sys.executable, str(script)]


def signer(hwi: list[str], **kwargs: object) -> HwiSigner:
    """Return an HwiSigner over the stand-in, selected by its fingerprint."""
    return HwiSigner(FINGERPRINT, executable=hwi, **kwargs)  # type: ignore[arg-type]


def test_the_adapter_answers_the_signer_contract(hwi: list[str]) -> None:
    """The three protocols, over five commands of a command line."""
    device = signer(hwi)
    assert isinstance(device, PsbtSigner)
    assert isinstance(device, AddressDisplay)
    assert isinstance(device, MessageSigner)

    assert device.master_fingerprint == bytes.fromhex(FINGERPRINT)
    assert device.xpub("m/84h/0h/0h") == xpub_from_xprv(
        derive(XPRV_ROOT, "m/84h/0h/0h")
    )
    assert device.capabilities == SignerCapabilities()
    # what a model supports is not in the json a command line answers, so
    # a caller that knows its device is what says so
    taproot = signer(hwi, capabilities=SignerCapabilities(taproot=True))
    assert taproot.capabilities.taproot


def test_enumerate_reads_hwi_s_own_shape(tmp_path: Path) -> None:
    """A list of devices, the ones that cannot be talked to included.

    A locked device is enumerated on purpose: what a caller does about it
    is unlock it, and leaving it out would say it is not there.
    """
    locked = {
        "type": "trezor",
        "model": "trezor_1",
        "path": "usb:1",
        "needs_pin_sent": True,
        "error": "Could not open client or get fingerprint information: Trezor is locked",
        "code": -12,
    }
    hwi = stand_in(tmp_path, {"enumerate": [locked]})
    (device,) = enumerate_devices(executable=hwi)

    assert device == HwiDevice(
        type="trezor",
        model="trezor_1",
        path="usb:1",
        fingerprint=None,
        needs_pin_sent=True,
        error=locked["error"],  # type: ignore[arg-type]
        code=-12,
    )
    assert not device.is_usable


def test_a_device_is_named_by_its_fingerprint(tmp_path: Path) -> None:
    """Selection is not optional, and two devices are not a choice to make.

    HWI's `--device-type` connects to "the first device of this type
    enumerated", so with two of one vendor the answer would depend on
    enumeration order. One usable device is selected; two are refused with
    both fingerprints named, and none is refused with what was wrong with
    each.
    """
    one = {"type": "stand-in", "model": "m", "path": "a", "fingerprint": FINGERPRINT}
    other = {**one, "path": "b", "fingerprint": "deadbeef"}

    assert HwiSigner(executable=stand_in(tmp_path, {})).master_fingerprint.hex() == (
        FINGERPRINT
    )
    hwi = stand_in(tmp_path, {"enumerate": [one, other]})
    with pytest.raises(
        SignerError, match=f"2 usable devices \\({FINGERPRINT}, deadbeef"
    ):
        HwiSigner(executable=hwi)

    locked = {
        "type": "trezor",
        "model": "t",
        "path": "c",
        "error": "locked",
        "code": -12,
    }
    hwi = stand_in(tmp_path, {"enumerate": [locked]})
    with pytest.raises(SignerError, match="no usable device: trezor \\(locked\\)"):
        HwiSigner(executable=hwi)
    hwi = stand_in(tmp_path, {"enumerate": []})
    with pytest.raises(SignerError, match="no device"):
        HwiSigner(executable=hwi)

    # and every command carries the fingerprint, so HWI refuses to talk to
    # another device before btclib has to notice
    hwi = stand_in(tmp_path, {})
    signer(hwi).xpub("m/0")
    argv = last_argv(hwi)
    assert argv[argv.index("--fingerprint") + 1] == FINGERPRINT


def last_argv(hwi: list[str]) -> list[str]:
    """Return the arguments the stand-in was last run with.

    Written out by the stand-in itself, so what is read here is what
    crossed the process boundary rather than what this module thinks the
    adapter would have built.
    """
    recorded = Path(hwi[-1]).with_suffix(".argv.json")
    return json.loads(recorded.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def test_the_network_is_the_chain_hwi_is_told(tmp_path: Path) -> None:
    """`--chain` decides the version bytes of the xpubs that come back.

    So a btclib network name is translated rather than passed on, and
    testnet4 is translated to `test`: `btclib.hwi`'s `_HWI_CHAIN` says
    why the chain of that name is not what goes out.

    Every network btclib has is a chain HWI is told, which is what a
    sixth network would have to be given here: the mapping stands between
    `NETWORKS` and a command line, and a network missing from it reaches
    a caller as a refusal after the signer was built.
    """
    for network, chain in (
        ("mainnet", "main"),
        ("testnet", "test"),
        ("regtest", "regtest"),
        ("signet", "signet"),
        ("testnet4", "test"),
    ):
        hwi = stand_in(tmp_path, {})
        HwiSigner(FINGERPRINT, executable=hwi, network=network).xpub("m/0")
        argv = last_argv(hwi)
        assert argv[argv.index("--chain") + 1] == chain

    assert set(_HWI_CHAIN) == set(NETWORKS)

    with pytest.raises(BTClibValueError, match="unknown network"):
        HwiSigner(FINGERPRINT, executable=stand_in(tmp_path, {}), network="nosuchnet")
    # `enumerate_devices` names no device and checks no name against
    # `NETWORKS`, so it is where the chain lookup can be asked for one
    with pytest.raises(BTClibValueError, match="no HWI chain for network nosuchnet"):
        enumerate_devices(executable=stand_in(tmp_path, {}), network="nosuchnet")


def account_psbt(device: HwiSigner) -> tuple[Psbt, Descriptor]:
    """Return a psbt spending the first address of the device's account."""
    receive = export_account(device, "m/84h/0h/0h")[0]
    prev_out = TxOut(100_000, receive.script_pub_key(0))
    prev_tx = Tx(vin=[TxIn(OutPoint(b"\x08" * 32, 0))], vout=[prev_out])
    psbt = Psbt.from_tx(
        Tx(
            vin=[TxIn(OutPoint(prev_tx.id, 0))],
            vout=[TxOut(90_000, prev_out.script_pub_key)],
        )
    )
    psbt.inputs[0].non_witness_utxo = prev_tx
    return receive.update_psbt_input(psbt, 0, 0), receive


def test_a_psbt_goes_out_and_comes_back_checked(hwi: list[str]) -> None:
    """The whole exchange, with the checks of `psbt_signer` over it.

    The stand-in signs with the same key the account was exported from, so
    what comes back is what a device would send: `request_signatures` then
    holds it to the psbt that went out before combining.
    """
    device = signer(hwi)
    psbt, _ = account_psbt(device)

    signed = request_signatures(device, psbt)
    assert signed.inputs[0].partial_sigs
    assert not psbt.inputs[0].partial_sigs


def test_an_answer_that_changed_the_transaction_is_refused(tmp_path: Path) -> None:
    """The adapter parses and does not judge; `request_signatures` judges.

    A device answering with a psbt of another transaction is caught there,
    which is why the adapter hands back what it was given rather than
    checking it twice in two places.
    """
    device = signer(stand_in(tmp_path, {}))
    psbt, receive = account_psbt(device)

    elsewhere = Psbt.from_tx(
        Tx(
            vin=[TxIn(OutPoint(b"\x09" * 32, 0))],
            vout=[TxOut(1_000, receive.script_pub_key(0))],
        )
    )
    lying = signer(stand_in(tmp_path, {"signtx": {"psbt": elsewhere.b64encode()}}))
    with pytest.raises(BTClibValueError, match="the transaction being signed"):
        request_signatures(lying, psbt)


def test_an_address_is_asked_for_at_the_index_it_is_wanted(tmp_path: Path) -> None:
    """HWI derives a ranged descriptor at index 0, whatever was meant.

    So the descriptor goes out with the index written into it: a caller
    asking for index 5 and shown index 0 would be told the wrong address
    is the right one. `psbt_signer.display_address` then compares the
    answer with what the descriptor describes, which is the check that
    catches a device disagreeing.
    """
    device = signer(stand_in(tmp_path, {}))
    receive = export_account(device, "m/84h/0h/0h")[0]

    assert display_address(device, receive, 5) == receive.address(5)
    # what went out is the descriptor of that one script, wildcard gone
    text = str(at_index(receive, 5))
    assert text.endswith("/0/5)")
    assert parse(text).script_pub_key() == receive.script_pub_key(5)

    lying = signer(
        stand_in(tmp_path, {"displayaddress": {"address": receive.address(0)}})
    )
    with pytest.raises(BTClibValueError, match="the signer displayed"):
        display_address(lying, receive, 5)


def test_a_descriptor_is_registered_and_the_receipt_is_opaque(tmp_path: Path) -> None:
    """`registerdescriptor` is the one command with nothing to check the answer.

    What comes back is HWI's own receipt of an exchange this module has
    no opinion about -- an HMAC on a Ledger, nothing at all on a device
    that needs none -- so `register_descriptor` reads it the way
    `getxpub` reads an xpub: one field, taken as answered.
    """
    hwi = stand_in(tmp_path, {"registerdescriptor": {"registration": "cafe"}})
    device = signer(hwi)
    ranged = export_account(device, "m/84h/0h/0h")[0]

    assert device.register_descriptor("my wallet", ranged) == "cafe"
    # sent whole, ranged rather than at one index: registration is of the
    # policy, and displayaddress --index is what later asks for one
    # address of it
    argv = last_argv(hwi)
    assert argv[argv.index("registerdescriptor") + 1 :] == [
        "my wallet",
        add_checksum(str(ranged)),
    ]

    wrong = signer(stand_in(tmp_path, {"registerdescriptor": {"not-a": "key"}}))
    with pytest.raises(SignerError, match="did not answer a registration"):
        wrong.register_descriptor("my wallet", ranged)

    # the device refused the policy itself, HWI's own INVALID_POLICY
    invalid = signer(
        stand_in(
            tmp_path,
            {"registerdescriptor": {"error": "Invalid policy", "code": -19}},
        )
    )
    with pytest.raises(
        SignerError, match=r"Invalid policy \(signer error code -19\)"
    ) as e:
        invalid.register_descriptor("my wallet", ranged)
    assert e.value.code == -19


def test_a_registered_policy_s_address_is_asked_for_at_its_index(
    tmp_path: Path,
) -> None:
    """The registered-policy half of `displayaddress`.

    `--registration`, `--index` and `--multipath-index` in place of
    `--desc`: `registration` is what `register_descriptor` returned, and
    `psbt_signer.display_policy_address` is what then compares the answer
    with what `descriptors.wallet_policy_address` computes for the policy
    at that index and that multipath index.
    """
    hwi = stand_in(tmp_path, {"displayaddress": {"address": "shown"}})
    device = signer(hwi)

    assert device.display_policy_address("cafe", 5, 1) == "shown"
    argv = last_argv(hwi)
    assert argv[argv.index("displayaddress") + 1 :] == [
        "--registration",
        "cafe",
        "--index",
        "5",
        "--multipath-index",
        "1",
    ]
    # the defaults, the way `display_address`'s index defaults to 0
    device.display_policy_address("cafe")
    argv = last_argv(hwi)
    assert argv[argv.index("displayaddress") + 1 :] == [
        "--registration",
        "cafe",
        "--index",
        "0",
        "--multipath-index",
        "0",
    ]

    wrong = signer(stand_in(tmp_path, {"displayaddress": {"not-a": "key"}}))
    with pytest.raises(SignerError, match="did not answer a address"):
        wrong.display_policy_address("cafe")


def test_a_message_signature_is_verified_against_the_address(hwi: list[str]) -> None:
    """And a message that is not text is one this cannot ask for.

    The command line takes text, so bytes are decoded as utf-8 -- what the
    device displays and what HWI passes on. Anything else is refused here
    rather than mangled on the way.
    """
    device = signer(hwi)
    address = export_account(device, "m/44h/0h/0h")[0].address(0)
    der_path = "m/44h/0h/0h/0/0"

    signature = sign_message(device, b"hello", der_path, address)
    # `Octets` as everywhere else in btclib: the hex of those bytes is the
    # same message, and the command line carries the text either way
    assert sign_message(device, b"hello".hex(), der_path, address) == signature
    with pytest.raises(BTClibValueError, match="not utf-8"):
        device.sign_message(b"\xff\xfe", der_path)


def test_what_the_subprocess_can_do_wrong(tmp_path: Path) -> None:
    """Every failure is a SignerError, with HWI's code where there is one.

    The ways a command line fails and the one way the device does: an
    executable that is not there, an answer that is not json, an answer
    past the limit, diagnostics past the limit, a command that prints
    nothing, one that never stops, and the error object HWI itself
    returns — the last being the one that carries a number.
    """
    # not installed is its own subclass: a caller offering signers of
    # other kinds tells it from a device it could not reach, and a
    # SignerError still, so code catching that keeps catching this
    with pytest.raises(SignerNotFoundError, match="cannot run"):
        enumerate_devices(executable=str(tmp_path / "nowhere"))
    with pytest.raises(SignerError, match="cannot run"):
        enumerate_devices(executable=str(tmp_path / "nowhere"))

    # an OSError that is not a missing executable is not that subclass:
    # a directory is there, and running it is a different failure
    unrunnable = tmp_path / "a_directory"
    unrunnable.mkdir()
    with pytest.raises(SignerError, match="cannot run") as raised:
        enumerate_devices(executable=str(unrunnable))
    assert not isinstance(raised.value, SignerNotFoundError)

    not_json = tmp_path / "not_json.py"
    not_json.write_text("print('hello')\n", encoding="ascii")
    with pytest.raises(SignerError, match="did not answer json"):
        enumerate_devices(executable=[sys.executable, str(not_json)])

    silent = tmp_path / "silent.py"
    silent.write_text("import sys; sys.stderr.write('boom')\n", encoding="ascii")
    with pytest.raises(SignerError, match="answered nothing: boom"):
        enumerate_devices(executable=[sys.executable, str(silent)])

    flood = tmp_path / "flood.py"
    flood.write_text("print('x' * 100)\n", encoding="ascii")
    with pytest.raises(SignerError, match="answered more than 10 bytes"):
        enumerate_devices(executable=[sys.executable, str(flood)], max_output=10)

    # the limit is on the diagnostics too, and it is not conditional on
    # the answer: this one answered an empty device list, correctly, and
    # is refused for what it wrote beside it
    chatty = tmp_path / "chatty.py"
    chatty.write_text(
        "import sys\nsys.stderr.write('x' * 100)\nprint('[]')\n", encoding="ascii"
    )
    with pytest.raises(SignerError, match="wrote more than 10 bytes to stderr"):
        enumerate_devices(executable=[sys.executable, str(chatty)], max_output=10)

    # a backend that never stops writing is stopped, and the timeout is
    # not what stops it: these two would take the generous timeout below
    # and answer "timed out" if the limit were measured after the fact,
    # so the message is what says the child was killed while it ran
    endless = "import sys\nwhile True: sys.{0}.write('x' * 100_000)\n"
    flooding = tmp_path / "flooding.py"
    flooding.write_text(endless.format("stdout"), encoding="ascii")
    with pytest.raises(SignerError, match="answered more than 1000 bytes"):
        enumerate_devices(
            executable=[sys.executable, str(flooding)], max_output=1000, timeout=60
        )
    noisy = tmp_path / "noisy.py"
    noisy.write_text(endless.format("stderr"), encoding="ascii")
    with pytest.raises(SignerError, match="wrote more than 1000 bytes to stderr"):
        enumerate_devices(
            executable=[sys.executable, str(noisy)], max_output=1000, timeout=60
        )

    slow = tmp_path / "slow.py"
    slow.write_text("import time; time.sleep(5)\n", encoding="ascii")
    with pytest.raises(SignerError, match="timed out after"):
        enumerate_devices(executable=[sys.executable, str(slow)], timeout=0.2)

    # the device said no, which is HWI's ACTION_CANCELED
    cancelled = stand_in(tmp_path, {"signtx": {"error": "Canceled", "code": -14}})
    device = signer(cancelled)
    psbt = account_psbt(signer(stand_in(tmp_path, {})))[0]
    with pytest.raises(SignerError, match=r"Canceled \(signer error code -14\)") as e:
        device.sign_psbt(psbt)
    assert e.value.code == -14


def test_an_answer_of_the_wrong_shape_is_a_failure(tmp_path: Path) -> None:
    """A json object without the field asked for is not an answer."""
    device = signer(stand_in(tmp_path, {"getxpub": {"nothing": "here"}}))
    with pytest.raises(SignerError, match="did not answer a xpub"):
        device.xpub("m/0")

    listed = stand_in(tmp_path, {"enumerate": {"not": "a list"}})
    with pytest.raises(SignerError, match="did not answer a list"):
        enumerate_devices(executable=listed)


@pytest.mark.parametrize(
    "entry, message",
    [
        pytest.param("not a mapping", "did not answer a device", id="not-an-object"),
        pytest.param(["neither"], "did not answer a device", id="a-list"),
        pytest.param(
            {"fingerprint": "not hex"}, "invalid fingerprint", id="fingerprint-not-hex"
        ),
        pytest.param(
            {"fingerprint": "0011"}, "invalid fingerprint", id="fingerprint-too-short"
        ),
        pytest.param(
            {"fingerprint": 5}, "invalid fingerprint", id="fingerprint-a-number"
        ),
        pytest.param({"code": "oops"}, "code that is not a number", id="code-a-string"),
        pytest.param({"code": True}, "code that is not a number", id="code-a-bool"),
    ],
)
def test_a_malformed_enumerate_entry_is_a_signer_error(
    tmp_path: Path, entry: object, message: str
) -> None:
    """A list of the right shape holding the wrong thing is still a failure.

    `enumerate` is the one command whose answer is a list of objects, so
    it is where a backend that is not speaking HWI's protocol reaches the
    fields a caller acts on. Every one of these used to leave through a
    class this module does not name: an `AttributeError` from `.get` on a
    string, a `ValueError` from `bytes.fromhex` -- and a `code` that is
    not a number used to arrive intact, in a field annotated `int | None`
    and read as an HWI error code.
    """
    listed = stand_in(tmp_path, {"enumerate": [entry]})
    with pytest.raises(SignerError, match=message):
        enumerate_devices(executable=listed)


def test_an_enumerate_entry_is_read_for_what_it_says(tmp_path: Path) -> None:
    """And the fields that are prose are coerced rather than refused.

    `str` and `bool` accept every object there is, and a model name that
    arrived as a number describes the device it describes; the two fields
    a caller acts on are the two that are refused above. A device with no
    fingerprint is not one of those failures either -- it is a locked
    Trezor, which `HwiDevice` documents and `_select` names in its
    refusal.
    """
    entry = {"type": 5, "model": None, "error": ["locked"], "needs_pin_sent": "yes"}
    (device,) = enumerate_devices(executable=stand_in(tmp_path, {"enumerate": [entry]}))
    assert device.type == "5"
    assert device.model == "None"
    assert device.error == "['locked']"
    assert device.needs_pin_sent
    assert device.fingerprint is None
    assert device.code is None
    assert not device.is_usable


def test_a_closed_signer_runs_nothing(hwi: list[str]) -> None:
    """A subprocess per command holds nothing open, so closing is a decision.

    Making it refuse afterwards is what gives a caller the same shape as a
    signer that does hold something, so `contextlib.closing` works over
    either.
    """
    device = signer(hwi)
    device.close()
    device.close()

    assert device.master_fingerprint == bytes.fromhex(FINGERPRINT)
    with pytest.raises(SignerError, match="the signer is closed"):
        device.xpub("m/0")


def test_an_emulator_is_enumerated_only_when_asked(tmp_path: Path) -> None:
    """HWI's own `--emulators`, off by default.

    An emulator is a device with no secure element and no owner, so
    enumerating one without being asked would make a test fixture look
    like a signer to a caller that did not want one.
    """
    hwi = stand_in(tmp_path, {})
    enumerate_devices(executable=hwi)
    assert "--emulators" not in last_argv(hwi)

    enumerate_devices(executable=hwi, emulators=True)
    argv = last_argv(hwi)
    assert "--emulators" in argv
    # a global flag, so it goes before the command as HWI's parser wants
    assert argv.index("--emulators") < argv.index("enumerate")


def test_the_defaults_are_the_two_bounds(hwi: list[str]) -> None:
    """A person pressing a button, and one json object: the two are unlike."""
    device = signer(hwi)
    assert device.timeout == DEFAULT_TIMEOUT == 120.0
    assert device.max_output == DEFAULT_MAX_OUTPUT == 1 << 20
    # and nothing of hwilib is imported to get any of this
    assert not [name for name in sys.modules if name.startswith("hwilib")]


def test_whether_the_command_line_is_there_is_asked_before_it_is_run(
    hwi: list[str], tmp_path: Path
) -> None:
    """`is_available` looks for argv[0] of what would be run, and nothing else.

    The stand-in is `[sys.executable, script]`, so what has to be on the
    PATH is the interpreter and not the script: which element that is is
    this module's convention, which is the whole reason the question is
    answered here rather than by a caller writing `shutil.which` beside
    it. A path that names nothing is False, and it is False *before* any
    subprocess -- the same fact `enumerate_devices` reports afterwards,
    and by then it has run one.
    """
    assert is_available(hwi)
    assert is_available(sys.executable)
    assert not is_available(str(tmp_path / "nowhere"))
    assert not is_available([str(tmp_path / "nowhere"), "--flag"])
    # the default is the name every command here runs, so the two cannot
    # be answers about different executables
    assert DEFAULT_EXECUTABLE == "hwi"
    assert is_available() == (shutil.which(DEFAULT_EXECUTABLE) is not None)


def test_btclib_runs_the_commands_hwi_publishes(tmp_path: Path) -> None:
    """Every command sent is one of the six, spelled as HWI takes it.

    The argv is read back from what crossed the process boundary, so what
    is compared with the table is what a device would have received: the
    command name, the positional arguments in order, and the flags of
    each -- `--desc` being the one that is per-command rather than global.
    """
    hwi = stand_in(tmp_path, {})
    device = signer(hwi)
    receive = export_account(device, "m/84h/0h/0h")[0]

    ran = {}
    enumerate_devices(executable=hwi)
    ran["enumerate"] = last_argv(hwi)
    device.xpub("m/84h/0h/0h")
    ran["getxpub"] = last_argv(hwi)
    device.sign_message(b"hello", "m/84h/0h/0h/0/0")
    ran["signmessage"] = last_argv(hwi)
    device.display_address(receive, 0)
    ran["displayaddress"] = last_argv(hwi)
    device.register_descriptor("wallet", receive)
    ran["registerdescriptor"] = last_argv(hwi)

    for command, argv in ran.items():
        assert command in HWI_COMMANDS
        # the global flags come first, as HWI's parser wants them, and
        # each is one of the three btclib passes
        flags = [arg for arg in argv[: argv.index(command)] if arg.startswith("-")]
        assert set(flags) <= set(HWI_GLOBAL_FLAGS)
        after = argv[argv.index(command) + 1 :]
        positional = [arg for arg in after if not arg.startswith("-")]
        command_flags = [arg for arg in after if arg.startswith("-")]
        assert len(positional) == len(HWI_COMMANDS[command]) + len(command_flags)
        assert tuple(command_flags) == HWI_COMMAND_FLAGS.get(command, ())

    # and the chain is one of the names HWI takes
    assert set(_HWI_CHAIN.values()) <= set(HWI_CHAINS)
    assert ran["getxpub"][ran["getxpub"].index("--chain") + 1] in HWI_CHAINS


def test_btclib_reads_the_keys_hwi_answers_with(tmp_path: Path) -> None:
    """One key per command, and the refusal names the one that was missing.

    An answer of the right shape with the wrong key is the drift this
    catches on the btclib side: what the table says is read is what the
    adapter asks for, and nothing else.
    """
    fixed = parse(f"wpkh({xpub_from_xprv(XPRV_ROOT)}/0)")
    wrong = {"not-a": "key"}

    with pytest.raises(SignerError, match="did not answer a xpub"):
        signer(stand_in(tmp_path, {"getxpub": wrong})).xpub("m/0")
    with pytest.raises(SignerError, match="did not answer a signature"):
        signer(stand_in(tmp_path, {"signmessage": wrong})).sign_message(b"hi", "m/0")
    with pytest.raises(SignerError, match="did not answer a address"):
        signer(stand_in(tmp_path, {"displayaddress": wrong})).display_address(fixed)
    # signtx's two keys are checked where the pair is, `signed` being read
    # against the psbt rather than on its own
    assert HWI_ANSWER_KEYS["signtx"] == ("psbt", "signed")
    assert set(HWI_ANSWER_KEYS) == set(HWI_COMMANDS) - {"enumerate"}


def test_signtx_answers_a_psbt_and_whether_it_signed(tmp_path: Path) -> None:
    """HWI's `signed` is "what I return is not what I was given".

    So it is checked rather than believed: only this layer holds both
    strings, and a device that claims to have signed while handing back
    the psbt it was sent has answered two things that cannot both be
    true. Nothing else in the stack can see it -- `request_signatures`
    compares psbts and never sees the flag.
    """
    device = signer(stand_in(tmp_path, {}))
    psbt = account_psbt(device)[0]
    sent = psbt.b64encode()

    # the honest answers: signed with a different psbt, and not signed
    # with the same one. Neither raises, and an answer with no flag at
    # all is an older HWI and is not checked
    for answer in (
        {"psbt": device.sign_psbt(psbt).b64encode(), "signed": True},
        {"psbt": sent, "signed": False},
        {"psbt": sent},
    ):
        honest = signer(stand_in(tmp_path, {"signtx": answer}))
        assert honest.sign_psbt(psbt).b64encode() == answer["psbt"]

    # a device that signed nothing is not an error: one signer of an
    # m-of-n answers for its own key and for no other
    unchanged = signer(stand_in(tmp_path, {"signtx": {"psbt": sent, "signed": False}}))
    assert unchanged.sign_psbt(psbt) == psbt

    for answer, why in (
        ({"psbt": sent, "signed": True}, "was the one it was given"),
        (
            {"psbt": device.sign_psbt(psbt).b64encode(), "signed": False},
            "was not the one it was given",
        ),
    ):
        lying = signer(stand_in(tmp_path, {"signtx": answer}))
        with pytest.raises(SignerError, match=why):
            lying.sign_psbt(psbt)

    with pytest.raises(SignerError, match="did not answer a psbt"):
        signer(stand_in(tmp_path, {"signtx": {"signed": True}})).sign_psbt(psbt)


@pytest.mark.parametrize("code", sorted(HWI_ERROR_CODES))
def test_every_error_code_arrives_with_its_number(tmp_path: Path, code: int) -> None:
    """All nineteen, because the number is what a caller acts on.

    -14 is somebody pressing the button that says no and is not worth a
    retry, -3 is a cable and is worth one, -9 says this model will never
    do it. An adapter that dropped the number would leave a caller
    matching on the text of a message, which is what the field spares
    them.
    """
    name = HWI_ERROR_CODES[code]
    hwi = stand_in(tmp_path, {"enumerate": {"error": name, "code": code}})
    with pytest.raises(SignerError, match=f"{name} .signer error code {code}") as e:
        enumerate_devices(executable=hwi)
    assert e.value.code == code


def test_the_stand_in_is_a_subprocess_and_not_a_mock(hwi: list[str]) -> None:
    """What is under test is the exchange, so there is a process at the end.

    The stand-in runs as its own interpreter and answers over a pipe: a
    monkeypatched `subprocess.run` would test the code that builds an
    argv, and this tests the argv.
    """
    completed = subprocess.run(  # noqa: S603
        [*hwi, "--chain", "main", "enumerate"],
        capture_output=True,
        check=True,
        timeout=DEFAULT_TIMEOUT,
    )
    (device,) = json.loads(completed.stdout)
    assert device["fingerprint"] == FINGERPRINT


def test_a_device_is_usable_only_with_a_fingerprint_and_no_error() -> None:
    """Both halves, and HWI can answer both at once.

    A locked device answers an error and no fingerprint, and that is the
    pair this reads like -- but a device can be enumerated with a
    fingerprint *and* an error, HWI having asked it two questions, and
    then the fingerprint is one nothing may be signed against. Which is
    why the two are an `and`: either half alone would make that device
    usable, and `_select` would pick it as the one to sign with.
    """
    known = bytes.fromhex(FINGERPRINT)
    usable = HwiDevice(type="trezor", model="1", path="0001:0002", fingerprint=known)
    assert usable.is_usable

    locked = HwiDevice(type="trezor", model="1", path="0001:0002", error="locked")
    assert not locked.is_usable

    both = HwiDevice(
        type="trezor",
        model="1",
        path="0001:0002",
        fingerprint=known,
        error="Could not open client or get fingerprint",
    )
    assert not both.is_usable

    # and the flags a device does not carry are off: HWI omits them for a
    # device that needs nothing sent, so the default is what most devices
    # are read with
    assert not usable.needs_pin_sent
    assert not usable.needs_passphrase_sent


def test_every_refusal_names_the_command_it_ran(tmp_path: Path) -> None:
    """The message names argv[0], which is the executable and not a flag.

    A caller offering signers of several kinds reads that name to know
    which one failed, and every one of these messages is built from the
    same argv -- so naming any other element of it would name a chain
    flag, a subcommand or the script the interpreter was given.
    """
    # anchored on the colon that follows it, the OSError carried after it
    # naming the same path: what is being asserted is which element of the
    # argv the message opens with
    missing = str(tmp_path / "nowhere")
    with pytest.raises(SignerNotFoundError, match=f"cannot run {re.escape(missing)}:"):
        enumerate_devices(executable=missing)

    flood = tmp_path / "flood.py"
    flood.write_text("print('x' * 100)\n", encoding="ascii")
    with pytest.raises(SignerError, match=re.escape(sys.executable)):
        enumerate_devices(executable=[sys.executable, str(flood)], max_output=10)

    chatty = tmp_path / "chatty.py"
    chatty.write_text(
        "import sys\nsys.stderr.write('x' * 100)\nprint('[]')\n", encoding="ascii"
    )
    with pytest.raises(SignerError, match=re.escape(sys.executable)):
        enumerate_devices(executable=[sys.executable, str(chatty)], max_output=10)

    slow = tmp_path / "slow.py"
    slow.write_text("import time; time.sleep(5)\n", encoding="ascii")
    with pytest.raises(SignerError, match=re.escape(sys.executable)):
        enumerate_devices(executable=[sys.executable, str(slow)], timeout=0.2)


def test_the_emulators_flag_is_global_and_goes_before_the_command(
    tmp_path: Path,
) -> None:
    """HWI's parser reads it as a global flag, so it goes ahead of enumerate.

    Where in the argv it is inserted is not a style question: a global
    flag after the subcommand is an unrecognized argument to that
    subcommand, and the answer is HWI's usage message rather than a
    device list.
    """
    hwi = stand_in(tmp_path, {"enumerate": []})
    enumerate_devices(executable=hwi, emulators=True)
    argv = last_argv(hwi)
    assert argv[argv.index("--emulators") + 1] == "enumerate"
