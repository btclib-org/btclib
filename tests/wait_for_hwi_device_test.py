# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the device wait of `.github/scripts`.

What `integration-hwi.yml` shows every Wednesday is the branch that finds
a device: the emulator comes up, `enumerate_devices` answers one usable
entry, and the wait returns before its deadline is ever read. What that
run cannot show is the other branch, because arranging for the emulator
never to come up is not a rehearsal anybody schedules -- so the deadline,
the `::error::` it prints and everything that only a failure reaches are
tested here or nowhere, the run that would exercise them being the one
that also means the workflow failed.

`enumerate_devices` is substituted by a scripted sequence of answers,
each either a list of devices or a `SignerError` to raise, and `time` by
a clock that only moves when the script sleeps on it -- the same shape
`wait_for_pypi_release_test.py` uses for its own deadline, and for the
same reason: a regression that falls through to a real `time.sleep`
turns into an immediate failure here instead of a suite that sits for
whichever timeout was passed.

The script is loaded by path, `.github/scripts` being no package, as the
other scripts under it are tested. It defines no dataclass of its own --
`HwiDevice` is `btclib.hwi`'s -- so registering the module in
`sys.modules` before `exec_module` is not needed here, as
`verify_dist_contents_test.py` says for the same reason.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from btclib.exceptions import SignerError
from btclib.hwi import HwiDevice

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "wait_for_hwi_device.py"


class _Clock:
    """A monotonic clock that stands still until the script sleeps on it."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        """Return the reading, which only `sleep` below moves."""
        return self.now

    def sleep(self, seconds: float) -> None:
        """Spend the seconds a wait on a real clock would have spent."""
        self.slept.append(seconds)
        self.now += seconds


class _Enumerator:
    """The answers `enumerate_devices` gives, in order, and what it saw."""

    def __init__(self, answers: list[list[HwiDevice] | SignerError]) -> None:
        self.answers = answers
        self.asked: list[tuple[list[str], str]] = []

    def __call__(self, *, executable: list[str], network: str) -> list[HwiDevice]:
        """Answer the next scripted verdict, and record the question."""
        self.asked.append((executable, network))
        answer = self.answers.pop(0) if self.answers else []
        if isinstance(answer, SignerError):
            raise answer
        return answer


@pytest.fixture
def script() -> ModuleType:
    """Return the script, imported by path."""
    spec = importlib.util.spec_from_file_location("wait_for_hwi_device", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def clock(script: ModuleType, monkeypatch: pytest.MonkeyPatch) -> _Clock:
    """Put a clock this test moves where the script reads a real one."""
    fake = _Clock()
    monkeypatch.setattr(script, "time", fake)
    return fake


def _enumerate(
    script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    answers: list[list[HwiDevice] | SignerError],
) -> _Enumerator:
    """Put a scripted sequence of answers where `enumerate_devices` would be."""
    enumerator = _Enumerator(answers)
    monkeypatch.setattr(script, "enumerate_devices", enumerator)
    return enumerator


def test_describe_names_no_devices_for_an_empty_answer(script: ModuleType) -> None:
    """An enumerate that saw nothing is reported as exactly that."""
    assert script.describe([]) == "no devices"


def test_describe_names_the_fingerprint_of_a_usable_device(
    script: ModuleType,
) -> None:
    """A device with no error and a fingerprint is named by the fingerprint."""
    device = HwiDevice(
        type="trezor", model="1", path="0001:0002", fingerprint=b"\x01\x02\x03\x04"
    )

    assert script.describe([device]) == "trezor (01020304)"


def test_describe_names_the_error_of_a_device_that_answered_one(
    script: ModuleType,
) -> None:
    """A device HWI could not talk to is named by its error, not `_named`."""
    device = HwiDevice(type="ledger", model="nano", path="0001:0002", error="locked")

    assert script.describe([device]) == "ledger (locked)"


def test_describe_names_a_device_with_neither_error_nor_fingerprint(
    script: ModuleType,
) -> None:
    """`_named` falls back to saying so, for a device asked for one too soon."""
    device = HwiDevice(type="trezor", model="1", path="0001:0002")

    assert script.describe([device]) == "trezor (no fingerprint)"


def test_wait_returns_as_soon_as_one_usable_device_is_seen(
    script: ModuleType, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The success path: one usable device ends the wait before the deadline."""
    usable = HwiDevice(
        type="trezor", model="1", path="0001:0002", fingerprint=b"\x01\x02\x03\x04"
    )
    enumerator = _enumerate(script, monkeypatch, [[usable]])

    assert script.wait(["hwi"], "mainnet", 90.0) == 0

    assert enumerator.asked == [(["hwi"], "mainnet")]
    assert clock.slept == []


def test_wait_past_its_deadline_names_the_last_thing_seen(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A device that never becomes usable is what the `::error::` line names.

    Every scripted answer here is a device that answered no fingerprint and
    no error -- neither usable nor a `SignerError` -- so the loop sleeps on
    the fake clock until it, rather than an unrelated `StopIteration`, is
    what ends the test.
    """
    unusable = HwiDevice(type="trezor", model="1", path="0001:0002")
    enumerator = _enumerate(script, monkeypatch, [[unusable]] * 400)

    assert script.wait(["hwi"], "mainnet", 5.0) == 1

    assert clock.now >= 5.0
    assert enumerator.asked
    reported = capsys.readouterr().out
    assert "::error::no usable device within 5 s: trezor (no fingerprint)" in reported


def test_wait_treats_a_signer_error_as_nothing_seen_yet(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """HWI failing to run or to answer json is retried, not raised.

    The scripted answers raise `SignerError` throughout, so the deadline is
    what ends the wait, and the message the `::error::` line names is the
    exception's own text -- not `describe`'s, which never runs because no
    answer reaches the `else` branch.
    """
    enumerator = _enumerate(
        script, monkeypatch, [SignerError("hwi: command not found")] * 400
    )

    assert script.wait(["hwi"], "mainnet", 5.0) == 1

    assert clock.now >= 5.0
    assert enumerator.asked
    reported = capsys.readouterr().out
    assert "::error::no usable device within 5 s: hwi: command not found" in reported


def test_wait_keeps_going_past_two_or_more_usable_devices(
    script: ModuleType, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two usable devices at once is not the one this waits for.

    `HwiSigner`'s own `_select` is what refuses an ambiguous enumerate;
    this loop is not that check, and correctly is not -- it only asks
    whether the run has *something* to hand to it, so it keeps polling
    past two exactly as it does past zero, until one of the two is
    unplugged or the deadline is reached.
    """
    both_usable = [
        HwiDevice(
            type="trezor", model="1", path="0001:0002", fingerprint=b"\x01\x02\x03\x04"
        ),
        HwiDevice(
            type="trezor", model="1", path="0001:0003", fingerprint=b"\x05\x06\x07\x08"
        ),
    ]
    _enumerate(script, monkeypatch, [both_usable] * 400)

    assert script.wait(["hwi"], "mainnet", 5.0) == 1

    assert clock.now >= 5.0


def test_main_refuses_to_run_with_no_hwi_named(
    script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`BTCLIB_HWI` unset is a failure named before any enumerate is tried."""
    monkeypatch.delenv("BTCLIB_HWI", raising=False)
    monkeypatch.setattr("sys.argv", ["prog"])

    assert script.main() == 1
    assert (
        "::error::BTCLIB_HWI names the hwi to run, and is unset"
        in capsys.readouterr().out
    )


def test_main_splits_btclib_hwi_on_spaces_and_waits(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`--emulators` and the rest of `BTCLIB_HWI` reach `wait` as one argv."""
    usable = HwiDevice(
        type="trezor", model="1", path="0001:0002", fingerprint=b"\x01\x02\x03\x04"
    )
    enumerator = _enumerate(script, monkeypatch, [[usable]])
    monkeypatch.setenv("BTCLIB_HWI", "hwi --emulators")
    monkeypatch.setattr("sys.argv", ["prog", "--network", "testnet"])

    assert script.main() == 0

    assert enumerator.asked == [(["hwi", "--emulators"], "testnet")]
