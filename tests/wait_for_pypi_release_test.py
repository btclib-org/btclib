# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the release wait of `.github/scripts`.

What a run of `pypi-install.yml` shows is the wait that does not wait: on
a schedule and on a dispatch the tag is empty, and the matrix installing
anything at all is the check that the script returned. What no run can
show is any other outcome -- what is waited on is somebody else's upload,
so neither a release nor a rehearsal can arrange for the index to be
late -- so the retry, the deadline and the `::error::` are reached here
or nowhere.

Both of the wait's inputs are substituted for that. `_Transport` is the
index: a scripted sequence of answers that also records what it was
asked, timeout included. `_Clock` is the clock, and it moves only when
the script sleeps on it, which is what makes the deadline arrive in no
time at all and the attempts before it exact rather than approximate.

The script is loaded by path, `.github/scripts` being no package, as the
other scripts under it are tested.
"""

from __future__ import annotations

import importlib.util
import sys
from contextlib import contextmanager
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, NamedTuple
from urllib.error import HTTPError

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator
    from contextlib import AbstractContextManager

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "wait_for_pypi_release.py"
_URL = "https://pypi.org/pypi/btclib/2026.9.1/json"


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


class _Transport:
    """The answers the index gives, in order, and the questions it got."""

    def __init__(self, answers: list[bool]) -> None:
        self.answers = answers
        self.asked: list[tuple[str, float]] = []

    def __call__(self, url: str, timeout: float) -> bool:
        """Answer the next verdict in the script, and record the question."""
        self.asked.append((url, timeout))
        return self.answers.pop(0) if self.answers else False


class _Answer(NamedTuple):
    """What `served` reads of a response, which is its status alone."""

    status: int


@contextmanager
def _answering(status: int) -> Iterator[_Answer]:
    """Hand out a response the way `urlopen` hands one to a `with`."""
    yield _Answer(status)


@pytest.fixture
def script(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Return the script, imported by path, registered before it runs."""
    spec = importlib.util.spec_from_file_location("wait_for_pypi_release", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "wait_for_pypi_release", module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def clock(script: ModuleType, monkeypatch: pytest.MonkeyPatch) -> _Clock:
    """Put a clock this test moves where the script reads a real one."""
    fake = _Clock()
    monkeypatch.setattr(script, "time", fake)
    return fake


def _index(
    script: ModuleType, monkeypatch: pytest.MonkeyPatch, answers: list[bool]
) -> _Transport:
    """Put a scripted sequence of answers where the index would be."""
    transport = _Transport(answers)
    monkeypatch.setattr(script, "served", transport)
    return transport


def test_an_empty_tag_is_nothing_to_wait_for(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A run with no release behind it asks the index nothing at all.

    `clock` is asked for although nothing here should sleep, and that is
    the point: without it a regressed guard falls through to the real
    `time.sleep` and the suite sits for the whole default budget before
    reporting anything, where the fake turns the same regression into an
    immediate failure.
    """
    index = _index(script, monkeypatch, [])

    assert script.main(["btclib", ""]) == 0

    assert index.asked == []
    assert "nothing to wait for" in capsys.readouterr().out


def test_the_version_asked_for_is_the_one_the_tag_names(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The `v` of a tag is no part of the version the index serves."""
    index = _index(script, monkeypatch, [True])

    assert script.main(["btclib", "v2026.9.1"]) == 0

    assert index.asked == [(_URL, 10.0)]
    assert clock.slept == []
    assert "the index serves 2026.9.1" in capsys.readouterr().out


def test_a_version_not_served_yet_is_waited_for(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An index that has not caught up yet costs an interval, not the run."""
    index = _index(script, monkeypatch, [False, False, True])

    assert script.main(["btclib", "2026.9.1", "--interval", "15"]) == 0

    assert [url for url, _ in index.asked] == [_URL, _URL, _URL]
    assert clock.slept == [15.0, 15.0]
    assert "the index serves 2026.9.1 after 30 s" in capsys.readouterr().out


def test_a_version_that_never_arrives_is_the_deadline_speaking(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The wait ends where its deadline is, and names what never came."""
    index = _index(script, monkeypatch, [])

    assert script.main(["btclib", "2026.9.1", "--timeout", "300"]) == 1

    assert clock.now == pytest.approx(300.0)
    assert len(index.asked) == 20
    reported = capsys.readouterr().out
    assert "::error::2026.9.1 is not on the index 300 s later" in reported


def test_the_last_wait_is_cut_to_what_is_left_of_the_deadline(
    script: ModuleType, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deadline that is no multiple of the interval is still the deadline."""
    index = _index(script, monkeypatch, [])

    assert (
        script.main(["btclib", "2026.9.1", "--timeout", "20", "--interval", "15"]) == 1
    )

    assert clock.slept == [15.0, 5.0]
    assert clock.now == pytest.approx(20.0)
    assert [timeout for _, timeout in index.asked] == [10.0, 5.0]


def test_a_request_outlasting_the_deadline_leaves_no_negative_sleep(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A request that overruns its share still ends in the annotation.

    `served` is bounded by a socket timeout, which applies per blocking
    read, so an index answering a byte at a time can return after the
    deadline has already passed. What is left is then negative, and the
    clamp is what keeps `time.sleep` from being handed it -- a real one
    raises on a negative number, which would replace the `::error::`
    this exists to print with a traceback.
    """
    asked: list[tuple[str, float]] = []

    def slow(url: str, timeout: float) -> bool:
        """Answer no, having spent longer than the whole budget."""
        asked.append((url, timeout))
        clock.now += 40.0
        return False

    monkeypatch.setattr(script, "served", slow)

    assert script.main(["btclib", "2026.9.1", "--timeout", "30"]) == 1

    assert asked == [(_URL, 10.0)]
    assert clock.slept == [0.0]
    assert "::error::2026.9.1 is not on the index 30 s later" in capsys.readouterr().out


def test_the_defaults_are_the_budget_a_release_actually_gets(
    script: ModuleType, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The workflow passes no budget, so the shipped one is what bounds it.

    `DEFAULT_TIMEOUT` is the figure the job's `timeout-minutes` is set
    above, and no other case's outcome turns on it: three state a
    deadline of their own, and of the three that do not, one returns at
    the empty-tag guard before the wait is entered and the other two are
    answered well inside any deadline they could have been given. So the
    shipped number could be changed without a red run. This is the run
    the workflow makes.
    """
    index = _index(script, monkeypatch, [])

    assert script.main(["btclib", "2026.9.1"]) == 1

    assert clock.now == pytest.approx(300.0)
    assert clock.slept == [15.0] * 20
    assert [timeout for _, timeout in index.asked] == [10.0] * 20


def test_the_index_answering_the_document_is_it_serving_the_version(
    script: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The transport reads the status, not merely that something answered."""
    asked: list[tuple[str, float]] = []

    def urlopen(request: object, *, timeout: float) -> AbstractContextManager[_Answer]:
        """Answer as the index does once the file it names is there."""
        asked.append((request.full_url, timeout))  # type: ignore[attr-defined]
        return _answering(HTTPStatus.OK)

    monkeypatch.setattr(script, "urlopen", urlopen)

    assert script.served(_URL, 10.0)
    assert asked == [(_URL, 10.0)]


def test_a_2xx_that_is_not_ok_is_not_the_index_serving_it(
    script: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`served` compares the status rather than that a status arrived.

    The test above hands it `OK` alone, so it holds just as well against
    a `served` that returns `True` for whatever answers -- which is a
    mutation that survived it. This is the case that kills that one.
    """
    monkeypatch.setattr(
        script,
        "urlopen",
        lambda request, *, timeout: _answering(HTTPStatus.NO_CONTENT),
    )

    assert not script.served(_URL, 10.0)


@pytest.mark.parametrize(
    "failure",
    [
        HTTPError(_URL, HTTPStatus.NOT_FOUND, "Not Found", Message(), None),
        TimeoutError("timed out"),
        ConnectionResetError("reset by peer"),
    ],
)
def test_an_index_that_does_not_answer_is_not_serving_the_version(
    script: ModuleType, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    """Every way the exchange can fail is one more reason to keep waiting."""

    def urlopen(*_args: object, **_kwargs: object) -> AbstractContextManager[_Answer]:
        """Fail the way the index fails while the upload is still landing."""
        raise failure

    monkeypatch.setattr(script, "urlopen", urlopen)

    assert not script.served(_URL, 10.0)
