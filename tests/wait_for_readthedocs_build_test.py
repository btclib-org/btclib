# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the documentation wait of `.github/scripts`.

No run of `release.yml` shows any of what this drives. The `documented`
job runs on a tag push alone, so the wait is entered on release day and
on no other day, and what it does then is decided by somebody else's
build: neither a release nor a rehearsal can arrange for read the docs to
be late. The retry, the deadline and the `::error::` naming the builds
page are therefore reached here or nowhere.

Both of the wait's inputs are substituted for that. `_Transport` is the
site: a scripted sequence of answers that also records what it was asked,
timeout included. `_Clock` is the clock, and it moves only when the
script sleeps on it, which is what makes the deadline arrive in no time
at all and the requests before it exact rather than approximate.

The script is loaded by path, `.github/scripts` being no package, as the
other scripts under it are tested.
"""

from __future__ import annotations

import importlib.util
import sys
from contextlib import closing, contextmanager
from email.message import Message
from http import HTTPStatus
from http.client import HTTPException
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, NamedTuple
from urllib.error import HTTPError

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator
    from contextlib import AbstractContextManager

_SCRIPT = (
    Path(__file__).parents[1] / ".github" / "scripts" / "wait_for_readthedocs_build.py"
)
_URL = "https://btclib.readthedocs.io/en/v2026.9.1/"
_BUILDS = "https://app.readthedocs.org/projects/btclib/builds/"


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
    """The answers the site gives, in order, and the questions it got."""

    def __init__(self, answers: list[str | None]) -> None:
        self.answers = answers
        self.asked: list[tuple[str, float]] = []

    def __call__(self, url: str, timeout: float) -> str | None:
        """Answer the next verdict in the script, and record the question."""
        self.asked.append((url, timeout))
        return self.answers.pop(0) if self.answers else "HTTP 404"


class _Answer(NamedTuple):
    """What `unserved` reads of a response, which is its status alone."""

    status: int


@contextmanager
def _answering(status: int) -> Iterator[_Answer]:
    """Hand out a response the way `urlopen` hands one to a `with`."""
    yield _Answer(status)


@pytest.fixture
def script(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Return the script, imported by path, registered before it runs."""
    spec = importlib.util.spec_from_file_location("wait_for_readthedocs_build", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "wait_for_readthedocs_build", module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def clock(script: ModuleType, monkeypatch: pytest.MonkeyPatch) -> _Clock:
    """Put a clock this test moves where the script reads a real one."""
    fake = _Clock()
    monkeypatch.setattr(script, "time", fake)
    return fake


def _site(
    script: ModuleType, monkeypatch: pytest.MonkeyPatch, answers: list[str | None]
) -> _Transport:
    """Put a scripted sequence of answers where read the docs would be."""
    transport = _Transport(answers)
    monkeypatch.setattr(script, "unserved", transport)
    return transport


def test_the_page_asked_for_is_the_one_the_tag_names(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The tag is the version read the docs serves, `v` and all.

    Where the index wants the version the tag names, this one wants the
    tag itself: read the docs activates the tag under the name it was
    pushed under, so stripping the `v` would ask for a version that is
    not there and wait out the whole deadline on it.
    """
    site = _site(script, monkeypatch, [None])

    assert script.main(["btclib", "v2026.9.1"]) == 0

    assert site.asked == [(_URL, 10.0)]
    assert clock.slept == []
    assert f"{_URL} is served after 0 s" in capsys.readouterr().out


def test_a_build_that_has_not_finished_is_waited_for(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A build still running costs an interval, not the release."""
    site = _site(script, monkeypatch, ["HTTP 404", "HTTP 404", None])

    assert script.main(["btclib", "v2026.9.1", "--interval", "30"]) == 0

    assert [url for url, _ in site.asked] == [_URL, _URL, _URL]
    assert clock.slept == [30.0, 30.0]
    reported = capsys.readouterr().out
    assert reported.count(f"{_URL} answered HTTP 404") == 2
    assert f"{_URL} is served after 60 s" in reported


def test_a_build_that_never_arrives_is_the_deadline_speaking(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The wait ends where its deadline is, and names what it last saw.

    The two answers differ so that the annotation is pinned to the last
    of them rather than to whatever the site said first, which is the
    signal a reader needs: a 404 throughout is a build that never
    started, and a 404 turning into something else is a build that did.
    """
    site = _site(script, monkeypatch, ["HTTP 404", "HTTP 500"])

    assert script.main(["btclib", "v2026.9.1", "--timeout", "60"]) == 1

    assert clock.now == pytest.approx(60.0)
    assert len(site.asked) == 2
    reported = capsys.readouterr().out
    assert f"::error::tag v2026.9.1: {_URL} was never served in 60 s;" in reported
    assert "last seen: HTTP 500." in reported
    assert f"Read the builds page on {_BUILDS}" in reported


def test_a_deadline_already_spent_asks_nothing_and_still_annotates(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A budget of nothing is the one case with no answer to report.

    Every other path through the wait leaves `last_seen` holding what a
    request came back with, so what the annotation says here is the only
    thing that says a request was never made -- which is what tells a
    reader looking at the log that the site was never asked, rather than
    asked and silent.
    """
    site = _site(script, monkeypatch, [])

    assert script.main(["btclib", "v2026.9.1", "--timeout", "0"]) == 1

    assert site.asked == []
    assert clock.slept == []
    assert "last seen: no request has been made yet." in capsys.readouterr().out


def test_the_last_wait_is_cut_to_what_is_left_of_the_deadline(
    script: ModuleType, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deadline that is no multiple of the interval is still the deadline."""
    site = _site(script, monkeypatch, [])

    assert (
        script.main(["btclib", "v2026.9.1", "--timeout", "40", "--interval", "30"]) == 1
    )

    assert clock.slept == [30.0, 10.0]
    assert clock.now == pytest.approx(40.0)
    assert [timeout for _, timeout in site.asked] == [10.0, 10.0]


def test_a_request_outlasting_the_deadline_leaves_no_negative_sleep(
    script: ModuleType,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A request that overruns its share still ends in the annotation.

    `unserved` is bounded by a socket timeout, which applies per blocking
    read, so a site answering a byte at a time can return after the
    deadline has already passed. What is left is then negative, and the
    clamp is what keeps `time.sleep` from being handed it -- a real one
    raises on a negative number, which would replace the `::error::` this
    exists to print with a traceback.
    """
    asked: list[tuple[str, float]] = []

    def slow(url: str, timeout: float) -> str | None:
        """Answer nothing served, having spent longer than the budget."""
        asked.append((url, timeout))
        clock.now += 40.0
        return "TimeoutError: timed out"

    monkeypatch.setattr(script, "unserved", slow)

    assert script.main(["btclib", "v2026.9.1", "--timeout", "30"]) == 1

    assert asked == [(_URL, 10.0)]
    assert clock.slept == [0.0]
    reported = capsys.readouterr().out
    assert "last seen: TimeoutError: timed out." in reported


def test_the_request_bound_is_cut_to_what_is_left_of_the_deadline(
    script: ModuleType, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A request cannot be given longer than the whole wait has left."""
    site = _site(script, monkeypatch, [])

    assert (
        script.main(["btclib", "v2026.9.1", "--timeout", "34", "--interval", "30"]) == 1
    )

    assert [timeout for _, timeout in site.asked] == [10.0, 4.0]


def test_the_defaults_are_the_budget_a_release_actually_gets(
    script: ModuleType, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The workflow passes no budget, so the shipped one is what bounds it.

    `DEFAULT_TIMEOUT` is the figure the job's `timeout-minutes` is set
    above, and no other case's outcome turns on it: the cases that reach
    the deadline state one of their own, and the two that do not are
    answered well inside any deadline they could have been given. So the
    shipped number could be changed without a red run. This is the run
    the workflow makes.
    """
    site = _site(script, monkeypatch, [])

    assert script.main(["btclib", "v2026.9.1"]) == 1

    assert clock.now == pytest.approx(900.0)
    assert clock.slept == [30.0] * 30
    assert [timeout for _, timeout in site.asked] == [10.0] * 30


def test_the_site_answering_the_page_is_it_serving_the_tag(
    script: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The transport reads the status, not merely that something answered.

    The `User-Agent` it sends is asserted here too: the Cloudflare zone in
    front of read the docs bans the interpreter's own default outright, a
    403 this suite cannot reproduce without a live request, so nothing
    else in the tree would notice the header being dropped.
    """
    asked: list[tuple[str, float]] = []
    agents: list[str | None] = []

    def urlopen(request: object, *, timeout: float) -> AbstractContextManager[_Answer]:
        """Answer as the site does once the tag's build has succeeded."""
        asked.append((request.full_url, timeout))  # type: ignore[attr-defined]
        agents.append(request.get_header("User-agent"))  # type: ignore[attr-defined]
        return _answering(HTTPStatus.OK)

    monkeypatch.setattr(script, "urlopen", urlopen)

    assert script.unserved(_URL, 10.0) is None
    assert asked == [(_URL, 10.0)]
    assert agents == [script.USER_AGENT]


def test_a_2xx_that_is_not_ok_is_not_the_site_serving_it(
    script: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`unserved` compares the status rather than that a status arrived.

    The test above hands it `OK` alone, so it holds just as well against
    an `unserved` that returns `None` for whatever answers. This is the
    case that kills that one, and it is what carries the status into the
    annotation rather than a bare "not served".
    """
    monkeypatch.setattr(
        script,
        "urlopen",
        lambda request, *, timeout: _answering(HTTPStatus.NO_CONTENT),
    )

    assert script.unserved(_URL, 10.0) == "HTTP 204"


def test_a_status_the_site_refuses_with_is_named_by_its_number(
    script: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ordinary answer while no build has succeeded is a 404.

    `urlopen` raises rather than returns on it, so the status the
    annotation names comes off the exception and not off a response.

    `closing` is what keeps the refusal from ending the run somewhere
    else: `HTTPError` is a response as well as an exception, and inherits
    `tempfile._TemporaryFileWrapper` through `urllib.response.addbase`,
    so one collected without being closed raises `ResourceWarning` --
    which this suite turns into an error, against whichever test happens
    to be running when the collector reaches it.
    """
    refusal = HTTPError(_URL, HTTPStatus.NOT_FOUND, "Not Found", Message(), None)

    def urlopen(*_args: object, **_kwargs: object) -> AbstractContextManager[_Answer]:
        """Refuse the way the site refuses a version it has not built."""
        raise refusal

    monkeypatch.setattr(script, "urlopen", urlopen)

    with closing(refusal):
        assert script.unserved(_URL, 10.0) == "HTTP 404"


@pytest.mark.parametrize(
    "failure,named",
    [
        (TimeoutError("timed out"), "TimeoutError: timed out"),
        (ConnectionResetError("reset by peer"), "ConnectionResetError: reset by peer"),
        (HTTPException("truncated"), "HTTPException: truncated"),
    ],
)
def test_a_site_that_does_not_answer_is_named_by_the_failure(
    script: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    named: str,
) -> None:
    """A failure with no status of its own still reaches the annotation."""

    def urlopen(*_args: object, **_kwargs: object) -> AbstractContextManager[_Answer]:
        """Fail the way the exchange fails when nothing comes back."""
        raise failure

    monkeypatch.setattr(script, "urlopen", urlopen)

    assert script.unserved(_URL, 10.0) == named
