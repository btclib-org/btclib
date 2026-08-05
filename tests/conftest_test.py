# Copyright (C) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the golden-file check the suite's own fixture runs.

Eleven modules compare a `to_dict()` against a committed json through
`json_golden`, and the two paths that report a difference are the ones a
passing suite never takes: a golden that is missing and a golden that
does not match. They are the reason the fixture exists, so they are
tested here, against a tmp_path -- the source tree is what this check
stopped writing into, and a test of it must not put that back.
"""

from pathlib import Path

import pytest

from tests.conftest import REGENERATE, check_golden

MODULE = "something_test.py"


@pytest.fixture(autouse=True)
def _regenerate_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Take REGENERATE out of the environment, for every test here.

    `BTCLIB_REGENERATE_GOLDEN=1 uv run pytest` is the command the failure
    message names and tests/_data/README.md documents, and running it
    turned three of the tests below red: with the variable set,
    `check_golden` takes the regenerate branch, so the missing and the
    mismatch paths rewrite the file instead of failing and the
    `pytest.raises` around them finds nothing to catch. The escape hatch
    made the tests of the escape hatch fail, and it is the whole suite
    that command is meant for, not the eleven golden modules alone.
    The two tests that want the variable set still set it themselves.
    """
    monkeypatch.delenv(REGENERATE, raising=False)


def test_a_matching_golden_passes(tmp_path: Path) -> None:
    """Verify a committed file equal to what the check writes passes."""
    path = tmp_path / "net.json"
    # four spaces of indent and a trailing newline: what the check writes
    # is what it then accepts, and nothing else is
    path.write_text('{\n    "a": 1\n}\n', encoding="ascii")
    check_golden(path, "net.json", {"a": 1}, MODULE)


def test_a_missing_golden_says_how_to_write_it(tmp_path: Path) -> None:
    """Verify a missing file fails and names the regenerate command."""
    path = tmp_path / "absent.json"
    with pytest.raises(pytest.fail.Exception, match="missing golden file"):
        check_golden(path, "absent.json", {"a": 1}, MODULE)
    # the message carries the command, that being the whole point of it
    with pytest.raises(pytest.fail.Exception, match=f"{REGENERATE}=1 uv run pytest"):
        check_golden(path, "absent.json", {"a": 1}, MODULE)


def test_a_mismatching_golden_fails_with_the_diff(tmp_path: Path) -> None:
    """Verify a mismatch reports a unified diff of the changed line."""
    path = tmp_path / "net.json"
    path.write_text('{\n    "a": 1\n}\n', encoding="ascii")

    with pytest.raises(pytest.fail.Exception) as excinfo:
        check_golden(path, "net.json", {"a": 2}, MODULE)

    message = str(excinfo.value)
    assert "net.json does not match what to_dict() produces now." in message
    # the diff is the review the check exists to ask for: both sides of
    # the changed line, and the file names that say which is which
    assert '-    "a": 1' in message
    assert '+    "a": 2' in message
    assert "net.json (committed)" in message
    assert "net.json (this run)" in message
    assert f"{REGENERATE}=1 uv run pytest {MODULE}" in message


def test_regenerating_creates_the_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_generated_files` may not exist yet, for a new test module."""
    monkeypatch.setenv(REGENERATE, "1")
    path = tmp_path / "_generated_files" / "net.json"
    assert not path.parent.exists()

    check_golden(path, "net.json", {"a": 1}, MODULE)

    assert path.read_text(encoding="ascii") == '{\n    "a": 1\n}\n'


def test_regenerating_overwrites_a_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The escape hatch: what fails the check is what regenerating fixes."""
    path = tmp_path / "net.json"
    path.write_text('{\n    "a": 1\n}\n', encoding="ascii")
    with pytest.raises(pytest.fail.Exception, match="does not match"):
        check_golden(path, "net.json", {"a": 2}, MODULE)

    monkeypatch.setenv(REGENERATE, "1")
    check_golden(path, "net.json", {"a": 2}, MODULE)
    assert path.read_text(encoding="ascii") == '{\n    "a": 2\n}\n'

    # and the rewritten file is what the check then accepts, which is the
    # property that makes regenerating leave no diff of its own
    monkeypatch.delenv(REGENERATE)
    check_golden(path, "net.json", {"a": 2}, MODULE)
