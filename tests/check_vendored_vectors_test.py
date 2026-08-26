# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the vendored-vector re-checker of `.github/scripts`.

Its only external dependency is `gh`, called five different ways across
`_latest_commit`, `_open_issue_number` and `report`. Every test here
replaces `subprocess.run` with `FakeGh`, which answers each call the way
a real `gh api`/`gh issue` would rather than reaching GitHub: a real call
would need a token, would not be deterministic across a re-run, and is
the one thing the parsing and reporting logic below does not need to
have working to be tested.

The script is loaded by path, `.github/scripts` being no package: the
mutation-counter test does the same for the same reason. Its dataclasses
need one thing that one does not -- `Entry` and `Drift` are decorated
with `from __future__ import annotations` in scope, so `@dataclass`
resolves their field types through `sys.modules[cls.__module__]`, which
has to name the module before `exec_module` runs it.
"""

from __future__ import annotations

import importlib.util
import json
import runpy
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = (
    Path(__file__).parents[1] / ".github" / "scripts" / "check_vendored_vectors.py"
)


@pytest.fixture
def checker(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Return the script, imported by path, registered before it runs."""
    spec = importlib.util.spec_from_file_location("check_vendored_vectors", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "check_vendored_vectors", module)
    spec.loader.exec_module(module)
    return module


class FakeGh:
    """A `subprocess.run` stand-in, answering by which `gh` call this is.

    `commits` maps a (repo, path) pair to the sha and date
    `_latest_commit` should read back, or to None for a path upstream no
    longer has -- which the api answers with an empty list rather than an
    error. `open_issue` is the number `_open_issue_number` should report
    open, or None for no issue open. Every call is recorded in `calls`,
    argv and all, so a test can assert what was asked for rather than
    only what came back.
    """

    def __init__(self) -> None:
        self.commits: dict[tuple[str, str], tuple[str, str] | None] = {}
        self.open_issue: int | None = None
        self.calls: list[list[str]] = []

    def __call__(
        self, argv: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        """Record the call, and answer as the `gh` sub-command it names."""
        self.calls.append(list(argv))
        if argv[1] == "api":
            repo = argv[4].removeprefix("repos/").removesuffix("/commits")
            path = argv[6].removeprefix("path=")
            answer = self.commits[repo, path]
            # None is what the api answers for a path upstream no longer
            # has: an empty list, which is a 200 and not an error
            if answer is None:
                return subprocess.CompletedProcess(argv, 0, stdout="[]")
            sha, date = answer
            commit = {
                "sha": sha,
                "commit": {"committer": {"date": f"{date}T00:00:00Z"}},
            }
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps([commit]))
        if argv[2] == "list":
            issues = (
                [{"number": self.open_issue}] if self.open_issue is not None else []
            )
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(issues))
        return subprocess.CompletedProcess(argv, 0, stdout="")


@pytest.fixture
def fake_gh(checker: ModuleType, monkeypatch: pytest.MonkeyPatch) -> FakeGh:
    """Install a `FakeGh` in place of the script's own `subprocess.run`."""
    fake = FakeGh()
    monkeypatch.setattr(checker.subprocess, "run", fake)
    return fake


def readme(*blocks: str) -> str:
    """Join fenced ```text blocks under one ### heading each, README-shaped."""
    return "\n\n".join(blocks)


def entry(heading: str, **fields: str) -> str:
    """Return one `### heading` and its fenced field block, README-shaped."""
    body = "\n".join(f"{key}  {value}" for key, value in fields.items())
    return f"### {heading}\n\n```text\n{body}\n```"


def test_a_checkable_entry_is_returned(checker: ModuleType) -> None:
    """A pin with repo, path, commit and `behind: 0` is a checkable Entry."""
    text = readme(
        entry(
            "`f.json`",
            repo="btclib-org/btclib",
            path="tests/f.json",
            commit="deadbeef  2026-01-01",
            behind="0 revisions; that commit is the tip of the path",
        )
    )
    entries, skipped = checker._entries_at_tip(text)
    assert skipped == []
    assert entries == [
        checker.Entry("`f.json`", "btclib-org/btclib", "tests/f.json", "deadbeef")
    ]


def test_a_placeholder_path_is_skipped(checker: ModuleType) -> None:
    """A `<name>` path is a group pin, not a checkable single path."""
    text = readme(
        entry(
            "group",
            repo="bitcoin/bips",
            path="bip-0327/vectors/<name>.json",
            commit="deadbeef  2026-01-01",
            behind="0 revisions",
        )
    )
    entries, skipped = checker._entries_at_tip(text)
    assert entries == []
    assert skipped == ["group (one pin serves several files)"]


@pytest.mark.parametrize(
    "fields",
    [
        {"behind": "3 revisions, none touching the vectors"},
        {},  # no `behind` field at all
    ],
)
def test_a_behind_pin_is_skipped(checker: ModuleType, fields: dict[str, str]) -> None:
    """A `behind` reading anything but 0, explicit or absent, is a skip."""
    text = readme(
        entry(
            "stale",
            repo="btclib-org/btclib",
            path="tests/f.json",
            commit="deadbeef  2026-01-01",
            **fields,
        )
    )
    entries, skipped = checker._entries_at_tip(text)
    assert entries == []
    assert skipped == ["stale (already documented as behind)"]


@pytest.mark.parametrize(
    "fields",
    [
        {"repo": "btclib-org/btclib", "path": "tests/f.json"},  # no commit
        {"repo": "btclib-org/btclib", "commit": "deadbeef"},  # no path
        {"path": "tests/f.json", "commit": "deadbeef"},  # no repo
        {"pulled": "2020-01-01"},  # chain data: no pin at all
    ],
)
def test_an_entry_with_no_commit_is_skipped(
    checker: ModuleType, fields: dict[str, str]
) -> None:
    """Missing repo, path or commit skips too -- named, not silently."""
    text = readme(entry("no pin", **fields))
    entries, skipped = checker._entries_at_tip(text)
    assert entries == []
    assert skipped == ["no pin (no commit to check against)"]


def test_the_heading_is_the_nearest_one_before_the_block(checker: ModuleType) -> None:
    """An intro heading with no block of its own never names an entry."""
    text = (
        "### intro heading, no block of its own\n\n"
        "some prose about a whole group\n\n"
        + entry(
            "`f.json`",
            repo="btclib-org/btclib",
            path="tests/f.json",
            commit="deadbeef  2026-01-01",
            behind="0 revisions",
        )
    )
    entries, _ = checker._entries_at_tip(text)
    assert [e.heading for e in entries] == ["`f.json`"]


def test_a_heading_with_no_fenced_block_is_skipped(checker: ModuleType) -> None:
    """The shape the block-by-block walk cannot see, and reports anyway.

    `_entries_at_tip` iterates fenced blocks, so a heading with none
    never enters the loop and would be neither checked nor listed --
    which is what a pin whose block is lost to an edit looks like, and
    what the script's module docstring promises cannot happen
    (issue #1447).
    """
    text = "### `lost.json`\n\nprose, and no fenced block\n\n" + entry(
        "`f.json`",
        repo="btclib-org/btclib",
        path="tests/f.json",
        commit="deadbeef  2026-01-01",
        behind="0 revisions",
    )
    entries, skipped = checker._entries_at_tip(text)
    assert [e.heading for e in entries] == ["`f.json`"]
    assert skipped == ["`lost.json` (no pin of its own)"]


def test_a_block_with_no_heading_before_it_has_an_empty_one(
    checker: ModuleType,
) -> None:
    """A fenced block before any `### ` heading names an empty heading."""
    text = "```text\nrepo btclib-org/btclib\n```"
    entries, skipped = checker._entries_at_tip(text)
    assert entries == []
    assert skipped == [" (no commit to check against)"]


def test_commit_and_path_whitespace_is_stripped(checker: ModuleType) -> None:
    """Only the commit's own sha is kept, and the path is trimmed."""
    text = readme(
        entry(
            "`f.json`",
            repo="btclib-org/btclib",
            path=" tests/f.json ",
            commit="deadbeef  2026-01-01, refreshed 2026-08-06",
            behind="0 revisions",
        )
    )
    (found,) = checker._entries_at_tip(text)[0]
    assert found.path == "tests/f.json"
    assert found.commit == "deadbeef"


def test_latest_commit_asks_for_one_commit_touching_the_path(
    checker: ModuleType, fake_gh: FakeGh
) -> None:
    """The one `gh api` call, and the sha and date it reads back."""
    fake_gh.commits["btclib-org/btclib", "tests/f.json"] = ("cafe1234", "2026-08-01")
    sha, date = checker._latest_commit("btclib-org/btclib", "tests/f.json")
    assert (sha, date) == ("cafe1234", "2026-08-01")
    (call,) = fake_gh.calls
    assert call[1:5] == ["api", "--method", "GET", "repos/btclib-org/btclib/commits"]
    assert "path=tests/f.json" in call
    assert "per_page=1" in call


def test_latest_commit_is_none_when_upstream_has_no_commit_for_the_path(
    checker: ModuleType, fake_gh: FakeGh
) -> None:
    """An empty answer is None, not an unpacking error.

    `repos/{repo}/commits?path=` answers `[]` with a 200 when upstream
    has no commit touching that path -- it was renamed, moved or deleted.
    Unpacking one commit out of that raised `ValueError`, which took
    `find_drift` down with it and left `report` unreached: a red run and
    no issue, on the one drift a vendored file nobody re-reads would
    otherwise hide.
    """
    fake_gh.commits["btclib-org/btclib", "tests/gone.json"] = None
    assert checker._latest_commit("btclib-org/btclib", "tests/gone.json") is None


def test_find_drift_reports_a_path_upstream_no_longer_has(
    checker: ModuleType, fake_gh: FakeGh, tmp_path: Path
) -> None:
    """A pin whose path is gone is drift, and says so rather than a tip."""
    path = tmp_path / "README.md"
    path.write_text(
        readme(
            entry(
                "`gone.json`",
                repo="r",
                path="gone.json",
                commit="old0000  2020-01-01",
                behind="0",
            )
        ),
        encoding="utf-8",
    )
    fake_gh.commits["r", "gone.json"] = None

    drifted, skipped = checker.find_drift(path)

    assert skipped == []
    (drift,) = drifted
    assert drift.path_is_gone
    assert (drift.latest_commit, drift.latest_date) == ("", "")

    body = checker._issue_body(path, drifted, [])
    assert "commit touching `gone.json` any more" in body
    assert "renamed, moved or deleted upstream" in body


@pytest.mark.parametrize("argv", [["prog"], ["prog", "a.md", "b.md"]])
def test_main_says_how_to_be_called_when_it_is_not(
    checker: ModuleType,
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No README, or two of them, is the usage rather than an IndexError.

    Only a human running this by hand reaches it -- the workflow passes
    the path every time -- and what they used to get was `IndexError:
    list index out of range` naming a list they never saw.
    """
    monkeypatch.setattr(sys, "argv", argv)

    assert checker.main() == 2

    captured = capsys.readouterr()
    # argv[0] is what names the program, so the fixture's own "prog" is
    # what comes back here rather than the script's file name
    assert captured.err == "usage: prog <README path> [--dry-run]\n"
    assert not captured.out


def test_main_says_gone_rather_than_behind_for_a_vanished_path(
    checker: ModuleType,
    fake_gh: FakeGh,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Stdout distinguishes a moved pin from one whose path is gone."""
    path = _write_readme(
        tmp_path,
        entry(
            "`gone.json`",
            repo="r",
            path="gone.json",
            commit="old0000  2020-01-01",
            behind="0",
        ),
    )
    fake_gh.commits["r", "gone.json"] = None
    monkeypatch.setattr(sys, "argv", ["prog", str(path), "--dry-run"])

    assert checker.main() == 0

    out = capsys.readouterr().out
    assert "GONE: `gone.json` pinned to old0000" in out
    assert "BEHIND" not in out


def test_find_drift_tells_moved_pins_from_still_current_ones(
    checker: ModuleType, fake_gh: FakeGh, tmp_path: Path
) -> None:
    """One pin drifted, one did not, and a `behind` pin is skipped too."""
    path = tmp_path / "README.md"
    path.write_text(
        readme(
            entry(
                "`moved.json`",
                repo="r",
                path="moved.json",
                commit="old0000  2020-01-01",
                behind="0",
            ),
            entry(
                "`still.json`",
                repo="r",
                path="still.json",
                commit="cur0000  2020-01-01",
                behind="0",
            ),
            entry("stale", repo="r", path="stale.json", commit="x", behind="1"),
        ),
        encoding="utf-8",
    )
    fake_gh.commits["r", "moved.json"] = ("new0000", "2026-01-01")
    fake_gh.commits["r", "still.json"] = ("cur0000", "2020-01-01")

    drifted, skipped = checker.find_drift(path)

    assert skipped == ["stale (already documented as behind)"]
    (drift,) = drifted
    assert drift.entry.heading == "`moved.json`"
    assert (drift.latest_commit, drift.latest_date) == ("new0000", "2026-01-01")


def _entry(checker: ModuleType, heading: str, commit: str = "old0000") -> object:
    return checker.Entry(heading, "r", "p.json", commit)


def test_the_issue_body_names_every_drift_and_every_skip(checker: ModuleType) -> None:
    """The body names the pinned and the new commit, and every skip."""
    drift = checker.Drift(_entry(checker, "`p.json`"), "new0000", "2026-01-01")
    body = checker._issue_body(Path("tests/_data/README.md"), [drift], ["skipped one"])
    assert "`p.json`" in body
    assert "`old0000" in body
    assert "`new0000` (2026-01-01)" in body
    assert "Not checked by this run" in body
    assert "- skipped one" in body


def test_the_issue_body_omits_the_skip_section_when_nothing_was_skipped(
    checker: ModuleType,
) -> None:
    """No skip list at all, rather than an empty one, when nothing skipped."""
    drift = checker.Drift(_entry(checker, "`p.json`"), "new0000", "2026-01-01")
    body = checker._issue_body(Path("README.md"), [drift], [])
    assert "Not checked by this run" not in body


def test_open_issue_number_reads_the_first_match(
    checker: ModuleType, fake_gh: FakeGh
) -> None:
    """The number of the first issue `gh issue list` names, as a string."""
    fake_gh.open_issue = 42
    assert checker._open_issue_number() == "42"


def test_open_issue_number_is_none_when_none_is_open(
    checker: ModuleType, fake_gh: FakeGh
) -> None:
    """An empty `gh issue list` is None, not an empty string."""
    assert checker._open_issue_number() is None


def test_report_closes_an_open_issue_when_nothing_drifted(
    checker: ModuleType, fake_gh: FakeGh, tmp_path: Path
) -> None:
    """Nothing drifted, an issue was open: it gets closed."""
    fake_gh.open_issue = 7
    checker.report(tmp_path / "README.md", [], [])
    verbs = [call[2] for call in fake_gh.calls if call[1] == "issue"]
    assert verbs == ["list", "close"]


def test_report_does_nothing_when_clean_and_no_issue_is_open(
    checker: ModuleType, fake_gh: FakeGh, tmp_path: Path
) -> None:
    """Nothing drifted, no issue was open: nothing is written."""
    checker.report(tmp_path / "README.md", [], [])
    assert [call[2] for call in fake_gh.calls] == ["list"]


def test_report_creates_an_issue_when_none_is_open(
    checker: ModuleType, fake_gh: FakeGh, tmp_path: Path
) -> None:
    """Something drifted, no issue was open: a new one is created."""
    drift = checker.Drift(_entry(checker, "`p.json`"), "new0000", "2026-01-01")
    checker.report(tmp_path / "README.md", [drift], [])
    verbs = [call[2] for call in fake_gh.calls if call[1] == "issue"]
    assert verbs == ["list", "create"]


def test_report_edits_the_open_issue(
    checker: ModuleType, fake_gh: FakeGh, tmp_path: Path
) -> None:
    """Something drifted, an issue was already open: it is edited, by number."""
    fake_gh.open_issue = 9
    drift = checker.Drift(_entry(checker, "`p.json`"), "new0000", "2026-01-01")
    checker.report(tmp_path / "README.md", [drift], [])
    verbs = [call[2] for call in fake_gh.calls if call[1] == "issue"]
    assert verbs == ["list", "edit"]
    (edit_call,) = (call for call in fake_gh.calls if call[2] == "edit")
    assert edit_call[3] == "9"


def _write_readme(tmp_path: Path, *blocks: str) -> Path:
    path = tmp_path / "README.md"
    path.write_text(readme(*blocks), encoding="utf-8")
    return path


def test_main_dry_run_prints_but_never_calls_issue(
    checker: ModuleType,
    fake_gh: FakeGh,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Prints drift and skips, and never touches an issue, on --dry-run."""
    path = _write_readme(
        tmp_path,
        entry(
            "`p.json`",
            repo="r",
            path="p.json",
            commit="old0000  2020-01-01",
            behind="0",
        ),
        entry("stale", repo="r", path="s.json", commit="x", behind="1"),
    )
    fake_gh.commits["r", "p.json"] = ("new0000", "2026-01-01")
    monkeypatch.setattr(sys, "argv", ["prog", str(path), "--dry-run"])

    assert checker.main() == 0

    out = capsys.readouterr().out
    assert "BEHIND: `p.json` pinned to old0000, tip is new0000 (2026-01-01)" in out
    assert "SKIPPED: stale (already documented as behind)" in out
    assert not any(call[1] == "issue" for call in fake_gh.calls)


def test_main_reports_and_says_nothing_drifted_when_clean(
    checker: ModuleType,
    fake_gh: FakeGh,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Clean and not a dry run: prints the all-clear and closes the issue."""
    path = _write_readme(
        tmp_path,
        entry(
            "`p.json`",
            repo="r",
            path="p.json",
            commit="old0000  2020-01-01",
            behind="0",
        ),
    )
    fake_gh.commits["r", "p.json"] = ("old0000", "2020-01-01")
    fake_gh.open_issue = 3
    monkeypatch.setattr(sys, "argv", ["prog", str(path)])

    assert checker.main() == 0

    out = capsys.readouterr().out
    assert "Every checked pin is still at upstream's tip." in out
    assert [call[2] for call in fake_gh.calls if call[1] == "issue"] == [
        "list",
        "close",
    ]


def test_the_main_guard_runs_the_script_as___main__(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cover `if __name__ == "__main__":` without a subprocess.

    A real subprocess -- what the mutation-counter test uses for its own
    end-to-end check -- runs in its own interpreter, and this project
    collects no coverage from one: `mutation_counts.py`'s own guard is
    exactly as uncovered today. `runpy.run_path` executes the file fresh
    with `__name__` set to `"__main__"` in this interpreter instead, so
    the guard itself is under test, not only the function it calls.
    """
    path = _write_readme(
        tmp_path,
        entry(
            "`p.json`",
            repo="r",
            path="p.json",
            commit="old0000  2020-01-01",
            behind="0",
        ),
    )
    fake = FakeGh()
    fake.commits["r", "p.json"] = ("old0000", "2020-01-01")
    monkeypatch.setattr(subprocess, "run", fake)
    monkeypatch.setattr(sys, "argv", ["prog", str(path), "--dry-run"])

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(_SCRIPT), run_name="__main__")

    assert excinfo.value.code == 0
    assert "Every checked pin is still at upstream's tip." in capsys.readouterr().out
