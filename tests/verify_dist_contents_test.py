# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the distribution-content check of `.github/scripts`.

What CI can show is that a real build passes: the `dist` job of test.yml
runs the script on every pull request, and the same job -- reached
through release.yml's `test` call -- on the files it is about to
publish. What CI cannot show is that anything
*fails* -- a wheel with a shared object in it is not something a workflow
can produce on purpose -- so the archives here are synthetic, one member
planted per rule, and the assertion is the complaint.

The last two tests here ask a different question: whether
`docs/source/package-content-policy.md` states the same policy. A page
beside a script is a second copy of one list, and two copies are one that
can be wrong -- the page saying `.so` is forbidden while the script's
tuple says otherwise, with nothing to notice. Those two compare the page
against the script's own constants in both directions, which is what
makes the second copy safe rather than merely tidy.

The script is loaded by path, `.github/scripts` being no package, as the
mutation-counter and vendored-vector tests do. It has no dataclass, so
registering the module before `exec_module` is not needed here.
"""

from __future__ import annotations

import importlib.util
import io
import re
import runpy
import sys
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "verify_dist_contents.py"
_PAGE = Path(__file__).parents[1] / "docs" / "source" / "package-content-policy.md"

_VERSION = "1.0"
_ROOT = f"btclib-{_VERSION}"
_DIST_INFO = f"btclib-{_VERSION}.dist-info"

# the smallest pair that passes: the package, one data file, the metadata
# the backend writes, and the licences it copies. Normalized names -- the
# wheel installs the package flattened to btclib/, and _sdist_path below
# is what places the same names under the sdist's own src/btclib/
_PAYLOAD = ("btclib/__init__.py", "btclib/py.typed", "btclib/_data/mainnet.json")
_WHEEL_MEMBERS = (
    *_PAYLOAD,
    f"{_DIST_INFO}/METADATA",
    f"{_DIST_INFO}/RECORD",
    f"{_DIST_INFO}/WHEEL",
    f"{_DIST_INFO}/licenses/LICENSE",
)
_SDIST_MEMBERS = (
    *_PAYLOAD,
    "PKG-INFO",
    "pyproject.toml",
    "pyproject.toml.orig",
    "README.md",
    "uv.lock",
    ".python-version",
    "docs/index.rst",
    "tests/btclib_test.py",
)
_SDIST_DIRECTORIES = ("src", "src/btclib", "src/btclib/_data", "docs", "tests")


def _sdist_path(name: str) -> str:
    """Map a normalized payload name to its place in the sdist, under src/."""
    return f"src/{name}" if name.startswith("btclib/") else name


@pytest.fixture
def script() -> ModuleType:
    """Return the script, imported by path."""
    spec = importlib.util.spec_from_file_location("verify_dist_contents", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_wheel(
    directory: Path,
    *,
    extra: tuple[str, ...] = (),
    omit: tuple[str, ...] = (),
    version: str = _VERSION,
) -> Path:
    """Write a wheel carrying the default members, plus and minus these."""
    path = directory / f"btclib-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for name in (*(m for m in _WHEEL_MEMBERS if m not in omit), *extra):
            archive.writestr(name, "content")
    return path


def write_sdist(
    directory: Path,
    *,
    extra: tuple[str, ...] = (),
    omit: tuple[str, ...] = (),
    raw: tuple[str, ...] = (),
    specials: tuple[tarfile.TarInfo, ...] = (),
) -> Path:
    """Write an sdist: the default members, plus and minus, raw, special.

    `extra` and `omit` name members relative to the archive's own root
    directory, `raw` names them verbatim -- which is how a member outside
    that root is planted -- and `specials` are `TarInfo` objects passed
    through, for the member types a tar can carry and a zip cannot.
    """
    path = directory / f"{_ROOT}.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name in ("", *(f"/{d}" for d in _SDIST_DIRECTORIES)):
            info = tarfile.TarInfo(f"{_ROOT}{name}")
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        names = (
            *(f"{_ROOT}/{_sdist_path(m)}" for m in _SDIST_MEMBERS if m not in omit),
            *(f"{_ROOT}/{_sdist_path(m)}" for m in extra),
            *raw,
        )
        for name in names:
            info = tarfile.TarInfo(name)
            info.size = len(b"content")
            archive.addfile(info, io.BytesIO(b"content"))
        for info in specials:
            archive.addfile(info)
    return path


def one_complaint(script: ModuleType, directory: Path) -> str:
    """Verify the directory, asserting there is exactly one complaint."""
    (complaint,) = script.verify(directory)
    return str(complaint)


def test_a_clean_pair_passes(
    script: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Nothing to complain about, and the payload is reported once."""
    write_wheel(tmp_path)
    write_sdist(tmp_path)

    assert script.verify(tmp_path) == []

    out = capsys.readouterr().out
    assert "carry what they may and no more" in out
    assert f"one payload of {len(_PAYLOAD)} files, in both" in out


@pytest.mark.parametrize(
    "member, expected",
    [
        # the limit of the `_data/` amnesty, which admits by directory and
        # not by extension
        ("btclib/_data/libsecp256k1.so", "carries the forbidden suffix .so"),
        ("btclib/_data/vectors.tar.gz", "carries the forbidden suffix .tar.gz"),
        ("btclib/sitecustomize.py", "is sitecustomize.py, which Python imports"),
        ("btclib/usercustomize.py", "is usercustomize.py, which Python imports"),
        (
            "btclib/__pycache__/utils.cpython-314.pyc",
            "carries the forbidden suffix .pyc",
        ),
        # a `.py` the allowlist would otherwise take, in the one place a
        # wheel must not put one
        ("stray.py", "is neither package code nor package metadata"),
        ("btclib/curves/notes.rst", "is neither Python source nor a _data file"),
        (f"{_DIST_INFO}/entry_points.txt", "is not one of its files"),
        (f"{_DIST_INFO}/nested/METADATA", "is not one of its files"),
    ],
)
def test_a_planted_wheel_member_is_named(
    script: ModuleType, tmp_path: Path, member: str, expected: str
) -> None:
    """One member per rule, and the complaint says which rule it broke."""
    write_wheel(tmp_path, extra=(member,))
    write_sdist(tmp_path)

    complaints = script.verify(tmp_path)

    assert any(expected in complaint for complaint in complaints)


@pytest.mark.parametrize(
    "member", ["btclib/py.typed", "btclib/__init__.py", f"{_DIST_INFO}/RECORD"]
)
def test_a_missing_wheel_member_is_named(
    script: ModuleType, tmp_path: Path, member: str
) -> None:
    """PEP 561's marker, the package itself and the metadata are required.

    Each is absent in a way that installs and imports cleanly: a wheel
    with no `py.typed` type checks as `Any`, and one with no metadata
    reports `btclib.__version__` as "unknown" (issue #150).
    """
    write_wheel(tmp_path, omit=(member,))
    write_sdist(tmp_path, omit=(member,))

    complaints = script.verify(tmp_path)

    assert any(f"{member} is missing" in complaint for complaint in complaints)


@pytest.mark.parametrize(
    "extra, omit, raw, expected",
    [
        ((".editorconfig",), (), (), "is a root file the sdist does not ship"),
        (
            ("examples/demo.py",),
            (),
            (),
            "is not under one of the directories the sdist ships",
        ),
        (
            ("tests/vendored.dist-info/METADATA",),
            (),
            (),
            "holds the metadata of another distribution",
        ),
        # the project's own name buys nothing: no egg-info is written
        # into the sdist any more, so any is a leftover
        (
            ("btclib.egg-info/PKG-INFO",),
            (),
            (),
            "holds the metadata of another distribution",
        ),
        (("tests/_data/wheel.whl",), (), (), "carries the forbidden suffix .whl"),
        ((), (), ("elsewhere/setup.py",), "is outside the archive's own"),
        ((), (), (f"{_ROOT}/../escape.py",), "is not a relative path"),
        ((), (), ("/etc/passwd",), "is not a relative path"),
        ((), ("PKG-INFO",), (), "PKG-INFO is missing"),
        ((), ("pyproject.toml",), (), "pyproject.toml is missing"),
    ],
)
def test_a_planted_sdist_member_is_named(
    script: ModuleType,
    tmp_path: Path,
    extra: tuple[str, ...],
    omit: tuple[str, ...],
    raw: tuple[str, ...],
    expected: str,
) -> None:
    """One member per structural rule, and the complaint names the rule."""
    # the wheel omits what the sdist omits, so that the two payloads still
    # agree and the complaint under test is the only one
    write_wheel(tmp_path, omit=omit)
    write_sdist(tmp_path, extra=extra, omit=omit, raw=raw)

    complaints = script.verify(tmp_path)

    assert any(expected in complaint for complaint in complaints)


@pytest.mark.parametrize(
    "directory, expected",
    [
        ("examples", "is a directory the sdist does not ship"),
        # the one case the forbidden suffixes do not reach: an empty
        # bytecode directory is a directory member and no `.pyc`
        ("src/btclib/__pycache__", "is under __pycache__"),
    ],
)
def test_a_directory_member_is_judged_too(
    script: ModuleType, tmp_path: Path, directory: str, expected: str
) -> None:
    """A directory with no file under it is a member in its own right."""
    info = tarfile.TarInfo(f"{_ROOT}/{directory}")
    info.type = tarfile.DIRTYPE
    write_wheel(tmp_path)
    write_sdist(tmp_path, specials=(info,))

    complaints = script.verify(tmp_path)

    assert any(expected in complaint for complaint in complaints)


def test_a_member_that_is_not_a_file_or_a_directory_is_named(
    script: ModuleType, tmp_path: Path
) -> None:
    """A symlink is a member type a tar can carry and a zip cannot.

    Which is the whole reason the sdist is checked for it and the wheel is
    not: what a symlink in an sdist points at is decided when it is
    unpacked, so it is the one member whose content is not in the archive.
    """
    info = tarfile.TarInfo(f"{_ROOT}/tests/link.py")
    info.type = tarfile.SYMTYPE
    info.linkname = "../../../etc/passwd"
    write_wheel(tmp_path)
    write_sdist(tmp_path, specials=(info,))

    complaints = script.verify(tmp_path)

    assert any("is neither a regular file nor a directory" in c for c in complaints)


def test_a_payload_the_wheel_drops_is_named(script: ModuleType, tmp_path: Path) -> None:
    """A data file in the sdist and not in the wheel, which is issue #393."""
    write_wheel(tmp_path)
    write_sdist(tmp_path, extra=("btclib/_data/testnet.json",))

    assert "ships btclib/_data/testnet.json" in one_complaint(script, tmp_path)


def test_a_payload_only_the_wheel_has_is_named(
    script: ModuleType, tmp_path: Path
) -> None:
    """And the other direction: a file the sdist, hence the tree, lacks."""
    write_wheel(tmp_path, extra=("btclib/_data/testnet.json",))
    write_sdist(tmp_path)

    assert "ships btclib/_data/testnet.json" in one_complaint(script, tmp_path)


def test_a_directory_entry_in_the_wheel_is_not_a_member(
    script: ModuleType, tmp_path: Path
) -> None:
    """A zip may carry an entry per directory; the files are the policy."""
    write_wheel(tmp_path, extra=("btclib/curves/",))
    write_sdist(tmp_path)

    assert script.verify(tmp_path) == []


@pytest.mark.parametrize("pattern", ["*.whl", "*.tar.gz"])
def test_no_artifact_of_a_kind_is_named(
    script: ModuleType, tmp_path: Path, pattern: str
) -> None:
    """A dist directory with only one of the two is not half checked."""
    if pattern == "*.tar.gz":
        write_wheel(tmp_path)
    else:
        write_sdist(tmp_path)

    assert f"expected one {pattern}, found none" in one_complaint(script, tmp_path)


def test_a_second_artifact_of_a_kind_is_named(
    script: ModuleType, tmp_path: Path
) -> None:
    """Two wheels are refused rather than the newer one being picked.

    A stale artifact from an earlier build in the same directory is
    precisely what a check on the files about to be published must not
    skip over -- and it is the file the *other* one that gets uploaded.
    """
    write_wheel(tmp_path)
    write_wheel(tmp_path, version="0.9")
    write_sdist(tmp_path)

    complaints = script.verify(tmp_path)

    assert any("expected one *.whl, found" in complaint for complaint in complaints)


def test_main_says_how_to_be_called_when_it_is_not(
    script: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    """No dist directory, or two of them, is the usage rather than a crash."""
    assert script.main(["prog"]) == 2
    assert capsys.readouterr().err == "usage: prog <dist directory>\n"


def test_main_annotates_every_complaint_and_fails(
    script: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Each complaint is a workflow annotation, so the run summary has it."""
    write_wheel(tmp_path, extra=("stray.py",))
    write_sdist(tmp_path, extra=(".editorconfig",))

    assert script.main(["prog", str(tmp_path)]) == 1

    err = capsys.readouterr().err
    assert "::error::" in err
    assert err.count("::error::") == 2


def test_main_passes_on_a_clean_pair(script: ModuleType, tmp_path: Path) -> None:
    """The exit code a green workflow step reads."""
    write_wheel(tmp_path)
    write_sdist(tmp_path)

    assert script.main(["prog", str(tmp_path)]) == 0


# a code span holding the name of one of the script's constants: upper
# case with an underscore in it, which no member name and no suffix is --
# `METADATA` and `PKG-INFO` are values the page states, not names of
# lists, and this is what tells the two apart
_CONSTANT = re.compile(r"`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`")
_CODE_SPAN = re.compile(r"`([^`]+)`")
# what separates a rule from the reason for it, in a list item of the
# page. An em dash, spaced: the reason is prose and names whatever it
# needs to in code spans of its own, so a rule has to end somewhere
_REASON = " \N{EM DASH} "


def _rules(text: str) -> list[tuple[set[str], set[str]]]:
    """Pair every rule list of the page with the constants above it.

    A list states the constants its introducing paragraph names, and a
    list introduced by a paragraph naming none -- the policy items no
    check enforces, at the bottom of the page -- is not a rule list and
    is skipped. Each item contributes the code spans before its dash.
    """
    rules: list[tuple[set[str], set[str]]] = []
    # the paragraph being read, and the last one that ended: a list is
    # introduced by the paragraph before the blank line above it
    paragraph: list[str] = []
    lead: list[str] = []
    items: list[str] = []
    # the empty line is the flush: a list ending at the last line of the
    # file would otherwise be the one nothing compares
    for line in (*text.splitlines(), ""):
        if line.startswith("- "):
            items.append(line[2:])
        elif items and line.startswith("  "):
            items[-1] += " " + line.strip()
        elif items:
            named = set(_CONSTANT.findall(" ".join(lead)))
            if named:
                rules.append((named, _stated(items)))
            items, lead = [], []
        elif line.strip():
            paragraph.append(line)
        # `no branch`: a blank line with nothing pending would take the
        # other way out, and the markdown read here has none -- MD012
        # refuses two blank lines in a row, and the flush above is what
        # every list ends on
        elif paragraph:  # pragma: no branch
            lead, paragraph = paragraph, []
    return rules


def _stated(items: list[str]) -> set[str]:
    """Every member name and suffix a rule list states."""
    spans: set[str] = set()
    for item in items:
        rule, dash, _ = item.partition(_REASON)
        assert dash, f"a rule with no reason after it: {item}"
        spans.update(_CODE_SPAN.findall(rule))
    return spans


def _policy_constants(
    script: ModuleType,
) -> dict[str, tuple[str, ...] | frozenset[str]]:
    """Every constant of the script that is a list of members.

    Read off the module rather than named here: a rule added to the
    script is then one the page has to state before the test below
    passes, which is the direction a hand-written inventory would miss.
    """
    return {
        name: value
        for name, value in vars(script).items()
        if name.isupper() and isinstance(value, (tuple, frozenset))
    }


def test_the_page_states_what_the_script_enforces(script: ModuleType) -> None:
    """Every rule list on the page is its constants, exactly."""
    constants = _policy_constants(script)

    for named, stated in _rules(_PAGE.read_text(encoding="utf-8")):
        expected = {value for name in named for value in constants.get(name, ())}
        assert stated == expected, sorted(named)


def test_the_page_states_every_rule_the_script_has(script: ModuleType) -> None:
    """And no constant is left off the page, or stated twice."""
    named = [
        name for names, _ in _rules(_PAGE.read_text(encoding="utf-8")) for name in names
    ]

    assert sorted(named) == sorted(_policy_constants(script))


def test_the_main_guard_runs_the_script_as___main__(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cover `if __name__ == "__main__":` without a subprocess.

    This project collects no coverage from a child interpreter, so a real
    subprocess would leave the guard as uncovered as it is in
    `mutation_counts.py`. `runpy.run_path` executes the file fresh with
    `__name__` set to `"__main__"` in this one.
    """
    write_wheel(tmp_path)
    write_sdist(tmp_path)
    monkeypatch.setattr(sys, "argv", ["prog", str(tmp_path)])

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(_SCRIPT), run_name="__main__")

    assert excinfo.value.code == 0
