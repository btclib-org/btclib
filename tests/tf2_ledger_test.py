# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `TF2.md` must say about Core's test framework, and must not.

The ledger is one entry per Python file of Core's
`test/functional/test_framework/`, and its whole value is that the
entries can be re-checked. Two things rot such a record and neither is
loud: an upstream file with no entry, and an entry whose btclib side has
been renamed out from under it.

The shape here is `tests/p2p/core_commands_test.py`'s, for the same
reasons that module gives at length: Core's set is transcribed rather
than fetched, so the verdict does not depend on somebody else's uptime,
and the census is asserted in both directions, so a file gained upstream
and an entry that has outlived its subject each land on a different
assertion. `test_both_sides_of_the_census_were_read` is the guard
against the failure that would otherwise make every comparison below
pass for free -- a regex reworded past the text it reads answers with an
empty set, and an empty set is a subset of everything.

The entry's own grammar is not re-implemented here. It is
`.github/scripts/check_vendored_vectors.py`'s, and that script is loaded
by path and asked to parse `TF2.md`: a heading whose fenced block that
parser skips is a heading the weekly re-check would silently never look
at, which is exactly the drift the ledger exists to prevent. Loading it
that way is `tests/check_vendored_vectors_test.py`'s idiom,
`.github/scripts` being no package, and it is why `pyproject.toml`
excludes this module from the sdist: the script is not shipped, so from
an unpacked sdist this would be a fixture error rather than a test.

What none of it can see is upstream. Whether the pinned commit is still
the tip of its path is a network question, and the whole point of a pin
is that answering it is somebody's weekly job rather than a condition of
every test run. What is offline is that every upstream file has an
entry, that every entry is one the re-checker can put that question to,
that every btclib path an entry names is a file this tree has, and that
no entry states a count.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).parents[1]
_LEDGER = _ROOT / "TF2.md"
_CHECKER = _ROOT / ".github" / "scripts" / "check_vendored_vectors.py"

_UPSTREAM = "test/functional/test_framework"

# every Python file of that directory at the commit the entries pin,
# transcribed in the order `git/trees?recursive=1` lists them. A refresh
# of the ledger is a diff over this tuple.
_CORE_FILES = (
    "__init__.py",
    "address.py",
    "authproxy.py",
    "blockfilter.py",
    "blocktools.py",
    "compressor.py",
    "coverage.py",
    "crypto/bip324_cipher.py",
    "crypto/chacha20.py",
    "crypto/ellswift.py",
    "crypto/hkdf.py",
    "crypto/muhash.py",
    "crypto/poly1305.py",
    "crypto/ripemd160.py",
    "crypto/secp256k1.py",
    "crypto/siphash.py",
    "descriptors.py",
    "extendedkey.py",
    "ipc_util.py",
    "key.py",
    "mempool_util.py",
    "messages.py",
    "netutil.py",
    "p2p.py",
    "psbt.py",
    "script.py",
    "script_util.py",
    "segwit_addr.py",
    "socks5.py",
    "test_framework.py",
    "test_node.py",
    "test_shell.py",
    "util.py",
    "v2_p2p.py",
    "wallet.py",
    "wallet_util.py",
)

# the verdicts `TF2.md`'s own "The verdicts" section defines. A closed
# vocabulary rather than free text: a verdict spelled some other way is
# a row nobody can group with the rows it belongs with, and a verdict
# defined and never used is a definition that has outlived its subject
_VERDICTS = frozenset(
    {
        "covered",
        "covered in part",
        "vendored",
        "tf2's by decision",
        "tf2's (harness)",
        "empty upstream",
    }
)

# an entry's heading, which is the file's path in Core
_HEADING = re.compile(rf"^### `({_UPSTREAM}/[^`]+)`$", re.MULTILINE)

# the verdict opening the prose under a fenced block; what follows the
# closing asterisks is the entry's own argument and is not read here
_VERDICT = re.compile(r"^Verdict: \*\*([^*]+)\*\*", re.MULTILINE)

# a path in a backtick span, which is how the prose names both Core's
# files and this tree's. A trailing `.py` is what tells a path from the
# module attributes and class names the same spans also carry
_PATH = re.compile(r"`([\w./-]+\.py)`")

# a digit run, or a spelled-out cardinal as a whole word. "one" and
# "zero" are matched as digits only, never as words: in prose they are
# articles and pronouns far more often than counts, which is
# `tests/vendored_data_test.py`'s reading of the same rule
_NUMERAL = re.compile(
    r"(?i)\b(?:\d+|two|three|four|five|six|seven|eight|nine|ten|eleven|"
    r"twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|"
    r"nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|"
    r"hundred|thousand)\b"
)

# the numerals that name something rather than count it, subtracted
# before `_NUMERAL` runs: an ISO date, a specification as the bips and
# slips repositories spell one in a path, an RFC, an issue of this
# tracker in either form the prose uses, and the variant number a
# hyphen introduces after a name (RIPEMD-160). A specification spelled
# without the hyphen needs no entry, `BIP340` offering no word boundary
# in front of its digits
_NOT_A_COUNT = re.compile(
    r"\b\d{4}-\d{2}(?:-\d{2})?\b"
    r"|(?i:\b(?:bip|slip)-\d+)"
    r"|\bRFC \d+"
    r"|(?i:\bissues?[ /]#?\d+)|\bISS \d+"
    r"|(?<=[A-Za-z]-)\d+(?:-\d+)*"
)

_TEXT = _LEDGER.read_text(encoding="utf-8")
_ENTRIES = tuple(_HEADING.findall(_TEXT))
_VERDICTS_READ = tuple(_VERDICT.findall(_TEXT))


def _prose_lines() -> list[str]:
    """Every line of the ledger outside a fenced block.

    A fence holds either the pin fields, whose `commit` and `behind` are
    facts of a pin that "Reading an entry" already defines, or a shell
    command, where a digit is an argument. Neither is prose stating a
    count, and scanning them would say so once per entry.
    """
    lines = []
    in_fence = False
    for line in _TEXT.split("\n"):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)
    return lines


@pytest.fixture
def checker(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Return the weekly re-checker, imported by path.

    Registered in `sys.modules` before it runs, its `Entry` and `Drift`
    dataclasses resolving their field types through the module name
    under `from __future__ import annotations`. That is
    `tests/check_vendored_vectors_test.py`'s own fixture, and the
    duplication is deliberate: this module asks the script one question
    about a different file, and importing a fixture out of a test module
    of another subject would tie the two together for no other reason.
    """
    spec = importlib.util.spec_from_file_location("check_vendored_vectors", _CHECKER)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "check_vendored_vectors", module)
    spec.loader.exec_module(module)
    return module


def test_both_sides_of_the_census_were_read() -> None:
    """A comparison over a side that came up empty is true of nothing.

    Every assertion below subtracts one set from another, and each of
    them passes for free where the set being subtracted from is empty.
    The ledger's side is read by a regex, which answers empty for a
    heading spelled some other way; Core's side is a literal tuple,
    which cannot be empty but can hold a path twice, in which case the
    two censuses disagree about a file neither reports.
    """
    assert _ENTRIES, "no entry heading was found in TF2.md at all"
    assert len(set(_ENTRIES)) == len(_ENTRIES), (
        f"a file has more than one entry: {sorted(_ENTRIES)}"
    )
    assert len(set(_CORE_FILES)) == len(_CORE_FILES), (
        f"a Core file is transcribed twice: {sorted(_CORE_FILES)}"
    )
    assert len(_VERDICTS_READ) == len(_ENTRIES), (
        f"{len(_ENTRIES)} entries carry {len(_VERDICTS_READ)} verdicts"
    )


def test_every_core_file_has_an_entry() -> None:
    """The census: a file of Core's directory is answered for."""
    entries = {path.removeprefix(f"{_UPSTREAM}/") for path in _ENTRIES}
    missing = sorted(set(_CORE_FILES) - entries)
    assert not missing, f"no entry in TF2.md for: {missing}"


def test_every_entry_names_a_core_file() -> None:
    """The other direction, which is where a deleted file lands.

    A file upstream renames or removes leaves an entry describing
    something that is not there, and the entry goes on reading as a
    statement about Core. The transcription above is what the entry is
    held to; refreshing one means refreshing both.
    """
    entries = {path.removeprefix(f"{_UPSTREAM}/") for path in _ENTRIES}
    unaccounted = sorted(entries - set(_CORE_FILES))
    assert not unaccounted, f"an entry names no transcribed Core file: {unaccounted}"


def test_every_verdict_is_one_of_the_defined_ones() -> None:
    """A verdict is from the closed vocabulary the ledger defines."""
    unknown = sorted({v for v in _VERDICTS_READ if v not in _VERDICTS})
    assert not unknown, f"a verdict TF2.md does not define: {unknown}"


def test_every_defined_verdict_is_used() -> None:
    """A definition nothing uses is a definition nothing holds to.

    The mirror of the assertion above, and the one that catches a
    verdict whose last entry was rewritten: the definition survives, is
    read as describing part of the ledger, and describes nothing.
    """
    unused = sorted(_VERDICTS - set(_VERDICTS_READ))
    assert not unused, f"TF2.md defines a verdict no entry carries: {unused}"


def _unresolved(paths: Iterable[str]) -> list[str]:
    """Return the paths that name no file, in either of the two ways.

    A path is written the way this tree writes one: relative to
    `src/btclib` for the package's own modules, and from the root for
    anything else. Core's own paths are recognized by their prefix and
    held to the transcription above rather than to this checkout, there
    being no checkout of Core here to hold them to.

    A function rather than a loop inside the assertion below, so that
    `test_the_resolution_reports_a_path_that_is_not_there` can drive
    both of its answers: on a ledger that is right this reports nothing,
    and a branch no green run crosses is a branch the coverage floor
    fails on.
    """
    missing = []
    for path in sorted(set(paths)):
        if path.startswith(f"{_UPSTREAM}/"):
            if path.removeprefix(f"{_UPSTREAM}/") not in _CORE_FILES:
                missing.append(path)
            continue
        root = (
            _ROOT
            if path.split("/")[0] in {"tests", "src", ".github"}
            else _ROOT / "src" / "btclib"
        )
        if not (root / path).is_file():
            missing.append(path)
    return missing


def test_every_btclib_path_an_entry_names_exists() -> None:
    """A module renamed out from under an entry is the quiet rot."""
    missing = _unresolved(_PATH.findall(_TEXT))
    assert not missing, f"TF2.md names a path this tree does not have: {missing}"


def test_the_resolution_reports_a_path_that_is_not_there() -> None:
    """The guard above passes for free if nothing can be unresolved.

    One wrong path of each shape the ledger writes, beside the right one
    it was made from: a package module, a path from the root, and a
    Core path the transcription does not carry.
    """
    assert _unresolved(("block/build.py", "tests/block/build_test.py")) == []
    assert _unresolved(("block/built.py",)) == ["block/built.py"]
    assert _unresolved(("tests/block/built_test.py",)) == ["tests/block/built_test.py"]
    gone = f"{_UPSTREAM}/blocktoolz.py"
    assert _unresolved((gone,)) == [gone]


def test_the_path_pattern_still_matches() -> None:
    """The guard above passes for free if `_PATH` matches nothing.

    Both shapes the ledger writes, and one that must not be read as a
    path: a module attribute is a dotted name in a backtick span too,
    and reading `kdf.hkdf` as a file would make the assertion above red
    for a reason that is not a renamed module.
    """
    assert _PATH.findall("`block/build.py` and `tests/block/build_test.py`") == [
        "block/build.py",
        "tests/block/build_test.py",
    ]
    assert not _PATH.findall("`kdf.hkdf` and `hashes.siphash`")


def test_no_entry_states_a_count() -> None:
    """Enforces CLAUDE.md's "Never state how many of anything a file holds".

    The rule `tests/vendored_data_test.py` enforces on
    `tests/_data/README.md`, applied here with no allowlist beside it: a
    count of the entries, of the covered files or of the uncovered ones
    is exactly the number that is exact today, wrong after the next
    upstream commit, and plausible throughout. Nothing in this ledger
    needs one, the entries being the fact such a number would summarize.

    CLAUDE.md's own exception -- a count of what upstream published --
    has no instance here either, and that is a decision rather than an
    accident: a line count or a function count of a Core file measures
    upstream honestly and still has to be refreshed with the pin, so an
    entry states what the file is instead of how big it is.
    """
    offenders = sorted(
        {
            line
            for line in _prose_lines()
            if _NUMERAL.search(_NOT_A_COUNT.sub(" ", line))
        }
    )
    assert not offenders, f"TF2.md states a numeral that is not exempt: {offenders}"


def test_the_numeral_pattern_still_matches() -> None:
    """The guard above passes for free if `_NUMERAL` matches nothing.

    The failure mode of every assertion written in the negative, and the
    one the file it reads cannot reveal. The strings below are the
    shapes a count of this ledger would take.
    """
    for text in (
        "The ledger has 36 entries.",
        "Thirty-six files, of which twelve are tf2's.",
        "- 7 files here",
        "Nine of them are the harness.",
    ):
        assert _NUMERAL.search(_NOT_A_COUNT.sub(" ", text)), text


def test_a_numeral_that_names_something_is_subtracted() -> None:
    """`_NOT_A_COUNT` fails in two directions and one of them is quiet.

    A shape that stops matching puts its line back in front of
    `_NUMERAL`, and the guard above says which line. A shape reaching
    past what it names swallows a count beside it and nothing says so,
    which is what the second group is for: each of those states a count
    *and* carries something the subtraction takes out.
    """
    for named in (
        "commit  0f206eed51e2d00aa78f709ecc427b484d04b4d5  2026-09-05",
        "vectors of `bip-0327/vectors/`, vendored whole",
        "`tests/kdf_test.py` runs RFC 5869's own vectors",
        "[ISS 1120](https://github.com/btclib-org/btclib/issues/1120) is where",
        "`hashlib` offers no RIPEMD-160; its docstring carries",
        "secp256k1 alone, over BIP340's own vectors and MuHash3072",
    ):
        assert not _NUMERAL.search(_NOT_A_COUNT.sub(" ", named)), named
    for counted in (
        "Six entries were read at 2026-09-05.",
        "ISS 1120 left three of them out.",
    ):
        assert _NUMERAL.search(_NOT_A_COUNT.sub(" ", counted)), counted


def test_the_weekly_re_checker_reads_every_entry(checker: ModuleType) -> None:
    """Every entry is one the re-checker can ask upstream about.

    The grammar is that script's, so this is what says the ledger is in
    it: an entry whose fenced block lacks `repo`, `path` or `commit`, or
    whose `behind` does not read zero, is skipped by the script and
    would be skipped in silence once the ledger is wired into the weekly
    run. Wiring it is a change owed to btclib-secp256k1's copy of the
    script as well, and is not this file's; being parseable is.
    """
    entries, skipped = checker._entries_at_tip(_TEXT)
    assert not skipped, f"the re-checker would skip: {skipped}"
    assert [entry.heading for entry in entries] == [f"`{path}`" for path in _ENTRIES], (
        "the re-checker reads other headings than the ledger's own"
    )
    assert all(entry.repo == "bitcoin/bitcoin" for entry in entries)
    assert all(entry.path == entry.heading.strip("`") for entry in entries), (
        "an entry's `path` field and its heading name different files"
    )
    assert all(re.fullmatch(r"[0-9a-f]{40}", entry.commit) for entry in entries), (
        "a pin is not a full commit sha"
    )
