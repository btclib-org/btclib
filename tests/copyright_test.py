# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""LICENSE, __copyright__ and pyproject.toml's author, checked together.

Issue #389: LICENSE named "Ferdinando M. Ametrano and btclib contributors"
while __copyright__ had already moved to "The btclib developers", each
edited on its own with nothing to notice the other had not moved too.
docs/source/conf.py reads __copyright__ back by regex instead of
declaring a value of its own, which is why that one file never drifted;
LICENSE and pyproject.toml's `authors` are both static text with nothing
deriving either from the other, so a change to one is silent everywhere
else until something reads the same sources this reads.

The holder is what the three have in common, and the only thing: LICENSE
carries no year range, section 14 of the standard in btclib-org/.github
being where that is decided and why. So __copyright__ is the one place
the years are written, and there is no second copy of them for this to
hold in step -- what a year assertion here would compare it against is
itself.

Regex rather than `tomllib` for the one line wanted out of
pyproject.toml: the floor here is 3.10, and `tomllib` is 3.11 -- the same
reason `release.yml` gives for reaching for it only from a `python -` a
workflow can pin to a newer interpreter, which a module in this package
cannot. Once 3.10 is dropped, `_pyproject_author` can read the file the
way `release.yml` already does.

Issue #1507: `btclib.__author__`, `__author_email__` and `__license__`
each duplicated `pyproject.toml`'s `authors` table or `license` field
with nothing reading either copy, `__license__`'s own copy
("MIT License") not even a valid spelling of the SPDX expression
("MIT") it was a copy of. Unlike the holder above, each of the three has
exactly one other place stating the same fact, so there is nothing here
for a package-level literal to add: a caller after any of them reads the
installed distribution's own metadata instead, which cannot drift from
`pyproject.toml` the way a second literal can. So the three are gone
rather than added to the triangle, and the test below is what keeps
them from being silently redeclared.

Issue #1519: `docs/source/conf.py` declared its own Sphinx `author`
as a fourth literal naming the same holder, sitting beside
`project_copyright` two lines above it, which already reads
`__copyright__` back rather than repeating its years. `author` now
reads `pyproject.toml`'s `authors` table the same way, through the
`PYPROJECT` dict that file already parses for its own `release` and
`BLOB` -- a derivation rather than a fourth vertex to compare, since
unlike LICENSE and pyproject.toml above, `conf.py`'s copy has
nowhere it needs to diverge from the source it names. The test below
loads `conf.py` by path, the way it is not a package to import, and
checks the read rather than a value that can no longer drift on its
own.
"""

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import btclib

_ROOT = Path(__file__).parents[1]
_LICENSE_RE = r"Copyright \([Cc]\) (.+)"
_COPYRIGHT_RE = r"Copyright \([Cc]\) \d{4}-\d{4} (.+)"
_AUTHOR_RE = r'authors\s*=\s*\[\{\s*name\s*=\s*"([^"]+)"'


def _license_holder() -> str:
    text = (_ROOT / "LICENSE").read_text(encoding="utf-8")
    match = re.search(_LICENSE_RE, text)
    assert match, f"LICENSE has no 'Copyright (c) holder' line: {text[:80]!r}"
    return match.group(1)


def _copyright_holder() -> str:
    match = re.search(_COPYRIGHT_RE, btclib.__copyright__)
    assert match, (
        f"btclib.__copyright__ does not match the expected shape: {btclib.__copyright__!r}"
    )
    return match.group(1)


def _pyproject_author() -> str:
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(_AUTHOR_RE, text)
    assert match, "pyproject.toml has no 'authors = [{ name = ... }]' line"
    return match.group(1)


def _conf_module() -> ModuleType:
    """Load docs/source/conf.py by path: no package, so no import."""
    path = _ROOT / "docs" / "source" / "conf.py"
    spec = importlib.util.spec_from_file_location("conf", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_license_and_copyright_name_the_same_holder() -> None:
    """The two places a human edits a holder must edit it together."""
    license_holder = _license_holder()
    copyright_holder = _copyright_holder()
    assert license_holder == copyright_holder, (
        f"LICENSE says {license_holder!r}, btclib.__copyright__ says "
        f"{copyright_holder!r}. Edit both together, or make one read the "
        "other -- docs/source/conf.py already does, for its own copyright "
        "line"
    )


def test_license_holder_matches_the_declared_author() -> None:
    """The wheel's `Author` metadata is the same holder LICENSE names."""
    license_holder = _license_holder()
    author = _pyproject_author()
    assert license_holder == author, (
        f"LICENSE names {license_holder!r}, pyproject.toml's author "
        f"{author!r}. A wheel built from one and read from the other "
        "would disagree about who holds the copyright"
    )


def test_no_duplicate_author_or_license_dunders() -> None:
    """`__author__`, `__author_email__` and `__license__` stay gone.

    Each duplicated a fact `pyproject.toml` already states -- its
    `authors` table or its `license` field -- and nothing read the copy
    kept here (issue #1507). Re-adding one reopens exactly the drift this
    file exists to catch for the copyright holder, this time with no test
    watching it.
    """
    for dunder in ("__author__", "__author_email__", "__license__"):
        assert not hasattr(btclib, dunder), (
            f"btclib.{dunder} exists again; pyproject.toml already states "
            "the fact it would duplicate, and nothing in the tree reads it "
            "(issue #1507)"
        )


def test_conf_py_author_reads_pyproject_rather_than_repeating_it() -> None:
    """Sphinx's `author` is `pyproject.toml`'s, read back, not retyped."""
    conf_author = _conf_module().author
    pyproject_author = _pyproject_author()
    assert conf_author == pyproject_author, (
        f"docs/source/conf.py's author is {conf_author!r}, pyproject.toml's "
        f"is {pyproject_author!r}. conf.py reads pyproject.toml's `authors` "
        "table for this value (issue #1519); if the two differ here the "
        "read itself, not a stale literal, is what to look at"
    )
