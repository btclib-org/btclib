#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Every module btclib ships is documented.

The pages under `docs/source/` are hand written, and `docs/README.rst`
used to answer the drift that invites by telling contributors to re-run
`sphinx-apidoc -f` whenever modules change. Nobody did, for good reason:
`-f` regenerates every page from the template, discarding the hand-tuned
index and the myst links to the markdown files. `btclib.descriptors` was
the cost -- the one top-level module absent from the automodule
directives, and therefore from the published documentation, with nothing
anywhere to say so.

A test rather than a workflow step. It needs no environment the suite does
not already have, it runs on every interpreter of the matrix instead of on
one runner, and `tests-passed` gates it without a line being added to any
`needs` list.
"""

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]
_PACKAGE_DIR = _ROOT / "btclib"
_DOCS_DIR = _ROOT / "docs" / "source"

# what a documented module looks like to sphinx: ".. automodule:: name",
# whatever indentation and options follow it
_AUTOMODULE = re.compile(r"^\s*\.\.\s+automodule::\s+(\S+)\s*$", re.MULTILINE)
# and what a documented subpackage looks like: a line of the toctree in
# btclib.rst, which names the per-package page rather than a module
_TOCTREE_ENTRY = re.compile(r"^\s{3}(btclib\.\S+)\s*$", re.MULTILINE)


def _documented() -> set[str]:
    """Every dotted name the documentation sources mention."""
    names: set[str] = set()
    for page in _DOCS_DIR.glob("*.rst"):
        text = page.read_text(encoding="utf-8")
        names.update(_AUTOMODULE.findall(text))
        names.update(_TOCTREE_ENTRY.findall(text))
    return names


def _is_public(parts: tuple[str, ...]) -> bool:
    """Whether a module path names something a user is meant to import.

    `__init__` is the package itself and not a private name, which is the
    only reason this is not a one-line `startswith("_")`. Nothing under
    `btclib/` is private today -- `_data` holds data and no python -- so
    this returns True for every module in the tree, and the test below is
    what exercises the other answer rather than a future rename.
    """
    return not any(part.startswith("_") for part in parts if part != "__init__")


def _shipped() -> set[str]:
    """Every dotted name a user can import from an installed btclib.

    Read off the source tree rather than by walking the imported package
    with pkgutil: a module missing from the documentation is usually a
    module just added, and this way noticing it does not depend on it
    being importable.
    """
    names = {"btclib"}
    for path in sorted(_PACKAGE_DIR.rglob("*.py")):
        parts = path.relative_to(_PACKAGE_DIR).with_suffix("").parts
        # not reached by this tree, and kept: nothing under btclib/ is
        # private today, so the day something is, it must not turn up as a
        # module the documentation is missing. `_is_public` is unit tested
        # for both answers below, which is the coverage that matters here
        if not _is_public(parts):
            continue  # pragma: no cover
        if parts[-1] == "__init__":
            parts = parts[:-1]
        names.add(".".join(("btclib", *parts)))
    return names


# the two directions are separate tests because they fail for opposite
# reasons and are fixed in opposite files: something undocumented is a
# missing stanza in docs/source, something documented that no longer exists
# is a stanza left behind by a rename
def test_every_module_is_documented() -> None:
    undocumented = _shipped() - _documented()
    assert not undocumented, (
        "not documented in docs/source: "
        + ", ".join(sorted(undocumented))
        + " -- add an automodule stanza (see docs/README.rst; do not run"
        " sphinx-apidoc -f, which discards the hand-tuned pages)"
    )


def test_no_documented_module_has_gone_away() -> None:
    stale = _documented() - _shipped()
    assert not stale, "documented in docs/source but not shipped: " + ", ".join(
        sorted(stale)
    )


def test_the_docs_sources_were_found_at_all() -> None:
    """Guard the two tests above against passing vacuously.

    Both compare against a set built by globbing, and a wrong `_DOCS_DIR`
    would make `_documented()` empty, which `test_no_documented_module_has
    _gone_away` reports as success. The wheel ships no tests, so this file
    only ever runs from a source tree or an sdist, and both carry `docs/`.
    """
    assert _DOCS_DIR.is_dir()
    assert (_DOCS_DIR / "btclib.rst").is_file()
    assert len(_documented()) > 15


@pytest.mark.parametrize("name", sorted(_shipped()))
def test_shipped_module_is_a_dotted_btclib_name(name: str) -> None:
    """The set the assertions above are built on holds what it claims.

    A bug in `_shipped()` -- an `_data` path slipping through, a private
    module, a stray path separator -- would otherwise show up as a
    confusing failure of the two tests rather than as a failure here.
    """
    assert name == "btclib" or name.startswith("btclib.")
    assert not any(part.startswith("_") for part in name.split("."))


@pytest.mark.parametrize(
    ("parts", "public"),
    [
        (("curve",), True),
        (("ec", "curve"), True),
        (("__init__",), True),
        (("ec", "__init__"), True),
        (("_internal",), False),
        (("ec", "_helpers"), False),
        (("_internal", "curve"), False),
    ],
)
def test_is_public(parts: tuple[str, ...], public: bool) -> None:
    """Both answers, which the tree itself only ever gives one of."""
    assert _is_public(parts) is public
