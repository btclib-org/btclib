# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every module btclib ships is documented.

The pages under `docs/source/` are hand written, which invites drift, and
telling contributors to re-run `sphinx-apidoc -f` is no answer: `-f`
regenerates every page from the template, discarding the hand-tuned index
and the myst links to the markdown files. What drift costs is a module
absent from the automodule directives -- and therefore from the published
documentation -- with nothing anywhere to say so; this test is the thing
that says so.

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


def _documented_in(text: str) -> set[str]:
    """Every module one documentation page publishes the members of.

    An automodule stanza and nothing else. A toctree line naming
    `btclib.psbt` is not one: it makes the package's *page* reachable
    from `btclib.rst`, which is what a toctree is for, and says nothing
    about whether that page renders the package's own `__init__` -- the
    docstring, and the names re-exported flat that a caller reads
    `btclib.psbt` for. Counting it as documentation is what would let a
    package keep its page, its submodules and its toctree line while
    losing itself out of the middle of them.

    Nothing is lost by not counting it, because the toctree is gated
    where it belongs: a page no toctree includes is `toc.not_included`,
    which the `-W` of the documentation workflow turns into a failure.
    """
    return set(_AUTOMODULE.findall(text))


def _documented() -> set[str]:
    """Every module the documentation sources carry a stanza for."""
    names: set[str] = set()
    for page in _DOCS_DIR.glob("*.rst"):
        names.update(_documented_in(page.read_text(encoding="utf-8")))
    return names


def _is_public(parts: tuple[str, ...]) -> bool:
    """Whether a module path names something a user is meant to import.

    `__init__` is the package itself and not a private name, which is the
    only reason this is not a one-line `startswith("_")`. A module under a
    private name is not API, so it takes no automodule stanza, and the
    underscore is the whole of what says so -- `btclib._ripemd160`, the
    pure Python fallback `btclib.hashes` reaches where hashlib has no
    RIPEMD-160, and `btclib._libsecp256k1`, where the bindings are
    imported once for the package. `_data` holds data and no Python.
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
        # `_ripemd160` is what this skips: a private module is not
        # documentation the tree is missing. `_is_public` is unit tested
        # for both answers below, and for the shapes the tree has none of
        if not _is_public(parts):
            continue
        if parts[-1] == "__init__":
            parts = parts[:-1]
        names.add(".".join(("btclib", *parts)))
    return names


# the two directions are separate tests because they fail for opposite
# reasons and are fixed in opposite files: something undocumented is a
# missing stanza in docs/source, something documented that no longer exists
# is a stanza left behind by a rename
def test_every_module_is_documented() -> None:
    """Verify every shipped module has a stanza in docs/source."""
    undocumented = _shipped() - _documented()
    assert not undocumented, (
        "not documented in docs/source: "
        + ", ".join(sorted(undocumented))
        + " -- add an automodule stanza (see docs/README.rst; do not run"
        " sphinx-apidoc -f, which discards the hand-tuned pages)"
    )


def test_no_documented_module_has_gone_away() -> None:
    """Verify no automodule stanza names a module the tree lost."""
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


def test_a_toctree_line_is_not_a_stanza() -> None:
    """A package page is documentation of the package only if it says so.

    The two tests above are only as good as this scan, and the shape it
    has to tell apart is the one every per-package page has: a toctree
    line for `btclib.psbt` in `btclib.rst`, stanzas for the submodules in
    `btclib.psbt.rst`, and the package's own stanza at the end of it. Read
    the toctree as documentation and dropping that last stanza passes --
    the suite finding the name in the toctree, and sphinx warning about
    nothing, autodoc having no idea a page was meant to carry it.
    """
    source = (
        ".. toctree::\n"
        "   :maxdepth: 4\n"
        "\n"
        "   btclib.psbt\n"
        "\n"
        ".. automodule:: btclib.psbt.psbt_utils\n"
        "   :members:\n"
    )
    assert _documented_in(source) == {"btclib.psbt.psbt_utils"}


@pytest.mark.parametrize(
    "parts, public",
    [
        (("curve",), True),
        (("curves", "curve"), True),
        (("__init__",), True),
        (("curves", "__init__"), True),
        (("_internal",), False),
        (("curves", "_helpers"), False),
        (("_internal", "curve"), False),
    ],
)
def test_is_public(parts: tuple[str, ...], public: bool) -> None:
    """Both answers, and the two shapes the tree itself has none of.

    A private module it has, `btclib/_ripemd160.py`; a private package and
    a private module inside a package it does not.
    """
    assert _is_public(parts) is public
