# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Configuration file for the Sphinx documentation builder.

For the full list of built-in configuration values, see the
documentation: https://www.sphinx-doc.org/en/master/usage/configuration.html
"""

import posixpath
import re
import tomllib
from pathlib import Path

from docutils import nodes
from sphinx.addnodes import pending_xref
from sphinx.application import Sphinx
from sphinx.transforms.post_transforms import SphinxPostTransform

# the repository root, two levels up from this file, and the one place
# below that is allowed to name it
ROOT = Path(__file__).parents[2].resolve()
# read once, for the author and version below and the github url the
# transform at the bottom builds its links on
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "btclib"
# from src/btclib/__init__.py, where the years are declared once, minus
# the "Copyright (c) " that sphinx prepends itself. Read from the file
# rather than imported, for the same reason as the version below
project_copyright = re.search(
    r'^__copyright__ = "Copyright \(c\) (.+)"$',
    (ROOT / "src" / "btclib" / "__init__.py").read_text(encoding="utf-8"),
    re.MULTILINE,
)[1]
# pyproject.toml's `authors` table, the one place the holder is
# declared: PYPROJECT is already parsed above, so this is a second
# read of it rather than a second literal (issue #1519)
author = PYPROJECT["project"]["authors"][0]["name"]
# read from pyproject.toml, the one place the version is declared, and not
# from importlib.metadata: the value should not depend on whether btclib
# happens to be installed in the environment building the documentation
# (btclib-org/.github#1098)
release = PYPROJECT["project"]["version"]

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.coverage",
    "sphinx.ext.githubpages",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

# no sphinx.ext.todo: with todo_include_todos left at its default a
# `.. todo::` renders as nothing at all, so the directive is a note to
# nobody. Without the extension it is an unknown directive, which -W turns
# into a failed build -- the open questions belong in the issue tracker

source_suffix = [".rst", ".md"]

# anchors down to h6, which is what makes a link into a heading of
# another root markdown file resolve here: README.md links into
# CONTRIBUTING.md's "Breaking a caller is not an argument" that way, and
# CONTRIBUTING.md into REVIEWING.md's "The gates are the evidence".
# Left unset this defaults to 0, myst generates no anchor at all, and
# the fragment becomes an xref to a target no page has -- -W fails on a
# link the forge renders correctly, which is what makes the failure
# silent to whoever wrote it (issue #1587). The fragment that resolves
# is the one GitHub derives from the heading text, so the spelling
# written for where these files are read is the spelling this build
# accepts; the id it reaches is the one docutils gives the section, and
# need not be spelled the same.
#
# Six is every level markdown heads at, which makes the number a fixed
# point rather than a value re-derived from files that move -- and part
# of what such a re-derivation would read belongs to no one tree:
# section 14 of the organization's standard ports CONTRIBUTING.md's
# shared half into every repository, so a heading added there moves the
# depth in each of them at once, and which tree finds out is whichever
# carries a link into it (btclib-org/.github#715).
#
# Whether the depth is wide enough is not read off two builds: docutils
# gives every section an id whatever myst accepts as a target, so the
# pages this source renders at 4 and at 6 differ by no byte, and would
# differ by none if a heading here did reach h5. What answers is a link
# into such a heading: too narrow a depth makes it the same unresolved
# xref an unset key makes of every one of them
myst_heading_anchors = 6

# the ecc release uv.lock pins, read from the lock as the release above is
# from pyproject.toml, so that a lock bump moves the ecc inventory below
# with no edit here. ecc's `latest` docs follow its main branch, which can
# rename what the pinned release defines (issue #2968). Read the Docs
# builds each ecc tag under the tag's name, `v` and the version
[ECC_VERSION] = [
    package["version"]
    for package in tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))[
        "package"
    ]
    if package["name"] == "ecc"
]

# -n on the build (CONTRIBUTING.md's documented command, and docs.yml)
# turns an unresolved cross-reference into a warning for -W to fail on.
# Without an inventory to resolve against, a name from outside this tree
# -- collections.abc.Sequence, pathlib.Path, os.getcwd -- reports as this
# tree's own broken link; sphinx's own domain answers for the builtins
# (int, bytes, str), so no mapping is needed for those. typing_extensions
# carries no public inventory, but the only name this tree imports from
# it is the `override` decorator, which never appears in a signature or
# a docstring type field, so it draws no reference for -n to raise on
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", (None, "_inventories/python.inv")),
    # the classes of ecc that btclib's signatures name; the pages here
    # document none of that package
    "ecc": (
        f"https://btclib-ecc.readthedocs.io/en/v{ECC_VERSION}",
        (None, "_inventories/ecc.inv"),
    ),
}
# no reuse of a fetched inventory: in a reused doctree directory sphinx
# keeps one per mapping name, so a changed ecc URL would still read the
# old one. Section 2 of the organization's standard asks for 0 where a
# mapping names a sibling
intersphinx_cache_limit = 0
# `_inventories/python.inv` is a copy of Python 3.14's inventory and no
# cache: sphinx reads it only when `docs.python.org` fails, so a live site
# always wins. It is the Wayback Machine's capture of 2026-08-28,
# https://web.archive.org/web/20260828181213id_/https://docs.python.org/3/objects.inv
# To refresh it, run this from the repository root and rewrite the version
# and source above:
# curl -fsSL -o docs/source/_inventories/python.inv https://docs.python.org/3/objects.inv
# `_inventories/ecc.inv` is the same for ecc: a copy of the inventory that
# https://btclib-ecc.readthedocs.io/en/v2026.11.11/objects.inv served on
# 2026-11-12, read only when that site fails. To refresh it, run this from
# the repository root, with the version uv.lock pins, and rewrite the
# version and date:
# curl -fsSL -o docs/source/_inventories/ecc.inv https://btclib-ecc.readthedocs.io/en/v<version>/objects.inv

# What the mapping above does not answer for is the shapes below, and each
# entry carries its own reason rather than a nitpick_ignore_regex that
# would give the check up entirely:
#
# - a subscripted generic written inline in a signature -- Callable's
#   argument list, a bare tuple[int, ...], a list of tuples, a union built
#   out of either -- where sphinx's own type-to-xref splitter (measured
#   against sphinx 9.1.0) stops at the first nested bracket and reports the
#   truncated fragment as the unresolved class, rather than resolving the
#   pieces on either side of it. No mapping answers a target that is not a
#   name to begin with
# - a private name: the p2p payload classes and the sig_hash input hashes
#   below begin with an underscore, and automodule does not document a
#   name spelled that way at all, so `:members:` renders no page for a
#   signature naming one to link to
# - `Octets` as autodoc renders it in a signature it cannot evaluate,
#   `ConsensusParams.script_flags_at`'s `block_hash: Octets | None`, where
#   `consensus.py` imports it under TYPE_CHECKING: `btclib.alias` imports it
#   from ecc, autodoc documents no imported name, and the bare name
#   has no page to link to
nitpick_ignore = [
    ("py:class", "collections.abc.Callable[[]"),
    ("py:class", "tuple[int"),
    ("py:class", "list[tuple[bytes"),
    ("py:class", "collections.abc.Mapping[bytes"),
    ("py:class", "bytes | str | bytearray | memoryview | tuple[int"),
    ("py:class", "int | bytes | str | bytearray | memoryview | tuple[int"),
    ("py:class", "btclib.p2p.inventory._InventoryPayload"),
    ("py:class", "btclib.p2p.inventory._LocatorPayload"),
    ("py:class", "btclib.p2p.keepalive._NoncePayload"),
    ("py:class", "btclib.p2p.block_filters._FilterRangeRequest"),
    ("py:class", "btclib.script.sig_hash._TaprootInputHashes"),
    ("py:class", "btclib.script.sig_hash._SigHashCache"),
    ("py:class", "Octets"),
]

# no suppress_warnings, and myst.xref_missing least of all: the transform
# at the bottom of this file resolves every link the included root files
# carry, so a myst target still missing is a link with nowhere to go and
# -W is what says so. Suppressing that subtype hides exactly the defect
# issue #195 is about, because what myst emits for a target it cannot
# resolve is not a visibly broken link, it is an anchor to an id the page
# does not have

exclude_patterns: list[str] = []


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = "furo"

# no html_static_path: this project overrides no stylesheet and ships no
# image, so the "_static" the sphinx template declares was a directory that
# has never existed, and sphinx warns about it on every build. That warning
# was harmless while nothing read it and is a failure now that
# .readthedocs.yaml builds with -W. Re-add the setting with the directory,
# not before it


# -- Links out of the included root markdown files ----------------------------

# Some pages of the toctree are this repository's root markdown files,
# each pulled into a *_link.md shim by a myst {include}. The code below
# reads the include of every docs/source/*.md page, so adding a shim needs
# no edit here. Those files are written for the places that read them
# unrendered: the GitHub file view and, for README.md, the PyPI long
# description. So a root file links another as "./SECURITY.md", the
# spelling links.yml checks, resolving it as a path relative to the file.
# Sphinx sees them lifted out of the tree that makes it correct, and myst
# resolves not one of those links. README.md links it as BLOB plus its
# path, PyPI resolving no relative link against the tree (section 2 of the
# organization's standard), and myst renders that as a link to GitHub.
#
# What myst emits for a relative link is the reason this needs code
# rather than a warning filter: for a target it cannot resolve, a
# warning, and then an anchor on the page the link is already on,
# href="#./SECURITY.md", an id nothing has. A filter on the subtype would
# take the warning and leave the anchor, and lychee reads the sources,
# where the path is right (issue #195).
#
# The transform below answers each link from the repository rather than
# from a table that would have to be kept in step with this directory: a
# path a page of docs/source includes, or a page of docs/source itself,
# becomes a reference to that page, whether written relative or as BLOB
# plus the path; any other relative path that exists in the tree becomes
# a link to the file on GitHub, and a relative path that exists nowhere
# is left to myst -- which reports it, and -W then fails.
#
# It also reads a link written this way on a page that includes no file,
# resolved against the document that wrote it. A page under docs/source
# is itself read unrendered on the forge, so a link composed relative to
# its own file -- climbing out of docs/source the way a checkout
# resolves it -- works there verbatim, and this is what lets the same
# link resolve here too, through the shim page that carries the heading
# once the {include} has run (issue #1562).
#
# Not the {include} directive's :relative-docs: option, which is what it
# looks like the job of. It rewrites destinations that begin with the
# prefix it is given, so "docs/source/" leaves "./SECURITY.md" untouched;
# and giving it "./" is worse than doing nothing, measured -- the
# destination becomes "../../SECURITY.md", a path outside srcdir that is
# no document, sphinx reads it as a download, finds nothing to copy, and
# renders the link text with no link at all.
#
# Not copying the root files into this directory at build time either.
# CONTRIBUTING.md links to tests/README.md, which is not part of the
# documentation, so copies leave that link dead however many are made;
# and the copies are generated files in a source tree, which is a second
# definition of files that already exist.

# main, not a permalink pinned to a commit: these are navigation links
# to files that keep changing, and a reader following one wants the file
# as it stands. The base url comes from pyproject.toml, where every url
# this project publishes is declared
BLOB = f"{PYPROJECT['project']['urls']['repository']}/blob/main/"


# a line opening or closing a fence: the spaces before it, its marker, and
# the info string after it. Behind four spaces, a line at the top level of
# a page is no fence
FENCE = re.compile(r"^( {0,3})(`{3,}|~{3,})\s*(.*?)\s*$")

# the info string of an include fence; its argument runs to the end of the line
INCLUDE = re.compile(r"^\{include\}\s+(.+)$")

# the name of the directive an info string opens
DIRECTIVE = re.compile(r"^\{([^}]+)\}")

# the directives whose body this reads as markup, among them the
# admonitions, containers and version notes of docutils and sphinx. Every
# directive not named here is read as code, so an include inside it is
# not read: {code-block}, {eval-rst} and {toctree}, and also some that
# do parse their body, as {figure}, {list-table} and {glossary}. The list
# names only directives MyST renders by parsing their body, and grows
# when a page needs an include inside another one
PARSED = (
    "admonition",
    "attention",
    "caution",
    "danger",
    "error",
    "hint",
    "important",
    "note",
    "tip",
    "warning",
    "seealso",
    "topic",
    "sidebar",
    "epigraph",
    "highlights",
    "pull-quote",
    "compound",
    "container",
    "only",
    "hlist",
    "acks",
    "deprecated",
    "versionadded",
    "versionchanged",
    "versionremoved",
    "version-deprecated",
    "version-added",
    "version-changed",
    "version-removed",
)


def includes(text: str) -> list[str]:
    """Return the paths of the include fences of a page, in page order.

    A fence opening a directive of `PARSED` holds markdown, which myst
    parses, so a fence inside it is read. Any other fence is code, and
    what it holds is shown, not parsed. A fence closes at a bare marker
    of its own character, at least as long as the one that opened it.
    A marker behind spaces may close a fence but opens none: it may sit
    in a list item, which this does not read.

    :param text: the page.
    :returns: the paths, as the fences write them.
    """
    paths: list[str] = []
    # the open fences, innermost last: marker, and whether it is code
    open_fences: list[tuple[str, bool]] = []
    for line in text.splitlines():
        fence = FENCE.match(line)
        if fence is None:
            continue
        indent, marker, info = fence.groups()
        if open_fences:
            top, _ = open_fences[-1]
            if not info and marker[0] == top[0] and len(marker) >= len(top):
                open_fences.pop()
                continue
            if open_fences[-1][1]:
                continue
        if indent:
            continue
        if include := INCLUDE.match(info):
            paths.append(include[1])
        directive = DIRECTIVE.match(info)
        open_fences.append((marker, directive is None or directive[1] not in PARSED))
    return paths


def included(page: Path) -> tuple[str, str] | None:
    """Map the file a page of docs/source includes to the page's docname.

    A page with no include fence renders no file, and maps nothing. One
    with more than one stops the build: a relative link on it would have
    two files to start from, and which one is not a question this can
    answer.
    """
    paths = includes(page.read_text(encoding="utf-8"))
    if len(paths) > 1:
        err_msg = f"{page.name}: {len(paths)} include fences, expected at most one"
        raise ValueError(err_msg)
    if not paths:
        return None
    return str((page.parent / paths[0]).resolve().relative_to(ROOT)), page.stem


# repository-relative path -> the docname whose page renders it
INCLUDED = dict(
    entry
    for entry in map(included, sorted(Path(__file__).parent.glob("*.md")))
    if entry is not None
)


class RootFileLinks(SphinxPostTransform):
    """Resolve the links naming a file of this tree."""

    # ahead of myst's own resolver, which runs at 9 and is what turns an
    # unresolved target into that anchor
    default_priority = 5

    @staticmethod
    def _to_page(node: pending_xref, page: str, anchor: str | None) -> None:
        """Point a myst xref at `page`, a docname."""
        node["refdomain"] = "doc"
        node["reftarget"] = page
        node["reftargetid"] = anchor or None

    def _broken_doc_target(self, node: pending_xref) -> tuple[Path, str | None] | None:
        """Recover the file behind a "doc" xref `path2doc` resolved wrong.

        myst already thinks this resolves; a real docname is a working
        cross-reference and none of this file's business. Anything else is
        `Project.path2doc` stripping a matching suffix off *any* file that
        exists on disk, docs or not (sphinx/project.py), so a link climbing
        out of srcdir into a real file -- a page under docs/source
        linking into README.md -- reads as resolved when it is not.
        Recover the file it actually named: reftarget is that path with
        its suffix gone, and only one of the two the tree parses still
        fits.
        """
        if node["reftarget"] in self.env.all_docs:
            return None
        candidates = (Path(f"{node['reftarget']}{suffix}") for suffix in source_suffix)
        found = next((c for c in candidates if c.is_file()), None)
        return None if found is None else (found, node.get("reftargetid"))

    def _unbound_target(
        self, node: pending_xref, refdoc: str
    ) -> tuple[Path, str | None]:
        """Resolve a link myst left with no domain at all.

        A page that includes a file holds links written relative to that
        file; any other page's links are written relative to wherever the
        page sits in the source tree -- doc2path is what answers that
        without assuming every docname sits flat under docs/source.
        """
        raw, _, anchor = node["reftarget"].partition("#")
        rendered = [path for path, page in INCLUDED.items() if page == refdoc]
        origin = (
            (ROOT / rendered[0]).parent
            if rendered
            else Path(self.env.doc2path(refdoc)).parent
        )
        return origin / raw, anchor or None

    def _source_page(self, target: str) -> str | None:
        """Return the docname of `target` where it is a page of docs/source."""
        stem, suffix = posixpath.splitext(target)
        docname = stem.removeprefix("docs/source/")
        if docname == stem or suffix not in source_suffix:
            return None
        # the file itself, and not only its docname: a missing page.rst
        # would otherwise read as page.md
        if not (ROOT / target).is_file():
            return None
        return docname if docname in self.env.found_docs else None

    def run(self, **_kwargs: object) -> None:
        """Rewrite every link naming a file of this repository."""
        # the list is taken before the tree is edited: replace_self on a
        # node the generator is standing on reparents its children under it
        for node in list(self.document.findall(pending_xref)):
            if node.get("reftype") != "myst":
                continue
            refdomain = node.get("refdomain")
            if refdomain == "doc":
                resolved = self._broken_doc_target(node)
            elif refdomain is None:
                refdoc = node.get("refdoc", self.env.docname)
                resolved = self._unbound_target(node, refdoc)
            else:
                resolved = None
            if resolved is None:
                continue
            found, anchor = resolved
            try:
                # "./tests/README.md" from a shim resolves to
                # "tests/README.md"; a page's own "../../README.md"
                # resolves to "README.md" the same way, against the real
                # filesystem, so a path climbing above ROOT raises rather
                # than reading as one of its own
                target = str(found.resolve().relative_to(ROOT))
            except ValueError:
                # outside the repository: nothing this can answer
                continue
            if target in INCLUDED:
                # handed back to myst as the link it would have been
                # written as, so the page title and the caption are its
                # business and not this file's
                self._to_page(node, INCLUDED[target], anchor)
            elif (ROOT / target).is_file():
                fragment = f"#{anchor}" if anchor else ""
                reference = nodes.reference(
                    "", "", refuri=f"{BLOB}{target}{fragment}", internal=False
                )
                reference.extend(node.children)
                node.replace_self(reference)
        self._blob_links()

    def _blob_links(self) -> None:
        """Turn a BLOB link to a file the docs render into a link to its page.

        myst made each BLOB link an external reference: one naming an
        included file or a page of docs/source becomes the xref myst makes
        from a relative link, which myst's resolver then renders alike.
        """
        for node in list(self.document.findall(nodes.reference)):
            url, _, anchor = node.get("refuri", "").partition("#")
            # the path ends at a query, as `?plain=1`, which the page drops
            url = url.partition("?")[0]
            target = url.removeprefix(BLOB)
            if target == url:
                continue
            page = INCLUDED.get(target) or self._source_page(target)
            if page is None:
                continue
            xref = pending_xref(
                "",
                nodes.inline("", "", *node.children, classes=["xref", "myst"]),
                reftype="myst",
                refexplicit=True,
                refdoc=self.env.docname,
            )
            xref.source, xref.line = node.source, node.line
            self._to_page(xref, page, anchor)
            node.replace_self(xref)


def setup(app: Sphinx) -> None:
    """Register the transform above; sphinx calls this."""
    app.add_post_transform(RootFileLinks)
