# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Configuration file for the Sphinx documentation builder.

For the full list of built-in configuration values, see the
documentation: https://www.sphinx-
doc.org/en/master/usage/configuration.html
"""

import posixpath
import re
from pathlib import Path
from typing import Any

import tomllib
from docutils import nodes
from sphinx.addnodes import pending_xref
from sphinx.application import Sphinx
from sphinx.transforms.post_transforms import SphinxPostTransform

# the repository root, two levels up from this file, and the one place
# below that is allowed to name it
ROOT = Path(__file__).parents[2].resolve()
# read once and read twice from: the version below and the github url the
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
).group(1)
author = "The btclib developers"
# read from pyproject.toml, the one place the version is declared, and not
# from importlib.metadata: that would need btclib installed in the
# environment building the documentation, which read the docs does not do
release = PYPROJECT["project"]["version"]

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    # "m2r2",
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.coverage",
    "sphinx.ext.githubpages",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

# no sphinx.ext.todo: with todo_include_todos left at its default a
# `.. todo::` renders as nothing at all, so the directive is a note to
# nobody. Without the extension it is an unknown directive, which -W turns
# into a failed build -- the open questions belong in the issue tracker

source_suffix = [".rst", ".md"]

# no suppress_warnings, and myst.xref_missing least of all: the transform
# at the bottom of this file resolves every link the included root files
# carry, so a myst target still missing is a link with nowhere to go and
# -W is what says so. Suppressing that subtype hides exactly the defect
# issue #195 is about, because what myst emits for a target it cannot
# resolve is not a visibly broken link, it is an anchor to an id the page
# does not have

templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = "sphinx_rtd_theme"

# no html_static_path: this project overrides no stylesheet and ships no
# image, so the "_static" the sphinx template declares was a directory that
# has never existed, and sphinx warns about it on every build. That warning
# was harmless while nothing read it and is a failure now that
# .readthedocs.yaml builds with -W. Re-add the setting with the directory,
# not before it


# -- Links out of the included root markdown files ----------------------------

# Some pages of the toctree are this repository's root markdown files --
# README, CONTRIBUTING, REVIEWING, SECURITY, RELEASE_NOTES and CHANGELOG --
# each pulled into a *_link.md shim by a myst {include}. The shims are what
# the code below reads, so adding one needs no edit here.
# Those files are written for the three places that read
# them unrendered -- the GitHub file view, btclib.org, which is served
# from master's root, and the PyPI long description -- so "./SECURITY.md"
# is the correct spelling there and the one links.yml checks, resolving it
# as a path relative to the file. Sphinx sees them lifted out of the tree
# that makes it correct, and myst resolves not one of those links.
#
# What it emits instead is the reason this needs code rather than a
# warning filter: a target myst cannot resolve becomes an anchor on the
# page it is already on, href="#./SECURITY.md", an id nothing has. The
# build succeeds, -W sees nothing, and lychee reads the sources, where the
# path is right (issue #195).
#
# The transform below answers each link from the repository rather than
# from a table that would have to be kept in step with this directory: a
# path a *_link.md shim includes becomes a reference to that page, any
# other path that exists in the tree becomes a link to the file on GitHub,
# and a path that exists nowhere is left to myst -- which reports it, and
# -W then fails, now that suppress_warnings no longer hides the subtype.
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

# a shim is one myst include fence, and everything after the directive
# name on that line is the directive's argument: the path of the file the
# shim renders, spaces included. Options are the lines under it, never
# this one, so the path ends where the line does
INCLUDE = re.compile(r"^```\{include\}\s+(.+?)\s*$", re.MULTILINE)


def included(shim: Path) -> tuple[str, str]:
    """Map the file a *_link.md shim renders to the shim's own docname."""
    # exactly one fence, and a shim with any other number stops the build
    # here rather than going missing from the mapping. Missing is the one
    # failure this file cannot report on itself: links *out* of that page
    # would be left to myst, which reports them, but links *into* it from
    # the other four would still resolve -- to the copy on github, next to
    # the page that renders it and silently not it
    paths = INCLUDE.findall(shim.read_text(encoding="utf-8"))
    if len(paths) != 1:
        err_msg = f"{shim.name}: {len(paths)} include fences, expected one"
        raise ValueError(err_msg)
    return str((shim.parent / paths[0]).resolve().relative_to(ROOT)), shim.stem


# repository-relative path -> the docname whose page renders it
INCLUDED = dict(map(included, sorted(Path(__file__).parent.glob("*_link.md"))))
# master, not a permalink pinned to a commit: these are navigation links
# to files that keep changing, and a reader following one wants the file
# as it stands. The base url comes from pyproject.toml, where every url
# this project publishes is declared
BLOB = f"{PYPROJECT['project']['urls']['repository']}/blob/master/"


class RootFileLinks(SphinxPostTransform):
    """Resolve the repository-relative links of the included root files."""

    # ahead of myst's own resolver, which runs at 9 and is what turns an
    # unresolved target into that anchor
    default_priority = 5

    def run(self, **kwargs: Any) -> None:
        """Rewrite every myst xref naming a file of this repository."""
        # the list is taken before the tree is edited: replace_self on a
        # node the generator is standing on reparents its children under it
        for node in list(self.document.findall(pending_xref)):
            # refdomain "doc" is a link myst has already resolved to a
            # page; None is one it has given up on, and only the shims
            # hold links written relative to the repository root, so
            # anywhere else a path that does not resolve is a defect to
            # report rather than one to rewrite
            if node.get("reftype") != "myst" or node.get("refdomain") is not None:
                continue
            if node.get("refdoc", self.env.docname) not in INCLUDED.values():
                continue
            target, _, anchor = node["reftarget"].partition("#")
            # "./tests/README.md" -> "tests/README.md"; a path climbing out
            # of the repository is nothing this can answer
            target = posixpath.normpath(target)
            if target.startswith(".."):
                continue
            if target in INCLUDED:
                # handed back to myst as the link it would have been
                # written as, so the page title and the caption are its
                # business and not this file's
                node["refdomain"] = "doc"
                node["reftarget"] = INCLUDED[target]
                node["reftargetid"] = anchor or None
            elif (ROOT / target).is_file():
                fragment = f"#{anchor}" if anchor else ""
                reference = nodes.reference(
                    "", "", refuri=f"{BLOB}{target}{fragment}", internal=False
                )
                reference.extend(node.children)
                node.replace_self(reference)


def setup(app: Sphinx) -> None:
    """Register the transform above; sphinx calls this."""
    app.add_post_transform(RootFileLinks)
