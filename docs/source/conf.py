#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Configuration file for the Sphinx documentation builder.

For the full list of built-in configuration values, see the
documentation: https://www.sphinx-
doc.org/en/master/usage/configuration.html
"""

import re
from pathlib import Path

import tomllib

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "btclib"
# from btclib/__init__.py, where the years are declared once, minus the
# "Copyright (C) " that sphinx prepends itself. Read from the file rather
# than imported, for the same reason as the version below
project_copyright = re.search(
    r'^__copyright__ = "Copyright \(C\) (.+)"$',
    (Path(__file__).parents[2] / "btclib" / "__init__.py").read_text(encoding="utf-8"),
    re.MULTILINE,
).group(1)
author = "The btclib developers"
# read from pyproject.toml, the one place the version is declared, and not
# from importlib.metadata: that would need btclib installed in the
# environment building the documentation, which read the docs does not do
release = tomllib.loads(
    (Path(__file__).parents[2] / "pyproject.toml").read_text(encoding="utf-8")
)["project"]["version"]

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
    "sphinx.ext.todo",
    "sphinx.ext.viewcode",
]

source_suffix = [".rst", ".md"]

# the four markdown pages of the toctree are this repository's README,
# CONTRIBUTING, SECURITY and HISTORY, pulled in by a myst {include}. They
# are written for GitHub, where "./SECURITY.md" is a correct link, and
# sphinx sees them lifted out of the tree that makes it correct: six such
# links have no target here, and two of them -- CODE_OF_CONDUCT.md and
# tests/README.md -- are not part of the documentation at all, so no
# rewriting could give them one.
# Suppressed by name rather than by dropping the -W that .readthedocs.yaml
# passes, because -W is there for the failure that actually mattered: an
# automodule whose module does not import, which is a warning and rendered
# as an empty page for as long as nobody read the log.
# Not absolute github urls in the markdown instead: the
# check-vcs-permalinks hook rejects a blob/master link, rightly, and a
# permalink pinned to a commit is the wrong thing for a navigation link
suppress_warnings = ["myst.xref_missing"]

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
