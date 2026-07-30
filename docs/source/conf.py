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

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]
