#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""The btclib package: __version__ is read off the installed metadata."""

from importlib.metadata import PackageNotFoundError, version

name = "btclib"
# read back from the installed distribution, so that pyproject.toml is the
# only place the version is written. It is what a caller asking for
# btclib.__version__ wants anyway: the version that is installed, rather
# than the one a source tree happens to carry
try:
    __version__ = version("btclib")
except PackageNotFoundError:
    # a source tree with no metadata beside it: git clone and import, or
    # read the docs, which builds without installing this package. Any
    # number here would be a guess, and reading pyproject.toml back is not
    # the way to stop guessing: tomllib is standard library from 3.11 only,
    # this package supports 3.10, and the file is not in the wheel anyway.
    # Importing has to keep working, so the version says it does not know
    __version__ = "unknown"
__author__ = "The btclib developers"
__author_email__ = "devs@btclib.org"
# the one place the years are written. The notice at the head of every
# source file carries none, by design: it comes from the COPYRIGHT file,
# which the copyright-notice hook enforces, so it never needs editing.
# docs/source/conf.py reads this line rather than importing it, read the
# docs not installing this package into the environment it builds in
__copyright__ = "Copyright (C) 2017-2026 The btclib developers"
__license__ = "MIT License"

# the distribution name is the whole of it, and the metadata dunders are
# deliberately not in the list: a star import binding __version__ would
# overwrite the importing module's own, which is not what asking for
# btclib's version can be made to mean. Every one of them is still an
# attribute -- btclib.__version__ is how a caller reads it -- and this
# list is what stops `from btclib import *` handing out the `version` and
# `PackageNotFoundError` the lookup above imports
__all__ = ["name"]
