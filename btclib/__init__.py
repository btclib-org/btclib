#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""__init__ module for the btclib package."""

from importlib.metadata import version

name = "btclib"
# read back from the installed distribution, so that pyproject.toml is the
# only place the version is written. It is what a caller asking for
# btclib.__version__ wants anyway: the version that is installed, rather
# than the one a source tree happens to carry
__version__ = version("btclib")
__author__ = "The btclib developers"
__author_email__ = "devs@btclib.org"
# the one place the years are written. The notice at the head of every
# source file carries none, by design: it comes from the COPYRIGHT file,
# which the copyright-notice hook enforces, so it never needs editing.
# docs/source/conf.py reads this line rather than importing it, read the
# docs not installing this package into the environment it builds in
__copyright__ = "Copyright (C) 2017-2026 The btclib developers"
__license__ = "MIT License"
