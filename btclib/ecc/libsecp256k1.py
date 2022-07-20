#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Helper functions to use the libsecp256k1 python bindings
"""

try:
    from btclib_libsecp256k1 import dsa, mult, ssa  # pylint: disable=unused-import

    LIBSECP256K1_AVAILABLE = True
except ImportError:  # pragma: no cover
    dsa, ssa, mult = None, None, None  # type: ignore
    LIBSECP256K1_AVAILABLE = False

LIBSECP256K1_ENABLED = True


def enable():
    global LIBSECP256K1_ENABLED  # pylint: disable=global-statement
    LIBSECP256K1_ENABLED = True


def disable():
    global LIBSECP256K1_ENABLED  # pylint: disable=global-statement
    LIBSECP256K1_ENABLED = False


def is_enabled():
    return LIBSECP256K1_ENABLED and LIBSECP256K1_AVAILABLE
