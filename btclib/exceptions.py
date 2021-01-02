#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Expception classes.

This are only meant to dicriminate between Exceptions being raised
by btclib from those raised by other codebase.

Users are usually better off just dealing with the regular
ValueError, TypeError, and RuntimeError
from which the btclib versions are derived.
"""


class BTClibValueError(ValueError):
    pass


class BTClibTypeError(TypeError):
    pass


class BTClibRuntimeError(RuntimeError):
    pass
