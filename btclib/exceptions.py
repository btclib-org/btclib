#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Expception classes.

This are only meant to dicriminate between Exceptions being raised by
btclib from those raised by other codebase.

Users are usually better off just dealing with the regular ValueError,
TypeError, and RuntimeError from which the btclib versions are derived.
"""


class BTClibValueError(ValueError):
    pass


class ScriptError(BTClibValueError):
    """A script verification failure, and where in the script it happened.

    Only the two interpreter loops know the index of the command being
    executed and the depth of the stack; the op code implementations,
    which are handed the stack alone, do not. They raise a plain
    BTClibValueError with what went wrong, and the loop re-raises it as
    this, adding where. A BTClibValueError still, so that code catching
    that keeps catching this.
    """

    def __init__(self, message: str, index: int, stack_depth: int) -> None:
        self.index = index
        self.stack_depth = stack_depth
        super().__init__(f"{message} (command {index}, stack depth {stack_depth})")


class BTClibTypeError(TypeError):
    pass


class BTClibRuntimeError(RuntimeError):
    pass
