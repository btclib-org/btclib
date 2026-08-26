# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.script.witness.Witness.parse`.

A witness is a count and then that many length-prefixed elements, which
is the shape a parser allocates on before anything in it is verified.
`Tx.parse` reads one per input, a `PSBT_IN_FINAL_SCRIPTWITNESS` value is
one whole, and BIP322's simple variant is one arriving as a signature --
three callers, none of which has checked a signature first.

A crash here on hostile bytes is a defect in `parse` itself, never in
this harness: `data` is unconstrained bytes handed straight to `parse`,
with nothing decoding or validating in between. The stack count is bound
against `MAX_WITNESS_STACK_ITEMS` before any element is read, which is
`src/btclib/script/witness.py`'s own reasoning and is a refusal like
every other: `BTClibException` is what `parse` answers malformed input
with, so that family is caught below as the expected outcome. An
`IndexError`, a `RecursionError` or an uncaught assertion is not, and
propagates to atheris as the finding it is.

The seed corpus is the witness of the vendored segwit transaction's own
input, and the empty stack, which is what an input with no witness
serializes as.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.script.witness import Witness


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a witness stack.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    with contextlib.suppress(BTClibException):
        Witness.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
