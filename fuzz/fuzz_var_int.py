# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.var_int.parse`.

Every length and every count in the bitcoin serializations is a
CompactSize, so this is the primitive under `Tx.parse`, `Block.parse`,
`Witness.parse` and the p2p payloads alike, and it is the one that
decides how much a caller is about to allocate on a stranger's own
number. `MAX_SIZE` is Bitcoin Core's `ReadCompactSize` range check and is
what stands between nine hostile octets and an allocation of 2^64-1
elements; the non-canonical encodings -- a number written wider than it
needs -- are refused beside it.

The composite parsers reach this on every field they read, which is why
it is fuzzed on its own as well: they filter what gets here, and a
harness of its own does not.

A crash here on hostile bytes is a defect in `parse` itself, never in
this harness: `data` is unconstrained bytes handed straight to `parse`,
with nothing decoding or validating in between. `BTClibException` is what
`parse` answers a truncated, non-canonical or over-large var_int with, so
that family is caught below as the expected outcome. An `IndexError`, a
`RecursionError` or an uncaught assertion is not, and propagates to
atheris as the finding it is.

`max_size` is left at its default: it is the caller's argument and not
the stream's, so a harness varying it would be fuzzing this library's
callers rather than this parser.

The seed corpus is one canonical encoding at each width the default
`max_size` admits, written by `var_int.serialize`.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib import var_int
from btclib.exceptions import BTClibException


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a variable-length integer.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    with contextlib.suppress(BTClibException):
        var_int.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
