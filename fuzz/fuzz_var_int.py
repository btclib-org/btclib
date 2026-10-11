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

A crash here on hostile bytes is a defect in `parse` or `serialize` itself,
never in this harness: `data` is unconstrained bytes handed straight to
`parse`, with nothing decoding or validating in between. `BTClibException`
is what `parse` answers a truncated, non-canonical or over-large var_int
with, so that family is caught below as the expected outcome. An
`IndexError`, a `RecursionError` or an uncaught assertion is not, and
propagates to atheris as the finding it is.

`max_size` is left at its default: it is the caller's argument and not
the stream's, so a harness varying it would be fuzzing this library's
callers rather than this parser.

The seed corpus is one canonical encoding at each width the default
`max_size` admits, written by `var_int.serialize`.

The format has one encoding, a number written wider than it needs being
refused. So the octets `parse` consumes must be what `serialize` writes for
its answer. `data` may run on past them, because `parse` reads a stream and
leaves the rest to its caller. An input that does not round-trip was misread
by `parse` or miswritten by `serialize`, and the `AssertionError` reaches
atheris as the finding it is.
"""

from __future__ import annotations

import io
import sys

import atheris

from btclib import var_int
from btclib.exceptions import BTClibException

# tests/fuzz_corpus_test.py reads this with ast.literal_eval.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = ("btclib.var_int:parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a variable-length integer.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    stream = io.BytesIO(data)
    try:
        value = var_int.parse(stream)
    except BTClibException:
        return
    assert var_int.serialize(value) == data[: stream.tell()]


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
