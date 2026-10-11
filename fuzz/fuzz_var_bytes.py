# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.var_bytes.parse`.

A var_int length and then that many octets: the encoding every script,
every witness element and every psbt key and value is written in, and the
first place a declared length is compared against what a stream actually
holds. `fuzz/fuzz_var_int.py` fuzzes the length on its own; this is the
read that follows it.

A crash here on hostile bytes is a defect in `parse` or `serialize` itself,
never in this harness: `data` is unconstrained bytes handed straight to
`parse`, with nothing decoding or validating in between. `BTClibException`
is what `parse` answers a length no stream can satisfy with, so that family
is caught below as the expected outcome. An `IndexError`, a `RecursionError`
or an uncaught assertion is not, and propagates to atheris as the finding it
is.

`forbid_zero_size` is left at its default, for the reason
`fuzz/fuzz_var_int.py` leaves `max_size` at its own: it is what the
caller knows about the field, not what the octets say.

The seed corpus is the empty payload and a script_pub_key of the vendored
segwit transaction, each written by `var_bytes.serialize`.

The format has one encoding, its length being a canonical var_int. So the
octets `parse` consumes must be what `serialize` writes for its answer.
`data` may run on past them, because `parse` reads a stream and leaves the
rest to its caller. An input that does not round-trip was misread by `parse`
or miswritten by `serialize`, and the `AssertionError` reaches atheris as
the finding it is.
"""

from __future__ import annotations

import io
import sys

import atheris

from btclib import var_bytes
from btclib.exceptions import BTClibException

# tests/fuzz_corpus_test.py reads this with ast.literal_eval.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = ("btclib.var_bytes:parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as length-prefixed octets.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    stream = io.BytesIO(data)
    try:
        octets = var_bytes.parse(stream)
    except BTClibException:
        return
    assert var_bytes.serialize(octets) == data[: stream.tell()]


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
