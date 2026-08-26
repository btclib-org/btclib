# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.var_bytes.parse`.

A var_int length and then that many octets: the encoding every script,
every witness element and every psbt key and value is written in, and the
first place a declared length is compared against what a stream actually
holds. `fuzz/fuzz_var_int.py` fuzzes the length on its own; this is the
read that follows it.

A crash here on hostile bytes is a defect in `parse` itself, never in
this harness: `data` is unconstrained bytes handed straight to `parse`,
with nothing decoding or validating in between. `BTClibException` is what
`parse` answers a length no stream can satisfy with, so that family is
caught below as the expected outcome. An `IndexError`, a `RecursionError`
or an uncaught assertion is not, and propagates to atheris as the finding
it is.

`forbid_zero_size` is left at its default, for the reason
`fuzz/fuzz_var_int.py` leaves `max_size` at its own: it is what the
caller knows about the field, not what the octets say.

The seed corpus is the empty payload and a script_pub_key of the vendored
segwit transaction, each written by `var_bytes.serialize`.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib import var_bytes
from btclib.exceptions import BTClibException

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = ("btclib.var_bytes:parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as length-prefixed octets.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    with contextlib.suppress(BTClibException):
        var_bytes.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
