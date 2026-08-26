# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.descriptors.parse`.

An output descriptor is what a wallet is handed to watch somebody else's
keys: it arrives in a file, in an rpc argument or pasted, and parsing it
builds a tree of nested function calls, key expressions and derivation
paths out of text nobody signed. That is a recursive grammar over a
stranger's own input, which is what this harness is for.

**A descriptor is text, so the octets are decoded here and the decode is
total.** `errors="replace"` is what makes it so: no input is filtered out
before `parse` sees it, and octets that are not utf-8 arrive as the
replacement character, which is outside BIP380's INPUT_CHARSET and
refused as any other character outside it would be. A decode that could
raise would make the harness answer for the decoder rather than for the
parser.

A crash on hostile text is a defect in `parse` itself, never in this
harness: nothing validates or normalizes between the decode and the call.
`BTClibException` is what `parse` answers a character outside the
charset, an unknown function, a bad key and a checksum that does not
match with, so that family is caught below as the expected outcome. An
`IndexError`, a `RecursionError` or an uncaught assertion is not, and
propagates to atheris as the finding it is.

`network` and `prv_keys` are left at their defaults: both are the
caller's own arguments rather than anything the descriptor says.

The seed corpus is two of BIP380's own descriptors, as
`tests/_data/descriptor_checksums.json` carries them, and it carries them
without a checksum. That is what a seed is worth here: the checksum is
optional in the language, and appending one to a seed makes the eight
characters a mutated descriptor cannot match, so the fuzzer would spend
its budget on `strip_checksum` and reach the grammar behind it almost
never.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.descriptors import descriptors
from btclib.exceptions import BTClibException

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = ("btclib.descriptors.descriptors:parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data`, decoded as text, as an output descriptor.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    with contextlib.suppress(BTClibException):
        descriptors.parse(data.decode("utf-8", errors="replace"))


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
