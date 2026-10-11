# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.script.taproot.parse`.

A tapscript is the leaf a spender reveals, so it arrives inside a witness
somebody else wrote and is decoded before the leaf hash it commits to has
been recomputed. `btclib.script.script.parse` is the same walk over the
other script language and is fuzzed in `fuzz/fuzz_script.py`; BIP342 puts
different rules on this one -- an unknown op code is refused where
`script.parse` names it, and an `OP_SUCCESSx` ends the walk with whatever
follows returned unparsed -- so the two decoders answer the same octets
differently and neither reaches the other.

A crash here on hostile bytes is a defect in `parse` or `serialize` itself,
never in this harness: `data` is unconstrained bytes handed straight to
`parse`, with nothing decoding or validating in between. `BTClibException`
is what `parse` answers an unknown op code, a truncated push and an
oversized element with, so that family is caught below as the expected
outcome. An `IndexError`, a `RecursionError` or an uncaught assertion is
not, and propagates to atheris as the finding it is.

`exit_on_op_success` is left at its default: it decides which of two
answers `parse` computes rather than what the octets are, so the default
is the walk that reads all of them.

The seed corpus is a single-key leaf script -- an x-only public key
pushed and checked -- and a script whose `OP_SUCCESS80` is followed by
the raw octets BIP342 does not require to be a script at all.

**A script has several encodings of one value, so this asserts less.** A
push is accepted in every width that can hold it and written back in the
shortest, as BIP62 asks, so `serialize(parse(data))` need not be `data`.
What is asserted instead is that writing settles it: the octets `serialize`
writes parse and are written back unchanged. The comparison is on octets
and not on commands: `parse` spells an empty push `OP_PUSHDATA1 0x00` as `""`
and `OP_0` as `"OP_0"`
([ISS 2607](https://github.com/btclib-org/btclib/issues/2607)).
"""

from __future__ import annotations

import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.script import taproot

# tests/fuzz_corpus_test.py reads this with ast.literal_eval.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = ("btclib.script.taproot:parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a tapscript.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    try:
        commands = taproot.parse(data)
    except BTClibException:
        return
    written = taproot.serialize(commands)
    assert taproot.serialize(taproot.parse(written)) == written


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
