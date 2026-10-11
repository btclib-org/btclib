# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.script.script.parse`.

A script_pub_key comes out of an output somebody else wrote and a
script_sig out of an input somebody else signed, so a script is decoded
long before anything about it is verified -- and it is decoded to be
shown, which is where a decoder that walks off the end of its own buffer
is read as an address or an asm listing.

**Nothing is suppressed here, and that is this parser's own contract
rather than an omission.** `parse` decodes whatever the octets are, as
Bitcoin Core's `GetScriptOp` does: the one thing Core refuses -- a push
running past the end of the script -- is answered with the terminal
`ERROR_COMMAND` that `ScriptToAsmStr` writes, not with an exception, and
every other question belongs to the interpreter. So this parser has no
refusal for a `contextlib.suppress(BTClibException)` to cover, and every
exception `parse` raises is the finding. `fuzz/fuzz_tapscript.py`, whose
parser does refuse, catches that family the way the p2p harnesses do.

A crash here on hostile bytes is a defect in `parse` itself, never in
this harness: `data` is unconstrained bytes handed straight to `parse`,
with nothing decoding or validating in between.

The seed corpus is a script_pub_key of the vendored segwit transaction,
and an `OP_RETURN` whose payload is written with an `OP_PUSHDATA1` --
the shortest of the three widths a declared length is read from.

**A script has several encodings of one value, so this asserts less.** A
push is accepted in every width that can hold it and written back in the
shortest, as BIP62 asks, so `serialize(parse(data))` need not be `data`.
What is asserted instead is that writing settles it: the octets `serialize`
writes parse and are written back unchanged. The comparison is on octets
and not on commands, because an empty push, `OP_PUSHDATA1 0x00`, parses as
the command `""` and is written as `OP_0`, which parses as `"OP_0"`.

The terminal `ERROR_COMMAND` is dropped first: it marks a place in the
bytes and not an instruction, and `serialize` refuses it.
"""

from __future__ import annotations

import sys

import atheris

from btclib.script import script

# tests/fuzz_corpus_test.py reads this with ast.literal_eval.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = ("btclib.script.script:parse",)


def fuzz_target(data: bytes) -> None:
    """Decode `data` as a script.

    Every exception propagates: `parse` refuses no octets, so there is no
    expected failure to tell a defect from, and `serialize` refuses none
    of what `parse` returns.
    """
    commands = script.parse(data)
    if commands[-1:] == [script.ERROR_COMMAND]:
        commands = commands[:-1]
    written = script.serialize(commands)
    assert script.serialize(script.parse(written)) == written


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
