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
"""

from __future__ import annotations

import sys

import atheris

from btclib.script import script

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = ("btclib.script.script:parse",)


def fuzz_target(data: bytes) -> None:
    """Decode `data` as a script.

    Every exception propagates: `parse` refuses no octets, so there is no
    expected failure to tell a defect from.
    """
    script.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
