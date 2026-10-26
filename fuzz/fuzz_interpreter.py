# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness running `btclib.script.engine.script.eval_script`.

A spender chooses both the script and the stack it starts from, so the
interpreter runs input nobody has checked. Each input runs under
`ALL_FLAGS` and under `NO_FLAGS`.

**A refusal is an answer here, so nothing is caught.** `eval_script`
returns the `ScriptError` that stopped a script rather than raising it,
and every exception it raises is the finding.

`split` reads one input as a stack and a script. The first octet is the
number of stack elements. Each element follows its length, two octets
little-endian. What is left is the script. An input shorter than what it
declares gives shorter elements, so that every input runs.

The seeds come from `tests/script_engine/_data/script_tests.json`, one
per distinct split. The stack is a vector's witness, with the
placeholders filled as `tests/script_engine/script_test.py` fills them.
The script is the vector's scriptSig followed by its scriptPubKey, each
compiled by `tests/script_engine/__init__.py`'s `parse_script`. A seed is
named after the index in that file of the first vector giving it.
"""

from __future__ import annotations

import sys

import atheris

from btclib.script.engine import ALL_FLAGS, NO_FLAGS
from btclib.script.engine import script as engine

# tests/fuzz_corpus_test.py reads this with ast.literal_eval.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = ("btclib.script.engine.script:eval_script",)


def split(data: bytes) -> tuple[bytes, list[bytes]]:
    """Return the script and the stack elements `data` holds."""
    count, rest = data[:1], data[1:]
    stack = []
    for _ in range(count[0] if count else 0):
        size = int.from_bytes(rest[:2], "little")
        stack.append(rest[2 : 2 + size])
        rest = rest[2 + size :]
    return rest, stack


def fuzz_target(data: bytes) -> None:
    """Run the script `data` holds on its stack, under both sets of flags."""
    script_bytes, stack = split(data)
    for flags in (ALL_FLAGS, NO_FLAGS):
        engine.eval_script(script_bytes, stack, flags)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
