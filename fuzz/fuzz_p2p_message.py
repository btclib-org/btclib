# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing the p2p wire-format envelope parser.

`btclib.p2p.message.Message.parse` is the earliest point at which bytes
read off a peer connection enter this codebase: no signature check and
no per-command dispatch stands in front of it, so a stranger's own
choice of bytes reaches it directly. That ranking is
btclib-org/.github#342's own -- an entry point reached from the network
before any cryptographic verification is worth more than one reached
only after a signature checks out -- and it is why this is the target
rather than a deserializer a caller only reaches once a `version`
message has already been accepted.

A crash here on hostile bytes is a defect in `parse` itself, never in
this harness: `data` is unconstrained bytes handed straight to `parse`,
with nothing decoding, validating or otherwise standing between the
fuzzer's own choice of octets and the parser being fuzzed. `parse`'s own
contract is to raise `BTClibException` on every malformed input it can
be given -- `BTClibValueError` for octets no valid message carries,
`IncompleteMessageError` for one the peer has not finished sending -- so
that family is caught below as the expected outcome. An `IndexError`, a
`RecursionError` or an uncaught assertion is not, and propagates to
atheris as the finding it is.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.message import Message

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = ("btclib.p2p.message:Message.parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a p2p message, as a connection reading a socket would.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    with contextlib.suppress(BTClibException):
        Message.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
