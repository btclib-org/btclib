# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.data`'s payload parsers.

`tx` and `block` are reached behind `Message.parse`'s envelope and ahead
of any signature check -- a peer sends either unsolicited, in answer to
a `getdata` it was never asked to prove anything about first.
`fuzz/fuzz_handshake.py`'s own docstring is where the absence of a
dispatch table is argued; the same reasoning puts `TxPayload.parse` and
`BlockPayload.parse` here, reached directly on `message.payload` once a
caller has read `message.command`. `p2p_` is in the filename because
`fuzz_data.py` would read as fuzzing data rather than as fuzzing
`btclib.p2p.data`, the same reason `fuzz_p2p_message.py` is not
`fuzz_message.py`.

The module has two `Payload` subclasses -- `TxPayload` and
`BlockPayload` -- so this harness runs both `parse` methods against the
same bytes. Each wraps `btclib.tx.Tx.parse`/`btclib.block.Block.parse`
with no octet of its own in front, `src/btclib/p2p/data.py`'s own
docstring is where that is argued; `Tx.parse` and `Block.parse` are
`fuzz/fuzz_tx.py`'s and `fuzz/fuzz_block.py`'s, reached by every caller
holding a transaction or a block with no peer connection behind it.

The format has one encoding, so what `parse` accepts must `serialize` back
to `data` itself. An input that does not was misread by `parse`, and the
`AssertionError` reaches atheris as the finding it is.
"""

from __future__ import annotations

import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.data import BlockPayload, TxPayload

# tests/fuzz_corpus_test.py reads this with ast.literal_eval.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = (
    "btclib.p2p.data:TxPayload.parse",
    "btclib.p2p.data:BlockPayload.parse",
)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a `tx` payload, then as a `block` payload.

    `BTClibException` is swallowed as each `parse`'s own refusal of
    malformed input; any other exception propagates, which is how
    atheris tells a defect in `parse` from the domain of input it
    already rejects.
    """
    for cls in (TxPayload, BlockPayload):
        try:
            parsed = cls.parse(data)
        except BTClibException:
            continue
        assert parsed.serialize() == data


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
