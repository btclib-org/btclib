# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.merkleblock.MerkleBlock.parse`.

A `merkleblock` is a header and a partial Merkle tree, read off a peer
that answers a bloom-filtered request. Its payload reaches this parser
behind `Message.parse`'s envelope and ahead of any check of the proof it
carries. The tree is the part a peer controls: a count of hashes, a
count of flag bytes and what the two say about the shape of the block.

`data` is unconstrained bytes handed straight to `parse`, which raises
`BTClibException` on every malformed input. Any other exception is a
defect in `parse` and propagates to atheris as the finding it is.

The format has one encoding, so what `parse` accepts must `serialize` back
to `data` itself. An input that does not was misread by `parse` or
miswritten by `serialize`, and the `AssertionError` reaches atheris as the
finding it is.
"""

from __future__ import annotations

import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.merkleblock import MerkleBlock

# tests/fuzz_corpus_test.py reads this with ast.literal_eval.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = ("btclib.p2p.merkleblock:MerkleBlock.parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a `merkleblock` payload.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input.
    """
    try:
        merkle_block = MerkleBlock.parse(data)
    except BTClibException:
        return
    assert merkle_block.serialize() == data


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
