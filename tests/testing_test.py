# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.testing` package and its `blocks` module.

`tests/block/block_test.py` checks each block's hash and contents, read
through `blocks`. What is left here is the refusals.
`tests/imports_test.py` holds that `from btclib.testing import *` works
without hypothesis.
"""

import pytest

from btclib.block import Block
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.testing.blocks import NAMES, read_bytes


@pytest.mark.parametrize("name", NAMES)
def test_every_name_reads_a_block(name: str) -> None:
    """Each file `NAMES` lists is there, and parses as a mainnet block."""
    block_bytes = read_bytes(name)
    assert Block.parse(block_bytes).serialize() == block_bytes


@pytest.mark.parametrize(
    "name", ["block_1.bin", "block_481824.bin", "../blocks.py", "", "BLOCK_170.BIN"]
)
def test_a_name_not_listed_is_refused(name: str) -> None:
    """A name `NAMES` does not list is refused, a path included."""
    with pytest.raises(BTClibValueError, match="unknown block file: "):
        read_bytes(name)


def test_a_name_that_is_not_text_is_refused() -> None:
    """Bytes, a number or None is not a name."""
    for name in (b"block_170.bin", 170, None):
        with pytest.raises(BTClibTypeError, match="invalid block file name type: "):
            read_bytes(name)  # type: ignore[arg-type]
