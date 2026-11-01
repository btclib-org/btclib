# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Mainnet blocks, serialized as `bitcoin-cli getblock <hash> 0` returns them.

`NAMES` lists the files: the blocks at heights 170, 200000 and 481824, the
last with its witnesses. `read_bytes` returns one of them.
`tests/_data/README.md` records each block's hash and the day it was
pulled.
"""

from pathlib import Path

from btclib.exceptions import BTClibValueError
from btclib.utils import assert_type

__all__ = ["NAMES", "read_bytes"]

NAMES = ("block_170.bin", "block_200000.bin", "block_481824_complete.bin")

_DATA = Path(__file__).parent / "_data"


def read_bytes(name: str) -> bytes:
    """Return the bytes of the block file `name`, one of `NAMES`."""
    assert_type(name, str, "block file name")
    if name not in NAMES:
        raise BTClibValueError(f"unknown block file: {name}")
    return (_DATA / name).read_bytes()
