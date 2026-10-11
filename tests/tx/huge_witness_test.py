# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A transaction whose witness is almost all of it.

rust-bitcoin's `huge_witness.hex` holds a one-input transaction whose
witness stack has hundreds of thousands of items, all but two of them
empty. rust-bitcoin's commit adding it says it broke past versions of
rust-bitcoin and LND, and points at
https://github.com/romanz/electrs/issues/783.

`_data/huge_witness.bin` holds the bytes. tests/_data/README.md has the source,
the pinned revision and the licence. The txid and the wtxid below are
what Bitcoin Core's `decoderawtransaction` answers for those bytes
(`txid` and `hash`).
"""

from pathlib import Path

from btclib.consensus import MAX_BLOCK_WEIGHT
from btclib.tx import Tx

_TXID = "73be398c4bdc43709db7398106609eea2a7841aaf3a4fa2000dc18184faa2a7e"
_WTXID = "48b0f5ea87a2a7acbd7e7d9a44821f0cbeaeda73443c3c867ccc081fdebbcc67"

_RAW = (Path(__file__).parent / "_data" / "huge_witness.bin").read_bytes()


def test_parse_serialize_round_trip() -> None:
    """Serialize gives back the bytes `parse` read."""
    tx = Tx.parse(_RAW)
    assert tx.serialize(include_witness=True) == _RAW


def test_ids_are_the_ones_core_answers() -> None:
    """The txid and the wtxid are Core's."""
    tx = Tx.parse(_RAW)
    assert tx.id.hex() == _TXID
    assert tx.hash.hex() == _WTXID


def test_the_witness_is_all_but_a_few_bytes_of_it() -> None:
    """The stripped transaction is tiny and the witness stack is huge."""
    tx = Tx.parse(_RAW)
    assert tx.is_segwit
    assert tx.size == len(_RAW)
    assert len(tx.serialize(include_witness=False)) < 100
    assert tx.weight < MAX_BLOCK_WEIGHT
    assert len(tx.vin) == 1
    stack = tx.vin[0].script_witness.stack
    assert len(stack) > 100_000
    assert sum(1 for item in stack if item) == 2
