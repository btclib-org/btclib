# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Fuzz corpora of Bitcoin Core and rust-bitcoin, replayed through btclib.

`bitcoin-core/qa-assets` holds, per Core fuzz target, the inputs that
target's fuzzers found interesting. `rust-bitcoin/qa-assets` does the
same for rust-bitcoin's targets. Where the input is the raw bytes of a
format btclib parses, the same bytes go to the btclib parser. A parser
may refuse them with a `BTClibException`; any other exception is a
defect, because the parsers' contract is that malformed octets are
refused in that one family.

A source is skipped where its variable is unset or empty:
`BTCLIB_QA_ASSETS` for Core's checkout, `BTCLIB_RUST_BITCOIN_QA_ASSETS`
for rust-bitcoin's.

    BTCLIB_QA_ASSETS=/path/to/qa-assets uv run pytest \
        tests/integration/qa_assets_test.py

`qa-assets.yml` runs it weekly against both repositories' default
branch, sparse-checking out the directories `TARGETS` names.

`TARGETS` is the table from a qa-assets directory to the parser that
reads its bytes. `reading` says how the source's own target reads them:
a file of `src/test/fuzz/` in `bitcoin/bitcoin`, or of
`fuzz/fuzz_targets/` in `rust-bitcoin/rust-bitcoin`. Core's
targets read an object off the front of the input and ignore what
follows (`SpanReader{buffer} >> obj`), while `parse` on bytes refuses
trailing bytes before it builds the object. So a Core row hands `parse` a
`BytesIO`, which it reads from and leaves where the object ends, and
reaches the code a refused-at-the-end input would never reach. The rows
whose source consumes the whole input (`decode_tx`, which needs the hex
of the whole input to decode, and every rust-bitcoin row) hand it the
bytes.

Each parser that takes `check_validity` is replayed with it on and off,
the second reaching the code that runs on a structure the first would
have refused.

A directory gets a row only where its target reads the input as the
octets of one format btclib parses. So these are not replayed:

- a target that builds its values from the input, as Core's
  `FuzzedDataProvider` does (`script`, `primitives_transaction`) and
  rust-bitcoin's typed `fuzz_target!` does (`bitcoin_arbitrary_block`):
  the bytes are choices, not a format;
- a text target (`key_io`, `parse_script`, `bitcoin_parse_address`):
  not octets of a format;
- PSBT and descriptors (`psbt`, `descriptor_parse`,
  `bitcoin_0_32_deserialize_psbt`): btclib reads neither;
  `btclib-wallet` does;
- a target that reads no format (`hashes_sha256`).

Some directories that fit have no row yet: issue #2631.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

import pytest

from btclib import script, var_bytes
from btclib.alias import BinaryData
from btclib.block.block import Block
from btclib.block.block_header import BlockHeader
from btclib.block.partial_merkle_tree import PartialMerkleTree
from btclib.exceptions import BTClibException
from btclib.p2p.compact_blocks import (
    BlockTxn,
    CmpctBlock,
    GetBlockTxn,
    PrefilledTransaction,
)
from btclib.p2p.inventory import Inventory
from btclib.p2p.merkleblock import MerkleBlock
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut

pytestmark = pytest.mark.integration

# a parser and the way to ask it: (octets or a stream, check_validity)
Parser = Callable[[BinaryData, bool], object]


@dataclass(frozen=True)
class Target:
    """A qa-assets directory, how its source reads it, and btclib's readings."""

    directory: str
    reading: str
    parsers: tuple[Parser, ...]
    source: str = "bitcoin-core"
    # whether the source reads an object off the front of the input and
    # ignores the rest, so the parser is given a stream and not the bytes
    front: bool = True
    # the values of `check_validity` to replay with
    validity: tuple[bool, ...] = (True, False)


def _parser(parse: Callable[..., object]) -> Parser:
    """Return `parse`, called with `check_validity` by keyword."""
    return lambda data, check_validity: parse(data, check_validity=check_validity)


def _script_deserialize(data: BinaryData, check_validity: bool) -> object:
    """Return the script a CompactSize-prefixed byte vector holds."""
    return script.parse(var_bytes.parse(data))


def _script(data: BinaryData, check_validity: bool) -> object:
    """Return the script the octets are, with no length prefix."""
    return script.parse(data)


def _decode_hex_tx_without_witness(data: BinaryData, check_validity: bool) -> object:
    """Return the transaction read as `DecodeHexTx` reads it with no witness."""
    return Tx.parse_without_witness(data, check_validity=check_validity)


_WITH_WITNESS = "CBlock, TX_WITH_WITNESS"

TARGETS = (
    Target(
        "block_deserialize",
        f"deserialize.cpp: {_WITH_WITNESS}",
        (_parser(Block.parse),),
    ),
    Target(
        "block", f"block.cpp: {_WITH_WITNESS}, then CheckBlock", (_parser(Block.parse),)
    ),
    Target(
        "blockheader_deserialize",
        "deserialize.cpp: CBlockHeader",
        (_parser(BlockHeader.parse),),
    ),
    Target(
        "script_deserialize",
        "deserialize.cpp: CScript, a CompactSize length and its bytes",
        (_script_deserialize,),
        validity=(True,),
    ),
    Target(
        "tx_in_deserialize",
        "deserialize.cpp: CTxIn, which carries no witness",
        (_parser(TxIn.parse),),
    ),
    Target("tx_in", "tx_in.cpp: CTxIn", (_parser(TxIn.parse),)),
    Target("tx_out", "tx_out.cpp: CTxOut", (_parser(TxOut.parse),)),
    Target(
        "out_point_deserialize",
        "deserialize.cpp: COutPoint",
        (_parser(OutPoint.parse),),
    ),
    Target(
        "transaction",
        "transaction.cpp: CTransaction, TX_WITH_WITNESS",
        (_parser(Tx.parse),),
    ),
    Target(
        "decode_tx",
        "decode_tx.cpp: DecodeHexTx on the hex of the input, which neither"
        " runs CheckTransaction nor requires a witness",
        (_parser(Tx.parse), _decode_hex_tx_without_witness),
        front=False,
    ),
    Target(
        "prefilled_transaction_deserialize",
        "deserialize.cpp: PrefilledTransaction",
        (_parser(PrefilledTransaction.parse),),
    ),
    Target(
        "blocktransactions_deserialize",
        "deserialize.cpp: BlockTransactions, `blocktxn`",
        (_parser(BlockTxn.parse),),
    ),
    Target(
        "blocktransactionsrequest_deserialize",
        "deserialize.cpp: BlockTransactionsRequest, `getblocktxn`",
        (_parser(GetBlockTxn.parse),),
    ),
    Target(
        "block_header_and_short_txids_deserialize",
        "deserialize.cpp: CBlockHeaderAndShortTxIDs, `cmpctblock`",
        (_parser(CmpctBlock.parse),),
    ),
    Target(
        "merkle_block_deserialize",
        "deserialize.cpp: CMerkleBlock, `merkleblock`",
        (_parser(MerkleBlock.parse),),
    ),
    Target(
        "partial_merkle_tree_deserialize",
        "deserialize.cpp: CPartialMerkleTree",
        (_parser(PartialMerkleTree.parse),),
    ),
    Target(
        "inv_deserialize",
        "deserialize.cpp: CInv, an inventory entry",
        (_parser(Inventory.parse),),
    ),
    Target(
        "bitcoin_deserialize_transaction",
        "deserialize_transaction.rs: bitcoin::Transaction",
        (_parser(Tx.parse),),
        source="rust-bitcoin",
        front=False,
    ),
    Target(
        "bitcoin_deserialize_block",
        "deserialize_block.rs: bitcoin::Block",
        (_parser(Block.parse),),
        source="rust-bitcoin",
        front=False,
    ),
    Target(
        "bitcoin_deserialize_prefilled_transaction",
        "deserialize_prefilled_transaction.rs: p2p::bip152::PrefilledTransaction",
        (_parser(PrefilledTransaction.parse),),
        source="rust-bitcoin",
        front=False,
    ),
    Target(
        "bitcoin_deserialize_script",
        "deserialize_script.rs: bitcoin::ScriptPubKeyBuf,"
        " a CompactSize length and its bytes",
        (_script_deserialize,),
        source="rust-bitcoin",
        front=False,
        validity=(True,),
    ),
    Target(
        "bitcoin_deserialize_witness",
        "deserialize_witness.rs: bitcoin::Witness",
        (_parser(Witness.parse),),
        source="rust-bitcoin",
        front=False,
    ),
    Target(
        "bitcoin_script_bytes_to_asm_fmt",
        "script_bytes_to_asm_fmt.rs: bitcoin::WitnessScript::from_bytes",
        (_script,),
        source="rust-bitcoin",
        front=False,
        validity=(True,),
    ),
)

# the environment variable that names a checkout, per source
_CHECKOUTS = {
    "bitcoin-core": "BTCLIB_QA_ASSETS",
    "rust-bitcoin": "BTCLIB_RUST_BITCOIN_QA_ASSETS",
}


@pytest.mark.parametrize(
    "target", TARGETS, ids=lambda target: f"{target.source}-{target.directory}"
)
def test_corpus_is_refused_in_btclibs_own_exception(target: Target) -> None:
    """Every input is parsed, or refused with `BTClibException`."""
    variable = _CHECKOUTS[target.source]
    checkout = os.environ.get(variable)
    if not checkout:
        # the prefix is what integration-bitcoind.yml exempts from its
        # check that the tests ran
        pytest.skip(
            f"qa-assets: set {variable} to a {target.source} qa-assets checkout"
        )
    inputs = sorted((Path(checkout) / "fuzz_corpora" / target.directory).iterdir())
    # a renamed or emptied directory would otherwise pass by replaying nothing
    assert inputs, f"{target.directory} holds no input"

    defects = []
    for path in inputs:
        data = path.read_bytes()
        for parse in target.parsers:
            for check_validity in target.validity:
                # a stream per call: a parse leaves it where the object ends
                subject = BytesIO(data) if target.front else data
                try:
                    parse(subject, check_validity)
                except BTClibException:
                    pass
                except Exception as exc:  # noqa: BLE001 -- any other is the finding
                    defects.append(
                        f"{path.name} ({len(data)} octets),"
                        f" check_validity={check_validity}: {exc!r}"
                    )
    assert not defects, "\n".join([target.reading, *defects])
