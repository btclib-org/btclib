# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The strategies draw valid values, and reach the shapes they are for."""

from typing import Any

import pytest
from hypothesis import find, given

from btclib.alias import ScriptType
from btclib.block import Block, BlockHeader
from btclib.block.partial_merkle_tree import _MAX_TRANSACTIONS
from btclib.block.proof_of_work import REGTEST_POW_LIMIT_BITS
from btclib.p2p import (
    BIP155Network,
    BlockPayload,
    Feature,
    GetBlockTxn,
    Inventory,
    InventoryType,
    MerkleBlock,
    Message,
    NetworkAddress,
    NetworkAddressV2,
    Payload,
    Reject,
    TimestampedNetworkAddress,
)
from btclib.p2p.limits import (
    MAX_ADDRV2_SIZE,
    MAX_BLOCK_TX_INDEX,
    MAX_FEATUREDATA_LENGTH,
    MAX_FEATUREID_LENGTH,
    MAX_SUBVERSION_LENGTH,
    MIN_FEATUREID_LENGTH,
)
from btclib.script import ScriptPubKey, Witness, parse
from btclib.script.script import ERROR_COMMAND
from btclib.testing.strategies import (
    BLOCK_HEADERS,
    BLOCKS,
    OUT_POINTS,
    SCRIPT_PUB_KEYS,
    SCRIPTS,
    TX_INS,
    TX_OUTS,
    TXS,
    WITNESSES,
)
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests.strategies.p2p import (
    CMPCT_BLOCKS,
    INVENTORIES,
    MESSAGES,
    NETWORK_ADDRESSES,
    NETWORK_ADDRESSES_V2,
    PAYLOAD_STRATEGIES,
    PAYLOADS,
    TIMESTAMPED_NETWORK_ADDRESSES,
    TX_PAYLOADS,
    VERSIONS,
)


@given(out_point=OUT_POINTS, witness=WITNESSES, tx_out=TX_OUTS, tx_in=TX_INS)
def test_strategies_draw_valid_values(
    out_point: OutPoint, witness: Witness, tx_out: TxOut, tx_in: TxIn
) -> None:
    """Every value a strategy draws passes its type's `assert_valid`."""
    out_point.assert_valid()
    witness.assert_valid()
    tx_out.assert_valid()
    tx_in.assert_valid()


@given(tx=TXS)
def test_strategy_draws_valid_transactions(tx: Tx) -> None:
    """Every transaction the strategy draws passes `assert_valid`."""
    tx.assert_valid()


def test_scripts_include_a_push_cut_short() -> None:
    """A script that parse ends with ERROR_COMMAND is among the draws."""
    find(SCRIPTS, lambda script: ERROR_COMMAND in parse(script))


def test_scripts_include_a_push_of_over_255_bytes() -> None:
    """A push with a two-byte length, OP_PUSHDATA2, is among the draws."""
    find(
        SCRIPTS,
        lambda script: any(isinstance(c, str) and len(c) > 510 for c in parse(script)),
    )


@given(script_pub_key=SCRIPT_PUB_KEYS)
def test_strategy_draws_valid_script_pub_keys(script_pub_key: ScriptPubKey) -> None:
    """Every output script the strategy draws passes `assert_valid`."""
    script_pub_key.assert_valid()


@pytest.mark.parametrize(
    "script_type",
    [
        "nulldata",
        "p2ms",
        "p2pk",
        "p2pkh",
        "p2sh",
        "p2tr",
        "p2wpkh",
        "p2wsh",
        "unknown",
        "witness_unknown",
    ],
)
def test_script_pub_keys_include_each_type(script_type: ScriptType) -> None:
    """Each type `type_and_payload` names is among the draws."""
    find(SCRIPT_PUB_KEYS, lambda script_pub_key: script_pub_key.type == script_type)


@given(header=BLOCK_HEADERS)
def test_strategy_draws_valid_block_headers(header: BlockHeader) -> None:
    """Every header the strategy draws passes `assert_valid`."""
    header.assert_valid()


@given(block=BLOCKS)
def test_strategy_draws_valid_blocks(block: Block) -> None:
    """Every block drawn passes `assert_valid` with regtest's limit."""
    block.assert_valid(REGTEST_POW_LIMIT_BITS)


def test_blocks_include_a_witness_commitment() -> None:
    """A block carrying a BIP141 commitment is among the draws."""
    find(BLOCKS, lambda block: block.witness_commitment is not None)


def test_blocks_include_a_coinbase_alone_and_several_transactions() -> None:
    """A block of the coinbase alone, and one of three or more transactions."""
    find(BLOCKS, lambda block: len(block.transactions) == 1)
    find(BLOCKS, lambda block: len(block.transactions) >= 3)


@given(
    address=NETWORK_ADDRESSES,
    entry=TIMESTAMPED_NETWORK_ADDRESSES,
    entry_v2=NETWORK_ADDRESSES_V2,
    item=INVENTORIES,
    message=MESSAGES,
)
def test_strategies_draw_valid_p2p_values(
    address: NetworkAddress,
    entry: TimestampedNetworkAddress,
    entry_v2: NetworkAddressV2,
    item: Inventory,
    message: Message,
) -> None:
    """Every value a p2p strategy draws passes its type's `assert_valid`."""
    address.assert_valid()
    entry.assert_valid()
    entry_v2.assert_valid()
    item.assert_valid()
    message.assert_valid()


@given(payload=PAYLOADS)
def test_strategy_draws_valid_payloads(payload: Payload) -> None:
    """Every payload drawn passes `assert_valid`, a block with regtest's."""
    # `Payload` declares no `assert_valid`; every subclass has one
    checked: Any = payload
    if isinstance(payload, BlockPayload):
        payload.block.assert_valid(REGTEST_POW_LIMIT_BITS)
    else:
        checked.assert_valid()


@pytest.mark.parametrize("relay", [None, True, False])
def test_versions_include_each_relay_flag(relay: bool | None) -> None:
    """A `version` with no relay octet, one asking for it and one refusing."""
    find(VERSIONS, lambda version: version.relay is relay)


def test_network_addresses_v2_include_an_unnamed_id_and_the_longest_address() -> None:
    """An entry whose id is a plain integer, and one of the longest address."""
    find(
        NETWORK_ADDRESSES_V2,
        lambda entry: not isinstance(entry.network_id, BIP155Network),
    )
    find(NETWORK_ADDRESSES_V2, lambda entry: len(entry.address) == MAX_ADDRV2_SIZE)


def test_network_addresses_include_an_ipv4_peer() -> None:
    """An address held as `::ffff:a.b.c.d`."""
    find(NETWORK_ADDRESSES, lambda address: address.ip.ipv4_mapped is not None)


def test_inventories_include_a_type_code_no_member_names() -> None:
    """An entry whose type code is a plain integer."""
    find(INVENTORIES, lambda item: not isinstance(item.type_code, InventoryType))


def test_compact_blocks_include_prefilled_transactions_and_short_ids() -> None:
    """A compact block carrying both kinds of transaction."""
    find(
        CMPCT_BLOCKS,
        lambda block: bool(block.short_ids) and bool(block.prefilled_txns),
    )


def test_block_transaction_requests_include_the_last_index() -> None:
    """A request reaching the last index a block holds."""
    find(
        PAYLOAD_STRATEGIES[GetBlockTxn],
        lambda request: MAX_BLOCK_TX_INDEX in request.indexes,
    )


def test_tx_payloads_include_a_witness() -> None:
    """A `tx` payload written with a witness, and one without."""
    find(TX_PAYLOADS, lambda payload: payload.include_witness)
    find(TX_PAYLOADS, lambda payload: not payload.include_witness)


def test_rejects_include_a_hash() -> None:
    """A `reject` that names the transaction or block it refuses."""
    find(PAYLOAD_STRATEGIES[Reject], lambda payload: bool(payload.data))


def test_merkle_blocks_include_a_large_count_and_a_foreign_root() -> None:
    """A tree counting the most transactions, and a header with another root."""
    find(
        PAYLOAD_STRATEGIES[MerkleBlock],
        lambda payload: payload.tree.n_transactions == _MAX_TRANSACTIONS,
    )
    find(
        PAYLOAD_STRATEGIES[MerkleBlock],
        lambda payload: payload.header.merkle_root != payload.tree.merkle_root,
    )


def test_versions_include_the_longest_user_agent() -> None:
    """A user agent of the limit, past where its var_int grows."""
    find(VERSIONS, lambda v: len(v.user_agent) == MAX_SUBVERSION_LENGTH)


@pytest.mark.parametrize(
    "field, limit",
    [
        ("feature_id", MAX_FEATUREID_LENGTH),
        ("feature_id", MIN_FEATUREID_LENGTH),
        ("feature_data", MAX_FEATUREDATA_LENGTH),
        ("feature_data", 253),
    ],
)
def test_features_include_each_length_limit(field: str, limit: int) -> None:
    """The feature lengths the format bounds are drawn.

    A feature id at both of its limits, and feature data at its limit and
    at 253.
    """
    find(
        PAYLOAD_STRATEGIES[Feature],
        lambda payload: len(getattr(payload, field)) == limit,
    )
