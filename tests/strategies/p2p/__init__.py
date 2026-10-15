# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Hypothesis strategies for the p2p payload types and the envelope.

Each strategy but the block payload's draws values the type's own
`assert_valid` accepts, so the property they serve is
`parse(serialize(x)) == x`. Numeric fields are drawn across their whole
width, the lowest and highest values included, except the indexes of a
compact block's prefilled transactions, which stay low because a high one
needs as many short ids. Lists, and byte strings with no limit of their
own, stay short: the boundary tests reach the counts Core bounds, such as
`MAX_ADDR_TO_SEND` and `MAX_INV_SZ`. A byte string with its own limit, such
as `MAX_SUBVERSION_LENGTH`, is drawn up to it, except a message's payload,
whose limit is the protocol's message size.

`PAYLOAD_STRATEGIES` maps every concrete payload type to its strategy, and
`PAYLOADS` draws from all of them. `BlockPayload` holds a block of regtest
work: its own `assert_valid` refuses it, and the block's
`assert_valid(REGTEST_POW_LIMIT_BITS)` accepts it.
"""

from dataclasses import replace
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from hypothesis import strategies as st

from btclib.block import PartialMerkleTree
from btclib.block.partial_merkle_tree import _MAX_TRANSACTIONS
from btclib.p2p import (
    Addr,
    AddrV2,
    BIP155Network,
    BlockFilterType,
    BlockPayload,
    BlockTxn,
    CFCheckpt,
    CFHeaders,
    CFilter,
    CmpctBlock,
    Feature,
    FeeFilter,
    GetAddr,
    GetBlocks,
    GetBlockTxn,
    GetCFCheckpt,
    GetCFHeaders,
    GetCFilters,
    GetData,
    GetHeaders,
    Headers,
    Inv,
    Inventory,
    InventoryType,
    Mempool,
    MerkleBlock,
    Message,
    NetworkAddress,
    NetworkAddressV2,
    NotFound,
    Payload,
    Ping,
    Pong,
    PrefilledTransaction,
    Reject,
    RejectCode,
    SendAddrV2,
    SendCmpct,
    SendHeaders,
    SendTxRcncl,
    ServiceFlags,
    TimestampedNetworkAddress,
    TxPayload,
    Verack,
    Version,
    WtxidRelay,
)
from btclib.p2p.limits import (
    MAX_ADDRV2_SIZE,
    MAX_BLOCK_TX_INDEX,
    MAX_FEATUREDATA_LENGTH,
    MAX_FEATUREID_LENGTH,
    MAX_SUBVERSION_LENGTH,
    MIN_FEATUREID_LENGTH,
    PROTOCOL_VERSION,
)
from tests.strategies import BLOCK_HEADERS, BLOCKS, TX_IDS, TXS


def _unsigned(bits: int) -> st.SearchStrategy[int]:
    """Draw an unsigned integer of the width, its bounds drawn on purpose."""
    high = (1 << bits) - 1
    return st.one_of(st.sampled_from([0, 1, high]), st.integers(0, high))


def _signed(bits: int) -> st.SearchStrategy[int]:
    """Draw a signed integer of the width, its bounds drawn on purpose."""
    low = -(1 << (bits - 1))
    high = (1 << (bits - 1)) - 1
    return st.one_of(st.sampled_from([low, -1, 0, 1, high]), st.integers(low, high))


_UINT16 = _unsigned(16)
_UINT32 = _unsigned(32)
_UINT64 = _unsigned(64)

# some lengths cross 253, where a var_int takes three bytes
_LONG_OCTETS = st.one_of(st.binary(max_size=40), st.binary(min_size=250, max_size=260))


def _octets_between(low: int, high: int) -> st.SearchStrategy[bytes]:
    """Draw bytes of a limited length, both limits included.

    Lengths past 253 are drawn where the limit allows.

    `st.binary` keeps its draws short whatever its `max_size`, so the length
    is drawn first.
    """
    lengths = st.sampled_from([low, high]) | st.integers(low, min(high, 40))
    if high >= 250:
        lengths |= st.integers(max(low, 250), high)
    return lengths.flatmap(lambda size: st.binary(min_size=size, max_size=size))


def _short_lists(strategy: st.SearchStrategy[Any]) -> st.SearchStrategy[list[Any]]:
    """Draw a short list."""
    return st.lists(strategy, max_size=5)


# a service bitfield: each named bit, all of them together, any value
_SERVICES = st.one_of(
    st.sampled_from([*ServiceFlags, ServiceFlags(sum(ServiceFlags))]),
    _UINT64,
)

# an IPv4 address is held mapped into sixteen octets, so both are drawn
_IP_ADDRESSES = st.one_of(
    st.builds(IPv4Address, st.binary(min_size=4, max_size=4)),
    st.builds(IPv6Address, st.binary(min_size=16, max_size=16)),
)

NETWORK_ADDRESSES = st.builds(
    NetworkAddress, services=_SERVICES, ip=_IP_ADDRESSES, port=_UINT16
)

TIMESTAMPED_NETWORK_ADDRESSES = st.builds(
    TimestampedNetworkAddress, timestamp=_UINT32, address=NETWORK_ADDRESSES
)

ADDRS = st.builds(Addr, addresses=_short_lists(TIMESTAMPED_NETWORK_ADDRESSES))

# the lengths assert_valid holds an id to, the ones Core checks
_BIP155_ADDRESS_SIZES: dict[int, int] = {
    BIP155Network.IPV4: 4,
    BIP155Network.IPV6: 16,
    BIP155Network.TORV3: 32,
    BIP155Network.I2P: 32,
    BIP155Network.CJDNS: 16,
}


@st.composite
def _network_addresses_v2(draw: st.DrawFn) -> NetworkAddressV2:
    """Draw an entry whose address has the length its network id fixes.

    `assert_valid` holds TORV2, YGGDRASIL and an id no member names to no
    length: lengths up to 40, and `MAX_ADDRV2_SIZE`, are drawn for them.
    """
    network_id = draw(
        st.one_of(st.sampled_from(list(BIP155Network)), st.integers(0, 255))
    )
    size = _BIP155_ADDRESS_SIZES.get(network_id)
    if size is None:
        size = draw(st.sampled_from([0, 1, MAX_ADDRV2_SIZE]) | st.integers(0, 40))
    return NetworkAddressV2(
        timestamp=draw(_UINT32),
        services=draw(_UINT64),
        network_id=network_id,
        address=draw(st.binary(min_size=size, max_size=size)),
        port=draw(_UINT16),
    )


NETWORK_ADDRESSES_V2 = _network_addresses_v2()

ADDRS_V2 = st.builds(AddrV2, addresses=_short_lists(NETWORK_ADDRESSES_V2))

# a type code no member names is drawn as well as each member
_INVENTORY_TYPE_CODES = st.one_of(st.sampled_from(list(InventoryType)), _unsigned(32))

INVENTORIES = st.builds(Inventory, type_code=_INVENTORY_TYPE_CODES, hash=TX_IDS)

_FILTER_TYPES = st.one_of(st.sampled_from(list(BlockFilterType)), _unsigned(8))

# a text the wire holds as UTF-8: no surrogates, which `str.encode` refuses
_TEXTS = st.text(max_size=40)

# the characters the envelope's command holds
_COMMANDS = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=126), max_size=12
)

MESSAGES = st.builds(
    Message,
    magic=st.binary(min_size=4, max_size=4),
    command=_COMMANDS,
    payload=_LONG_OCTETS,
)

VERSIONS = st.builds(
    Version,
    version=st.one_of(st.just(PROTOCOL_VERSION), _signed(32)),
    services=_SERVICES,
    timestamp=_signed(64),
    addr_recv=NETWORK_ADDRESSES,
    addr_from=NETWORK_ADDRESSES,
    nonce=_UINT64,
    user_agent=_octets_between(0, MAX_SUBVERSION_LENGTH),
    start_height=_signed(32),
    relay=st.sampled_from([None, True, False]),
)

# the block's header and transactions are drawn by the block strategies; an
# include_witness that disagrees with the transaction is not a value that
# parses back, and `parse` answers with what the octets carry
TX_PAYLOADS = TXS.map(lambda tx: TxPayload(tx, tx.is_segwit))

BLOCK_PAYLOADS = BLOCKS.map(
    lambda block: BlockPayload(block, block.is_segwit, check_validity=False)
)


@st.composite
def _merkle_blocks(draw: st.DrawFn) -> MerkleBlock:
    """Draw a header and a partial tree.

    Either the tree is built over a few transaction ids and the header
    carries its root, or the tree matches nothing, holds one hash and
    counts any number of transactions, and the header is drawn on its own:
    `assert_valid` does not ask the header's root to be the tree's.
    """
    if draw(st.booleans()):
        count = draw(
            st.one_of(
                st.sampled_from([1, _MAX_TRANSACTIONS]),
                st.integers(1, _MAX_TRANSACTIONS),
            )
        )
        tree = PartialMerkleTree(count, [draw(TX_IDS)], b"\x00")
        return MerkleBlock(draw(BLOCK_HEADERS), tree)
    txids = draw(st.lists(st.binary(min_size=32, max_size=32), min_size=1, max_size=8))
    # equal siblings make the tree mutated, which `assert_valid` refuses
    txids = list(dict.fromkeys(txids))
    matches = draw(st.lists(st.booleans(), min_size=len(txids), max_size=len(txids)))
    tree = PartialMerkleTree.from_txids(txids, matches)
    header = replace(draw(BLOCK_HEADERS), merkle_root=tree.merkle_root)
    return MerkleBlock(header, tree)


MERKLE_BLOCKS = _merkle_blocks()


@st.composite
def _prefilled_transactions(draw: st.DrawFn) -> list[PrefilledTransaction]:
    """Draw prefilled transactions at increasing, low indexes.

    The whole range of indexes is drawn in `compact_blocks_test.py`.
    """
    indexes = draw(st.lists(st.integers(0, 6), max_size=3, unique=True).map(sorted))
    return [PrefilledTransaction(index, draw(TXS)) for index in indexes]


@st.composite
def _cmpct_blocks(draw: st.DrawFn) -> CmpctBlock:
    """Draw a compact block whose prefilled indexes fall inside it."""
    prefilled = draw(_prefilled_transactions())
    # the block holds the short ids' transactions and the prefilled ones
    minimum = prefilled[-1].index + 1 - len(prefilled) if prefilled else 0
    short_ids = draw(st.lists(_unsigned(48), min_size=minimum, max_size=minimum + 3))
    return CmpctBlock(draw(BLOCK_HEADERS), draw(_UINT64), short_ids, prefilled)


CMPCT_BLOCKS = _cmpct_blocks()

# strictly increasing, from zero to the last index a block holds
_BLOCK_TX_INDEXES = st.lists(
    st.one_of(
        st.sampled_from([0, 1, 252, 253, MAX_BLOCK_TX_INDEX]),
        st.integers(0, MAX_BLOCK_TX_INDEX),
    ),
    max_size=8,
    unique=True,
).map(sorted)

# the payload strategies, keyed by the type each draws
PAYLOAD_STRATEGIES: dict[type[Payload], st.SearchStrategy[Payload]] = {
    Version: VERSIONS,
    Verack: st.builds(Verack),
    Addr: ADDRS,
    AddrV2: ADDRS_V2,
    SendAddrV2: st.builds(SendAddrV2),
    Ping: st.builds(Ping, nonce=_UINT64),
    Pong: st.builds(Pong, nonce=_UINT64),
    Inv: st.builds(Inv, items=_short_lists(INVENTORIES)),
    GetData: st.builds(GetData, items=_short_lists(INVENTORIES)),
    NotFound: st.builds(NotFound, items=_short_lists(INVENTORIES)),
    GetBlocks: st.builds(
        GetBlocks,
        version=_signed(32),
        locator=_short_lists(TX_IDS),
        hash_stop=TX_IDS,
    ),
    GetHeaders: st.builds(
        GetHeaders,
        version=_signed(32),
        locator=_short_lists(TX_IDS),
        hash_stop=TX_IDS,
    ),
    Headers: st.builds(Headers, headers=_short_lists(BLOCK_HEADERS)),
    GetCFilters: st.builds(
        GetCFilters, filter_type=_FILTER_TYPES, start_height=_UINT32, stop_hash=TX_IDS
    ),
    CFilter: st.builds(
        CFilter,
        filter_type=_FILTER_TYPES,
        block_hash=TX_IDS,
        filter_bytes=_LONG_OCTETS,
    ),
    GetCFHeaders: st.builds(
        GetCFHeaders,
        filter_type=_FILTER_TYPES,
        start_height=_UINT32,
        stop_hash=TX_IDS,
    ),
    CFHeaders: st.builds(
        CFHeaders,
        filter_type=_FILTER_TYPES,
        stop_hash=TX_IDS,
        previous_filter_header=TX_IDS,
        filter_hashes=_short_lists(TX_IDS),
    ),
    GetCFCheckpt: st.builds(GetCFCheckpt, filter_type=_FILTER_TYPES, stop_hash=TX_IDS),
    CFCheckpt: st.builds(
        CFCheckpt,
        filter_type=_FILTER_TYPES,
        stop_hash=TX_IDS,
        filter_headers=_short_lists(TX_IDS),
    ),
    TxPayload: TX_PAYLOADS,
    BlockPayload: BLOCK_PAYLOADS,
    SendCmpct: st.builds(SendCmpct, announce=st.booleans(), version=_UINT64),
    CmpctBlock: CMPCT_BLOCKS,
    GetBlockTxn: st.builds(GetBlockTxn, block_hash=TX_IDS, indexes=_BLOCK_TX_INDEXES),
    BlockTxn: st.builds(
        BlockTxn, block_hash=TX_IDS, transactions=st.lists(TXS, max_size=3)
    ),
    MerkleBlock: MERKLE_BLOCKS,
    GetAddr: st.builds(GetAddr),
    Mempool: st.builds(Mempool),
    SendHeaders: st.builds(SendHeaders),
    WtxidRelay: st.builds(WtxidRelay),
    SendTxRcncl: st.builds(SendTxRcncl, version=_UINT32, salt=_UINT64),
    FeeFilter: st.builds(FeeFilter, feerate=_signed(64)),
    Feature: st.builds(
        Feature,
        feature_id=_octets_between(MIN_FEATUREID_LENGTH, MAX_FEATUREID_LENGTH),
        feature_data=_octets_between(0, MAX_FEATUREDATA_LENGTH),
    ),
    Reject: st.builds(
        Reject,
        message=_TEXTS,
        code=st.one_of(st.sampled_from(list(RejectCode)), _unsigned(8)),
        reason=_TEXTS,
        data=st.sampled_from([0, 32]).flatmap(
            lambda size: st.binary(min_size=size, max_size=size)
        ),
    ),
}

PAYLOADS = st.one_of(*PAYLOAD_STRATEGIES.values())
