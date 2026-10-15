# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Hypothesis strategies for the transaction types, scripts and blocks.

Each transaction strategy draws values the type's own `assert_valid`
accepts, and never a coinbase input: the property they serve is
`parse(serialize(x)) == x`, and a value the library refuses to build is
not a value to round-trip. Boundaries are drawn on purpose, not left to
chance: the null transaction id, an amount of zero and the largest one,
and the lowest and highest of each four-byte field. Some lengths reach
253, where a var_int takes three bytes.

`COMMAND_LISTS` draws commands as `script.parse` spells them, so
`parse(serialize(c)) == c`. `MIXED_COMMAND_LISTS` adds integers, bytes,
lower-case hex and the aliases. `SCRIPTS` draws bytes, well formed or not.

`SCRIPT_PUB_KEYS` draws the standard output scripts of every type the
classifier names, and bytes of any kind, on every network. `BLOCK_HEADERS`
draws headers `assert_valid` accepts, with no work done: its bits are any
four bytes. Its times are whole seconds, the only ones the four bytes hold
without loss. `BLOCKS` draws blocks that `assert_valid` accepts with
`REGTEST_POW_LIMIT_BITS` as the limit, mainnet's work being out of reach
of a test; each has a coinbase, up to `MAX_BLOCK_TRANSACTIONS` - 1 other
transactions and, where any carries a witness, the BIP141 commitment.

The p2p payload types and the envelope are in `tests.strategies.p2p`, which
builds on these.
"""

from datetime import UTC, datetime, timedelta, timezone

from btclib_ecc.curves import bytes_from_point, mult
from hypothesis import strategies as st

from btclib.amount import _MAX_SATOSHI
from btclib.block import Block, BlockHeader
from btclib.block.build import build_block, build_coinbase
from btclib.block.mining import mine
from btclib.block.proof_of_work import REGTEST_POW_LIMIT_BITS
from btclib.network import NETWORKS
from btclib.script import ScriptPubKey, Witness, serialize
from btclib.script.script import (
    BYTE_FROM_OP_CODE_NAME,
    OP_CODE_NAME_FROM_INT,
    push_int,
)
from btclib.tx import OutPoint, Tx, TxIn, TxOut

_UINT32 = st.one_of(
    st.sampled_from([0, 0xFFFFFFFF]), st.integers(min_value=0, max_value=0xFFFFFFFF)
)

# one draw in eight is long enough to cross 253, where a var_int takes three
# bytes; a flatmap, since `one_of` merges the repeated branches of a weighting
_OCTETS = st.integers(min_value=0, max_value=7).flatmap(
    lambda k: (
        st.binary(min_size=250, max_size=300) if k == 0 else st.binary(max_size=80)
    )
)

# a Tx takes at most this many outputs, each at most
# _MAX_SATOSHI // MAX_OUTPUTS, so that their sum stays inside the cap
MAX_OUTPUTS = 8

TX_IDS = st.one_of(st.just(bytes(32)), st.binary(min_size=32, max_size=32))

# `OutPoint` accepts the coinbase marker, but `Tx` refuses it outside a coinbase
OUT_POINTS = st.builds(OutPoint, tx_id=TX_IDS, vout=_UINT32).filter(
    lambda out_point: not out_point.is_coinbase
)

# empty elements included: a P2WSH multisig stack starts with the empty dummy
# element CHECKMULTISIG pops
WITNESSES = st.builds(Witness, stack=st.lists(_OCTETS, max_size=6).map(tuple))

TX_OUTS = st.builds(
    TxOut,
    value=st.one_of(
        st.sampled_from([0, _MAX_SATOSHI]),
        st.integers(min_value=0, max_value=_MAX_SATOSHI),
    ),
    script_pub_key=_OCTETS,
)

_SMALL_TX_OUTS = st.builds(
    TxOut,
    value=st.integers(min_value=0, max_value=_MAX_SATOSHI // MAX_OUTPUTS),
    script_pub_key=_OCTETS,
)

TX_INS = st.builds(
    TxIn,
    prev_out=OUT_POINTS,
    script_sig=_OCTETS,
    sequence=_UINT32,
    script_witness=WITNESSES,
)


@st.composite
def _txs(draw: st.DrawFn) -> Tx:
    """Draw a Tx of one or more inputs, no two spending the same outpoint."""
    vin = draw(
        st.lists(
            TX_INS,
            min_size=1,
            max_size=5,
            unique_by=lambda tx_in: tx_in.prev_out,
        )
    )
    vout = draw(st.lists(_SMALL_TX_OUTS, min_size=1, max_size=MAX_OUTPUTS))
    return Tx(version=draw(_UINT32), lock_time=draw(_UINT32), vin=vin, vout=vout)


TXS = _txs()


# `parse` reads the bytes 1 to 78 as pushes, so no op code name stands for
# them in a list it returns; OP_0 is byte 0, which it names
_PARSED_OP_CODE_NAMES = [
    name for byte, name in OP_CODE_NAME_FROM_INT.items() if byte == 0 or byte > 78
]

# the bytes no table names, which `parse` spells UNKNOWN_OP_CODE_n
_UNKNOWN_OP_CODE_NAMES = [
    f"UNKNOWN_OP_CODE_{byte}"
    for byte in range(256)
    if not 0 < byte <= 78 and byte not in OP_CODE_NAME_FROM_INT
]

# every name in BYTE_FROM_OP_CODE_NAME for a byte that is not a push, its
# aliases included
_OP_CODE_NAMES = [
    name
    for name, byte in BYTE_FROM_OP_CODE_NAME.items()
    if byte == b"\x00" or byte[0] > 78
]

# the lengths where the push operator changes: a length byte up to 75,
# OP_PUSHDATA1 up to 255, OP_PUSHDATA2 from 256; half of the data draws
# take one of them
_PUSH_DATA = st.one_of(
    st.binary(min_size=1, max_size=80),
    st.sampled_from([75, 76, 255, 256]).flatmap(
        lambda size: st.binary(min_size=size, max_size=size)
    ),
)

# `parse` writes data as upper-case hex; no empty push is drawn, the empty
# vector being OP_0
_PARSED_COMMANDS = st.one_of(
    st.sampled_from(_PARSED_OP_CODE_NAMES),
    st.sampled_from(_UNKNOWN_OP_CODE_NAMES),
    _PUSH_DATA.map(lambda data: data.hex().upper()),
)

COMMAND_LISTS = st.lists(_PARSED_COMMANDS, max_size=12)

# an integer in [-1, 16] but zero makes `serialize` warn that an op code is
# one byte shorter; the tests of that warning are `script_test.py`'s
_INTEGERS = st.one_of(
    st.just(0),
    st.integers(min_value=17, max_value=2**63 - 1),
    st.integers(min_value=-(2**63), max_value=-2),
)

_MIXED_COMMANDS = st.one_of(
    _PARSED_COMMANDS,
    st.sampled_from(_OP_CODE_NAMES),
    _INTEGERS,
    st.binary(max_size=80),
    _PUSH_DATA.map(lambda data: data.hex()),
)

MIXED_COMMAND_LISTS = st.lists(_MIXED_COMMANDS, max_size=12)

# bytes of any kind; a script of well formed commands; and the same
# followed by bytes of any kind, which may cut a push short or end in a byte
# no table names
SCRIPTS = st.one_of(
    st.binary(max_size=80),
    COMMAND_LISTS.map(serialize),
    # a lambda: PyPy's bytes.__add__ is a function, which hypothesis labels
    # by its code, and that builtin code has no `co_code`
    st.builds(
        lambda script, tail: script + tail,
        COMMAND_LISTS.map(serialize),
        st.binary(max_size=40),
    ),
)


# a few points of the curve, compressed and not: the shapes that name a key
# are classified only if the bytes are a point
_KEYS = [
    bytes_from_point(mult(k), compressed=compressed)
    for k in (1, 2, 3, 0xDEADBEEF)
    for compressed in (True, False)
]

_HASH160 = st.binary(min_size=20, max_size=20)
_HASH256 = st.binary(min_size=32, max_size=32)

_P2MS_COMMANDS = st.integers(min_value=1, max_value=20).flatmap(
    lambda n: st.tuples(
        st.integers(min_value=1, max_value=n),
        st.lists(st.sampled_from(_KEYS), min_size=n, max_size=n),
    )
)

# one shape for each type `type_and_payload` names but "unknown", which
# SCRIPTS covers, and the witness programs of a version no rule defines
_STANDARD_SCRIPTS = st.one_of(
    st.sampled_from(_KEYS).map(lambda key: serialize([key.hex(), "OP_CHECKSIG"])),
    _P2MS_COMMANDS.map(
        lambda mk: serialize(
            [push_int(mk[0]), *mk[1], push_int(len(mk[1])), "OP_CHECKMULTISIG"]
        )
    ),
    _HASH160.map(
        lambda h: serialize(
            ["OP_DUP", "OP_HASH160", h, "OP_EQUALVERIFY", "OP_CHECKSIG"]
        )
    ),
    _HASH160.map(lambda h: serialize(["OP_HASH160", h, "OP_EQUAL"])),
    st.binary(max_size=80).map(lambda data: serialize(["OP_RETURN", data])),
    _HASH160.map(lambda h: serialize(["OP_0", h])),
    _HASH256.map(lambda h: serialize(["OP_0", h])),
    _HASH256.map(lambda h: serialize(["OP_1", h])),
    st.tuples(
        st.integers(min_value=2, max_value=16), st.binary(min_size=2, max_size=40)
    ).map(lambda vp: serialize([f"OP_{vp[0]}", vp[1]])),
)

# on any network: the output script is the same bytes on all of them
SCRIPT_PUB_KEYS = st.builds(
    ScriptPubKey,
    script=st.one_of(_STANDARD_SCRIPTS, SCRIPTS),
    network=st.sampled_from(list(NETWORKS)),
)


# the first instant a header can carry is the genesis block's, the last is
# the largest four-byte one; the same instant in another time zone is the
# same header
_GENESIS_TIME = 1231006505
_TIME_ZONES = st.sampled_from(
    [UTC, timezone(timedelta(hours=5, minutes=30)), timezone(-timedelta(hours=8))]
)

_TIMES = st.builds(
    datetime.fromtimestamp,
    st.one_of(
        st.sampled_from([_GENESIS_TIME, 0xFFFFFFFF]),
        st.integers(min_value=_GENESIS_TIME, max_value=0xFFFFFFFF),
    ),
    _TIME_ZONES,
)

# the version is a signed four-byte integer, negative ones included
_VERSIONS = st.one_of(
    st.sampled_from([-0x80000000, -1, 0, 1, 0x20000000, 0x7FFFFFFF]),
    st.integers(min_value=-0x80000000, max_value=0x7FFFFFFF),
)

BLOCK_HEADERS = st.builds(
    BlockHeader,
    version=_VERSIONS,
    previous_block_hash=TX_IDS,
    merkle_root=TX_IDS,
    time=_TIMES,
    bits=st.binary(min_size=4, max_size=4),
    nonce=_UINT32,
)

# a block of this many transactions, the coinbase included, keeps the draw
# small: each transaction takes up to a few kilobytes
MAX_BLOCK_TRANSACTIONS = 4


@st.composite
def _blocks(draw: st.DrawFn) -> Block:
    """Draw a solved regtest block: a coinbase and other transactions.

    The coinbase commits to a height, as BIP34 asks, and carries up to 90
    bytes of extra nonce, which keeps its script_sig under 100. No two
    transactions share an id: equal siblings make the merkle tree mutated,
    which `assert_valid` refuses. At most `MAX_BLOCK_TRANSACTIONS` are
    drawn, coinbase included. The nonce is searched, as regtest's limit is a
    target half the hashes meet.
    """
    height = draw(st.one_of(st.sampled_from([0, 16, 17]), st.integers(0, 2**31)))
    coinbase = build_coinbase(
        height,
        draw(st.binary(max_size=80)),
        extra_nonce=draw(st.binary(max_size=90)),
        version=draw(_UINT32),
        lock_time=draw(_UINT32),
    )
    others = draw(
        st.lists(
            TXS,
            max_size=MAX_BLOCK_TRANSACTIONS - 1,
            unique_by=lambda tx: tx.id,
        )
    )
    candidate = build_block(
        draw(TX_IDS),
        [coinbase, *others],
        draw(_TIMES),
        REGTEST_POW_LIMIT_BITS,
        version=draw(_VERSIONS),
    )
    header = mine(candidate.header)
    assert header is not None
    return Block(header, candidate.transactions, check_validity=False)


BLOCKS = _blocks()
