# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Hypothesis strategies for the transaction types and scripts.

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
"""

from hypothesis import strategies as st

from btclib.amount import _MAX_SATOSHI
from btclib.script import Witness, serialize
from btclib.script.script import BYTE_FROM_OP_CODE_NAME, OP_CODE_NAME_FROM_INT
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
    st.builds(bytes.__add__, COMMAND_LISTS.map(serialize), st.binary(max_size=40)),
)
