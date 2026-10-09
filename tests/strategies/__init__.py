# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Hypothesis strategies for the transaction types, shared by the tests.

Each one draws values the type's own `assert_valid` accepts, and never a
coinbase input: the property they serve is `parse(serialize(x)) == x`,
and a value the library refuses to build is not a value to round-trip.
Boundaries are drawn on purpose, not left to chance: the null
transaction id, an amount of zero and the largest one, and the lowest and
highest of each four-byte field. Some lengths reach 253, where a var_int
takes three bytes.
"""

from hypothesis import strategies as st

from btclib.amount import _MAX_SATOSHI
from btclib.script import Witness
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
