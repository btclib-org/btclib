# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""How many inputs and outputs a transaction may declare.

A module of its own, as `block/limits.py` and `script/limits.py` are and
for the same reason: `tx.py` is the dataclass and its serialization, while
each name here is a rule about the transaction the wire declares.

Core has no constant for either count. What it has is the weight a block
may not exceed, and a transaction that does not fit in a block is one no
parser has to allocate for: each count below is `MAX_BLOCK_WEIGHT` divided
by the weight of the smallest thing it counts, so neither is a number this
library picked (issue #569). `btclib.consensus` is where the two constants
divided here come from, and its docstring is why they are not read from
`btclib.block.limits` beside the rest of Core's header.

The minimum sizes are the same arithmetic's other half, and they are
`tests/tx`'s to check against a serialization rather than to be believed.
"""

from btclib.consensus import MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR

__all__ = [
    "MAX_TX_IN_COUNT",
    "MAX_TX_OUT_COUNT",
    "MIN_TX_IN_SIZE",
    "MIN_TX_OUT_SIZE",
]

# The smallest a TxIn serializes to: a 32-octet previous transaction id, a
# four-octet output index, the one octet of a var_int announcing an empty
# script_sig, and a four-octet sequence. The smallest a TxOut serializes
# to: an eight-octet amount and the one octet of an empty script_pub_key
MIN_TX_IN_SIZE = 32 + 4 + 1 + 4
MIN_TX_OUT_SIZE = 8 + 1

# How many inputs and outputs a transaction that can be mined may declare.
# Neither is witness data, so each weighs WITNESS_SCALE_FACTOR times its
# size, and a count above these names a transaction no block has room for
# -- which is what lets a parser refuse it before allocating for it
MAX_TX_IN_COUNT = MAX_BLOCK_WEIGHT // (MIN_TX_IN_SIZE * WITNESS_SCALE_FACTOR)
MAX_TX_OUT_COUNT = MAX_BLOCK_WEIGHT // (MIN_TX_OUT_SIZE * WITNESS_SCALE_FACTOR)
