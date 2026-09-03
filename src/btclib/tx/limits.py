# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""How many inputs and outputs a transaction may declare.

And the numbers `btclib.tx.tx_context`'s rules compare a lock time or a
sequence against.

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

`LOCKTIME_THRESHOLD`, `SEQUENCE_FINAL` and the four `SEQUENCE_LOCKTIME_*`
constants are Core's `src/script/script.h` and `src/primitives/
transaction.h`, at bitcoin/bitcoin@9be056a8a7; `COINBASE_MATURITY` is
`src/consensus/consensus.h`, same tag. `block/limits.py` used to carry a
paragraph explaining why `COINBASE_MATURITY` was absent from it -- "a
rule about spending an output, so it needs the chain the output was
created on" -- and that reasoning is what put it here instead: a
`btclib.tx.coin.Coin` carrying its own creation height is that chain, so
the rule is a function of its arguments and belongs beside the module
that reads it rather than beside `block/limits.py`'s header rules, which
`btclib.tx` cannot import.
"""

from btclib.consensus import MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR

__all__ = [
    "COINBASE_MATURITY",
    "LOCKTIME_THRESHOLD",
    "MAX_TX_IN_COUNT",
    "MAX_TX_OUT_COUNT",
    "MIN_TX_IN_SIZE",
    "MIN_TX_OUT_SIZE",
    "SEQUENCE_FINAL",
    "SEQUENCE_LOCKTIME_DISABLE_FLAG",
    "SEQUENCE_LOCKTIME_GRANULARITY",
    "SEQUENCE_LOCKTIME_MASK",
    "SEQUENCE_LOCKTIME_TYPE_FLAG",
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

# Core's LOCKTIME_THRESHOLD: a lock_time below this is a block height, at
# or above it a unix timestamp -- Tue Nov 5 00:53:20 1985 UTC, far past any
# height a chain will reach and far before any timestamp a block will carry
LOCKTIME_THRESHOLD = 500_000_000

# Core's CTxIn::SEQUENCE_FINAL: every input carrying it makes lock_time
# irrelevant, whatever lock_time says (Consensus::CheckTxInputs never
# reads it once every input is this)
SEQUENCE_FINAL = 0xFFFFFFFF

# Core's CTxIn::SEQUENCE_LOCKTIME_*: bit 31 opts a whole input out of
# BIP68 entirely, bit 22 picks a time-based relative lock over a
# height-based one, and the low sixteen bits are the lock itself, in
# whichever unit bit 22 named -- GRANULARITY is how far that field is
# shifted to turn 512-second units into seconds
SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
SEQUENCE_LOCKTIME_MASK = 0x0000FFFF
SEQUENCE_LOCKTIME_GRANULARITY = 9

# Core's own COINBASE_MATURITY: how many blocks a coinbase output has to
# sit before a spend of it may connect (Consensus::CheckTxInputs,
# bad-txns-premature-spend-of-coinbase). The same on every network,
# regtest included -- unlike the heights and limits `btclib.consensus`
# tabulates per network, nothing in chainparams.cpp relaxes this one
COINBASE_MATURITY = 100
