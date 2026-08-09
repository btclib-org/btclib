# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The consensus limits on a block, with Bitcoin Core's names.

Core declares the first three in `consensus/consensus.h` and
`MAX_FUTURE_BLOCK_TIME` in `chain.h`, beside the wider window the wallet
compares its own timestamps against; it is a consensus bound all the same,
and `ContextualCheckBlockHeader` rejects `time-too-new` with it.

A module of its own, as `script/limits.py` is and for the same reason:
`block.py` is the dataclass and its serialization, while each name here is
a rule about a block being *accepted*. `WITNESS_SCALE_FACTOR` is not a
limit but the unit the other two are expressed in -- a byte outside the
witness weighs four, and so does one legacy signature check -- which is
why it is here rather than beside the arithmetic that reads it.

Three of `consensus.h`'s constants are deliberately absent.
`MAX_BLOCK_SERIALIZED_SIZE` is marked in Core's own comment as a buffer
bound and not a network rule, the weight being what consensus caps.
`COINBASE_MATURITY` is a rule about spending an output, so it needs the
chain the output was created on. `MAX_TIMEWARP` is BIP94's bound on the
first block of a retarget period, which needs the previous block.

`MIN_SERIALIZABLE_TRANSACTION_WEIGHT` is here, where its neighbour
`MIN_TRANSACTION_WEIGHT` is not, and the pair is what says why: the second
is the smallest a *valid* transaction can be and is fee estimation's, the
first the smallest one that *deserializes* -- so it is the one a parser
divides MAX_BLOCK_WEIGHT by to bound how many transactions a block may
declare before it allocates for them (issue #569). `btclib.tx.limits`
derives the same kind of bound for a transaction's own inputs and outputs
and reads the two constants above from here.
"""

__all__ = [
    "MAX_BLOCK_SIGOPS_COST",
    "MAX_BLOCK_WEIGHT",
    "MAX_FUTURE_BLOCK_TIME",
    "MAX_TX_IN_COUNT",
    "MAX_TX_OUT_COUNT",
    "MIN_SERIALIZABLE_TRANSACTION_WEIGHT",
    "MIN_TX_IN_SIZE",
    "MIN_TX_OUT_SIZE",
    "WITNESS_SCALE_FACTOR",
]

# Maximum allowed weight for a block, see BIP141 (network rule)
MAX_BLOCK_WEIGHT = 4_000_000

# Maximum allowed cost of the signature check operations in a block
# (network rule); the cost of a legacy sigop is WITNESS_SCALE_FACTOR, so
# the bound is 20,000 of them
MAX_BLOCK_SIGOPS_COST = 80_000

# The weight of a byte a legacy node sees, and the cost of a legacy sigop
WITNESS_SCALE_FACTOR = 4

# The smallest weight a transaction can deserialize from, ten octets being
# Core's lower bound for the size of a serialized CTransaction
MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10

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
# (issue #569)
MAX_TX_IN_COUNT = MAX_BLOCK_WEIGHT // (MIN_TX_IN_SIZE * WITNESS_SCALE_FACTOR)
MAX_TX_OUT_COUNT = MAX_BLOCK_WEIGHT // (MIN_TX_OUT_SIZE * WITNESS_SCALE_FACTOR)

# Maximum number of seconds a block timestamp may exceed the current time,
# spelled as Core spells it
MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60
