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
first block of a retarget period, which needs the previous block. The two
`MIN_*_TRANSACTION_WEIGHT` bounds are about a transaction and are read by
fee estimation rather than by consensus.
"""

__all__ = [
    "MAX_BLOCK_SIGOPS_COST",
    "MAX_BLOCK_WEIGHT",
    "MAX_FUTURE_BLOCK_TIME",
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

# Maximum number of seconds a block timestamp may exceed the current time,
# spelled as Core spells it
MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60
