# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The consensus limits on a block, with Bitcoin Core's names.

Core declares all but `MAX_FUTURE_BLOCK_TIME` in `consensus/consensus.h`,
and that one in `chain.h`, beside the wider window the wallet
compares its own timestamps against; it is a consensus bound all the same,
and `ContextualCheckBlockHeader` rejects `time-too-new` with it.

A module of its own, as `script/limits.py` is and for the same reason:
`block.py` is the dataclass and its serialization, while each name here is
a rule about a block being *accepted*. `WITNESS_SCALE_FACTOR` is not a
limit but the unit the other two are expressed in -- a byte outside the
witness weighs four, and so does one legacy signature check -- which is
why it is here rather than beside the arithmetic that reads it.

It and `MAX_BLOCK_WEIGHT` are defined in `btclib.consensus` and re-exported
here, which is a layering fact and not a second home for them: what a
transaction and a witness may declare is arithmetic on the block that has
to hold them, and neither `btclib.tx` nor `btclib.script` can import this
package. `btclib.consensus` says why; a caller reading a block's rules
still names this module, which is where the rest of Core's header is.

Some of `consensus.h`'s constants are deliberately absent.
`MAX_BLOCK_SERIALIZED_SIZE` is marked in Core's own comment as a buffer
bound and not a network rule, the weight being what consensus caps.
`COINBASE_MATURITY` is a rule about spending an output, so it needs the
chain the output was created on: `btclib.tx.coin.Coin` carries that
height, and the constant is `btclib.tx.limits`'s, beside
`btclib.tx.tx_context.assert_coinbase_maturity`, which reads it.

`MAX_TIMEWARP` is here and not among those: it is BIP94's bound on the
first block of a new retarget period, checked against that block's own
parent -- the last block of the period before it -- so it needs one
header rather than the whole chain, which is what makes it a bound
rather than a rule of its own.
`btclib.block.header_context.next_bits_required` is where it is read,
behind `ConsensusParams.enforce_bip94`.

`MIN_SERIALIZABLE_TRANSACTION_WEIGHT` is here, where its neighbour
`MIN_TRANSACTION_WEIGHT` is not, and the pair is what says why: the second
is the smallest a *valid* transaction can be and is fee estimation's, the
first the smallest one that *deserializes* -- so it is the one a parser
divides MAX_BLOCK_WEIGHT by to bound how many transactions a block may
declare before it allocates for them (issue #569). `btclib.tx.limits`
derives the same kind of bound for a transaction's own inputs and outputs.
"""

from btclib.consensus import MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR

__all__ = [
    "MAX_BLOCK_SIGOPS_COST",
    "MAX_BLOCK_WEIGHT",
    "MAX_FUTURE_BLOCK_TIME",
    "MAX_TIMEWARP",
    "MIN_SERIALIZABLE_TRANSACTION_WEIGHT",
    "WITNESS_SCALE_FACTOR",
]

# Maximum allowed cost of the signature check operations in a block
# (network rule); the cost of a legacy sigop is WITNESS_SCALE_FACTOR, so
# the bound is 20,000 of them
MAX_BLOCK_SIGOPS_COST = 80_000

# The smallest weight a transaction can deserialize from, ten octets being
# Core's lower bound for the size of a serialized CTransaction
MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10

# Maximum number of seconds a block timestamp may exceed the current time,
# spelled as Core spells it
MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60

# BIP94: how far behind its own parent the first block of a new retarget
# period may be timestamped, on the networks ConsensusParams.enforce_bip94
# names -- testnet4, and regtest under -test=bip94, which the table does
# not carry since it is a command-line option and not a fact about the
# chain
MAX_TIMEWARP = 600
