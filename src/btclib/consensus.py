# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The consensus constants more than one package measures against.

Two names of Bitcoin Core's `consensus/consensus.h` and one bound derived
from them, in a module that imports nothing and is therefore below every
package that reads them. `btclib.block.limits` is where the rest of that
header is and where a caller reading a block's own rules goes; these two
are here because of who else divides by them. A transaction's input and
output counts (`btclib.tx.limits`) and a witness stack's element count are
arithmetic on `MAX_BLOCK_WEIGHT`, and neither `btclib.tx` nor
`btclib.script` can import `btclib.block`: `btclib.block` imports
`btclib.tx`, which imports `btclib.script`, so either edge back closes a
cycle on a half-initialized package -- issue #147's shape, and what
`tests/imports_test.py` reports.

`btclib.block.limits` re-exports both, so nothing that reads them from
there has to move.

`MAX_WITNESS_STACK_ITEMS` is here and not in `btclib.script.limits` for a
second reason on top of the layering. That module holds the five caps the
script *engine* enforces, and reading an execution limit in a decoder is
what let a 1443-byte push be refused as unparsable when it was merely
unspendable (issue #123). The bound below is not `MAX_STACK_SIZE`: it
refuses a count no block could carry, not a witness no script could run.
"""

__all__ = [
    "MAX_BLOCK_WEIGHT",
    "MAX_WITNESS_STACK_ITEMS",
    "WITNESS_SCALE_FACTOR",
]

# Maximum allowed weight for a block, see BIP141 (network rule)
MAX_BLOCK_WEIGHT = 4_000_000

# The weight of a byte a legacy node sees, and the cost of a legacy sigop
WITNESS_SCALE_FACTOR = 4

# How many elements a witness stack may declare. An element costs at least
# the one octet of the var_int announcing it empty, and a witness octet
# weighs one, so the weight a block may not exceed is the count no witness
# in it can exceed either -- which is what lets a parser refuse a count
# before allocating a Python object per declared element (issue #569)
MAX_WITNESS_STACK_ITEMS = MAX_BLOCK_WEIGHT
