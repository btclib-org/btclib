# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BlockContext dataclass.

What a block cannot be validated against from its own bytes: the height it
is being accepted at, the instant it is being accepted at, and the height
BIP34 takes effect at on the chain in question. Bitcoin Core reads all
three off `pindexPrev` and the chain parameters, which is what
`ContextualCheckBlockHeader` and `ContextualCheckBlock` are given and
`CheckBlock` is not -- and `Block.assert_valid` is `CheckBlock`, called by
`Block.parse` with nothing to give it.

One carrier rather than a parameter per rule, because the list grows and
each addition is chain state: `time-too-old` is the median time past of
eleven ancestors, `bad-diffbits` is the target the retarget arithmetic of
`proof_of_work.py` computes from a whole period, `bad-version` needs two
more activation heights. Each becomes a field here when the chain state it
takes arrives, and none of them changes the signature of
`Block.assert_valid_contextual`.

The rules underneath take the datum they read and not the whole context --
`BlockHeader.assert_valid_time(now)`,
`Block.assert_valid_coinbase_height(height)` -- so a caller holding one
half of a context asks the half it can answer, and nothing is skipped for
want of the other.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import assert_type, is_integer

__all__ = [
    "BIP34_HEIGHT",
    "BlockContext",
]

# Core's chainparams: 227,931 on mainnet, 21,111 on testnet3, and 1 on
# testnet4, signet and regtest. Mainnet is the default, as it is
# everywhere else in btclib.
#
# A field of this dataclass rather than one of `Network`, which holds no
# consensus parameter at all: the first one to go in belongs there with
# the others a chain-aware validator needs -- the retarget interval,
# BIP66's and BIP65's heights, the subsidy halving interval -- and putting
# this one there alone would answer for a table that is otherwise absent.
BIP34_HEIGHT = 227_931


@dataclass(frozen=True)
class BlockContext:
    """What Block.assert_valid_contextual reads: a height and a clock.

    The two facts a block cannot answer for itself, supplied by the
    caller; bip34_height is the chain's activation height, defaulting
    to mainnet's.
    """

    # the height the block is being accepted at, i.e. Core's
    # pindexPrev->nHeight + 1
    height: int
    # the instant the block is being accepted at, from the caller's clock
    now: datetime
    # the height from which the chain enforces BIP34
    bip34_height: int = BIP34_HEIGHT

    @property
    def is_bip34_active(self) -> bool:
        """Whether the coinbase must commit to the height (BIP34).

        Core's `DeploymentActiveAfter(pindexPrev, DEPLOYMENT_HEIGHTINCB)`,
        which is this comparison: the rule binds from the activation
        height on, and not from the block version. A version 1 block at
        or above it is refused too, by `bad-version`, which needs the
        chain and is out of scope here.
        """
        return self.height >= self.bip34_height

    # frozen, as Script and Witness are: a context is a value, nothing
    # serializes it, and the two rules that read it must not see it change
    # between them
    def __init__(
        self,
        height: int,
        now: datetime,
        bip34_height: int = BIP34_HEIGHT,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "height", height)
        object.__setattr__(self, "now", now)
        object.__setattr__(self, "bip34_height", bip34_height)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a negative or non-int height, or a now that is no datetime.

        Naive-datetime refusal is assert_valid_time's, the reader of
        the clock being where the comparison happens.
        """
        for key in ("height", "bip34_height"):
            value = getattr(self, key)
            # a float here would compare fine and read as a height, so
            # the type is checked rather than coerced -- and a bool is not
            # an integer for this purpose either, `true` out of json being
            # how a height becomes one
            if not is_integer(value):
                err_msg = f"invalid {key} type: {type(value).__name__}"
                raise BTClibTypeError(err_msg)
            if value < 0:
                raise BTClibValueError(f"invalid {key}: {value}")

        assert_type(self.now, datetime, "now")

        # a naive datetime has no instant attached to it: timestamp() would
        # read it as local time, so the same block would be too far in the
        # future on one machine and not on another
        if self.now.tzinfo is None or self.now.tzinfo.utcoffset(self.now) is None:
            raise BTClibValueError(f"naive current time (no time zone): {self.now}")
