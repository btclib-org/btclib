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

`median_time_past` and `required_bits` are the first two, arrived: values
rather than a callable, because a context stays what it always was, a
photograph of a moment rather than an object with a chain behind it that
the two rules reading it could disagree about. Computing them is
`btclib.block.header_context`'s `median_time_past` and
`next_bits_required`, which walk the chain through a `ParentOf` callable
the caller supplies and BlockContext never sees; both default to `None`,
which is how a caller that has not walked the chain -- most of the
existing callers of this class, checking only `bad-cb-height` and
`time-too-new` -- still builds one, and how the two rules below stay
skipped rather than fed a value nobody computed.

The rules underneath take the datum they read and not the whole context --
`BlockHeader.assert_valid_time(now)`,
`Block.assert_valid_coinbase_height(height)` -- so a caller holding one
half of a context asks the half it can answer, and nothing is skipped for
want of the other.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from btclib.consensus import CONSENSUS_PARAMS
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import assert_type, is_integer

__all__ = [
    "BIP34_HEIGHT",
    "BlockContext",
]

# mainnet's, which is the default here as it is everywhere else in
# btclib. Every network's is a field of its `btclib.consensus` row, so a
# caller validating another chain writes
# `NETWORKS[name].consensus.bip34_height` rather than the number.
#
# A default of this dataclass and not a second copy: the context is what
# a validator hands to one block, and the chain it came from is the table
# -- which is also where the rest of what such a validator reads is, the
# other activation heights and the subsidy interval among them
BIP34_HEIGHT = CONSENSUS_PARAMS["mainnet"].bip34_height


@dataclass(frozen=True)
class BlockContext:
    """What Block.assert_valid_contextual reads: a height and a clock.

    The facts a block cannot answer for itself, supplied by the caller;
    bip34_height is the chain's activation height, defaulting to
    mainnet's, and median_time_past and required_bits default to None,
    which skips the rule each answers for.
    """

    # the height the block is being accepted at, i.e. Core's
    # pindexPrev->nHeight + 1
    height: int
    # the instant the block is being accepted at, from the caller's clock
    now: datetime
    # the height from which the chain enforces BIP34
    bip34_height: int = BIP34_HEIGHT
    # time-too-old's bound: the caller's own
    # `header_context.median_time_past(parent, parent_height, parent_of)`,
    # or None to leave the rule unchecked
    median_time_past: int | None = None
    # bad-diffbits' answer: the caller's own
    # `header_context.next_bits_required(header, parent, parent_height,
    # parent_of, consensus)`, or None to leave the rule unchecked
    required_bits: bytes | None = None

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
        median_time_past: int | None = None,
        required_bits: bytes | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "height", height)
        object.__setattr__(self, "now", now)
        object.__setattr__(self, "bip34_height", bip34_height)
        object.__setattr__(self, "median_time_past", median_time_past)
        object.__setattr__(self, "required_bits", required_bits)

        if check_validity:
            self.assert_valid()

    def _assert_valid_chain_state(self) -> None:
        """Refuse a median_time_past or required_bits given and malformed.

        Split out of assert_valid to keep it under the complexity floor:
        both fields are optional, so this is two independent, unrelated
        checks rather than one.
        """
        if self.median_time_past is not None:
            if not is_integer(self.median_time_past):
                type_name = type(self.median_time_past).__name__
                raise BTClibTypeError(f"invalid median_time_past type: {type_name}")
            if self.median_time_past < 0:
                err_msg = f"invalid median_time_past: {self.median_time_past}"
                raise BTClibValueError(err_msg)

        if self.required_bits is not None:
            # bytes and not Octets: this is a value a caller computed with
            # next_bits_required, not one read off the wire, so nothing
            # here coerces a str or a bytearray into it
            assert_type(self.required_bits, bytes, "required_bits")
            if len(self.required_bits) != 4:
                err_msg = f"invalid required_bits length: {len(self.required_bits)}"
                err_msg += " bytes instead of 4"
                raise BTClibValueError(err_msg)

    def assert_valid(self) -> None:
        """Refuse a negative or non-int height, or a now that is no datetime.

        Naive-datetime refusal is assert_valid_time's, the reader of
        the clock being where the comparison happens. median_time_past
        and required_bits are refused only when given -- None is what
        leaves the rule each answers for unchecked, not a value to
        validate -- and _assert_valid_chain_state is where that happens.
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

        self._assert_valid_chain_state()
