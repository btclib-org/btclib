# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BlockContext dataclass.

What a block cannot be validated against from its own bytes: the height it
is being accepted at, the instant it is being accepted at, and the chain it
is being accepted on. Bitcoin Core reads all three off `pindexPrev` and the
chain parameters, which is what `ContextualCheckBlockHeader` and
`ContextualCheckBlock` are given and `CheckBlock` is not -- and
`Block.assert_valid` is `CheckBlock`, called by `Block.parse` with nothing
to give it.

The chain is its `ConsensusParams` row, carried whole: every activation
height a rule reads comes from one row, so a context cannot pair one
network's BIP34 height with another's segwit height.

`median_time_past` and `required_bits` are chain state a caller computes
by walking the chain: `btclib.block.header_context`'s `median_time_past`
and `next_bits_required`. They are values rather than a callable, so the
rules reading them cannot disagree about the chain behind them. Both
default to `None`, which skips the rules that need them.

`BlockHeader.assert_valid_time(now)` and
`Block.assert_valid_coinbase_height(height)` take only the datum they
read, so a caller without a whole context can still ask those two.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from btclib.consensus import CONSENSUS_PARAMS, ConsensusParams
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import _message_text, assert_type, is_integer

__all__ = ["BlockContext"]


@dataclass(frozen=True)
class BlockContext:
    """What Block.assert_valid_contextual reads: a height, a clock, a chain.

    The facts a block cannot answer for itself, supplied by the caller.
    consensus is the chain's parameters, mainnet's by default as
    everywhere else in btclib. median_time_past and required_bits default
    to None, which skips the rules that need them.
    """

    # the height the block is being accepted at, i.e. Core's
    # pindexPrev->nHeight + 1
    height: int
    # the instant the block is being accepted at, from the caller's clock
    now: datetime
    # the chain the block is being accepted on: its activation heights
    consensus: ConsensusParams = CONSENSUS_PARAMS["mainnet"]
    # the median time past of the block's parent: the caller's own
    # `header_context.median_time_past(parent, parent_height, parent_of)`,
    # or None to leave time-too-old unchecked, and bad-txns-nonfinal for
    # time-locked transactions where BIP113 binds
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
        height on, and not from the block version.
        """
        return self.height >= self.consensus.bip34_height

    @property
    def is_bip113_active(self) -> bool:
        """Whether lock times are compared against the median time past.

        Core's `DeploymentActiveAfter(pindexPrev, DEPLOYMENT_CSV)`: from
        the CSV activation height on, a transaction's time lock is final
        against the parent's median time past, and before it against the
        block's own timestamp.
        """
        return self.height >= self.consensus.csv_height

    @property
    def is_segwit_active(self) -> bool:
        """Whether a block may carry witness data (BIP141).

        Core's `DeploymentActiveAfter(pindexPrev, DEPLOYMENT_SEGWIT)`:
        from the segwit activation height on, a block's witnesses must be
        committed to in its coinbase; before it, no witness is allowed.
        """
        return self.height >= self.consensus.segwit_height

    @property
    def min_version(self) -> int:
        """Return the least header version the chain accepts at this height.

        Core's `bad-version` in `ContextualCheckBlockHeader`: version 2
        from the BIP34 height on, 3 from BIP66's, 4 from BIP65's.
        """
        least = 1
        for version, activation in (
            (2, self.consensus.bip34_height),
            (3, self.consensus.bip66_height),
            (4, self.consensus.bip65_height),
        ):
            if self.height >= activation:
                least = max(least, version)
        return least

    # frozen, as Script and Witness are: a context is a value, nothing
    # serializes it, and the rules that read it must not see it change
    # between them
    def __init__(
        self,
        height: int,
        now: datetime,
        consensus: ConsensusParams = CONSENSUS_PARAMS["mainnet"],
        median_time_past: int | None = None,
        required_bits: bytes | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "height", height)
        object.__setattr__(self, "now", now)
        object.__setattr__(self, "consensus", consensus)
        object.__setattr__(self, "median_time_past", median_time_past)
        object.__setattr__(self, "required_bits", required_bits)

        if check_validity:
            self.assert_valid()

    def _assert_valid_chain_state(self) -> None:
        """Refuse a median_time_past or required_bits given and malformed.

        Split out of assert_valid to keep it under the complexity floor:
        both fields are optional, so this is two independent checks.
        """
        if self.median_time_past is not None:
            if not is_integer(self.median_time_past):
                type_name = type(self.median_time_past).__name__
                raise BTClibTypeError(f"invalid median_time_past type: {type_name}")
            if self.median_time_past < 0:
                err_msg = (
                    f"invalid median_time_past: {_message_text(self.median_time_past)}"
                )
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
        """Refuse a bad height, a now that is no aware datetime, a bad chain.

        Naive-datetime refusal is assert_valid_time's too, the reader of
        the clock being where the comparison happens. median_time_past
        and required_bits are refused only when given: None leaves the
        rules they answer for unchecked.
        """
        # a float here would compare fine and read as a height, so the
        # type is checked rather than coerced -- and a bool is not an
        # integer for this purpose either, `true` out of json being how a
        # height becomes one
        if not is_integer(self.height):
            raise BTClibTypeError(f"invalid height type: {type(self.height).__name__}")
        if self.height < 0:
            raise BTClibValueError(f"invalid height: {_message_text(self.height)}")

        assert_type(self.now, datetime, "now")

        # a naive datetime has no instant attached to it: timestamp() would
        # read it as local time, so the same block would be too far in the
        # future on one machine and not on another
        if self.now.tzinfo is None or self.now.tzinfo.utcoffset(self.now) is None:
            raise BTClibValueError(f"naive current time (no time zone): {self.now}")

        assert_type(self.consensus, ConsensusParams, "consensus")

        self._assert_valid_chain_state()
