# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The interface a chain backend answers to quote a fee rate.

Kept apart from `Fetcher`, the way `Broadcaster` is: not every backend
that answers `Fetcher`'s questions can quote a price.
`BitcoinCoreRestFetcher`, over Core's read-only `-rest` interface, is
exactly that backend again -- Core's `-rest` interface carries no fee
estimation at all, `estimatesmartfee` being RPC only. A `Protocol` lets
`BitcoinCoreFetcher`, `ElectrumFetcher` and `EsploraFetcher` satisfy
`FeeEstimator` structurally, with nothing to say about
`BitcoinCoreRestFetcher` at all -- the same reasoning `broadcaster.py`'s
docstring gives for that class, one capability over.

Not `runtime_checkable`, for the reason `Broadcaster` is not: the
contract below is not what `isinstance(x, FeeEstimator)` would verify.

**One target asked, one answer -- not a mapping.** Core and Electrum
answer one confirmation target per request, so a mapping would be
synthesized for two backends out of three; Esplora's own targets are a
fixed set rather than a general shape, so a mapping is not the answer
there either.

**The target answered for need not be the target asked for, so the
return is not a bare `FeeRate`.** Core's `blocks` field is documented as
the target the estimate was found at, clamped to at least 2 and at most
the estimator's own maximum usable target -- asking for 1 and being
answered for 2 is the ordinary case, and a bare rate handed back as
though it answered the question asked would misreport it. `FeeQuote`
carries both.

This module sits above `fee.py`: it may import `FeeRate` from there, and
`fee.py` imports nothing from here, which is also the direction issue
#2129 cuts the two into different distributions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate
from btclib.utils import is_integer

__all__ = ["FeeEstimator", "FeeQuote", "valid_confirmation_target"]


@dataclass(frozen=True)
class FeeQuote:
    """A fee rate, and the confirmation target it is valid for.

    `target` is not necessarily the target `FeeEstimator.estimate_fee`
    was asked for: a backend may answer for a target it clamped or
    rounded to, and this is where that answer is carried rather than
    lost by returning `rate` alone.
    """

    rate: FeeRate
    target: int


def valid_confirmation_target(target: int) -> int:
    """Return `target`, refusing what no backend answers a fee for.

    Checked once, ahead of the request, the way `fetcher.block_header_height`
    checks a height before the first request that needs one: a target
    that is not a positive int is refused here rather than left to
    surface as whichever error the backend happens to answer for it.
    """
    if not is_integer(target):
        err_msg = f"invalid confirmation target type: {type(target).__name__}"
        raise BTClibTypeError(err_msg)
    if target < 1:
        raise BTClibValueError(f"invalid confirmation target: {target}")
    return target


class FeeEstimator(Protocol):
    """A backend able to quote a fee rate for a confirmation target.

    One method and one contract, binding on every implementation of it:

    - the target answered for need not be the target asked for, and the
      `FeeQuote` returned carries the one the rate is actually valid for;
    - a quote a backend expresses more finely than `FeeRate` can hold
      exactly is rounded up, never down -- `FeeRate.from_sats_per_vbyte`
      and `FeeRate.from_btc_per_kvbyte` take `round_up=True` here, rather
      than the refusal each raises by default for a caller who is
      *stating* a price: refusing an ordinary explorer answer would make
      the backend unusable, and truncating would under-pay. Rounding a
      conservative estimate up leaves it an estimate;
    - a backend that cannot quote a rate for the target -- Core's
      `feerate` absent from a reply that carries `errors` instead,
      Electrum's `-1` -- declines rather than answering, and is raised as
      a `FetchError` keeping the backend's own reason, unreshaped, the way
      `Broadcaster`'s third contract bullet already requires of a
      refusal. No sentinel reaches `FeeQuote`.
    """

    def estimate_fee(self, target: int) -> FeeQuote:
        """Return a fee rate expected to confirm within `target` blocks."""
        ...
