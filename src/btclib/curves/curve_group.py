# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The group law of a short Weierstrass curve.

btclib_ecc.curves.curve_group's: every name here is that module's
own object, bound again so that `btclib.curves.curve_group` keeps
answering for it (issue #2282).
"""

from btclib_ecc.curves.curve_group import (
    BOS_COSTER_THRESHOLD,
    HEX_THRESHOLD,
    MAX_W,
    CurveGroup,
    signed_odd_digits,
)

__all__ = [
    "BOS_COSTER_THRESHOLD",
    "HEX_THRESHOLD",
    "MAX_W",
    "CurveGroup",
    "signed_odd_digits",
]
