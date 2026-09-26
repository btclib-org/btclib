# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Diffie-Hellman key agreement.

btclib_ecc.ecc.dh's: every name here is that module's own object,
bound again so that `btclib.ecc.dh` keeps answering for it (issue
#2282).
"""

from btclib_ecc.ecc.dh import (
    diffie_hellman,
)

__all__ = [
    "diffie_hellman",
]
