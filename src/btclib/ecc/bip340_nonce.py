# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP340's nonce derivation.

btclib_ecc.ecc.bip340_nonce's: every name here is that module's own
object, bound again so that `btclib.ecc.bip340_nonce` keeps answering
for it (issue #2282).
"""

from btclib_ecc.ecc.bip340_nonce import (
    bip340_nonce_,
)

__all__ = [
    "bip340_nonce_",
]
