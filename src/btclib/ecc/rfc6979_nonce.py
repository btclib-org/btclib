# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""RFC6979's deterministic nonce.

ellipticcurves.ecc.rfc6979_nonce's: every name here is that module's own
object, bound again so that `btclib.ecc.rfc6979_nonce` keeps answering
for it (issue #2282).
"""

from ellipticcurves.ecc.rfc6979_nonce import (
    challenge_,
    rfc6979_nonce_,
)

__all__ = [
    "challenge_",
    "rfc6979_nonce_",
]
