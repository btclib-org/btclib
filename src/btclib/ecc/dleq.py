# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP374's proof of discrete logarithm equality.

btclib_ecc.ecc.dleq's: every name here is that module's own object,
bound again so that `btclib.ecc.dleq` keeps answering for it (issue
#2282).
"""

from btclib_ecc.ecc.dleq import (
    assert_proof_as_valid,
    generate_proof,
    verify_proof,
)

__all__ = [
    "assert_proof_as_valid",
    "generate_proof",
    "verify_proof",
]
