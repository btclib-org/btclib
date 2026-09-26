# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The BIE1 Elliptic Curve Integrated Encryption Scheme.

ellipticcurves.ecc.ecies's: every name here is that module's own object,
bound again so that `btclib.ecc.ecies` keeps answering for it (issue
#2282).
"""

from ellipticcurves.ecc.ecies import (
    MAGIC,
    Envelope,
    decrypt,
    derive_keys,
    encrypt,
)

__all__ = [
    "MAGIC",
    "Envelope",
    "decrypt",
    "derive_keys",
    "encrypt",
]
