# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Number theory and modular arithmetic.

btclib_ecc.number_theory's: every name here is that module's own
object, bound again so that `btclib.number_theory` keeps answering for
it (issue #2282).
"""

from btclib_ecc.number_theory import (
    legendre_symbol_var,
    mod_inv,
    mod_inv_batch,
    mod_inv_batch_var,
    mod_inv_var,
    mod_sqrt_var,
    tonelli_var,
    xgcd_var,
)

__all__ = [
    "legendre_symbol_var",
    "mod_inv",
    "mod_inv_batch",
    "mod_inv_batch_var",
    "mod_inv_var",
    "mod_sqrt_var",
    "tonelli_var",
    "xgcd_var",
]
