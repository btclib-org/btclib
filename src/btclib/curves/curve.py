# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The curve, its catalogue and the scalar multiplications.

ellipticcurves.curves.curve's: every name here is that module's own
object, bound again so that `btclib.curves.curve` keeps answering for it
(issue #2282).
"""

from ellipticcurves.curves.curve import (
    CURVES,
    NIST,
    Brainpool,
    Brainpool_params2,
    Curve,
    NIST_params2,
    PreparedPoint,
    SEC2v1,
    SEC2v1_params2,
    SEC2v2,
    SEC2v2_params2,
    TweakChain,
    double_mult_var,
    is_libsecp256k1_serving,
    is_x_coordinate_var,
    mult,
    multi_mult_var,
    secp256k1,
    set_libsecp256k1_serving,
    sum_var,
    tweak_add_var,
)

__all__ = [
    "CURVES",
    "NIST",
    "Brainpool",
    "Brainpool_params2",
    "Curve",
    "NIST_params2",
    "PreparedPoint",
    "SEC2v1",
    "SEC2v1_params2",
    "SEC2v2",
    "SEC2v2_params2",
    "TweakChain",
    "double_mult_var",
    "is_libsecp256k1_serving",
    "is_x_coordinate_var",
    "mult",
    "multi_mult_var",
    "secp256k1",
    "set_libsecp256k1_serving",
    "sum_var",
    "tweak_add_var",
]
