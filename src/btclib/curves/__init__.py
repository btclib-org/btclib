# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib.curves: the elliptic curve arithmetic, btclib_ecc.curves'.

The curve, the catalogue it is looked up in, the scalar multiplications and
the SEC codec are the `btclib_ecc` package's, which btclib depends on.
Every name here, and in each module of this package, is that package's own
object bound again, so that `from btclib.curves import mult` and
`from btclib.curves.curve import secp256k1` keep answering for it
(issue #2282). What each name does is documented where it is defined.

What is built *on* a curve is btclib.ecc, and the rule between the two is
that direction: ecc imports curves, never the other way round.
"""

from btclib_ecc.curves import (
    CURVES,
    Curve,
    CurveGroup,
    PreparedPoint,
    PubKey,
    TweakChain,
    bytes_from_point,
    bytes_from_prv_key_int,
    double_mult_var,
    find_all_points,
    find_subgroup_points,
    is_libsecp256k1_serving,
    is_x_coordinate_var,
    mult,
    mult_pub_key,
    multi_mult_var,
    point_from_octets,
    point_from_pub_key,
    scalar_from_prv_key,
    secp256k1,
    set_libsecp256k1_serving,
    sum_var,
    tweak_add_var,
)

__all__ = [
    "CURVES",
    "Curve",
    "CurveGroup",
    "PreparedPoint",
    "PubKey",
    "TweakChain",
    "bytes_from_point",
    "bytes_from_prv_key_int",
    "double_mult_var",
    "find_all_points",
    "find_subgroup_points",
    "is_libsecp256k1_serving",
    "is_x_coordinate_var",
    "mult",
    "mult_pub_key",
    "multi_mult_var",
    "point_from_octets",
    "point_from_pub_key",
    "scalar_from_prv_key",
    "secp256k1",
    "set_libsecp256k1_serving",
    "sum_var",
    "tweak_add_var",
]
