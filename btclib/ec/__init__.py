#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Module btclib.ec.

What this package exports is the curve API: a Curve, the three scalar
multiplications, and the SEC point codec. The eleven other mult_* of
btclib.ec.curve_group and btclib.ec.curve_group_2 -- mult_aff, mult_jac,
mult_base_3, mult_mont_ladder, the two mult_recursive_*, the two
mult_fixed_window*, mult_sliding_window, mult_w_NAF and
mult_endomorphism_secp256k1 -- used to be exported alongside them, and so
did the multiples, cached_multiples and jac_from_aff they are built on.

They are implementations of one operation, kept side by side to be measured
against each other, and exporting them made a menu out of a benchmark: a
caller reading btclib.ec had fourteen ways to multiply a point and nothing
to say that mult is the one to use, that it dispatches to libsecp256k1 for
secp256k1 and the generator, and that mult_jac is not the faster
alternative its name suggests. Each is still importable from the module
that defines it, which is where the test suite takes them from.
"""

from btclib.ec.curve import Curve, double_mult, mult, multi_mult, secp256k1
from btclib.ec.curve_group import CurveGroup
from btclib.ec.curve_group_f import find_all_points, find_subgroup_points
from btclib.ec.sec_point import bytes_from_point, point_from_octets

__all__ = [
    "Curve",
    "CurveGroup",
    "bytes_from_point",
    "double_mult",
    "find_all_points",
    "find_subgroup_points",
    "mult",
    "multi_mult",
    "point_from_octets",
    "secp256k1",
]
