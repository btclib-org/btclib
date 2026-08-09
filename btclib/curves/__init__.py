# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib.curves.

**The arithmetic.** btclib.curves holds the elliptic curve itself: the field
and group operations of `curve_group`, the `Curve` built on them, the
catalogued curves (secp256k1 among them), and the SEC encoding of a
point. Nothing here knows what a signature is.

What is built *on* a curve lives in btclib.ecc -- dsa, ssa, bms, borromean,
pedersen, Diffie-Hellman, the nonces -- and the rule between the two is that
direction: ecc imports curves, never the other way round.

The two names are easy to conflate -- everything in ecc is also about
curves -- so the anchor is worth stating: `from btclib.curves import mult`,
`from btclib.ecc import dsa`.

What this package exports is the curve API: a Curve, the catalogue they
are looked up in, the three scalar multiplications, and the SEC point
codec. `CURVES` is what makes the catalogue reachable -- `secp256k1` is
exported by name because nearly every caller wants that one, and every
other curve is `CURVES["secp256r1"]` -- so exporting the name and not the
dictionary left the paragraph above naming curves a caller could not get
at without importing the module the name is defined in. The four
catalogues it is the union of (SEC2v1, SEC2v2, NIST, Brainpool) stay
where they are defined: which standard a curve comes from is a question
about a curve, not a way of finding one. The other mult_* of
btclib.curves.curve_group and btclib.curves.curve_group_2 -- mult_aff, mult_jac,
mult_base_3, mult_mont_ladder, the two mult_recursive_*, the two
mult_fixed_window*, mult_regular_window, mult_sliding_window, mult_w_NAF and
mult_endomorphism_secp256k1 -- are deliberately not exported, nor are the
multiples, cached_multiples, odd_multiples and jac_from_aff they are built on.

They are implementations of one operation, kept side by side to be measured
against each other, and exporting them would make a menu out of a benchmark:
a caller reading btclib.curves would find every way of multiplying a point
this package implements and nothing to say that mult is the one to use, that
it dispatches to libsecp256k1 for secp256k1 and the generator, and that
mult_jac is not the faster alternative its name suggests. Each is importable
from the module that defines it, which is where the test suite takes them
from.

The codec has a third function, bytes_from_prv_key_int: the composition of
a multiplication and an encoding that every private-to-public conversion
is, answered for secp256k1 out of the bindings' own serialization, without
materializing the point (issue #127).
"""

from btclib.curves.curve import (
    CURVES,
    Curve,
    double_mult,
    mult,
    multi_mult,
    secp256k1,
)
from btclib.curves.curve_group import CurveGroup
from btclib.curves.curve_group_f import find_all_points, find_subgroup_points
from btclib.curves.sec_point import (
    bytes_from_point,
    bytes_from_prv_key_int,
    point_from_octets,
)

__all__ = [
    "CURVES",
    "Curve",
    "CurveGroup",
    "bytes_from_point",
    "bytes_from_prv_key_int",
    "double_mult",
    "find_all_points",
    "find_subgroup_points",
    "mult",
    "multi_mult",
    "point_from_octets",
    "secp256k1",
]
