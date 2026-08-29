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
are looked up in, the three scalar multiplications, the SEC point codec,
and PreparedPoint, which is a point plus a caller's word that it will be
multiplied again -- the one thing the memoized tables below cannot infer
and the whole of what stands between a repeated point and the treatment
the generator gets.

`CURVES` is what makes the catalogue reachable -- `secp256k1` is
exported by name because nearly every caller wants that one, and every
other curve is `CURVES["secp256r1"]` -- so exporting the name and not the
dictionary left the paragraph above naming curves a caller could not get
at without importing the module the name is defined in. The four
catalogues it is the union of (SEC2v1, SEC2v2, NIST, Brainpool) stay
where they are defined: which standard a curve comes from is a question
about a curve, not a way of finding one.

The other multiplications of btclib.curves.curve_group and
btclib.curves.curve_group_2 -- _mult_aff_var, _mult_jac_var,
_mult_base_3_var, _mult_mont_ladder_var, the two _mult_recursive_*_var, the
two _mult_fixed_window*_var, _mult_fixed_base, _mult_regular_window,
_mult_sliding_window_var, _mult_w_NAF_var, the three _double_mult_*, and the
two _mult_endomorphism_secp256k1* -- are private, as are the _multiples,
_cached_multiples, _cached_fixed_base_multiples, _odd_multiples and
_jac_from_aff they are built on.

The _var suffix on most of those is libsecp256k1's, and it says the same
thing: the number of point operations such a multiplication makes depends
on the coefficient it is given, where _mult_regular_window,
_mult_fixed_base and _double_mult_regular_window make the same number for
every scalar of the curve. CONTRIBUTING.md states the rule, and states
what its absence does not promise: nothing here is constant-time.

**Which one runs is not a setting, and a census says why it is not**
(issue #849). On the generator the regular form is also the faster one,
by a factor of four: _mult_fixed_base makes no doubling at all, where a
wNAF makes one per bit however wide its table is and however thoroughly
it is cached, the factor holding over the memoized odd multiples of G at
w=8, w=10 and w=12 alike. So the arm every key derivation, every BIP32
child and every signing nonce runs has no variable-time alternative to
offer. What is left is a variable-base mult with a secret scalar, which
in this package is ecc.dh: 1.13x on secp256k1 and 1.03x on nistp256, the
second being that measurement's own noise. Beside it, the blinded nonce
inverse is a fraction of a percent of a signature, the projective
blinding of curve_group._blinded_jac is 1%, and every verification is
already _var. The 1.13x was measured with the bindings switched off.
btclib_secp256k1 is the secp256k1 extra rather than a required
dependency, so a caller who skips it is already in that state, with
nothing to switch.

They are implementations of one operation, kept side by side to be measured
against each other, and a menu of them is not an API: a caller reading them
would find every way of multiplying a point this package implements and
nothing to say that mult is the one to use, that it dispatches to
libsecp256k1 for secp256k1 and the generator, and that _mult_jac_var is
not the faster alternative its name suggests.

The underscore says the second thing too, which is what decided it: each
takes a point it assumes to be on the curve and checks nothing, so a
malformed one is answered with a point rather than refused. mult,
double_mult_var and multi_mult_var are where require_on_curve runs, on every
argument and every path, and reaching past them is reaching past that. The
test suite takes each variant from the module that defines it, which is
what a private name is still good for.

Beside the two point conversions the codec carries bytes_from_prv_key_int,
the composition of a multiplication and an encoding that every
private-to-public conversion is, answered for secp256k1 out of the
bindings' own serialization, without materializing the point (issue #127);
and scalar_from_prv_key, which reads a private key the other way, as the
scalar in 1..n-1 that it is. What a private key may be spelled as at this
layer is the integer, its n_size octets, or their hex. That is narrower
than everything Integer takes -- int_from_integer reads a "0x" prefix
and a short hex string, which a key of a fixed size must not be -- and
the annotation is Integer because the two are the same union of types
and a second name for it would say nothing mypy could check. A WIF and
an extended key are not among the spellings at all, belonging to b58 and
bip32, above here (issue #1188).
"""

from btclib.curves.curve import (
    CURVES,
    Curve,
    PreparedPoint,
    double_mult_var,
    is_libsecp256k1_serving,
    mult,
    multi_mult_var,
    secp256k1,
    set_libsecp256k1_serving,
)
from btclib.curves.curve_group import CurveGroup
from btclib.curves.curve_group_f import find_all_points, find_subgroup_points
from btclib.curves.sec_point import (
    bytes_from_point,
    bytes_from_prv_key_int,
    point_from_octets,
    scalar_from_prv_key,
)

__all__ = [
    "CURVES",
    "Curve",
    "CurveGroup",
    "PreparedPoint",
    "bytes_from_point",
    "bytes_from_prv_key_int",
    "double_mult_var",
    "find_all_points",
    "find_subgroup_points",
    "is_libsecp256k1_serving",
    "mult",
    "multi_mult_var",
    "point_from_octets",
    "scalar_from_prv_key",
    "secp256k1",
    "set_libsecp256k1_serving",
]
