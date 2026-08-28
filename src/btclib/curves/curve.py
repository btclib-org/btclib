# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The prime-order Curve and the multiplications built on it.

mult, double_mult_var and multi_mult_var dispatch secp256k1 to the
libsecp256k1 bindings and answer every other curve -- and the cases
the bindings cannot express -- with curve_group's arithmetic.

What this module exports is the class, the three multiplications,
`PreparedPoint` -- the one way a caller has of saying that a point of
its own will come back, so that the tables built for it are kept -- the
catalogue, the four standards it is the union of -- which is where
btclib.curves keeps them, a standard being a question about a curve and
not a way of finding one -- and the `*_params2` each of those four is
built from, which is what test_catalogued_curves rebuilds every curve
out of with both expensive checks on.

`datadir` stays out: it is where this package keeps the four json files
loaded below, so it answers a question about the installation rather than
about a curve, and `btclib.network` has a `datadir` of its own for the
network files. The loader's own names are underscored, a `with` target and
a `for` target being module globals like any other.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from math import isqrt
from pathlib import Path
from typing import Any

from typing_extensions import override

from btclib._libsecp256k1 import ENABLED as _bindings_enabled
from btclib._libsecp256k1 import INSTALLED as _bindings_installed
from btclib._libsecp256k1 import (
    PubkeyTweakChain as Libsecp256k1PubkeyTweakChain,
)
from btclib._libsecp256k1 import (
    pubkey_from_prvkey as libsecp256k1_pubkey_from_prvkey,
)
from btclib._libsecp256k1 import pubkey_sum as libsecp256k1_pubkey_sum
from btclib._libsecp256k1 import pubkey_tweak_add as libsecp256k1_pubkey_tweak_add
from btclib._libsecp256k1 import (
    pubkey_tweak_mul_sum as libsecp256k1_pubkey_tweak_mul_sum,
)
from btclib._libsecp256k1 import (
    xonly_pubkey_verify as libsecp256k1_xonly_pubkey_verify,
)
from btclib._libsecp256k1 import xonly_to_pubkey as libsecp256k1_xonly_to_pubkey
from btclib.alias import INF, HashF, Integer, JacPoint, Point
from btclib.curves.curve_group import (
    HEX_THRESHOLD,
    CurveGroup,
    _blinded_jac,
    _is_prime,
    _jac_from_aff,
    _mult,
    _mult_fixed_base,
    _multi_mult_var,
)
from btclib.curves.curve_group_2 import (
    _double_mult_endomorphism_secp256k1_var,
    _double_mult_w_NAF_var,
    _mult_endomorphism_secp256k1,
)
from btclib.exceptions import BTClibValueError
from btclib.number_theory import legendre_symbol_var
from btclib.utils import assert_type, hex_string, int_from_integer

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
    "double_mult_var",
    "is_libsecp256k1_serving",
    "mult",
    "multi_mult_var",
    "secp256k1",
    "set_libsecp256k1_serving",
]


def _generator_from_point(G: Point, ec: CurveGroup) -> Point:
    """Return the generator, checked against the group it must lie in.

    SEC 1 v.2 3.1.1.2.1 steps 2 and 4: the coordinates are integers in
    0..p-1, and they solve the curve equation. `ec` is the group under
    construction, which has its p, a and b by the time this is asked.
    """
    if len(G) != 2:
        raise BTClibValueError("generator must be a sequence[int, int]")
    point = int_from_integer(G[0]), int_from_integer(G[1])
    if not ec.is_on_curve(point):
        raise BTClibValueError("Generator is not on the curve")
    return point


def _assert_mov_resistant(p: int, n: int) -> None:
    """Refuse a curve whose embedding degree is under 100.

    SEC 1 v.2 3.1.1.2.1 step 8: p^i ≠ 1 (mod n) for 1 <= i < 100, which
    rejects the curves whose logarithm the MOV attack carries into an
    extension field where it is easy, and nothing downstream would notice.

    Its 99 modular exponentiations are the second cost of building a
    curve, once nG is gated: 5.2 ms of the 9.7 ms the catalogue would
    spend at import time, which is why the catalogue passes
    weakness_check=False and test_catalogued_curves runs it instead.

    A BTClibValueError, as every other rejection in this constructor is:
    the embedding degree is a parameter of the curve being refused, so
    the caller that catches an unusable `n` catches this one too. The
    n == p check below is the other weak-curve refusal, and the two
    disagreeing on their class is what left this one uncatchable for
    anyone holding the library to its own exception contract.
    """
    for i in range(1, 100):
        if pow(p, i, n) == 1:
            err_msg = "weak curve: the embedding degree is "
            err_msg += f"{i}, which is below 100"
            raise BTClibValueError(err_msg)


class Curve(CurveGroup):
    """Cyclic subgroup of prime order n, generated by G, of the curve points.

    The subgroup is ⟨G⟩ = {INF, G, 2G, …, (n-1)G}, of prime order n,
    inside the group of all the points of the curve — the `CurveGroup`
    this is built on, whose order is n times the cofactor h. The curve is
    that group and this is a subgroup of it, so the name is the wrong way
    round on purpose: this is the only group anything else in btclib
    multiplies in, and `Curve` is what a caller asks for.

    Two things follow from n being prime, and btclib.ecc relies on both:
    the integers modulo n are a field, so every scalar but zero has an
    inverse — the nonce and s that ecdsa inverts, the challenge that ssa's
    key recovery does — and the subgroup has no subgroup other than itself
    and {INF}, so every point of it but INF is a generator and no
    confinement to a small subgroup is possible.

    n is a parameter and not a computed quantity: the order of G is the
    order of the whole group divided by the index of ⟨G⟩ in it, and
    counting the points of a curve this size is Schoof-Elkies-Atkin rather
    than arithmetic on p, a and b. What the constructor does compute is
    that the parameter *is* the order, and that is where the primality of
    n earns its second keep. nG = INF proves only that n annihilates G,
    i.e. that the order of G divides n; pinning it to n in general asks
    for (n/q)G ≠ INF for every prime q dividing n, which is the
    factorization of n — a number no curve publishes alongside its
    parameters. With n prime and G ≠ INF the single nG = INF is the whole
    of it.

    Which is also why the two classes are the whole hierarchy, with no
    third one between them for the cyclic subgroup of unstated order:
    ⟨G⟩ carrying an n it cannot verify, or no n at all, is a cyclic group
    that cannot say how many elements it has, cannot reduce a scalar, and
    cannot bound a private key. Nothing here could take one as an
    argument.
    """

    def __init__(
        self,
        p: Integer,
        a: Integer,
        b: Integer,
        G: Point,
        n: Integer,
        cofactor: int,
        weakness_check: bool = True,
        order_check: bool = True,
        name: str | None = None,
    ) -> None:
        super().__init__(p, a, b)

        self.G = _generator_from_point(G, self)
        self.GJ = self.G[0], self.G[1], 1  # Jacobian coordinates
        # the generator and its opposite are what a verification hands the
        # same on every call, so their wNAF tables are memoized and held
        # wide; _cached_odd_multiples_aff says what that buys. The
        # endomorphism's images of the two are fixed as well and are added
        # by _double_mult_endomorphism_secp256k1_var, which is what forms them
        self._fixed_points = frozenset({self.GJ, self.negate_jac(self.GJ)})

        n = int_from_integer(n)

        # Security level is expressed in bits, where n-bit security
        # means that the attacker would have to perform 2^n operations
        # to break it. Security bits are half the key size for asymmetric
        # elliptic curve cryptography, i.e. half of the number of bits
        # required to express the group order n or, holding Hasse theorem,
        # to express the field prime p

        self.n = n
        self.nlen = n.bit_length()
        self.n_size = (self.nlen + 7) // 8
        # a scalar here is reduced mod n and not mod the order of the whole
        # curve, so nlen is a tighter bound than the plen + 1 CurveGroup
        # took from Hasse -- one window less at w=4 on secp256k1, and
        # log2(cofactor) bits less on a curve with a cofactor.
        # _mult_regular_window fixes its digit count to it, and reads it
        # under this name rather than as nlen so that a CurveGroup, which
        # has no n, can be multiplied in as well
        self.scalar_len = self.nlen

        # 5. Check that n is prime.
        if not _is_prime(n):
            err_msg = "n is not prime: "
            err_msg += f"{hex_string(n)}" if n > HEX_THRESHOLD else f"{n}"
            raise BTClibValueError(err_msg)
        # Hasse's half-width, floor(2*sqrt(p)), in integer arithmetic:
        # math.sqrt rounds p to 53 bits of mantissa before the truncation,
        # which on a 256-bit p overshoots by one and widens the interval
        # below by that much. isqrt(4*p) and not 2*isqrt(p): the two are
        # the same number only when p is a perfect square, floor(2*sqrt(p))
        # being what this is -- on p = 7 they are 5 and 4, and the second
        # refuses an n of 13 that Hasse admits
        delta = isqrt(4 * self.p)
        # also check n with Hasse Theorem
        if cofactor < 2 and not self.p + 1 - delta <= n <= self.p + 1 + delta:
            err_msg = "n not in p+1-delta..p+1+delta: "
            err_msg += f"{hex_string(n)}" if n > HEX_THRESHOLD else f"{n}"
            raise BTClibValueError(err_msg)

        # 7. Check that G ≠ INF, nG = INF
        if self.G[1] == 0:
            err_msg = "INF point cannot be a generator"
            raise BTClibValueError(err_msg)
        # n*G is by far the most expensive check here -- a Python
        # double-and-add over nlen bits -- and it dominates the cost of
        # building a curve: at import time the 27 catalogued curves would
        # spend ~118 ms of ~168 ms on it, against ~2 ms for the
        # primality of n. The catalogue therefore passes
        # order_check=False, as it does weakness_check=False below: its
        # parameters are constants, and test_catalogued_curves rebuilds
        # every one of them from the json data with both checks on, while
        # tests/curves/curve_group_test.py and curve_group_2_test.py assert
        # n*G == INF for every curve of CURVES through ten distinct mult
        # implementations. It stays on by default all the same, and is not
        # merely a test-time luxury: a caller-defined curve whose n is
        # not the order of G is accepted by every other check here and
        # then fails silently downstream, mult and sign returning
        # answers in a group nobody asked for
        if order_check and _mult(n, self.GJ, self)[2] != 0:
            err_msg = "n is not the group order: "
            err_msg += f"{hex_string(n)}" if n > HEX_THRESHOLD else f"{n}"
            raise BTClibValueError(err_msg)

        # 6. Check cofactor
        # floor((p + 1 + delta) / n), the upper end of the Hasse interval
        # divided by the subgroup order, in integer arithmetic for the
        # reason delta is: three float divisions of 256-bit integers each
        # round before they are added, where the quotient of a curve with
        # a cofactor of 1 sits one ulp above the integer it must truncate
        # to
        exp_cofactor = (1 + delta + self.p) // n
        if cofactor != exp_cofactor:
            err_msg = f"invalid cofactor: {cofactor}, expected {exp_cofactor}"
            raise BTClibValueError(err_msg)
        self.cofactor = cofactor

        # 8. Check that n ≠ p
        # self.p, not the p parameter: that one is still an Integer, and
        # every curve of this library's own catalogue spells it as a hex
        # string, so the comparison would be int == str -- false whatever
        # the curve. What it must reject is an anomalous curve, #E = p,
        # whose logarithm transfers to addition in F_p and is
        # polynomial-time (Smart, Semaev, Satoh-Araki), and the MOV check
        # below cannot catch it either: pow(self.p, i, n) with n == p is
        # 0, never 1 (issue #166)
        if n == self.p:
            raise BTClibValueError(f"n=p weak curve: {hex_string(n)}")

        if weakness_check:
            _assert_mov_resistant(self.p, n)

        self.name = name

    @override
    def __str__(self) -> str:
        result = super().__str__()
        # the generator is rendered as the curve is, in hex above the
        # threshold: a coordinate is the size of p, whatever its own
        # leading bits
        if self.p > HEX_THRESHOLD:
            result += f"\n x_G = {hex_string(self.G[0])}"
            result += f"\n y_G = {hex_string(self.G[1])}"
        else:
            result += f"\n x_G = {self.G[0]}"
            result += f"\n y_G = {self.G[1]}"
        if self.n > HEX_THRESHOLD:
            result += f"\n n   = {hex_string(self.n)}"
        else:
            result += f"\n n   = {self.n}"
        result += f"\n cofactor = {self.cofactor}"
        return result

    @override
    def __repr__(self) -> str:
        result = super().__repr__()[:-1]
        if self.p > HEX_THRESHOLD:
            result += f", ('{hex_string(self.G[0])}', '{hex_string(self.G[1])}')"
        else:
            result += f", ({self.G[0]}, {self.G[1]})"
        if self.n > HEX_THRESHOLD:
            result += f", '{hex_string(self.n)}'"
        else:
            result += f", {self.n}"
        result += f", {self.cofactor}"
        result += ")"
        return result

    @override
    def _eq_key(self) -> tuple[int, ...]:
        # name is not part of the curve: the same curve is catalogued as
        # secp256r1 by SEC 2 and as P-256 by NIST, and weakness_check and
        # order_check are construction-time options, not parameters. G is
        # one: it is the point every scalar is measured against, so two
        # curves differing in it hold the same points under a different
        # correspondence with the integers modulo n
        return (*super()._eq_key(), *self.G, self.n, self.cofactor)


def _assert_valid_ec(ec: Curve) -> None:
    """Refuse an ec that is not a prime-order curve.

    The Curve twin of `curve_group._assert_valid_ec`, and it is the class
    and not the group it derives from because `n` and `G` are Curve's:
    every multiplication below reduces its scalar mod n, so a CurveGroup
    would pass a group check and fail on a field it has not got.

    A type and not a field lookup, the way `hashes._assert_valid_hf` asks
    `callable` rather than making a digest: an ec is an object of the
    library's own making, with no conversion from anything else the way a
    network name has one, so the type is the whole of the question. That
    is what makes it `utils.assert_type`'s, which is the one spelling of
    the refusal for the whole library.

    `assert_type` costs about what an empty function of the same arity
    costs, negligible next to any public function that reaches it -- a
    signature, a verification, a multi-level BIP32 derivation, a
    multiplication -- so asking it where each public function first
    reads the parameter, once per parameter rather than once per
    function, adds nothing worth avoiding. A wall clock is a number
    that drifts, so `timeit` over the guard, over an empty function of
    the same arity, and over `dsa.sign` is what says whether that still
    holds -- and a harness drifts too, a closure around the guard
    measuring higher than the plain call does, so the guard and what it
    is measured against go in one process or neither is comparable.
    """
    assert_type(ec, Curve, "ec")


datadir = Path(__file__).parent / "_data"


def _catalogued_curve(params: list[Any], name: str) -> Curve:
    """Build one curve of the shipped catalogue, from its json parameters.

    One function for the four catalogues, so that the flags cannot drift
    apart. Both expensive checks are off: these parameters are the
    standardized constants of SEC 2, FIPS 186-4 and RFC 5639, and
    re-deriving from them at every interpreter start that n is the order
    of G, and that the curve is not MOV-weak, would cost 118 ms and 5 ms
    of a ~168 ms module import. What is verified once, by
    test_catalogued_curves rebuilding each curve from the same json data
    with both checks on, does not have to be verified again on the way to
    every signature.
    """
    p, a, b, G, n, cofactor = params
    return Curve(
        p, a, b, G, n, cofactor, weakness_check=False, order_check=False, name=name
    )


# Elliptic Curve Cryptography (ECC)
# Brainpool Standard Curves and Curve Generation
# https://www.rfc-editor.org/rfc/rfc5639.html
_filename = datadir / "ec_Brainpool.json"
with _filename.open(encoding="ascii") as _file:
    Brainpool_params2 = json.load(_file)
Brainpool: dict[str, Curve] = {
    _ec_name: _catalogued_curve(Brainpool_params2[_ec_name], _ec_name)
    for _ec_name in Brainpool_params2
}
# FIPS PUB 186-4
# FEDERAL INFORMATION PROCESSING STANDARDS PUBLICATION
# Digital Signature Standard (DSS)
# https://oag.ca.gov/sites/all/files/agweb/pdfs/erds1/fips_pub_07_2013.pdf
_filename = datadir / "ec_NIST.json"
with _filename.open(encoding="ascii") as _file:
    NIST_params2 = json.load(_file)
NIST: dict[str, Curve] = {
    _ec_name: _catalogued_curve(NIST_params2[_ec_name], _ec_name)
    for _ec_name in NIST_params2
}
# SEC 2 v.1 curves, removed from SEC 2 v.2 as insecure ones
# http://www.secg.org/SEC2-Ver-1.0.pdf
_filename = datadir / "ec_SEC2v1_insecure.json"
with _filename.open(encoding="ascii") as _file:
    SEC2v1_params2 = json.load(_file)
SEC2v1: dict[str, Curve] = {
    _ec_name: _catalogued_curve(SEC2v1_params2[_ec_name], _ec_name)
    for _ec_name in SEC2v1_params2
}
# curves included in both SEC 2 v.1 and SEC 2 v.2
# http://www.secg.org/sec2-v2.pdf
_filename = datadir / "ec_SEC2v2.json"
with _filename.open(encoding="ascii") as _file:
    SEC2v2_params2 = json.load(_file)
SEC2v2: dict[str, Curve] = {}
for _ec_name in SEC2v2_params2:
    # one object in both catalogues, not two: building the curve twice
    # would hand out two objects, and only one of them the secp256k1 the
    # libsecp256k1 dispatch below compares against
    SEC2v2[_ec_name] = _catalogued_curve(SEC2v2_params2[_ec_name], _ec_name)
    SEC2v1[_ec_name] = SEC2v2[_ec_name]

# a new dict, deliberately: aliasing (CURVES = SEC2v1) followed by
# update() calls would pour NIST and Brainpool into the SEC 2 v.1
# catalogue -- SEC2v1 with 27 entries instead of its own 15, and
# SEC2v1["nistp256"] answering a curve that is not in SEC 2 v.1 at all.
# Each catalogue holds what it is named after
CURVES = SEC2v1 | NIST | Brainpool

secp256k1 = CURVES["secp256k1"]


# whether the bindings may be used at all: the one question
# _libsecp256k1_serves below does not answer, which is not "can these
# bindings serve this call" but "may they serve any of them". Assigning
# False turns the delegation off across the whole package, because every
# dispatch asks the predicate and the predicate reads this global --
# whereas rebinding the predicate itself reaches one module of the nine
# that import it by name, so a caller that names them delegates in
# silence wherever it forgets one, and times C while calling it Python.
#
# What the import answered, and not a constant: `btclib._libsecp256k1` is
# the one place the bindings are imported, so an installation without
# them starts here at False and every dispatch in the package declines.
# It is also the seam whatever wants the Python arithmetic closes to
# reach it -- the test suite included, which assigns False to it where
# the bindings are installed and serving
_libsecp256k1_available = _bindings_enabled


def is_libsecp256k1_serving() -> bool:
    """Return True if the bindings are what this process delegates to.

    One question and not two: installed, and not refused. A caller has no
    use for the difference -- what it can act on is whether the answer it
    is about to get comes from libsecp256k1 or from the Python
    arithmetic -- and two observable states where there is one is how a
    caller comes to handle only the state it happened to meet.

    The public reading of the seam every dispatch consults. It is what a
    project built on btclib asks when it must not check libsecp256k1 with
    libsecp256k1: Bitcoin Core's own test framework keeps that rule --
    `crypto/secp256k1.py` is "designed for ease of understanding, not
    performance" -- and issue #198 is btclib's side of it.
    """
    return _libsecp256k1_available


def set_libsecp256k1_serving(*, serving: bool) -> None:
    """Ask for the bindings, or for the Python arithmetic, from here on.

    Process-wide and immediate: every dispatch in the package asks
    `_libsecp256k1_serves`, and that predicate reads the global this
    assigns, so nothing has to be re-imported and no module keeps an
    answer of its own.

    `serving=True` with the bindings not installed is a request that
    cannot be served, and is refused rather than silently ignored:
    a caller that asked for C and got Python would be timing Python and
    calling it C. `is_libsecp256k1_serving` is how the answer is read back.

    The environment variable is the other way in, and the earlier one:
    `BTCLIB_NO_LIBSECP256K1` set to a non-empty value makes the initial
    state False, which is what a test runner wants -- it settles before
    the first import, where this function cannot.
    """
    assert_type(serving, bool, "serving")
    if serving and not _bindings_installed:
        raise BTClibValueError(
            "btclib_secp256k1 is not installed: the bindings cannot serve"
        )

    global _libsecp256k1_available  # noqa: PLW0603
    _libsecp256k1_available = serving


def _libsecp256k1_serves(ec: Curve, hf: HashF | None) -> bool:
    """Return True if the libsecp256k1 bindings serve this ec and hf.

    Every dispatch to the bindings asks here, so that the predicates
    cannot drift apart the way hand-written copies would; a caller
    with a further condition of its own -- mult, whose bindings take the
    generator and a non-zero scalar alone -- ands it on top.

    hf is compared by identity, deliberately: nothing short of running
    the two functions tells sha256 from a look-alike, so a wrapper such
    as functools.partial(sha256) falls back to the Python path. That is
    the conservative direction -- slower, never wrong.
    """
    if not _libsecp256k1_available:
        return False
    if ec != secp256k1:
        return False
    return hf is None or hf is sha256


def _x_octets(x: int, ec: Curve) -> bytes | None:
    """Return x as the octets the bindings read, None if they cannot.

    The two functions below ask libsecp256k1 about an x coordinate, and
    this is the argument they ask with, plus the conditions under which
    there is one: the curve has to be secp256k1, and x has to be a field
    element, `xonly` taking no x-coordinate at or above ec.p and
    x.to_bytes raising OverflowError rather than answering for one.

    An x-only key and nothing built around it: `xonly.pubkey_verify` and
    `xonly.to_pubkey` are the x-only calls this feeds, and neither wants
    a compressed public key (0x02 || x) built around x. That
    concatenation belongs to `_multi_mult_x_only_var` instead, which
    needs a point for `pubkey_tweak_mul_sum`'s public-key API and has no
    x-only multiplication to reach for -- libsecp256k1 converts a point
    to an x-only key and offers nothing the other way, so the lift is
    that caller's rule, not this one's.
    """
    if not _libsecp256k1_serves(ec, None) or not 0 <= x < ec.p:
        return None
    return x.to_bytes(ec.p_size, "big")


def _is_x_coordinate_var(x: int, ec: Curve) -> bool:
    """Return True if x is the x-coordinate of a point of the curve.

    Existence and nothing else, which is what a caller with no use for
    the y has to ask, and it is a question the Legendre symbol answers
    without ever forming a root: 14 us on secp256k1 against the 75 of
    ec.y, and `xonly.pubkey_verify` answers the same of the x alone in
    2.4, being secp256k1_xonly_pubkey_parse and a verdict -- the same
    answer three ways, all three refusing the same x. It is
    libsecp256k1's own shape, `secp256k1_ge_x_on_curve_var` being
    `secp256k1_fe_is_square_var` of x^3 + ax + b and nothing else.

    A bool rather than an exception, because the value that names itself
    in an error message is the caller's and not this x: dsa.Sig's
    congruence check tries every x congruent to r and reports r. That is
    also what keeps the refusal cheap, where _y_even_var below cannot: half
    of the field elements are not x-coordinates, and the symbol costs the
    same for those as for the others.
    """
    octets = _x_octets(x, ec)
    if octets is not None:
        return libsecp256k1_xonly_pubkey_verify(octets)

    if not 0 <= x < ec.p:
        return False
    # the symbol is 0 for a y^2 of zero, which is the two-torsion point:
    # its root is zero and it is on the curve, so -1 is the whole of what
    # says otherwise
    return legendre_symbol_var(ec._y2(x), ec.p) != -1


def _y_even_var(x: int, ec: Curve) -> int:
    """Return the even y-coordinate associated to x.

    ec.y_even_var, delegated for secp256k1: the even y is the one an
    x-only key names, so `xonly.to_pubkey` asked for the uncompressed
    form hands back the y that was lifted -- 3.6 us against 73. That is
    1.2 more than _is_x_coordinate_var above, which is why both exist:
    finding the root is what the verdict does not do.

    An x the bindings refuse falls through to ec.y_even_var instead of
    raising here, so that the message stays in the one place that has the
    value to name: "invalid x-coordinate" is curve_group's to phrase, and
    the callers of this function wrap that message rather than restating
    it. The fallthrough pays the Python square root on a path whose
    answer is an exception, which is the trade _is_x_coordinate_var exists
    not to make. `to_pubkey` raises for one thing only -- an x that is no
    x-coordinate -- which is the one thing this falls through on.
    """
    octets = _x_octets(x, ec)
    if octets is not None:
        with contextlib.suppress(ValueError):
            uncompressed = libsecp256k1_xonly_to_pubkey(octets, compressed=False)
            return int.from_bytes(uncompressed[ec.p_size + 1 :], "big")

    return ec.y_even_var(x)


def _sec_from_point(Q: Point) -> bytes:
    """Return a point of secp256k1 as the octets the bindings parse.

    Neither on-curve nor infinity is checked here: this is the inside of
    the dispatches below, past their require_on_curve, and sec_point's
    bytes_from_point is unreachable from this module anyway -- that one
    is built on this one.

    Uncompressed, 0x04 || x || y, which is what makes the round trip
    worth taking, in both directions. It is the form ec_pubkey_parse
    reads without lifting an x coordinate back to a point, 2.1 us of the
    13 a whole multiplication costs; and, asked of ec_pubkey_serialize on
    the way out, the form that does not drop a y this side would have to
    lift again -- 3.2 us of point_from_octets against 1.2, a lift
    delegated to the bindings against two int.from_bytes, the lesson
    bip32.py records for public derivation. The 32 octets more cost
    0.09 us to write here.
    """
    p_size = secp256k1.p_size
    return b"\x04" + Q[0].to_bytes(p_size, "big") + Q[1].to_bytes(p_size, "big")


def _libsecp256k1_multi_mult_(
    scalars: Sequence[int], secs: Sequence[bytes]
) -> bytes | None:
    """Return sum(scalars[i]*points[i]) as octets, None for infinity.

    The bytes-in/bytes-out layer the gain lives on: one
    `keys.pubkey_tweak_mul_sum`, which is an ec_pubkey_tweak_mul per term
    and one ec_pubkey_combine over them, and no intermediate crosses the
    boundary at all -- neither as a Point, which would pay a parse on the
    way out and a serialization on the way back in, nor as the octets a
    term written here would be, which is the same pair one layer down.

    None rather than octets, because infinity has no serialization: a
    libsecp256k1 pubkey is a point of the curve and never the identity.
    Every scalar is therefore required to be in [1, n-1] and every point
    to be a point of secp256k1 that is not infinity -- the callers below
    gate on exactly that -- which leaves the sum as the one infinity to
    answer for: u*H + v*Q with v*Q == -u*H, and v = n - u with Q == H is
    the one-line case of it.

    The sum inside answers it, being `pubkey_combine` with that one sum
    answered rather than refused: libsecp256k1 reports 0 both for a key
    it could not read and for a total at infinity, and the first raises
    through the illegal callback, so a None back from here is the
    infinity and nothing else. What that replaces is a combine per term
    with a running total this side compared coordinates on, the only way
    of telling the two zeros apart while the sum was assembled here.

    The terms stopped crossing after it, which is the other half and the
    smaller one: a `pubkey_tweak_mul` per term serialized its product for
    a `pubkey_sum` that parsed it straight back, a seventh of what the
    call cost with them from eight terms up, a little less below it --
    including `double_mult_var`'s two, the count most callers have.
    Handing over the whole equation is what stops it, and that is the one
    composition the bindings hold rather than this side
    (btclib-secp256k1#182): a term of a multi-scalar multiplication is a
    `secp256k1_pubkey` nobody outside the sum has a use for, and this
    library holds no parsed key by design. The measurement per term count
    is in the CHANGELOG entry that took each half, which is where a
    figure belongs: an entry is read as the history of a release and this
    is read as a statement about the code as it stands.

    At least one term, the sum refusing an empty sequence as
    `pubkey_combine` does, and as many scalars as points, which is what
    the entry point raises for itself. Neither narrows what the callers
    below reach: fewer than two terms is not a multi_mult_var, and the two
    other entry points hand over one and two, each with its scalar.
    """
    return libsecp256k1_pubkey_tweak_mul_sum(secs, scalars, False)


def _multi_mult_x_only_var(
    scalars: Sequence[int], x_coords: Sequence[int], ec: Curve
) -> Point:
    """Return sum(scalars[i]*P_i), each P_i the even-y point of an x.

    The terms of BIP340's batch verification, which is the one caller and
    the one place in btclib that hands the bindings many scalars at once,
    libsecp256k1 exposing no batch verification of its own.

    The two arms differ in what they need of a term. `0x02 || x` is the
    even-y point an x-only key names, and the bindings lift it inside the
    multiplication that wants the point anyway; the Python arithmetic
    takes a `Point`, so there the lift is the work and is paid here. That
    is why this takes x-coordinates rather than points, and why the
    concatenation is written here rather than left to `xonly.to_pubkey`:
    what the octets are on their way to is `pubkey_tweak_mul_sum`, whose
    terms are public keys, and libsecp256k1 has no x-only multiplication
    to hand them to instead. It is the same rule `_x_octets` above serves,
    reached through the one door that exists for it.

    `_libsecp256k1_multi_mult_` and not the public `multi_mult_var`, that
    one taking points -- which is the form the lift would have to build
    and the multiplication would then write straight back out. The
    thirty-two terms of sixteen signatures: 301.9 us against 387.5 with
    both terms lifted by the caller, of the 553.9 that batch costs end to
    end.

    Every scalar is required to be in 1..n-1 and every x to be an
    x-coordinate. The caller is what holds to that -- ssa's rand is drawn
    in that range, its challenge is refused at zero, n is prime -- so
    what is left for the bindings to refuse is a term they cannot read,
    and finding which is the lift the accepting path does not pay. Issue
    622 made that trade the other way round in `Sig.assert_valid`, and it
    is the same one: the refusing path can afford a square root. The
    message is `ec.y_var`'s, from the lift itself rather than restated.
    """
    if _libsecp256k1_serves(ec, None):
        secs = [b"\x02" + x.to_bytes(ec.p_size, "big") for x in x_coords]
        try:
            total = _libsecp256k1_multi_mult_(scalars, secs)
        except ValueError:
            for x in x_coords:
                _y_even_var(x, ec)
            # the loop above raises, every ValueError from the bindings
            # here being a term they could not read: the pragma is the
            # one borromean and bms carry, for a line the arithmetic
            # rules out
            raise  # pragma: no cover
        return INF if total is None else _point_from_sec(total)

    points = [(x, _y_even_var(x, ec)) for x in x_coords]
    return multi_mult_var(scalars, points, ec)


def _point_from_sec(sec: bytes) -> Point:
    """Return the point of an uncompressed 0x04 || x || y serialization.

    The inverse of `_sec_from_point`, and read rather than parsed through
    `point_from_octets` for the same reason it writes rather than
    serializes: these are octets libsecp256k1 has just written, of a point
    it has just computed, so proving them a point of the curve again is
    work with a known answer.
    """
    p_size = secp256k1.p_size
    return (
        int.from_bytes(sec[1 : p_size + 1], "big"),
        int.from_bytes(sec[p_size + 1 :], "big"),
    )


def _libsecp256k1_multi_mult(scalars: Sequence[int], points: Sequence[Point]) -> Point:
    """Return sum(scalars[i]*points[i]), through the bindings.

    The Point signature the callers keep; the arithmetic is the bytes
    layer above, whose None is this function's INF.
    """
    sec = _libsecp256k1_multi_mult_(scalars, [_sec_from_point(Q) for Q in points])
    return INF if sec is None else _point_from_sec(sec)


# the widths mult and double_mult_var hand the variants below them; the
# measurement behind each is in the docstring of the function it is passed
# to, and they are two constants rather than one because what a window is
# measured on is the length of the scalars in it: the GLV endomorphism's
# halves take the first, whether one coefficient was split into two of
# them or two into four, and an interleaved wNAF's full-length
# coefficients take the second
_ENDOMORPHISM_W = 4
_DOUBLE_MULT_W = 4
# and the width the fixed-base ladder holds a table at, which is a
# third question again: its table is memoized, so what the width buys
# is paid in memory once and not in additions per call. The
# measurement is in _mult_fixed_base's docstring
_FIXED_BASE_W = 6


def mult(m_int: Integer, Q: Point | None = None, ec: Curve = secp256k1) -> Point:
    """Elliptic curve scalar multiplication."""
    _assert_valid_ec(ec)
    m: int = int_from_integer(m_int) % ec.n
    if Q is not None and Q != ec.G:
        # hoisted out of the two arms below, which each ran it: the
        # generator needs none, and every other point needs it on both
        # paths. Hoisted no further, so that a wrong `ec` is still the
        # first thing refused
        ec.require_on_curve(Q)
    return _mult_checked(m, Q, ec, prepared=False)


def _mult_checked(m: int, Q: Point | None, ec: Curve, *, prepared: bool) -> Point:
    """Return m*Q, the arguments already validated and m already reduced.

    What `mult` and `PreparedPoint.mult` share, so that the dispatch to
    the bindings is written once: the two differ in one thing, which is
    the Python arm a point that is not the generator takes.

    `prepared` says the caller has undertaken to multiply this point
    again -- `PreparedPoint` is where that undertaking is made and where
    what it costs is written. It sends the point to the same fixed-base
    ladder the generator runs, whose tables are memoized per point,
    instead of to the GLV endomorphism, which builds nothing and keeps
    nothing. On the bindings path it changes nothing at all: libsecp256k1
    is 22.8 us against the ladder's warm 142.3, so a prepared point is
    still faster delegated, and the tables are only reached where the
    bindings decline.
    """
    # m == 0 is the infinity point, which the bindings reject as a scalar
    if m and _libsecp256k1_serves(ec, None):
        # the generator is ec_pubkey_create, with no point to parse first
        if Q is None or Q == ec.G:
            # uncompressed and read by `_point_from_sec`, which is what
            # the other arm below reads its own answer with: the two ways
            # back to a `Point` were one function each until the bindings
            # folded their `mult` module into `keys`, that module's last
            # call having been this one with the flag fixed
            sec = libsecp256k1_pubkey_from_prvkey(m, compressed=False)
            return _point_from_sec(sec)
        # any other point, infinity excepted: that one is not a pubkey,
        # and m*INF == INF is what the Python path below answers anyway
        if Q[1]:
            return _libsecp256k1_multi_mult([m], [Q])

    if Q is None or Q == ec.G:
        # the fixed-base case, and the whole of what makes it one: the
        # point is the same on every call, so its per-position tables are
        # built once and kept and the multiplication makes no doubling at
        # all. It is faster than the endomorphism below on secp256k1 too,
        # so the test is on the point before it is on the curve
        return ec.aff_from_jac_var(_mult_fixed_base(m, ec.GJ, ec, _FIXED_BASE_W))

    QJ = _jac_from_aff(Q)

    if prepared:
        # the same ladder the generator takes, on the caller's word that
        # this point is the same on the next call too. No blinding of the
        # point here, and none is missing: _mult_fixed_base rescales its
        # accumulator instead, the table it indexes being memoized and
        # therefore canonical
        return ec.aff_from_jac_var(_mult_fixed_base(m, QJ, ec, _FIXED_BASE_W))

    # what reaches here on secp256k1 is the arguments the bindings decline
    # -- a zero scalar, or infinity -- and, with the dispatch
    # above switched off, every multiplication of the curve: that is the
    # reference implementation the test suite holds the bindings against,
    # and the GLV endomorphism is its fastest form, 0.59 ms against the
    # 0.82 of _mult, the decomposition being secp256k1's own lambda and
    # beta. Both are regular: the number of point additions either makes
    # is the same for every scalar, which is what a private key or a nonce
    # arriving here needs and what issue 254 is about -- the endomorphism
    # over interleaved wNAFs would be 0.51 ms and 51 to 64 additions.
    # Not spelled as _libsecp256k1_serves, though it is the same
    # test today: what decides here is whether the curve has that
    # endomorphism, so switching the bindings off must leave this arm --
    # python_path_test.py's pattern, which otherwise would compare the
    # bindings against the generic double-and-add of every other curve
    # the scalar of a mult is a private key or a nonce in every caller
    # btclib has, so the point it multiplies is rescaled first: same
    # affine point, a Z nobody can predict, and intermediate values that
    # stop being a function of m alone. _blinded_jac says what that buys
    # and what it does not
    QJ = _blinded_jac(QJ, ec)

    R = (
        _mult_endomorphism_secp256k1(m, QJ, ec, _ENDOMORPHISM_W)
        if ec == secp256k1
        else _mult(m, QJ, ec)
    )
    return ec.aff_from_jac_var(R)


@dataclass(frozen=True, init=False)
class PreparedPoint:
    """A point whose multiplication tables are kept, because it will come back.

    The tables of `curve_group` are memoized on `(point, curve, width)`
    already, so a repeated point would find its own: what is missing is
    anyone to say that a point *is* repeated. Only the generator is
    assumed to be, and everything else is treated as arriving once --
    which is right for most callers and wrong for a few, and no
    measurement can tell which a caller is. This is where a caller says
    so.

    Two tables answer to it, one per operation:

    - `mult` takes the fixed-base ladder of the generator instead of the
      GLV endomorphism: 142.3 us a call against 551.0, once 9.50 ms has
      built the per-position tables -- 43 positions of 64 points on
      secp256k1, some 366 KiB. Break-even is 23 multiplications of the
      one point -- `dh.diffie_hellman` against a counterparty, a taproot
      internal key tweaked repeatedly, `pedersen` against a fixed second
      generator.
    - a verification under it -- `dsa` and `ssa` both take one where they
      take a public key -- memoizes the wNAF tables of the key's two
      endomorphism halves at `_FIXED_POINT_W` instead of rebuilding them
      at `_DOUBLE_MULT_W` per signature: 2 tables built per verification
      become 0, and the verification 609.1 us against 471.0 for ECDSA,
      664.5 against 531.2 for BIP340. Break-even is 22 signatures under
      the one key, the first verification costing 3599 us where a bare
      key's costs 630.

    Both are the Python arithmetic. On secp256k1 with the bindings
    available neither is reached -- libsecp256k1 verifies in 22.8 us and
    holds its own tables in its own context -- so what this is for is the
    Python path: another curve, another hash function, or a deployment
    without the compiled bindings. Handing one in on the delegated path
    is not an error and costs nothing; it simply buys nothing.

    Preparing is a caller's word and never inferred, and the memory is
    why: the tables are per distinct point, so a library that memoized
    whatever public key arrived would hold a few MB for keys nobody will
    see again -- issue #287, the bound `_cached_base58_decode` and
    `pedersen.second_generator` hold too. What bounds it here is that
    nothing is prepared unless asked, and beyond that the `lru_cache`
    maxsize the tables live under.

    Nothing is built by the constructor. It parses and validates the
    point, which is the other half of what a verifier repeats -- 75.2 us
    of decompression per signature, on the Python path where a
    compressed key is a field square root -- and leaves the tables to the
    first multiplication that wants them, because which of the two
    families above is wanted is a question only that call answers.

    Measured on an Apple M5, macOS 26.6, arm64, CPython 3.14, with
    `curve._libsecp256k1_available` set to False; best of five
    alternating rounds of 300 to 800 calls, and the median of seven for
    the cold rows, each on a freshly derived point so that the tables are
    built rather than found. A working desktop rather than a quiesced
    machine: a ratio, not a figure to quote.

    Attributes:
        point: the point, as the constructor validated it.
        ec: the curve it was validated against.
        fixed: the Jacobian set a verification hands straight down,
            derived by the constructor from the two above; the comment
            beside the field is what it holds and why it is derived.

    Args:
        point: the point to prepare, on the curve and not infinity.
        ec: the curve it belongs to.

    Raises:
        BTClibValueError: if the point is not on the curve, or is
            infinity, which has no tables and multiplies to itself.
    """

    point: Point
    ec: Curve = secp256k1
    # the set `_multi_mult_w_NAF_var` reads, complete rather than the
    # point's own share of it, so that a verification hands it straight
    # down and nothing on the hot path unions two frozensets per call.
    # The negation is in it for the reason `Curve.__init__` puts the
    # generator's there: the GLV split of a point is +-P and +-lambda*P,
    # and which sign it asks for is the coefficient's business. The two
    # lambda images are not here, being formed by
    # _double_mult_endomorphism_secp256k1_var and added by it.
    # Out of the repr and out of the comparison because it is derived:
    # two prepared points of the same point and curve are the same
    # preparation, and a frozenset of Jacobian triples printed beside a
    # Curve is a screenful saying nothing the point does not
    fixed: frozenset[JacPoint] = field(init=False, repr=False, compare=False)

    # init=False on the decorator, as `dsa.Sig` has it, and on the
    # `fixed` field besides: that one is derived rather than passed, and
    # a field with no default following `ec`, which has one, is a
    # signature dataclasses refuses to generate and mypy refuses to read
    def __init__(self, point: Point, ec: Curve = secp256k1) -> None:
        _assert_valid_ec(ec)
        ec.require_on_curve(point)
        # infinity is on the curve and is not a point to prepare: it has
        # no affine table -- `_signed_odd_multiples_aff` would convert it
        # -- and m*INF is INF without any of this
        if not point[1]:
            raise BTClibValueError("cannot prepare the point at infinity")

        object.__setattr__(self, "point", point)
        object.__setattr__(self, "ec", ec)
        PJ = _jac_from_aff(point)
        object.__setattr__(self, "fixed", ec._fixed_points | {PJ, ec.negate_jac(PJ)})

    def mult(self, m_int: Integer) -> Point:
        """Return m*point, through the tables this point keeps.

        `curve.mult` with the fixed-base arm taken for this point instead
        of only for the generator; everything else about the call, the
        dispatch to the bindings included, is the same.
        """
        m: int = int_from_integer(m_int) % self.ec.n
        return _mult_checked(m, self.point, self.ec, prepared=True)


def _double_mult_python(
    u: int, HJ: JacPoint, v: int, QJ: JacPoint, ec: Curve, fixed: frozenset[JacPoint]
) -> JacPoint:
    """Return u*HJ + v*QJ in Python, through the endomorphism if there is one.

    The arm `double_mult_var` and `_jac_double_mult` share, so that one place
    decides which double multiplication a curve gets and both reach the
    same one. On secp256k1 that is the GLV split of both coefficients,
    which is to `_double_mult_w_NAF_var` what `_mult_endomorphism_secp256k1`
    is to `_mult`: the same answer for ~128 doublings instead of ~256.

    Dispatched on the curve having the endomorphism, not on
    `_libsecp256k1_serves` -- the same test today, and not the same
    question. `mult` says why at length: switching the bindings off is how
    python_path_test.py holds them against the Python arithmetic, and a
    dispatch spelled the other way would answer that test with the generic
    interleaved wNAF every other curve runs instead of with secp256k1's
    own fastest path.

    Which makes this the second curve comparison of the call, the guard
    above having asked `_libsecp256k1_serves` the first: 0.394 us on a
    curve that is not secp256k1, the frame and `Curve.__eq__`'s two
    _eq_key tuples together, where the identical object short-circuits on
    identity. That is 8% of a low-cardinality double multiplication and
    two tenths of a second of the suite, spent for the same reason
    _double_mult_w_NAF_var spends about 3 us a call there: what the saving
    would buy is a fraction of a second, and what it would cost is a
    second copy of the dispatch, one per caller, free to drift. `mult`
    makes the same two comparisons for the same reason.

    `fixed` is the points whose tables are memoized, passed down rather
    than read off `ec` at the bottom: a verification under a
    `PreparedPoint` names the key there, and every other caller names
    `ec._fixed_points`, so passing it down is what lets a `PreparedPoint`'s
    own superset reach the bottom instead of a direct read of
    `ec._fixed_points` losing it.
    """
    if ec == secp256k1:
        return _double_mult_endomorphism_secp256k1_var(
            u, HJ, v, QJ, ec, _ENDOMORPHISM_W, fixed
        )
    return _double_mult_w_NAF_var(u, HJ, v, QJ, ec, _DOUBLE_MULT_W, fixed)


def double_mult_var(
    u: Integer, H: Point, v: Integer, Q: Point, ec: Curve = secp256k1
) -> Point:
    """Double scalar multiplication (u*H + v*Q)."""
    _assert_valid_ec(ec)
    ec.require_on_curve(H)
    ec.require_on_curve(Q)

    u = int_from_integer(u) % ec.n
    v = int_from_integer(v) % ec.n

    # a zero scalar and infinity are what the bindings decline, and the
    # term they make is nothing: dropping it here would leave the empty
    # sum -- infinity -- to answer for as well, which the Python path
    # below answers already, so the whole call goes there instead
    if u and v and H[1] and Q[1] and _libsecp256k1_serves(ec, None):
        return _libsecp256k1_multi_mult([u, v], [H, Q])

    HJ = _jac_from_aff(H)
    QJ = _jac_from_aff(Q)
    # nothing prepared: this entry point takes two bare points, and a
    # caller with a point that repeats says so through `PreparedPoint`,
    # which the verifications take
    R = _double_mult_python(u, HJ, v, QJ, ec, ec._fixed_points)
    return ec.aff_from_jac_var(R)


def _sum_var(points: Sequence[Point], ec: Curve) -> Point:
    """Return the sum of points, no scalar in it.

    `ec.add_var` is one modular inversion and a few products, and the
    reason to hand it over was not obvious: a delegated addition is two
    serializations and a parse around one C addition, where the Python is
    an extended Euclid. Measured, the Euclid is what dominates: one
    addition 4.41 us delegated against 11.03, and the gap widens with
    every term -- an addition of the Python chain costs 11 us where a
    term added to a delegated sum costs 0.46. The crossing is cheap
    because it is the uncompressed serialization `_sec_from_point`
    writes, which ec_pubkey_parse reads without lifting an x; a
    compressed one would be a field square root a term.

    A sequence and not a pair, because the callers are sums: BIP352's
    `pub_key_sum` over the eligible inputs and MuSig2's `nonce_agg` over
    the signers, where one `keys.pubkey_sum` of all the terms replaces a
    running total that crossed the boundary at every step, and is worth
    better than half of both. The measurement per term count, and at
    those two callers, is in the CHANGELOG entry that took it, an entry
    being read as the history of a release where this is read as a
    statement about the code as it stands.

    Infinity is the identity and libsecp256k1 has no public key for it,
    so a term at infinity is dropped rather than handed over, and a sum
    at infinity comes back as the None `pubkey_sum` answers with --
    both handled below rather than left to the C call, an intermediate
    sum at infinity being a real BIP352 vector.
    """
    for Q in points:
        ec.require_on_curve(Q)

    if _libsecp256k1_serves(ec, None):
        # infinity is the identity and libsecp256k1 has no public key for
        # it, so a term at infinity is dropped rather than handed over.
        # y == 0 is infinity and nothing else *here*: the one real point
        # with a zero y is the two-torsion one, and a group of prime
        # order has none -- which this arm is, secp256k1 being what
        # `_libsecp256k1_serves` above has just agreed to. The Python arm
        # below cannot make that assumption and does not: `add_aff_var`
        # tests the same y and says why in its own comment
        secs = [_sec_from_point(Q) for Q in points if Q[1]]
        # and a run with no addition left in it is answered without
        # crossing: one term is that term, and none is infinity. 7.11 us
        # against 10.31 for BIP352's one-input sum, which is a crossing
        # to be told what was handed over
        if len(secs) < 2:
            return _point_from_sec(secs[0]) if secs else INF
        total = libsecp256k1_pubkey_sum(secs, False)
        return INF if total is None else _point_from_sec(total)

    # already on the curve, so add_aff_var rather than add_var, which
    # would ask it again of every partial sum as well
    total_point: Point = INF
    for Q in points:
        total_point = ec.add_aff_var(total_point, Q)
    return total_point


def _tweak_add_var(P: Point, t: int, ec: Curve) -> Point:
    """Return P + t*G, a point plus a multiple of the generator.

    One shape in several places: the point a sign-to-contract commitment
    lands on, the outputs and labels of BIP352, a MuSig2 tweak. Spelled
    `add_var(P, mult(t, ec.G, ec))` it is a delegated multiplication, the
    product read back into a Point, P written out again for the addition,
    and that addition made here; `secp256k1_ec_pubkey_tweak_add` is the
    shape itself, one call on the serialized point -- 10.89 us against
    19.62 on secp256k1.

    Not `double_mult_var(1, P, t, ec.G, ec)`, which is the same sum and
    delegates too: that one multiplies P by one, and a scalar
    multiplication is the cost this exists not to pay.

    BIP32's public derivation and BIP341's output key are this shape as
    well and do not come through here: each has a libsecp256k1 entry point
    of its own -- `keys.PubkeyTweakChain`, which holds the parsed point
    across a whole path, and `xonly.tweak_add`, which carries the parity
    BIP341 commits to.

    The Python arm is the pair above, and answers what the bindings
    decline: an infinite P, a curve that is not secp256k1, and the sum at
    infinity -- which libsecp256k1 has no public key for and `add_var`
    returns.

    A zero tweak is not in that list: libsecp256k1 takes a tweak "valid
    according to secp256k1_ec_seckey_verify *or 32 zero bytes*", which
    its own header says of `secp256k1_ec_pubkey_tweak_add`, and answers
    P directly, at 5.01 us against the 131.40 that routing it to the
    Python pair instead would cost -- there `mult` has the scalar
    libsecp256k1 declines and takes the fixed-base ladder for an answer
    that is the point already in hand.
    """
    ec.require_on_curve(P)
    t %= ec.n

    if P[1] and _libsecp256k1_serves(ec, None):
        with contextlib.suppress(ValueError):
            sec = libsecp256k1_pubkey_tweak_add(_sec_from_point(P), t, False)
            return _point_from_sec(sec)

    return ec.add_var(P, mult(t, ec.G, ec))


class _TweakChain:
    """One point, many tweaks of it, and one parse on the far side.

    `_tweak_add_var` above crosses the boundary once per tweak: the point
    is serialized here, libsecp256k1 parses it, tweaks it and serializes
    the answer, and this side reads that back. A caller tweaking *one*
    point over and over pays the parse at every tweak, for a point that
    has not changed since the last one -- BIP352's `scan_outputs` is the
    caller, walking k upward from one spend key.

    The tweaks asked of this are absolute, each measured from the point
    the chain was built on, because that is what the caller means by
    t_k. What crosses is their differences:

        P_k     = B + t_k*G
        P_(k+1) = P_k + (t_(k+1) - t_k)*G

    which makes many tweaks of one point a chain of steps, each step's
    output the next one's input, and `keys.PubkeyTweakChain` is the
    object that holds the parsed point across such a chain. So this
    needs no fan-out entry point of its own, and the bindings have none:
    the fan-out is a chain read the other way round. Sixteen tweaks of
    one point 112.7 us against 133.8, the difference being the fifteen
    parses that do not happen; what that is worth at the one caller, per
    number of outputs found, is in the CHANGELOG entry that took it.

    Nothing is required of the order the tweaks arrive in. The
    difference is taken modulo n, so the same tweak may be asked for
    twice -- a zero step, which libsecp256k1 adds like any other and
    answers with the point it already holds, its header saying so of
    every tweak it takes -- and a later tweak may be smaller than an
    earlier one. An instance is reusable for that reason: the base never
    moves, and what is held beside it is only the tweak the next
    difference is measured from.

    Args:
        base: the point every tweak is added to.
        ec: the curve it belongs to.

    Raises:
        BTClibTypeError: if the curve is not a Curve.
        BTClibValueError: if the point is not on the curve.
    """

    def __init__(self, base: Point, ec: Curve = secp256k1) -> None:
        # both, and in this order, as `PreparedPoint` above has them: the
        # point is on a curve, so a curve that is not one is what has to
        # be refused first
        _assert_valid_ec(ec)
        ec.require_on_curve(base)
        self.base = base
        self.ec = ec
        # the tweak the chain's point currently stands at, from which the
        # next step is measured; zero is the base itself
        self._tweak = 0
        # infinity has no public key on the other side, and a curve that
        # is not secp256k1 has no bindings at all: either way there is
        # nothing to hold across the calls, and `point` below answers
        # each of them on its own
        self._chain = (
            Libsecp256k1PubkeyTweakChain(_sec_from_point(base))
            if base[1] and _libsecp256k1_serves(ec, None)
            else None
        )

    def point(self, t: int) -> Point:
        """Return base + t*G, taking the step from the last tweak asked for."""
        t %= self.ec.n
        if self._chain is not None:
            try:
                sec = self._chain.tweak_add((t - self._tweak) % self.ec.n, False)
            except ValueError:
                # the step landed on infinity, which libsecp256k1 has no
                # public key for. The failure clears the point the chain
                # was holding, so there is nothing left to continue from
                # and it is dropped rather than resumed -- this tweak and
                # every later one go to the one-shot pair above, whose
                # Python arm is what has an infinity to answer with
                self._chain = None
            else:
                self._tweak = t
                return _point_from_sec(sec)

        return _tweak_add_var(self.base, t, self.ec)


def _jac_double_mult(
    u: int, HJ: JacPoint, v: int, QJ: JacPoint, ec: Curve, fixed: frozenset[JacPoint]
) -> JacPoint:
    """Return u*HJ + v*QJ in Jacobian coordinates, delegated where it can be.

    double_mult_var for a caller whose equation is written in projective
    coordinates: dsa's and ssa's _assert_as_valid_, which are the two
    verifications the bindings' own decline -- a hash function that is not
    sha256, a BIP340 message that is not 32 bytes (issue 169), a
    caller-imposed nonce, another curve -- and which paid a Python
    double_mult_var underneath whatever the reason. 1.02 ms against 28 us on
    secp256k1.

    Jacobian in and Jacobian out, rather than those two rewritten in
    affine coordinates, because it is not only their arithmetic that is
    projective: so are the infinity test, the y parity and the x
    comparison each makes, and so is the QJ that public key recovery
    threads through dsa's. _jac_from_aff is what keeps that exact --
    infinity has no serialization on the other side of the boundary, and
    it answers the z == 0 both functions already recognize, so each still
    raises what it raised before, from the same line.

    The two conversions in are one modular inversion each on the z == 1
    that a parsed key and a lifted r arrive as, and a shortcut for that
    case -- the affine point being the same pair of coordinates, no
    inversion at all -- saves both of them, 3% of the 28 us the call
    costs. Not worth a branch, and neither is the caller's own
    mod_inv_var(1) on the way back out, the same inversion again on the
    cheapest operand it has.
    """
    if not _libsecp256k1_serves(ec, None):
        return _double_mult_python(u, HJ, v, QJ, ec, fixed)

    # `fixed` is dropped on this arm and nothing is lost: libsecp256k1
    # holds its own tables in its own context, and what a caller prepared
    # here is a table of the Python arithmetic
    R = double_mult_var(u, ec.aff_from_jac_var(HJ), v, ec.aff_from_jac_var(QJ), ec)
    return _jac_from_aff(R)


def multi_mult_var(
    scalars: Sequence[Integer], points: Sequence[Point], ec: Curve = secp256k1
) -> Point:
    """Return the multi scalar multiplication u1*Q1 + ... + un*Qn.

    Interleaved wNAF on few scalars, Bos-Coster on many: curve_group's
    _multi_mult_var dispatches on the count, at the size the two measure the
    same. On secp256k1 the bindings serve the whole sum instead.

    ssa's batch verification is what hands many scalars over at once,
    libsecp256k1 exposing no batch verification of its own, and it is the
    Python arm of that sum which arrives here: the delegated arm reaches
    `_libsecp256k1_multi_mult_` below with its terms as octets, this
    signature taking points and a point being what its terms would have
    to be lifted into for the multiplication to write them straight back
    out.
    """
    _assert_valid_ec(ec)
    if len(scalars) != len(points):
        err_msg = "mismatch between number of scalars and points: "
        err_msg += f"{len(scalars)} vs {len(points)}"
        raise BTClibValueError(err_msg)

    ints = [int_from_integer(s) % ec.n for s in scalars]
    for Q in points:
        ec.require_on_curve(Q)

    # as in double_mult_var; and fewer than two terms is not a multi_mult_var at
    # all, an error the Python path below is the one to raise
    if (
        len(points) > 1
        and _libsecp256k1_serves(ec, None)
        and all(m and Q[1] for m, Q in zip(ints, points, strict=True))
    ):
        return _libsecp256k1_multi_mult(ints, points)

    jac_points = [_jac_from_aff(Q) for Q in points]
    R = _multi_mult_var(ints, jac_points, ec)
    return ec.aff_from_jac_var(R)
