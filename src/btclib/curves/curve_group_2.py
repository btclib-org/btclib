# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Elliptic curve point multiplication functions.

The implemented algorithms are:

    - Montgomery Ladder
    - Scalar multiplication on basis 3
    - Fixed window
    - Regular window, signed odd digits (Joye-Tunstall recoding)
    - Sliding window
    - w-ary non-adjacent form (wNAF)
    - Interleaved-wNAF double multiplication (HMV algorithm 3.51)
    - Regular-window double multiplication
    - GLV endomorphism multiplication for secp256k1 (HMV algorithm 3.77)
    - GLV endomorphism double multiplication for secp256k1

References:
    - https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
    - https://cryptojedi.org/peter/data/eccss-20130911b.pdf
    - https://ecc2017.cs.ru.nl/slides/ecc2017school-castryck.pdf
    - https://cr.yp.to/bib/2003/joye-ladder.pdf
    - D. Hankerson, 'Guide to Elliptic Curve Cryptography' chapter 3
    - M. Joye and M. Tunstall, 'Exponent Recoding and Regular
      Exponentiation Algorithms', AFRICACRYPT 2009, for the signed odd
      digits of a regular window
    - https://bitcointalk.org/index.php?topic=3238.msg45565#msg45565
    - https://medium.com/@CoinExChain/acceleration-of-ecdsa-verification-with-endomorphism-mapping-of-secp256k1-126e77a51dba

Further improvements, and the material for them. These are not
bibliography: each is an improvement this module could take, with what
would be needed to take it, kept next to the code it is about. The
point-addition special cases are settled where they live, in
`curve_group`'s own comments, and issue 183 tracks the smaller
follow-ups; what is here is the rest:

    - Computational cost of the different multiplications, measured rather
      than assumed: which of the six is fastest, and at what scalar size
    - New algorithms at the state of the art:

        - https://hal.archives-ouvertes.fr/hal-00932199/document
        - https://iacr.org/workshops/ches/ches2006/presentations/Douglas%20Stebila.pdf
        - https://arxiv.org/abs/1801.08589
        - https://eprint.iacr.org/2005/419
        - https://www.esat.kuleuven.be/cosic/publications/article-2293.pdf
        - https://crypto.stackexchange.com/questions/58506/what-is-the-curve-type-of-secp256k1
        - 1-s_2.0-S1071579704000395-main (the file name it was saved as; the
          paper it refers to has not been identified)
    - Joint sparse form (JSF, HMV algorithm 3.50) for double mult: the
      alternative to the interleaving _double_mult_w_NAF_var implements --
      one joint recoding of both scalars instead of one NAF each, fewer
      total additions in exchange for digit pairs that do not index a
      per-point table of odd multiples

Measured against libsecp256k1 and not taken. Each of these is an algorithm
that library carries and this one does not, with the result that decided
it, so that what the next reader has is the verdict and not the
measurement to make again. Best of five on secp256k1's p, Python 3.14.6,
macOS arm64:

    - the field inverse by an addition chain, Peter Dettman's and Brian
      Smith's, and libsecp256k1's own safegcd beside them:
      `pow(a, -1, p)` is CPython's extended Euclid in C, where 255
      modular squarings in bytecode -- fewer than any chain needs --
      cost several times what it does. `pow(a, p - 2, p)` costs about
      what those squarings do, which is why `mod_inv_var` does not
      spell Fermat either:

        - https://briansmith.org/ecc-inversion-addition-chains-01
    - fast reduction for a pseudo-Mersenne p: the Solinas form for
      `2^256 - 2^32 - 977`, two products by a 33-bit constant and a
      conditional subtraction, costs more than `x % p` does. CPython's
      division is C, and 512 bits by 256 is small
    - limbs with delayed reduction, libsecp256k1's 5 by 52 bits and its
      magnitude tracking: the Python analogue is letting intermediates
      grow, which `add_jac`'s own comment measured at 2.0x to 3.0x the
      wrong way -- an integer costs what its size costs
    - a separate squaring routine: CPython's long_mul already takes the
      squaring path when both operands are the same object, `a*a % p`
      costing measurably less than `a*b % p`
    - the masked table lookup of `secp256k1_ecmult_table_get_ge`, which
      reads every entry of a table under a cmov: a list index is a list
      index
    - the lambda split's division by a multiply and a shift,
      `secp256k1_scalar_mul_shift_var`: `_multiplier_decomposer` rounds
      with `(_B2 * m + n // 2) // n`, 384 bits by 256, where libsecp256k1
      multiplies by a precomputed reciprocal instead. The rounding is
      the dearer of the two and is paid once per multiplication, which
      is three orders of magnitude above either
    - the table built with no inversion at all,
      `secp256k1_ecmult_odd_multiples_table` with
      `secp256k1_ge_table_set_globalz`: the odd multiples are formed on an
      isomorphic curve where the doubled point is affine, the z-ratios are
      kept as they go, and the entries reach one common Z by products
      alone. What it would remove is the single inversion a call now
      spends, which is 1% of a `_mult` and 0.2% of what a 16-point
      `_multi_mult_var` takes; the rest of that conversion is the three
      products an entry costs, and the isomorphic construction pays
      those in its own coin. An accumulator that has to live in that
      frame and be rescaled out of it at the end, for those two ceilings
    - the square root by an addition chain is the one of these that
      measures positive and is still not here: `pow(a, (p + 1) // 4, p)`
      is 1.16x libsecp256k1's chain, for some twenty lines holding for
      secp256k1's p alone, on a function a point decompression away from
      these loops

"""

from __future__ import annotations

from math import ceil

from btclib.alias import INFJ, JacPoint

# the wNAF recoding and the table of odd multiples it indexes live in
# curve_group, next to _convert_number_to_base and for the same reason:
# its interleaved _multi_mult_w_NAF_var needs them, and the dependency runs
# one way, this module importing that one
from btclib.curves.curve_group import (
    CurveGroup,
    _convert_number_to_base,
    _jac_from_aff,
    _multi_mult_w_NAF_var,
    _signed_odd_multiples_aff,
    _wNAF_of_m,
    signed_odd_digits,
)
from btclib.exceptions import BTClibValueError

# empty, and declared rather than omitted: every multiplication here is a
# variant kept to be measured against the others, which is what the leading
# underscore says, so this module has nothing public of its own.
# `curve.py`'s mult, double_mult_var and multi_mult_var are what a caller
# reaches, and they validate every point before dispatching to any of these
__all__: list[str] = []


def _sliding_window_table(Q: JacPoint, ec: CurveGroup, w: int) -> list[JacPoint]:
    """Return the multiples a full window can name, 2^(w-1)*Q to (2^w - 1)*Q.

    Half the table the fixed window needs, which is where "roughly half
    as complex a pre-computation" comes from: a window is only ever
    opened on a nonzero digit, so its value has its top bit set and no
    multiple below 2^(w-1) is ever indexed.
    """
    P = Q
    for _ in range(w - 1):
        P = ec.double_jac(P)
    T = [P]
    for _ in range(1, pow(2, w - 1)):
        T.append(ec.add_jac(T[-1], Q))
    return T


def _double_and_add(
    R: JacPoint, Q: JacPoint, digits: list[int], ec: CurveGroup
) -> JacPoint:
    """Fold digits into R by the plain binary method, one bit at a time."""
    for digit in digits:
        R = ec.double_jac(R)
        if digit == 1:
            R = ec.add_jac(R, Q)
    return R


def _mult_sliding_window_var(m: int, Q: JacPoint, ec: CurveGroup, w: int) -> JacPoint:
    """Scalar multiplication using "sliding window".

    It has the benefit that the pre-computation stage is roughly half as
    complex as the normal windowed method. It is not constant time. For
    256-bit scalars choose w=4 or w=5.

    The input point is assumed to be on curve and the m coefficient is
    assumed to have been reduced mod n if appropriate (e.g. cyclic
    groups of order n).
    """
    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise BTClibValueError(f"non positive w: {w}")

    # at each step one of the points in T will be added
    T = _sliding_window_table(Q, ec, w)
    p = pow(2, w - 1)

    digits = _convert_number_to_base(m, 2)

    R = INFJ
    i = 0
    while i < len(digits):
        if digits[i] == 0:
            R = ec.double_jac(R)
            i += 1
            continue
        # a window opens here, and only a whole one indexes the table:
        # with fewer than w digits left the remainder is folded in bit by
        # bit instead, which is where the multiplication ends
        if len(digits) - i < w:
            return _double_and_add(R, Q, digits[i:], ec)
        # the w digits as a binary number; its top digit being 1, it is at
        # least 2^(w-1) and below 2^w, so entry t - 2^(w-1) of the table is
        # the multiple t*Q to be added
        t = 0
        for a in range(w):
            t = 2 * t + digits[i + a]
        for _ in range(w):
            R = ec.double_jac(R)
        R = ec.add_jac(R, T[t - p])
        i += w

    return R


def _mult_w_NAF_var(m: int, Q: JacPoint, ec: CurveGroup, w: int) -> JacPoint:
    """Scalar multiplication in Jacobian coordinates using wNAF.

    The "w-ary non-adjacent form": on a Weierstrass curve -P costs
    nothing once P is known, so subtraction is as cheap as addition and
    the recoding spends fewer operations than a sliding window.

    The input point is assumed to be on curve and
    the m coefficient is assumed to have been reduced mod n
    if appropriate (e.g. cyclic groups of order n).
    'right-to-left' method.

    """
    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise BTClibValueError(f"non positive w: {w}")

    M = _wNAF_of_m(m, w)

    p = len(M)

    b = pow(2, w)

    Q2 = ec.double_jac(Q)
    T = [Q]
    T.extend(ec.add_jac(T[i - 1], Q2) for i in range(1, (b // 4)))
    T.extend(ec.negate_jac(T[i - (b // 4)]) for i in range((b // 4), (b // 2)))
    R = INFJ
    for j in range(p - 1, -1, -1):
        R = ec.double_jac(R)
        if M[j] != 0:
            if M[j] > 0:
                # It adds the element jQ
                R = ec.add_jac(R, T[(M[j] - 1) // 2])
            elif w == 1:
                # Case w=1 must be studied on its own for now
                R = ec.add_jac(R, T[1])
            else:
                # In this case it adds the opposite, ie -jQ
                R = ec.add_jac(R, T[(b // 4) - ((M[j] + 1) // 2)])
    return R


def _double_mult_w_NAF_var(
    u: int,
    HJ: JacPoint,
    v: int,
    QJ: JacPoint,
    ec: CurveGroup,
    w: int,
    fixed: frozenset[JacPoint],
) -> JacPoint:
    """Double scalar multiplication (u*H + v*Q), interleaved wNAFs.

    Algorithm 3.51 of D. Hankerson, 'Guide to Elliptic Curve
    Cryptography': each coefficient gets its own width-w NAF and its own
    table of odd multiples, and one left-to-right loop shares the
    doublings, adding a (possibly negated) table entry wherever either
    NAF has a nonzero digit. Against curve_group's _double_mult_var -- the
    Shamir-Strauss binary loop -- the doublings are the same and the
    additions drop from one per bit to ~2/(w+1) per bit, the negative
    digits costing only an on-the-fly negation.

    This is the one the library calls on every curve without the GLV
    endomorphism: `curves.double_mult_var`, `dsa` and `ssa` verification and
    public key recovery all reach it through `curve`'s
    _double_mult_python, which sends secp256k1 to
    _double_mult_endomorphism_secp256k1_var instead -- four half-length
    coefficients where this takes two full-length ones, and 0.81 ms where
    this is 1.02. Measured over random 256-bit coefficients, best of
    seven: 1.03 ms against the 1.53 ms of curve_group's _double_mult_var,
    which stays as the reference the tests compare this against. w=5
    measures 0.99 ms and w=3 1.10, so the w=4 `curve.py` passes is within
    4% of the best window and its table is half the size of w=5's.

    The gap over _double_mult_var is the wider since add_jac stopped
    shortcutting infinity: fewer additions is worth the more when an
    addition of infinity costs what any other costs, and the
    Shamir-Strauss loop makes one for a quarter of its digit pairs.

    The tables are also why it is not faster everywhere: they are built
    per call and per point, so a coefficient too short to amortize them
    pays for them. Against _double_mult_var, by coefficient size on
    secp256k1: 8 bits 1.37x *slower*, 16 bits 0.98, 24 bits 0.85, 32 bits
    0.81, 64 bits 0.72, 128 bits 0.68, 256 bits 0.67. The crossover is
    around 16 bits, so every curve with a real order is on the winning
    side and the toy curves of the test suite -- n = 11, n = 31 -- are
    the ones paying. Taken as it is rather than guarded by a size test:
    the guard would buy back a fraction of a second of the suite and put
    a branch in the middle of signature verification.

    `fixed` is the points whose tables are memoized rather than built
    here, `_multi_mult_w_NAF_var` says what that buys, and it is the
    caller's rather than read off `ec` because a caller may have prepared
    a point of its own: `ec._fixed_points` is what a caller with nothing
    prepared passes.

    The input points are assumed to be on curve, and the u and v
    coefficients are assumed to have been reduced mod n if appropriate
    (e.g. cyclic groups of order n).
    """
    if u < 0:
        raise BTClibValueError(f"negative first coefficient: {hex(u)}")
    if v < 0:
        raise BTClibValueError(f"negative second coefficient: {hex(v)}")
    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise BTClibValueError(f"non positive w: {w}")

    # curve_group's interleaved _multi_mult_w_NAF_var for two points, rather
    # than a second copy of the same loop: it is what recodes each
    # coefficient, builds each table -- memoized and wide for a point the
    # curve names, per call and narrow for one it does not -- and shares
    # the doublings. What this function adds is the pair of messages its
    # own coefficients answer with, and the name the algorithm has
    return _multi_mult_w_NAF_var([u, v], [HJ, QJ], ec, w, fixed)


def _double_mult_regular_window(
    u: int,
    HJ: JacPoint,
    v: int,
    QJ: JacPoint,
    ec: CurveGroup,
    w: int,
    scalar_len: int,
) -> JacPoint:
    """Double scalar multiplication (u*H + v*Q), regular windows.

    curve_group's _mult_regular_window for two coefficients, sharing the
    doublings as the interleaved wNAF above does: one recoding and one
    table of signed odd multiples per coefficient, and a loop of w
    doublings and two additions per window, both of them made whatever the
    digits are. So the cost is the same for every pair (u, v) of a given
    scalar_len -- 143 additions and 254 doublings on secp256k1, over 200
    random pairs -- where _double_mult_w_NAF_var's is the recoded weight of the
    two coefficients and is 101 to 116 additions over the same pairs, and
    0.996 ms against 1.11.

    Which is _mult_regular_window's trade, twice: a table of 2^(w-1) points
    per coefficient, and their opposites, to make one addition per window
    per coefficient -- where the wNAF builds half as many points and adds
    on one digit in w+1. This function is therefore not what
    `double_mult_var` runs -- verification's coefficients are public -- but
    what _mult_endomorphism_secp256k1 runs, whose two are halves of a
    secret.

    scalar_len is the bit count the digits are fixed to, ec.scalar_len by
    default. It is a parameter because the caller that wants this function
    has coefficients shorter than the group's by construction:
    _mult_endomorphism_secp256k1 splits a 256-bit scalar into two halves of
    128 bits, and the group's own 256 would double the work for nothing.

    The input points are assumed to be on curve, and the u and v
    coefficients are assumed to have been reduced mod n if appropriate
    (e.g. cyclic groups of order n).
    """
    if u < 0:
        raise BTClibValueError(f"negative first coefficient: {hex(u)}")
    if v < 0:
        raise BTClibValueError(f"negative second coefficient: {hex(v)}")
    # a number cannot be written in basis 1 (ie w=0)
    if w <= 0:
        raise BTClibValueError(f"non positive w: {w}")

    # as in _mult_regular_window: the count is the curve's, or the caller's,
    # and a coefficient above it is multiplied in the digits it needs
    bits = max(scalar_len or ec.scalar_len, u.bit_length(), v.bit_length())
    size = ceil(bits / w)
    us = signed_odd_digits(u | 1, w, size)
    vs = signed_odd_digits(v | 1, w, size)

    TH = _signed_odd_multiples_aff(HJ, ec, w)
    TQ = _signed_odd_multiples_aff(QJ, ec, w)
    offset = (1 << w) - 1

    # the accumulator starts at the sum of two table entries, so infinity
    # is out of the loop here too
    R = ec.add_jac_aff(
        _jac_from_aff(TH[(us[-1] + offset) // 2]), TQ[(vs[-1] + offset) // 2]
    )
    for du, dv in zip(us[-2::-1], vs[-2::-1], strict=True):
        for _ in range(w):
            R = ec.double_jac(R)
        R = ec.add_jac_aff(R, TH[(du + offset) // 2])
        R = ec.add_jac_aff(R, TQ[(dv + offset) // 2])
    # and the two parity corrections, each made whatever the parity
    R = ec.add_jac(R, (INFJ, ec.negate_jac(HJ))[not u & 1])
    return ec.add_jac(R, (INFJ, ec.negate_jac(QJ))[not v & 1])


# secp256k1 constants for the GLV endomorphism, all four functions of
# them below being specific to that curve:
# the group order,
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# a cube root of 1 mod _N -- lam*(k1*G + k2*G) is (k1*lam)*G + (k2*lam)*G,
# which is what makes m1 + m2*lam a decomposition of a multiplier --
_LAM = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
# the matching cube root of 1 mod p: lam*(x, y) = (beta*x, y), one field
# multiplication where a scalar multiplication by lam would be the very
# cost being avoided,
_BETA = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
# and the lattice basis of algorithm 3.74, satisfying
# a1 + b1*lam = a2 + b2*lam = 0 mod _N with all four ~ sqrt(_N)
_A1 = 0x3086D221A7D46BCDE86C90E49284EB15
_B1 = -0xE4437ED6010E88286F547FA90ABFE4C3
_A2 = 0x114CA50F7A8E2F3F657C1108D9D44CFD8
_B2 = 0x3086D221A7D46BCDE86C90E49284EB15


def _multiplier_decomposer(m: int) -> tuple[int, int]:
    """Decompose m into m1, m2 with m1 + m2*lambda = m mod n.

    Balanced length-two representation, algorithm 3.74 of D. Hankerson,
    'Guide to Elliptic Curve Cryptography', with the constants of
    secp256k1: both m1 and m2 are signed and at most 128 bits, so the
    double multiplication they feed costs half the doublings of the
    single one it replaces. Any integer decomposes, a negative or
    oversized m being reduced mod n first.

    Signed and mod n are the whole of the algorithm (issue #215): the
    congruence only holds mod the group order, and secp256k1's p and n
    share their top 128 bits, so reducing mod ec.p instead would send
    every scalar above ~2^127 to a wrong answer. Rounding is to nearest,
    not with ceil, whose bias costs the balance: round-to-nearest is
    what makes c1, c2 the closest lattice point and m1, m2 short. The
    results stay signed, since a final mod-p reduction would throw away
    the sign that point negation is there to absorb, and hand
    _double_mult_var two 256-bit multipliers for an 8-bit m.
    """
    m %= _N

    # round-to-nearest as (2*x + n) // (2*n), spelled with the shared
    # n // 2 offset: Python floor division makes (x + n//2) // n exact,
    # where round(b2 * m / _N) would go through a float
    c1 = (_B2 * m + _N // 2) // _N
    c2 = (-_B1 * m + _N // 2) // _N

    m1 = m - c1 * _A1 - c2 * _A2
    m2 = -c1 * _B1 - c2 * _B2

    return m1, m2


# the bits either half of the decomposition can have, and the digit count
# _double_mult_regular_window is fixed to below. It is the rounding error of
# _multiplier_decomposer and not a measurement: round-to-nearest leaves at
# most half a basis vector of each, |m1| <= (|a1| + |a2|)/2 and
# |m2| <= (|b1| + |b2|)/2, both of which are 128-bit numbers with the
# constants above. libsecp256k1's scalar_split_lambda states the same 128
_HALF_LEN = 128


def _endomorphism_split_secp256k1(
    m: int, Q: JacPoint, ec: CurveGroup
) -> tuple[int, JacPoint, int, JacPoint]:
    """Return (m1, P, m2, K) with m1*P + m2*K == m*Q and both halves short.

    The half of algorithm 3.77 that is not the double multiplication:
    `_multiplier_decomposer`'s two signed halves, the endomorphism's image
    of Q, and the signs moved off the coefficients and onto the points.
    Both multiplications built on it want exactly this, and the sign
    handling is what neither should own a second copy of.

    m1 and m2 come back non-negative, which is what the double
    multiplications require; the caller owes them nothing else.
    """
    m1, m2 = _multiplier_decomposer(m)

    K = ((Q[0] * _BETA) % ec.p), Q[1], Q[2]  # K = lambda*Q, direct calculation

    # the decomposition is signed on purpose -- balance is what makes the
    # halves short -- and the sign belongs to the point: -m1*Q is m1*(-Q),
    # one modular negation of a y-coordinate. Negated whatever the sign and
    # selected afterwards, rather than under an `if`: the sign of a half is
    # a bit of the scalar, and a modular subtraction is what a branch on it
    # would put on the clock
    P = (Q, ec.negate_jac(Q))[m1 < 0]
    K = (K, ec.negate_jac(K))[m2 < 0]
    return abs(m1), P, abs(m2), K


def _mult_endomorphism_secp256k1(
    m: int, Q: JacPoint, ec: CurveGroup, w: int
) -> JacPoint:
    """Scalar multiplication in Jacobian coordinates using endomorphism.

    Algorithm 3.77 of D. Hankerson, 'Guide to Elliptic Curve
    Cryptography': m*Q as m1*Q + m2*(lambda*Q), the halves coming from
    _multiplier_decomposer and a double multiplication sharing their
    doublings. It is what `curves.mult` runs for a secp256k1 point that is
    not the generator and that the bindings do not take.

    The regular windows of _double_mult_regular_window, so the number of
    point additions is the same for every scalar: the scalar of a
    `curves.mult` is a private key or a nonce in every caller btclib has,
    which is what issue 254 is about. _mult_endomorphism_secp256k1_var
    below is algorithm 3.77 as it is written, and what it costs to be
    regular is measured there.

    w=4 by measurement: the regular windows give 0.589 ms at w=4 and
    0.610 at w=5, over 30 random 256-bit scalars, best of five.
    """
    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    m1, P, m2, K = _endomorphism_split_secp256k1(m, Q, ec)
    return _double_mult_regular_window(m1, P, m2, K, ec, w, _HALF_LEN)


def _mult_endomorphism_secp256k1_var(
    m: int, Q: JacPoint, ec: CurveGroup, w: int
) -> JacPoint:
    """Algorithm 3.77 as it is written: the interleaved wNAFs.

    The same decomposition as `_mult_endomorphism_secp256k1`, over
    `_double_mult_w_NAF_var` rather than the regular windows, and the
    faster of the two: 0.509 ms against 0.589, over 30 random 256-bit
    scalars, best of five, at w=4. What the 16% buys is 51 to 64 additions
    and 124 to 131 doublings over 200 random scalars, where the regular
    windows make 79 and 126 for every one of them -- a quarter more work
    for the worst scalar than for the best, and which it is is a property
    of the scalar.

    So nothing signs with this one, and it is here to be measured against
    the other. A verification's coefficients are public and go to
    `_double_mult_endomorphism_secp256k1_var` below, which splits two of
    them rather than one and interleaves the four halves.

    w=4 by measurement here too: 0.527 ms at w=3 and 0.510 at w=5, which
    is w=4's own noise.
    """
    if m < 0:
        raise BTClibValueError(f"negative m: {hex(m)}")

    m1, P, m2, K = _endomorphism_split_secp256k1(m, Q, ec)
    return _double_mult_w_NAF_var(m1, P, m2, K, ec, w, ec._fixed_points)


def _double_mult_endomorphism_secp256k1_var(
    u: int,
    HJ: JacPoint,
    v: int,
    QJ: JacPoint,
    ec: CurveGroup,
    w: int,
    fixed: frozenset[JacPoint],
) -> JacPoint:
    """Double scalar multiplication (u*H + v*Q) through the endomorphism.

    Algorithm 3.77 for two coefficients: each is split into a pair of
    half-length halves over its own point and the endomorphism's image of
    it, and the four terms go through one interleaved wNAF, which shares
    one doubling per bit position among all of them. So the ~256 doublings
    the two full-length coefficients need become the ~128 of four halves,
    at the price of two more tables of odd multiples and the two field
    multiplications the images cost.

    That trade is the whole of the gain, and it is the same one
    `_mult_endomorphism_secp256k1` makes for a single coefficient: 0.81 ms
    against `_double_mult_w_NAF_var`'s 1.02, measured over 30 random pairs of
    256-bit coefficients, best of three, alternating the two so that
    neither is always warm. Both answer the same point on every pair the
    tests compare, boundary coefficients and infinities included.

    The interleaved wNAF rather than the regular windows: the coefficients
    of a double multiplication are public, being a verification's, which is
    the same reason `curve.double_mult_var` reaches `_double_mult_w_NAF_var`
    directly and not through the regular windows of
    `_mult_endomorphism_secp256k1`. A scalar that is a secret goes
    through `mult`.

    w=4 by measurement over the same pairs: 0.88 ms at w=3, 0.81 at w=4,
    0.82 at w=5, 0.91 at w=6 -- so w=4 and w=5 measure the same and the
    smaller table decides, as it does for `_double_mult_w_NAF_var`.

    `fixed` is `_double_mult_w_NAF_var`'s, and this is the function that
    grows it: a point named there has its two endomorphism images named
    too, because they are what actually reaches the interleaved wNAF and
    they are formed here. So a verification under a `curve.PreparedPoint`
    memoizes four tables and not one, which is what makes the key's half
    of the call cost what the generator's costs.

    The input points are assumed to be on curve. Either coefficient may be
    zero and either point may be infinity: the interleaved wNAF drops a
    zero half rather than building a table it would never index, and the
    empty sum is infinity, which is what the term of a zero coefficient
    contributes.
    """
    if u < 0:
        raise BTClibValueError(f"negative first coefficient: {hex(u)}")
    if v < 0:
        raise BTClibValueError(f"negative second coefficient: {hex(v)}")

    u1, U1, u2, U2 = _endomorphism_split_secp256k1(u, HJ, ec)
    v1, V1, v2, V2 = _endomorphism_split_secp256k1(v, QJ, ec)
    # the split of a fixed point is fixed: the halves are +-H and
    # +-lambda*H, determined by H alone and by which of the two signs the
    # coefficient asked for, so both are worth a memoized table whenever H
    # is one of the points `fixed` names. The images are formed here and
    # nowhere else, which is why they are added here rather than in Curve
    # or in whatever prepared the point
    if HJ in fixed:
        fixed = fixed | {U1, U2}
    if QJ in fixed:
        fixed = fixed | {V1, V2}
    return _multi_mult_w_NAF_var([u1, u2, v1, v2], [U1, U2, V1, V2], ec, w, fixed)
