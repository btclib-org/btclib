#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.rfc6979` module.

The last four compare it against `btclib.ecc.bip340_nonce`, the other
deterministic nonce this library derives.
"""

import hashlib
from collections import Counter
from typing import Any

import pytest

from btclib.alias import HashObject
from btclib.curves import mult
from btclib.curves.curve import CURVES, Curve
from btclib.ecc import dsa
from btclib.ecc.bip340_nonce import _bip340_nonce_, bip340_nonce_
from btclib.ecc.rfc6979_nonce import _rfc6979_nonce_, challenge_, rfc6979_nonce_
from btclib.hashes import reduce_to_hlen
from tests import vectors
from tests.curves.test_curve import low_card_curves


def test_rfc6979() -> None:
    # source: https://bitcointalk.org/index.php?topic=285142.40
    msg = b"Satoshi Nakamoto"
    msg_hash = hashlib.sha256(msg).digest()
    x = 0x1
    k = 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15
    k2 = rfc6979_nonce_(msg_hash, x, hf=hashlib.sha256)
    assert k == k2


def test_rfc6979_nonce_example() -> None:
    class _helper(Curve):
        def __init__(self, n: int) -> None:
            self.n = n
            self.nlen = n.bit_length()
            self.n_size = (self.nlen + 7) // 8

    # source: https://www.rfc-editor.org/rfc/rfc6979.html section A.1
    fake_ec = _helper(0x4000000000000000000020108A2E0CC0D99F8A5EF)
    x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
    msg = b"sample"
    msg_hash = hashlib.sha256(msg).digest()
    k = 0x23AF4074C90A02B3FE61D286D5C87F425E6BDD81B
    assert k == rfc6979_nonce_(msg_hash, x, fake_ec)


def rfc6979_vectors() -> list[Any]:
    """One case per (curve, vector) pair of RFC6979's appendix A.2.

    The file groups the vectors by curve, so the two nested loops become
    one flat list: the curve name belongs in the id, where a failure on
    NIST P-521 with sha512 says so, and not in an outer loop that stops
    the inner one from ever reaching the next curve.
    """
    test_dict = vectors.load("ecc", "_data", "rfc6979.json")
    return [
        pytest.param(
            CURVES[ec_name],
            *vector,
            id=vectors.vector_id(index, ec_name, vector[3], vector[4]),
        )
        for ec_name in test_dict
        for index, vector in enumerate(test_dict[ec_name])
    ]


@pytest.mark.parametrize(
    ("ec", "x", "x_U", "y_U", "hf", "msg", "k", "r", "s"), rfc6979_vectors()
)
def test_rfc6979_nonce_tv(
    ec: Curve, x: str, x_U: str, y_U: str, hf: str, msg: str, k: str, r: str, s: str
) -> None:
    lower_s = False
    prv_key = int(x, 16)
    msg_bytes = msg.encode()
    m = reduce_to_hlen(msg_bytes, hf=getattr(hashlib, hf))
    # test RFC6979 implementation
    k2 = rfc6979_nonce_(m, prv_key, ec, getattr(hashlib, hf))
    assert int(k, 16) == k2
    # test RFC6979 usage in DSA
    sig = dsa.sign_(m, prv_key, k2, lower_s, ec=ec, hf=getattr(hashlib, hf))
    assert int(r, 16) == sig.r
    assert int(s, 16) == sig.s
    # test that RFC6979 is the default nonce for DSA
    sig = dsa.sign_(m, prv_key, None, lower_s, ec=ec, hf=getattr(hashlib, hf))
    assert int(r, 16) == sig.r
    assert int(s, 16) == sig.s
    # test key-pair coherence
    U = mult(prv_key, ec.G, ec)
    assert (int(x_U, 16), int(y_U, 16)) == U
    # test signature validity
    dsa.assert_as_valid(msg_bytes, U, sig, lower_s, getattr(hashlib, hf))


# RFC6979 against BIP340: the two deterministic nonces this library
# derives, over the same inputs. TODO.md line 43 asked for the
# comparison and it is these four tests (issue #194).
#
# ec23_19 is where the difference between the two is observable at all.
# Its order is 19 and its nlen 5, so a hash candidate is one of 32 values
# and 14 of them are out of range: the rejection loop both schemes end in
# actually fires, where on secp256k1 it would take some 2^-128 of inputs
# to fire once.
_EC = low_card_curves["ec23_19"]

# BIP340 takes 32 bytes of auxiliary randomness and RFC6979 takes none,
# so a comparison over the same inputs has to fix it: these two are
# arbitrary, and the point of the second is only that it differs
AUX = bytes(32)
AUX2 = b"\xff" * 32


class CountingSha256:
    """A HashF that counts the hash objects it is asked for.

    Both derivations take `hf` as a parameter, so the work each does is
    observable without touching either implementation -- and the count is
    exact and repeatable, where a stopwatch in a test is neither.
    """

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> HashObject:
        self.calls += 1
        return hashlib.sha256()


def test_the_two_nonce_derivations_disagree() -> None:
    """They must: they are different schemes, not two spellings of one.

    Both map (message, private key) deterministically into [1, n-1], and
    that is all they share. Nothing in either forces the results apart --
    a signer swapping one for the other would produce valid signatures
    either way -- so the disagreement is worth asserting rather than
    assuming.
    """
    for i in range(200):
        msg = f"btclib {i}".encode()
        msg_hash = hashlib.sha256(msg).digest()
        prv_key = 1 + i % 8
        assert rfc6979_nonce_(msg_hash, prv_key) != bip340_nonce_(msg, prv_key, AUX)[0]


def test_what_each_nonce_derivation_reads() -> None:
    """RFC6979 reads the challenge; BIP340 reads the message, and more.

    Which is the substantive difference, and it is why the two cannot be
    compared over "the same message" alone. RFC6979 takes the challenge
    -- the message hash already reduced modulo n -- so two messages that
    collide there get the *same* nonce, and it takes no auxiliary
    randomness at all. BIP340 absorbs the whole message, the public key
    and 32 bytes of aux, and then normalizes: the k it returns is the one
    whose K has an even y-coordinate, so half of [1, n-1] is unreachable
    by construction.
    """
    # two messages with one challenge, which on a 5-bit order is easy to
    # find and on secp256k1 would be a hash collision
    by_challenge: dict[int, list[bytes]] = {}
    for i in range(40):
        msg = f"btclib {i}".encode()
        msg_hash = hashlib.sha256(msg).digest()
        by_challenge.setdefault(challenge_(msg_hash, _EC), []).append(msg)
    colliding = next(msgs for msgs in by_challenge.values() if len(msgs) > 1)
    msg_a, msg_b = colliding[0], colliding[1]
    assert hashlib.sha256(msg_a).digest() != hashlib.sha256(msg_b).digest()

    hash_a = hashlib.sha256(msg_a).digest()
    hash_b = hashlib.sha256(msg_b).digest()
    assert rfc6979_nonce_(hash_a, 7, _EC) == rfc6979_nonce_(hash_b, 7, _EC)
    # BIP340 hashes the message itself, so the same pair separates
    assert bip340_nonce_(msg_a, 7, AUX, _EC)[0] != bip340_nonce_(msg_b, 7, AUX, _EC)[0]

    # aux is BIP340's alone, and it changes the answer
    assert bip340_nonce_(msg_a, 7, AUX, _EC)[0] != bip340_nonce_(msg_a, 7, AUX2, _EC)[0]

    # and the returned k is exactly the half of [1, n-1] whose K is even
    returned = {bip340_nonce_(f"m{i}".encode(), 7, AUX, _EC)[0] for i in range(400)}
    assert returned == {k for k in range(1, _EC.n) if mult(k, ec=_EC)[1] % 2 == 0}
    assert len(returned) == _EC.n // 2


def test_neither_nonce_derivation_reduces_modulo_n() -> None:
    """Both loop until the candidate is in range, and it is measurable.

    Taking a hash modulo n biases the result towards the low end, which
    is why the comment in each module refuses to do it. The refusal is
    observable through the hash count: a candidate out of range costs
    another round, and on this curve 14 of the 32 candidates are out of
    range, so the loop fires for a good third of the inputs. A `% n`
    implementation would answer every input for the price of one round.

    A chi-square over the results would *not* settle this, and that is
    why it is not what is asserted: RFC6979's whole input space here is
    the 342 (challenge, private key) pairs the curve admits, and at that
    sample size the statistic for a mod-n reduction (about 27) sits
    inside the noise of an unbiased one (6.4 measured, 17 dof).
    """
    rfc_rounds: Counter[int] = Counter()
    for c in range(_EC.n):
        for q in range(1, _EC.n):
            hf = CountingSha256()
            nonce = _rfc6979_nonce_(c, q, _EC, hf)
            assert 0 < nonce < _EC.n
            rfc_rounds[hf.calls] += 1

    # one round is 11 hash objects and every retry is another 6
    assert min(rfc_rounds) == 11
    assert all((calls - 11) % 6 == 0 for calls in rfc_rounds)
    retried = sum(n for calls, n in rfc_rounds.items() if calls > 11)
    assert 0.30 < retried / 342 < 0.50  # 14/32 = 0.4375 expected

    # exhaustive, so this is every nonce the curve can produce: all of
    # them, none out of range -- which a mod-n reduction would also
    # manage, hence the round count above and not this line alone
    assert {
        _rfc6979_nonce_(c, q, _EC, hashlib.sha256)
        for c in range(_EC.n)
        for q in range(1, _EC.n)
    } == set(range(1, _EC.n))

    bip_rounds: Counter[int] = Counter()
    Q = mult(7, ec=_EC)[0]
    for i in range(342):
        hf = CountingSha256()
        nonce = _bip340_nonce_(f"btclib {i}".encode(), 7, Q, AUX, _EC, hf)
        assert 0 < nonce < _EC.n
        bip_rounds[hf.calls] += 1

    # one round is 5, every retry another 2
    assert min(bip_rounds) == 5
    assert all((calls - 5) % 2 == 0 for calls in bip_rounds)
    retried = sum(n for calls, n in bip_rounds.items() if calls > 5)
    assert 0.30 < retried / 342 < 0.50


def test_what_each_nonce_derivation_costs() -> None:
    """BIP340's nonce is half the hashing of RFC6979's.

    On secp256k1 the rejection loop never fires -- it would take about
    2^-128 of inputs -- so both are one round, and the round is the whole
    cost: HMAC-DRBG's four setup HMACs and one output HMAC, two hash
    objects apiece, against BIP340's two tagged hashes. The counts below
    include the one `hf()` each public wrapper makes to read digest_size.

    Not a stopwatch: hashing is what either does, the counts are exact,
    and neither goes anywhere near the point-multiplication that follows
    it -- BIP340's own two `mult` calls dwarf both.
    """
    hf = CountingSha256()
    rfc6979_nonce_(bytes(32), 7, hf=hf)
    assert hf.calls == 12

    hf = CountingSha256()
    bip340_nonce_(b"btclib", 7, AUX, hf=hf)
    assert hf.calls == 6
