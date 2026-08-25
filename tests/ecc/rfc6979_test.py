# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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
from btclib.curves.curve import CURVES, Curve, secp256k1
from btclib.ecc import dsa
from btclib.ecc.bip340_nonce import _bip340_nonce_, bip340_nonce_
from btclib.ecc.rfc6979_nonce import _rfc6979_nonce_, challenge_, rfc6979_nonce_
from btclib.hashes import reduce_to_hlen
from tests import load, vector_id
from tests.curves.curve_test import low_card_curves

# secp256k1 with sha256, the pair RFC6979's own appendix A.2 does not
# cover: the five vectors of `Test_RFC6979` in
# petertodd/python-bitcoinlib's `bitcoin/tests/test_wallet.py`, which is
# where the bitcointalk thread that first published the nonce of the
# first one ended up (issue 199). tests/_data/README.md pins the
# revision; not vendored as a file, upstream having none.
#
# Each pins the nonce *and* the signature, which is the half btclib had
# for none of the five. The s values are the low ones -- as libsecp256k1
# hands them back, and as `sign_` returns by default -- and four of the
# five differ from what RFC6979 arrives at before that normalization, so
# they pin lower_s as much as the nonce. The r values are the plain ones,
# which is the other half of what a vector here has to be asked for:
# `grind` is on by default and four of the five have a high r.
#
# The two long messages are named above the table rather than written in
# it: a multi-line string inside a tuple literal is a missing comma away
# from being one element instead of two, which is what flake8's ISC004
# objects to, and the names read better in the parametrize id anyway.
_TEARS_IN_RAIN = (
    "All those moments will be lost in time, like tears in rain. Time to die..."
)
_COMPUTER_DISEASE = (
    "There is a computer disease that anybody who works with computers knows "
    "about. It's a very serious disease and it interferes completely with the "
    "work. The trouble with computers is that you 'play' with them!"
)
# private key, message, nonce, r, s. A tuple of values rather than a list
# of pytest.param, so that the second test below can read the fields with
# their types instead of the `object` a param's `.values` hands back
SECP256K1_VECTORS: tuple[tuple[int, str, int, str, str], ...] = (
    (
        0x1,
        "Satoshi Nakamoto",
        0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15,
        "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8",
        "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5",
    ),
    (
        0x1,
        _TEARS_IN_RAIN,
        0x38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3,
        "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b",
        "547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21",
    ),
    (
        # n-1, the largest private key the curve admits
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140,
        "Satoshi Nakamoto",
        0x33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90,
        "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d0",
        "6b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5",
    ),
    (
        0xF8B8AF8CE3C7CCA5E300D33939540C10D45CE001B8F252BFBC57BA0342904181,
        "Alan Turing",
        0x525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1,
        "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c",
        "58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea",
    ),
    (
        0xE91671C46231F833A6406CCBEA0E3E392C76C167BAC1CB013F6F1013980455C2,
        _COMPUTER_DISEASE,
        0x1F4B84C23A86A221D233F2521BE018D9318639D5B8BBD6374A8A59232D16AD3D,
        "b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b",
        "279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6",
    ),
)


@pytest.mark.parametrize(
    "prv_key, msg, k, r, s",
    [
        pytest.param(*vector, id=vector_id(index, vector[1]))
        for index, vector in enumerate(SECP256K1_VECTORS)
    ],
)
def test_rfc6979_secp256k1(prv_key: int, msg: str, k: int, r: str, s: str) -> None:
    """Reproduce python-bitcoinlib's five secp256k1/sha256 vectors."""
    msg_hash = hashlib.sha256(msg.encode()).digest()
    assert rfc6979_nonce_(msg_hash, prv_key, hf=hashlib.sha256) == k

    # the nonce is the default, so the signature is what the library
    # produces unprompted -- the vector pins the whole of it, not the
    # derivation with the answer handed back in
    sig = dsa.sign_(msg_hash, prv_key, grind=False)
    assert (sig.r, sig.s) == (int(r, 16), int(s, 16))
    assert sig == dsa.sign_(msg_hash, prv_key, k, grind=False)

    U = mult(prv_key)
    assert dsa.verify_(msg_hash, U, sig)


def test_rfc6979_secp256k1_s_is_normalized() -> None:
    """Four of the five vectors pin the low s, not the one RFC6979 gives.

    Which is what makes them vectors for `sign_` and not only for the
    nonce: drop the normalization and four of the five signatures stop
    matching. libsecp256k1, the authority the suite validates against,
    hands back the low s and so does btclib by default.
    """
    normalized = 0
    for prv_key, msg, _, _, s in SECP256K1_VECTORS:
        msg_hash = hashlib.sha256(msg.encode()).digest()
        raw = dsa.sign_(msg_hash, prv_key, lower_s=False, grind=False)
        assert raw.s in {int(s, 16), secp256k1.n - int(s, 16)}
        normalized += raw.s != int(s, 16)
    assert normalized == 4


def test_rfc6979_secp256k1_grinding_leaves_only_the_low_r_one() -> None:
    """Four of the five have a high r, which is what grinding re-signs.

    The vectors are the plain RFC6979 signatures, which is why every test
    above asks for `grind=False`: grinding is on by default, as it is in
    Core, so the default reproduces the one whose r is already below
    2**255 and departs from the other four. That is the whole of what the
    flag does to a deterministic signature. `tests/ecc/dsa_test.py` is
    where the loop is held to Core's, this being about the vectors: no
    vector is lost, and the fourth is a vector for both spellings.
    """
    ground = 0
    for prv_key, msg, _, r, _ in SECP256K1_VECTORS:
        msg_hash = hashlib.sha256(msg.encode()).digest()
        sig = dsa.sign_(msg_hash, prv_key, grind=True)
        assert sig.r < 2**255
        assert (sig.r == int(r, 16)) == (int(r, 16) < 2**255)
        ground += sig.r != int(r, 16)
        assert dsa.verify_(msg_hash, mult(prv_key), sig)
    assert ground == 4


def test_rfc6979_nonce_example() -> None:
    """Reproduce the worked example of RFC6979's section A.1."""

    class _Helper(Curve):
        def __init__(self, n: int) -> None:
            self.n = n
            self.nlen = n.bit_length()
            self.n_size = (self.nlen + 7) // 8

    # source: https://www.rfc-editor.org/rfc/rfc6979.html section A.1
    fake_ec = _Helper(0x4000000000000000000020108A2E0CC0D99F8A5EF)
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
    test_dict = load("ecc", "_data", "rfc6979.json")
    return [
        pytest.param(
            CURVES[ec_name],
            *vector,
            id=vector_id(index, ec_name, vector[3], vector[4]),
        )
        for ec_name in test_dict
        for index, vector in enumerate(test_dict[ec_name])
    ]


@pytest.mark.parametrize("ec, x, x_U, y_U, hf, msg, k, r, s", rfc6979_vectors())
def test_rfc6979_nonce_tv(
    ec: Curve, x: str, x_U: str, y_U: str, hf: str, msg: str, k: str, r: str, s: str
) -> None:
    """Reproduce RFC6979's appendix A.2 vectors, nonce and signature."""
    lower_s = False
    prv_key = int(x, 16)
    msg_bytes = msg.encode()
    m = reduce_to_hlen(msg_bytes, hf=getattr(hashlib, hf))
    # test RFC6979 implementation
    k2 = rfc6979_nonce_(m, prv_key, ec, getattr(hashlib, hf))
    assert int(k, 16) == k2
    # test RFC6979 usage in DSA
    sig = dsa.sign_(
        m, prv_key, k2, lower_s, ec=ec, hf=getattr(hashlib, hf), grind=False
    )
    assert int(r, 16) == sig.r
    assert int(s, 16) == sig.s
    # test that RFC6979 is the default nonce for DSA
    sig = dsa.sign_(
        m, prv_key, None, lower_s, ec=ec, hf=getattr(hashlib, hf), grind=False
    )
    assert int(r, 16) == sig.r
    assert int(s, 16) == sig.s
    # test key-pair coherence
    U = mult(prv_key, ec.G, ec)
    assert (int(x_U, 16), int(y_U, 16)) == U
    # test signature validity
    dsa.assert_as_valid(msg_bytes, U, sig, getattr(hashlib, hf))


# RFC6979 against BIP340: the two deterministic nonces this library
# derives, over the same inputs, which is what these four tests compare
# (issue #194).
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
        """Return a fresh sha256 hash object, counting the request."""
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
            nonce = _rfc6979_nonce_(c, q, _EC, hf, None)
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
        _rfc6979_nonce_(c, q, _EC, hashlib.sha256, None)
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
