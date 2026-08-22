# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.ssa` module."""

from __future__ import annotations

from hashlib import sha256 as hf
from typing import Any

import pytest

from btclib._libsecp256k1 import ssa as libsecp256k1_ssa
from btclib.alias import INF, Octets, Point, String
from btclib.bip32 import BIP32KeyData
from btclib.curves import (
    PreparedPoint,
    bytes_from_point,
    curve_group,
    double_mult_var,
    mult,
    secp256k1,
)
from btclib.curves.curve import CURVES, Curve
from btclib.curves.curve_group import _jac_from_aff
from btclib.ecc import second_generator, ssa
from btclib.ecc.bip340_nonce import bip340_nonce_
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.hashes import reduce_to_hlen
from btclib.number_theory import mod_inv_var
from btclib.utils import int_from_bits
from tests import load_csv, needs_bindings, replace_unchecked, vector_id
from tests.curves.curve_test import low_card_curves, no_bindings, secp256k1_bis


def test_signature_on_an_equal_curve() -> None:
    """A curve equal to secp256k1 is secp256k1, bindings included."""
    # guards against the dispatch comparing identities, which sends any
    # other object holding the secp256k1 parameters down the Python path
    # in silence: with aux fixed the BIP340 nonce is deterministic, so
    # the two paths have one answer to agree on (issue #142)
    msg = b"Satoshi Nakamoto"
    aux = b"\x00" * 32
    q, x_Q = ssa.gen_keys(6, secp256k1_bis)

    sig = ssa.sign(msg, q, aux, secp256k1_bis)
    assert sig.ec == secp256k1
    assert sig == ssa.sign(msg, q, aux)
    assert ssa.verify(msg, x_Q, sig)


def test_signature() -> None:
    """Round-trip sign, verify and serialize, then the failure modes."""
    msg = b"Satoshi Nakamoto"
    aux = b"\x00" * 32
    q = 6
    q_fixed, x_Q = ssa.gen_keys(q)
    assert q_fixed != q
    sig = ssa.sign(msg, q, aux)
    ssa.assert_as_valid(msg, x_Q, sig)
    assert ssa.verify(msg, x_Q, sig)
    assert sig == ssa.Sig.parse(sig.serialize())
    assert sig == ssa.Sig.parse(sig.serialize().hex())

    msg_fake = b"Craig Wright"
    assert not ssa.verify(msg_fake, x_Q, sig)
    err_msg = r"y_K is odd|signature verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        ssa.assert_as_valid(msg_fake, x_Q, sig)

    _, x_Q_fake = ssa.gen_keys(q + 2)
    assert not ssa.verify(msg, x_Q_fake, sig)
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        ssa.assert_as_valid(msg, x_Q_fake, sig)

    # a value and not a type: the point at infinity is a `Point`, and
    # what is wrong with it is which point it is. It read as a type error
    # until the spelling dispatch stopped guessing (issue #1188)
    err_msg = "not a valid public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_as_valid(msg, INF, sig)
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.point_from_bip340pub_key(INF)

    sig_invalid = ssa.Sig(sig.ec.p, sig.s, check_validity=False)
    assert not ssa.verify(msg, x_Q, sig_invalid)
    # r outside the field and r inside it with no point are one refusal
    # now, phrased by Sig rather than by the lift it no longer takes
    # (issue 622): "x-coordinate not in 0..p-1" was ec.y's, reached
    # through _y_even_var, and a predicate has no such message to pass on
    err_msg = "r is not a valid x-coordinate: "
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_as_valid(msg, x_Q, sig_invalid)

    sig_invalid = ssa.Sig(sig.r, sig.ec.p, check_validity=False)
    assert not ssa.verify(msg, x_Q, sig_invalid)
    err_msg = "scalar s not in 0..n-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_as_valid(msg, x_Q, sig_invalid)

    # the boundary itself, not `ec.p` (a different, larger prime): `< n`
    # weakened to `<= n` would still refuse `ec.p` and miss `n` exactly
    with pytest.raises(BTClibValueError, match="scalar s not in 0..n-1: "):
        ssa.Sig(sig.r, sig.ec.n)

    # the lower boundary too: `0 <= s` weakened to `-1 <= s` would accept
    # a scalar one below the range BIP340's own zero-lower-bound allows
    with pytest.raises(BTClibValueError, match="scalar s not in 0..n-1: "):
        ssa.Sig(sig.r, -1)

    # `serialize`'s own default, not the constructor's: an invalid Sig
    # built with check_validity=False must still be refused when asked
    # to serialize at the default, and only there does check_validity=False
    # let it through
    sig_invalid = ssa.Sig(sig.r, sig.ec.n, sig.ec, check_validity=False)
    with pytest.raises(BTClibValueError, match="scalar s not in 0..n-1: "):
        sig_invalid.serialize()
    assert sig_invalid.serialize(check_validity=False)

    # a 31-byte message is a legal BIP340 message (since 2023-04), so a
    # truncated message is not a size error -- "invalid size: 31 bytes
    # instead of 32" -- but a *different* message, which this signature
    # does not sign (issue 169)
    m_bytes = reduce_to_hlen(msg, hf)
    assert not ssa.verify_(m_bytes[:31], x_Q, sig)
    err_msg = r"y_K is odd|signature verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        ssa.assert_as_valid_(m_bytes[:31], x_Q, sig)

    # and signing it works, giving a signature over those 31 bytes and no
    # other -- through the bindings, `sign_custom` taking a message of any
    # size, which is what the length used to gate on
    sig_31 = ssa.sign_(m_bytes[:31], q)
    assert ssa.verify_(m_bytes[:31], x_Q, sig_31)
    assert not ssa.verify_(m_bytes, x_Q, sig_31)

    err_msg = "private key not in 1..n-1"
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.sign(msg, 0)


def bip340_vectors() -> list[Any]:
    """One case per BIP340 vector.

    Four of the nineteen are the arbitrary-size messages BIP340 gained in
    2023-04, of 0, 1, 17 and 100 bytes. They were the Python path's alone
    while a 32-byte gate stood in front of the bindings (issue 169); it
    is gone, and all nineteen are signed and verified by libsecp256k1.
    """
    return [
        pytest.param(row, id=vector_id(int(row[0]), row[7]))
        for row in load_csv("ecc", "_data", "bip340_test_vectors.csv")
    ]


BIP340_VECTORS = bip340_vectors()


@pytest.mark.parametrize("row", BIP340_VECTORS)
def test_bip340_vectors(row: list[str]) -> None:
    """BIP340 (Schnorr) test vectors.

    - https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv

    The vector index and its comment are the test id, which pytest
    prints on failure without being asked.
    """
    (_index, seckey, pub_key, aux_rand, m, sig, result, _comment) = row

    if seckey:
        _, pub_key_actual = ssa.gen_keys(seckey)
        assert pub_key == hex(pub_key_actual).upper()[2:]

        sig_actual = ssa.sign_(m, seckey, aux_rand)
        ssa.assert_as_valid_(m, pub_key, sig_actual)
        assert ssa.Sig.parse(sig) == sig_actual

    if result == "TRUE":
        ssa.assert_as_valid_(m, pub_key, sig)
        assert ssa.verify_(m, pub_key, sig)
    else:
        assert not ssa.verify_(m, pub_key, sig)


@pytest.mark.parametrize("check_validity", [True, False], ids=["checked", "unchecked"])
@pytest.mark.parametrize("length", [0, 1, 31, 32, 33, 63, 65, 68])
def test_parse_takes_64_bytes_and_no_other_number(
    length: int, *, check_validity: bool
) -> None:
    """A BIP340 signature is sixty-four octets, and the length says so.

    Sixty-three of them used to parse into a signature of their own -- an
    s read out of thirty-one bytes is below the order, so it is a valid
    scalar -- and sixty-five into the signature of the first sixty-four,
    the last byte read as part of nothing. Both are one object with two
    encodings, and the second is the shape a taproot witness signature
    arrives in.
    """
    sig_bin = ssa.sign(b"parse contract", 1).serialize()
    assert len(sig_bin) == 64

    truncated_or_extended = (sig_bin + sig_bin)[:length]
    err_msg = f"invalid decoded length: {min(length, 64)} instead of 64"
    if length > 64:
        err_msg = f"{length - 64} bytes after the BIP340 signature"
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.Sig.parse(truncated_or_extended, check_validity=check_validity)


@pytest.mark.parametrize(
    "r",
    [5, secp256k1.p - 1, secp256k1.p, secp256k1.p + 1, 2**256],
    ids=["no point has it", "the last field element", "p", "p + 1", "above 2**256"],
)
def test_refusing_an_r_takes_no_square_root(
    r: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The r of a signature is refused by a predicate, not by a lift.

    Refusing used to cost more than verifying: `_y_even_var` falls back to
    `ec.y_even_var` for an x the bindings reject, that being where the
    message naming the value came from, so a bad r paid the whole Python
    square root -- 78.7 us against the 22.4 of verifying a good
    signature (issue 622). Half of the field elements are no
    x-coordinate and cost nothing to produce, so that was the expensive
    answer for the cheap input.

    mod_sqrt_var is patched to raise rather than timed: what the change has
    to be is a refusal that reaches no square root, on this machine and
    on a loaded one alike.

    Five r, because the refusal now covers two messages that used to be
    distinct: `invalid x-coordinate` for a field element no point has,
    and `x-coordinate not in 0..p-1` for one outside the field, which
    `Sig` never phrased itself. p - 1 is the last r that is inside it.
    """

    def refuse(*_: object) -> int:
        raise AssertionError(  # pragma: no cover
            "an r was lifted to a point in order to refuse it"
        )

    monkeypatch.setattr(curve_group, "mod_sqrt_var", refuse)
    with pytest.raises(BTClibValueError, match="r is not a valid x-coordinate: "):
        ssa.Sig(r, 1)


def test_the_sighash_type_of_a_witness_signature_is_the_callers() -> None:
    """BIP341's 65-byte witness signature is not a BIP340 signature.

    The 65th octet is the sighash type, a fact about the transaction
    rather than part of the signature, and it used to reach `verify` as
    part of one: True came back with the byte still attached, the first
    sixty-four read and the rest dropped. Stripping it is the caller's,
    which is what btclib's own script engine does with `signature[:64]`
    once `get_hashtype` has read it.
    """
    prv_key, pub_key = ssa.gen_keys(1)
    msg = b"witness signature"
    sig_bin = ssa.sign(msg, prv_key).serialize()

    # an encoding that is not a signature is False, as any other invalid
    # one is, and assert_as_valid is where the reason comes out
    assert not ssa.verify(msg, pub_key, sig_bin + b"\x01")
    with pytest.raises(BTClibValueError, match="1 bytes after the BIP340 signature"):
        ssa.assert_as_valid(msg, pub_key, sig_bin + b"\x01")

    assert ssa.verify(msg, pub_key, (sig_bin + b"\x01")[:64])
    assert ssa.verify(msg, pub_key, sig_bin)


def test_point_from_bip340pub_key() -> None:
    """Verify every accepted pub_key representation yields the point."""
    q, x_Q = ssa.gen_keys()
    Q = mult(q)
    # an int
    assert ssa.point_from_bip340pub_key(x_Q) == Q
    # the same integer as bytes
    x_Q_bytes = x_Q.to_bytes(32, "big", signed=False)
    assert ssa.point_from_bip340pub_key(x_Q_bytes) == Q
    # the same integer as a hex string
    assert ssa.point_from_bip340pub_key(x_Q_bytes.hex()) == Q
    # tuple Point
    assert ssa.point_from_bip340pub_key(Q) == Q
    # 33 bytes
    assert ssa.point_from_bip340pub_key(bytes_from_point(Q)) == Q
    # 33 bytes hex-string
    assert ssa.point_from_bip340pub_key(bytes_from_point(Q).hex()) == Q
    # 65 bytes
    assert ssa.point_from_bip340pub_key(bytes_from_point(Q, compressed=False)) == Q
    # 65 bytes hex-string
    assert (
        ssa.point_from_bip340pub_key(bytes_from_point(Q, compressed=False).hex()) == Q
    )


def test_an_extended_key_is_no_longer_a_bip340_key() -> None:
    """The three spellings of a public xpub, refused (issue #1188).

    An extended key is bip32's object, and turning one into a public key
    is bip32's call to make; `ssa` reaching it was `to_pub_key`'s doing,
    through a `point_from_pub_key` whose own union names `BIP32KeyData`.
    Dropping that import is what withdraws all three at once, and the
    annotation would otherwise say so while the code went on accepting
    them.

    The key field is replaced with a point of the curve, so what refuses
    these is their being extended keys and not their contents. Only the
    public half is here because only the public half ever arrived: an
    xprv was refused as octets that would not parse, and a private
    `BIP32KeyData` by name, both before this change.
    """
    q, _ = ssa.gen_keys()
    Q = mult(q)
    xpub_data = BIP32KeyData.b58decode(
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
    )
    xpub_data = replace_unchecked(xpub_data, key=bytes_from_point(Q))
    xpub = xpub_data.b58encode()

    with pytest.raises(BTClibTypeError, match="not a BIP340 public key"):
        ssa.point_from_bip340pub_key(xpub_data)
    # the two text spellings are refused as the octets they are not, and
    # not by the same complaint: a `str` is read as hex and the Base58
    # alphabet is not hex, where the same characters as `bytes` are
    # already octets and are refused for their length. Both are what
    # dropping the union leaves -- a string reaching here is octets or
    # it is nothing
    with pytest.raises(BTClibValueError, match="invalid hex string"):
        ssa.point_from_bip340pub_key(xpub)
    err_msg = r"invalid size: 111 bytes instead of \(32, 33, 65\)"
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.point_from_bip340pub_key(xpub.encode("ascii"))


def test_a_buffer_is_octets_at_every_size_this_takes() -> None:
    """A bytearray and a memoryview, at all three sizes (issue #1188).

    They are what `bytes_from_octets` accepts beside `Octets` and returns
    as they came, and what `to_pub_key` names at run time beside the
    static union -- the asymmetry `alias` states and this module
    inherits.

    All three sizes because two of them worked and one did not: the
    dispatch this replaces reached `point_from_octets` for a SEC key,
    which takes any buffer, and fell through to an x-only branch that
    asked for `(str, bytes)` and so refused the same value one size
    down. Nothing decided that; it was where the fallback sat.
    """
    q, x_Q = ssa.gen_keys()
    Q = mult(q)
    spellings = (
        x_Q.to_bytes(32, "big"),
        bytes_from_point(Q),
        bytes_from_point(Q, compressed=False),
    )

    for octets in spellings:
        for buffer in (bytearray(octets), memoryview(octets)):
            assert ssa.point_from_bip340pub_key(buffer) == Q


def test_octets_of_no_key_size_name_every_size_there_is() -> None:
    """Three sizes are accepted here, so three are named (issue #1188).

    `point_from_octets` knows two of them, the SEC pair, and this module
    adds the x-only one on top -- so a refusal delegated to it would
    tell a caller that 32 octets are wrong when they are the spelling
    BIP340 itself defines.
    """
    for size in (0, 31, 34, 64):
        err_msg = f"invalid size: {size} bytes instead of \\(32, 33, 65\\)"
        with pytest.raises(BTClibValueError, match=err_msg):
            ssa.point_from_bip340pub_key(b"\x11" * size)


def test_low_cardinality() -> None:
    """Test low-cardinality curves for all msg/key pairs."""
    # ec.n has to be prime to sign
    test_curves = [
        low_card_curves["ec13_11"],
        low_card_curves["ec13_19"],
        low_card_curves["ec17_13"],
        low_card_curves["ec17_23"],
        low_card_curves["ec19_13"],
        low_card_curves["ec19_23"],
        low_card_curves["ec23_19"],
        low_card_curves["ec23_31"],
    ]

    aux = b"\x00" * 32
    msg = b"\x01"
    # only low cardinality test curves or it would take forever
    for ec in test_curves:
        for q in range(1, ec.n // 2):  # all possible private keys
            q_fixed, x_Q = ssa.gen_keys(q, ec)
            QJ = _jac_from_aff((x_Q, ec.y_even_var(x_Q)))
            sig: ssa.Sig | None = None
            while sig is None:
                try:
                    sig = ssa.sign(msg, q, aux, ec)
                except BTClibRuntimeError:  # invalid zero challenge
                    msg += b"\x01"
            ssa.assert_as_valid(msg, x_Q, sig)
            for k in range(1, ec.n // 2):  # all possible ephemeral keys
                k_fixed, r = ssa.gen_keys(k, ec)
                for e in range(ec.n):  # all possible challenges
                    s = (k_fixed + e * q_fixed) % ec.n

                    if e == 0:
                        err_msg = "invalid zero challenge"
                        with pytest.raises(BTClibRuntimeError, match=err_msg):
                            ssa._sign_(e, q_fixed, k_fixed, r, ec)
                        # no public key can be recovered
                        with pytest.raises(BTClibRuntimeError, match=err_msg):
                            ssa._recover_pub_key_(e, r, s, ec)

                        # if e == 0 then the sig is always valid
                        ssa._assert_as_valid_(e, QJ, r, s, ec, ec._fixed_points)
                        #  for all {q, Q}
                        ssa._assert_as_valid_(e, ec.GJ, r, s, ec, ec._fixed_points)
                    else:
                        sig = ssa._sign_(e, q_fixed, k_fixed, r, ec)
                        # recover pub_key
                        assert x_Q == ssa._recover_pub_key_(e, r, s, ec)

                        assert ssa.Sig(r, s, ec) == sig
                        # valid signature must validate
                        ssa._assert_as_valid_(e, QJ, r, s, ec, ec._fixed_points)
                        # invalid signature must raise
                        err_msg = r"y_K is odd|INF has no y-coordinate|signature verification failed"
                        with pytest.raises(
                            (BTClibRuntimeError, BTClibValueError), match=err_msg
                        ):
                            ssa._assert_as_valid_(
                                e, QJ, r, (s - 1) % ec.n, ec, ec._fixed_points
                            )


def test_assert_as_valid_rejects_the_odd_y_twin_of_a_correct_k() -> None:
    """A K whose x matches r but whose y is odd is refused on its own.

    `(s - 1) % ec.n` above moves K by a whole generator and almost
    always moves its x-coordinate too, so the exhaustive sweep exercises
    'Fail if x_K != r' far more than 'Fail if y_K is odd' -- and never
    the two apart. `-(k*G)` is the one point sharing K's x-coordinate
    without sharing its y, which the algebra reaches directly: solving
    s'*G - e*Q = -(k*G) for s' gives n - k + e*q, a scalar this function
    is handed like any other, without producing the point first.
    """
    ec = secp256k1
    q, x_Q = ssa.gen_keys()
    QJ = _jac_from_aff((x_Q, ec.y_even_var(x_Q)))
    k, r = ssa.gen_keys()  # k's point has even y, by gen_keys' own normalization
    e = 5

    s_prime = (ec.n - k + e * q) % ec.n
    with pytest.raises(BTClibRuntimeError, match="y_K is odd"):
        ssa._assert_as_valid_(e, QJ, r, s_prime, ec, ec._fixed_points)


@needs_bindings
def test_a_message_of_any_size_reaches_the_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both calls are made whatever the size of the message.

    Nothing in an answer says which implementation produced it, which is
    how the 32-byte gate in front of the bindings went unnoticed until
    four of BIP340's own vectors fell through it (issue 169). So the two
    calls are recorded here and the record is asserted: a gate put back
    would leave it empty for every size but 32, while every assertion
    about the signatures still passed.

    31, 32 and 33 are the boundary; 0, 1, 17 and 100 are the sizes of the
    four vectors themselves.

    Args:
        monkeypatch: patches the two bindings functions with recorders.
    """
    sizes = (0, 1, 17, 31, 32, 33, 100)
    calls: list[tuple[str, int]] = []
    real_sign_custom = libsecp256k1_ssa.sign_custom
    # `verify` on the octets: proving x an x-coordinate is what that parse
    # does, so the key is not validated before it and the same 32 bytes
    # are not parsed twice (issue 887)
    real_verify = libsecp256k1_ssa.verify

    # `verify` taken and forwarded rather than swallowed: the signing
    # path writes the keyword out, and a recorder that dropped it would
    # both fail here and record a call the package does not make
    def sign_custom(msg: bytes, prvkey: int, aux: bytes, *, verify: bool) -> bytes:
        calls.append(("sign_custom", len(msg)))
        return real_sign_custom(msg, prvkey, aux, verify=verify)

    def verify(msg: bytes, pubkey_bytes: bytes, sig: bytes) -> bool:
        calls.append(("verify", len(msg)))
        return real_verify(msg, pubkey_bytes, sig)

    monkeypatch.setattr(libsecp256k1_ssa, "sign_custom", sign_custom)
    monkeypatch.setattr(libsecp256k1_ssa, "verify", verify)

    q, x_Q = ssa.gen_keys(0x1234567890ABCDEF)
    for size in sizes:
        msg = bytes(size)
        sig = ssa.sign_(msg, q)
        assert ssa.verify_(msg, x_Q, sig)

    assert calls == [
        (name, size) for size in sizes for name in ("sign_custom", "verify")
    ]


@needs_bindings
def test_the_delegated_arm_forwards_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    """`verify` reaches `secp256k1_schnorrsig_sign_custom`, as `sign_` took it.

    The recorder above holds that `sign_custom` is called and forwards
    the keyword -- a dropped one raises `TypeError` there, its own local
    `sign_custom` declaring `verify` with no default -- but every call it
    makes is at the caller's own default, `verify=True`. Nothing held the
    *value* that crosses to be the caller's own rather than one written
    over on the way (issue 986): BIP340 is the one scheme #984 argues
    must keep the check on, which is exactly what a silent `verify=True`
    written at this crossing would still pass.
    """
    real_sign_custom = libsecp256k1_ssa.sign_custom
    calls: list[bool] = []

    def sign_custom(*args: Any, **kwargs: Any) -> bytes:
        calls.append(kwargs["verify"])
        return real_sign_custom(*args, **kwargs)

    q, _ = ssa.gen_keys(0x1234567890ABCDEF)
    msg = b"a message"

    with monkeypatch.context() as patch:
        patch.setattr(libsecp256k1_ssa, "sign_custom", sign_custom)
        for verify in (True, False):
            calls.clear()
            ssa.sign_(msg, q, verify=verify)
            assert calls == [verify]


def test_verify_with_a_message_that_is_not_32_bytes_on_both_arithmetics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue 169's message, on both arithmetics.

    BIP340 takes a message of any size, and so now does every path here:
    `sign_custom` and `verify` take one, and the 32-byte gate that used
    to stand in front of them -- which made `_assert_as_valid_` the only
    path able to verify four of BIP340's own vectors -- is gone. So this
    exercises the bindings first and the Python arithmetic second, under
    `no_bindings`, because the two must not disagree about a signature
    and only one of them is now reached by default. The Python one is
    reached in earnest by another curve or another hash function; its
    multiplication is still the bindings' on secp256k1, 183 us against
    the 1.17 ms of the arithmetic under it.
    """
    msg = b"a message that is not 32 bytes"
    assert len(msg) != 32
    q, x_Q = ssa.gen_keys(0x1234567890ABCDEF)
    sig = ssa.sign_(msg, q)

    def checks() -> None:
        ssa.assert_as_valid_(msg, x_Q, sig)
        assert ssa.verify_(msg, x_Q, sig)
        # the same signature over another message of the same size
        assert not ssa.verify_(b"another message of the same size", x_Q, sig)

    checks()
    no_bindings(monkeypatch)
    checks()


def test_batch_validation() -> None:
    """Verify batch verification and the mismatches it must refuse."""
    ms: list[String] = []
    Qs: list[int] = []
    sigs: list[ssa.Sig] = []
    err_msg = "no signatures provided"
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_batch_as_valid(ms, Qs, sigs)
    assert not ssa.batch_verify(ms, Qs, sigs)

    aux = b"\x00" * 32
    # not the size of the msg_hash, just an arbitrary size for the msg
    msg_size = 16
    for i in range(1, 4):
        m = bytes(i) * msg_size
        ms.append(m)
        q, Q = ssa.gen_keys(i)
        Qs.append(Q)
        sigs.append(ssa.sign(m, q, aux))
        ssa.assert_batch_as_valid(ms, Qs, sigs)
        assert ssa.batch_verify(ms, Qs, sigs)

    ms.append(ms[0])
    sigs.append(sigs[1])
    Qs.append(Qs[0])
    err_msg = "signature verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        ssa.assert_batch_as_valid(ms, Qs, sigs)
    assert not ssa.batch_verify(ms, Qs, sigs)
    sigs[-1] = sigs[0]  # valid again

    ms.append(ms[0])  # add extra message
    err_msg = "mismatch between number of pub_keys "
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_batch_as_valid(ms, Qs, sigs)
    assert not ssa.batch_verify(ms, Qs, sigs)
    ms.pop()  # valid again

    # fewer messages than pub_keys, not only more: `!= batch_size`
    # weakened to `>` would let this one through
    short_ms = ms[:-1]
    err_msg = "mismatch between number of pub_keys "
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_batch_as_valid(short_ms, Qs, sigs)
    assert not ssa.batch_verify(short_ms, Qs, sigs)

    sigs.append(sigs[0])  # add extra sig
    err_msg = "mismatch between number of pub_keys "
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_batch_as_valid(ms, Qs, sigs)
    assert not ssa.batch_verify(ms, Qs, sigs)
    sigs.pop()  # valid again

    sigs[0] = ssa.Sig(
        sigs[0].r, sigs[0].s, CURVES["secp256r1"], check_validity=False
    )  # different curve
    err_msg = "not the same curve for all signatures"
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_batch_as_valid(ms, Qs, sigs)
    assert not ssa.batch_verify(ms, Qs, sigs)
    sigs[0] = ssa.Sig(sigs[0].r, sigs[0].s, CURVES["secp256k1"])  # same curve again

    # dropping a byte from a message is not a size error any more but a
    # different message, so the batch fails to verify rather than refusing
    # to look (issue 169)
    ms = [reduce_to_hlen(m, hf) for m in ms]
    assert ssa.batch_verify_(ms, Qs, sigs)
    ms[0] = ms[0][:-1]
    err_msg = "signature verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        ssa.assert_batch_as_valid_(ms, Qs, sigs)
    assert not ssa.batch_verify_(ms, Qs, sigs)


def test_a_batch_of_one_takes_the_single_signature_shortcut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`batch_size == 1` dispatches to `assert_as_valid_`, not the general sum.

    What the shortcut buys is one verification instead of a multi-scalar
    sum over a single term. What it does not decide is the answer: both
    paths validate every signature they are handed, so a malformed `Sig`
    no longer tells them apart, and the dispatch is what is asserted here
    -- a stand-in on the single-signature entry, reached by a batch of one
    and not by a batch of two.
    """
    reached: list[bool] = []

    def spy(*_args: object, **_kwargs: object) -> None:
        reached.append(True)

    monkeypatch.setattr(ssa, "assert_as_valid_", spy)

    q, x_Q = ssa.gen_keys()
    sig = ssa.sign(b"msg", q)
    # the reducing spelling, `sign` having reduced too: the underscored one
    # takes a prepared message, and a batch of two would fail the sum here
    # for that reason rather than for the dispatch under test
    ssa.assert_batch_as_valid([b"msg"], [x_Q], [sig])
    assert reached == [True]

    q_2, x_Q_2 = ssa.gen_keys(2)
    sig_2 = ssa.sign(b"msg_2", q_2)
    ssa.assert_batch_as_valid([b"msg", b"msg_2"], [x_Q, x_Q_2], [sig, sig_2])
    assert reached == [True]


@pytest.mark.parametrize("batch_size", [1, 2, 3])
def test_batch_and_single_verification_agree_about_a_non_canonical_s(
    batch_size: int,
) -> None:
    """One question, one answer, whatever the batch size (issue 688).

    `s` and `s + n` are congruent modulo the group order, so the
    multi-scalar equation is satisfied by both while BIP340, and
    `Sig.assert_valid` with it, admit only the canonical one. No 64-byte
    signature can carry `s + n`, so this takes a caller building `Sig`
    objects with `check_validity=False` -- which `tests/check_validity_test`
    shows is supported, and is what the batch equation used to be asked
    without anything checking.
    """
    keys = [ssa.gen_keys(i) for i in range(1, batch_size + 1)]
    msgs: list[String] = [bytes([i]) * 16 for i in range(1, batch_size + 1)]
    sigs = [ssa.sign(m, q) for m, (q, _) in zip(msgs, keys, strict=True)]
    Qs = [x_Q for _, x_Q in keys]

    assert ssa.batch_verify(msgs, Qs, sigs)
    assert all(ssa.verify(m, Q, s) for m, Q, s in zip(msgs, Qs, sigs, strict=True))

    # the last signature, with n added to its s
    last = sigs[-1]
    sigs[-1] = ssa.Sig(last.r, last.s + last.ec.n, last.ec, check_validity=False)

    assert not ssa.verify(msgs[-1], Qs[-1], sigs[-1])
    assert not ssa.batch_verify(msgs, Qs, sigs)
    err_msg = "scalar s not in 0..n-1: "
    with pytest.raises(BTClibValueError, match=err_msg):
        ssa.assert_batch_as_valid(msgs, Qs, sigs)


def test_batch_validation_on_the_python_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """The batch verification equation, on both point arithmetics.

    Batch verification is btclib's own: libsecp256k1 exposes no batch
    verify, so what serves it is the multi_mult_var of curves.curve -- and on
    secp256k1 that is the bindings, which makes this the one caller
    handing them many scalars at once. Patching the dispatch off is the
    only way the Python arithmetic sees a batch, and what this catches is
    the two implementations disagreeing about the verdict, on a batch that
    must pass and on one that must fail.
    """
    aux = b"\x00" * 32
    # not the size of the msg_hash, just an arbitrary size for the msg
    msg_size = 16
    msgs: list[String] = []
    Qs: list[int] = []
    sigs: list[ssa.Sig] = []
    for i in range(1, 5):
        msg = bytes(i) * msg_size
        msgs.append(msg)
        q, Q = ssa.gen_keys(i)
        Qs.append(Q)
        sigs.append(ssa.sign(msg, q, aux))

    ssa.assert_batch_as_valid(msgs, Qs, sigs)

    no_bindings(monkeypatch)
    ssa.assert_batch_as_valid(msgs, Qs, sigs)

    # one signature belonging to another message of the same batch: the
    # sum misses, and misses on either arithmetic
    sigs[-1] = sigs[0]
    with pytest.raises(BTClibRuntimeError, match="signature verification failed"):
        ssa.assert_batch_as_valid(msgs, Qs, sigs)


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_a_batch_refuses_a_bad_key_in_the_lift_s_words(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch refuses a key that is no x-coordinate as `ec.y_var` does.

    The twin of the single-signature test above, for the equation: the
    delegated arm does not lift a key either -- the multiplication's own
    parse is that square root -- so which term the bindings could not
    read is found on the refusing path alone, and the message has to come
    out the same as the arm that lifts. The same four x, for both
    messages in both renderings.
    """
    if not bindings:
        no_bindings(monkeypatch)

    ec = secp256k1
    msgs: list[Octets] = []
    Qs: list[int] = []
    sigs: list[ssa.Sig] = []
    for i in range(1, 3):
        msg = reduce_to_hlen(bytes(i) * 16)
        msgs.append(msg)
        q, Q = ssa.gen_keys(i)
        Qs.append(Q)
        sigs.append(ssa.sign_(msg, q))

    ssa.assert_batch_as_valid_(msgs, Qs, sigs)

    for x in (ec.p, ec.p + 1, 0xDEADBEEF00000000, 7):
        with pytest.raises(BTClibValueError) as batched:
            ssa.assert_batch_as_valid_(msgs, [Qs[0], x], sigs)
        with pytest.raises(BTClibValueError) as lifted:
            ec.y_var(x)
        assert str(batched.value) == str(lifted.value)


def test_musig1() -> None:
    """Testing 3-of-3 MuSig1, the three-round scheme MuSig2 replaced.

    ePrint 2018/068's first version (2018-01-18) proposed two rounds --
    exchange nonces, then partial signatures -- and was withdrawn: a
    signer that saw every other nonce before publishing its own could
    choose one adaptively, and no proof survives that choice. Its
    revision (2018-05-20, after the flaw was published as ePrint
    2018/417) added a round in front, committing to each nonce before
    revealing it. That three-round scheme is MuSig1, reproduced below.
    `btclib.ecc.musig2` is the two-round scheme that replaced it in
    turn, buying the round back with a pair of nonce points rather than
    a commitment.

    https://eprint.iacr.org/2018/068
    """
    ec = CURVES["secp256k1"]

    msg_hash = hf(b"message to sign").digest()

    # the signers private and public keys,
    # including both the curve Point and the BIP340-Schnorr public key
    q1, x_Q1_int = ssa.gen_keys()
    x_Q1 = x_Q1_int.to_bytes(ec.p_size, byteorder="big", signed=False)

    q2, x_Q2_int = ssa.gen_keys()
    x_Q2 = x_Q2_int.to_bytes(ec.p_size, byteorder="big", signed=False)

    q3, x_Q3_int = ssa.gen_keys()
    x_Q3 = x_Q3_int.to_bytes(ec.p_size, byteorder="big", signed=False)

    # (non interactive) key setup
    # this is MuSig core: the rest is just Schnorr signature additivity
    # 1. lexicographic sorting of public keys
    keys = [x_Q1, x_Q2, x_Q3]
    keys.sort()
    # 2. coefficients
    prefix = b"".join(keys)
    a1 = int_from_bits(hf(prefix + x_Q1).digest(), ec.nlen) % ec.n
    a2 = int_from_bits(hf(prefix + x_Q2).digest(), ec.nlen) % ec.n
    a3 = int_from_bits(hf(prefix + x_Q3).digest(), ec.nlen) % ec.n
    # 3. aggregated public key
    Q1 = mult(q1)
    Q2 = mult(q2)
    Q3 = mult(q3)
    Q = ec.add_var(double_mult_var(a1, Q1, a2, Q2), mult(a3, Q3))
    # the parity of the aggregated key is a coin flip on every run, so
    # the negation executes in half of them: the pragmas keep the
    # coverage gate deterministic. Keys pinned offline for an odd
    # parity would cover the lines instead, trading away the fresh
    # randomness that makes this protocol demo worth running
    if Q[1] % 2:
        a1 = ec.n - a1  # pragma: no cover
        a2 = ec.n - a2  # pragma: no cover
        a3 = ec.n - a3  # pragma: no cover

    # round 1: each signer picks a nonce and publishes only a commitment
    # to it. Committing before any nonce is visible is the round the
    # withdrawn two-round scheme skipped -- there, a signer choosing its
    # nonce after seeing everyone else's could choose adaptively, which
    # is exactly what a commit-then-reveal round rules out. There is no
    # standard tagging for this commitment: the paper states a hash
    # function with no domain separation, so hashing the serialized
    # point with a bare hf is this demo's choice, not a specification's.
    k1, _ = ssa.gen_keys()
    K1 = mult(k1)
    t1 = hf(bytes_from_point(K1, ec)).digest()

    k2, _ = ssa.gen_keys()
    K2 = mult(k2)
    t2 = hf(bytes_from_point(K2, ec)).digest()

    k3, _ = ssa.gen_keys()
    K3 = mult(k3)
    t3 = hf(bytes_from_point(K3, ec)).digest()

    # exchange {t_i} (interactive)

    # round 2: each signer reveals its nonce; every signer checks every
    # other commitment before using any of the revealed nonces. This
    # check is the point of the round: a nonce that does not match its
    # commitment must be rejected here, not accepted because it arrived
    # signed.
    for i, t_i, K_i in ((1, t1, K1), (2, t2, K2), (3, t3, K3)):
        assert hf(bytes_from_point(K_i, ec)).digest() == t_i, (
            f"signer {i} revealed a nonce that does not match its commitment"
        )

    # a signer revealing a nonce that does not match its commitment must
    # be caught by that same check, so it has to be a real assertion:
    # forge a mismatch and confirm round 2 rejects it
    k_x, _ = ssa.gen_keys()
    K_x = mult(k_x)
    with pytest.raises(AssertionError, match="does not match its commitment"):
        assert hf(bytes_from_point(K_x, ec)).digest() == t1, (
            "signer 1 revealed a nonce that does not match its commitment"
        )

    # exchange {K_i} (interactive)

    # round 3: computes s_i (non interactive)
    # same for all signers
    K = ec.add_var(ec.add_var(K1, K2), K3)
    # the same coin flip as above, on the aggregated nonce
    if K[1] % 2:
        k1 = ec.n - k1  # pragma: no cover
        k2 = ec.n - k2  # pragma: no cover
        k3 = ec.n - k3  # pragma: no cover
    r = K[0]
    e = ssa.challenge_(msg_hash, Q[0], r, ec, hf)
    s_1 = (k1 + e * a1 * q1) % ec.n
    s_2 = (k2 + e * a2 * q2) % ec.n
    s3 = (k3 + e * a3 * q3) % ec.n

    # exchange s_i (interactive)

    # finalize signature (non interactive)
    s = (s_1 + s_2 + s3) % ec.n
    sig = ssa.Sig(r, s, ec)
    # check signature is valid
    ssa.assert_as_valid_(msg_hash, Q[0], sig, hf)


def _share(f: list[int], x: int, ec: Curve) -> int:
    """Evaluate the sharing polynomial f at x, f(x) = sum_i f[i] x**i.

    Each term is reduced mod n and the sum is not: what every consumer
    of a share needs is its value mod n, and mult, double_mult_var and the
    Lagrange interpolation at the end each reduce again anyway.
    """
    return sum((f_i * pow(x, i)) % ec.n for i, f_i in enumerate(f))


def _commitment(commits: list[Point], x: int, ec: Curve) -> Point:
    """Evaluate the commitment polynomial at x, sum_i x**i commits[i].

    This is the same evaluation as _share, in the exponent: a share is
    consistent with the commitments when the two agree, which is what
    makes the sharing verifiable rather than trusted.
    """
    RHS = INF
    for i, commit in enumerate(commits):
        RHS = ec.add_var(RHS, mult(pow(x, i), commit))
    return RHS


def _deal(
    secret: int,
    secret_prime: int,
    xs: list[int],
    m: int,
    ec: Curve,
    H: Point,
    dealer: str,
) -> tuple[list[int], list[int]]:
    """Deal shares of secret to each x, and let each x verify its own.

    Pedersen VSS: two random degree m-1 polynomials through secret and
    its blinding twin, one commitment per coefficient, one share of each
    polynomial per recipient. The verification lives here rather than at
    the call site because an unchecked share is just a number from a
    dealer that may be cheating, and the protocol has no later moment to
    catch it.

    Neither the blinding polynomial nor the commitments outlive that
    check, so only f and the shares of the secret come back.
    """
    f = [secret]
    f_prime = [secret_prime]
    commits = [double_mult_var(secret_prime, H, secret, ec.G)]
    for _ in range(1, m):
        f.append(ssa.gen_keys()[0])
        f_prime.append(ssa.gen_keys()[0])
        commits.append(double_mult_var(f_prime[-1], H, f[-1], ec.G))

    shares: list[int] = []
    for x in xs:
        alpha = _share(f, x, ec)
        t = double_mult_var(_share(f_prime, x, ec), H, alpha, ec.G)
        assert t == _commitment(commits, x, ec), f"signer {dealer} is cheating"
        shares.append(alpha)
    return f, shares


def _partial_sig_point(
    x: int, e: int, Q: Point, K: Point, A: list[Point], B: list[Point], ec: Curve
) -> Point:
    """Compute B(x) + e A(x), what signer x's partial signature commits to.

    Q and K are arguments instead of A[0] and B[0]: an odd y negates the
    aggregates and the coefficient lists keep the sign they were built
    with, so the constant term is only right when it is taken from the
    negated points.
    """
    RHS = ec.add_var(K, mult(e, Q))
    for i in range(1, len(A)):
        RHS = ec.add_var(RHS, double_mult_var(pow(x, i), B[i], e * pow(x, i), A[i]))
    return RHS


def test_threshold() -> None:
    """Testing 2-of-3 threshold signature (Pedersen secret sharing)."""
    ec = CURVES["secp256k1"]

    # parameters
    m = 2
    H = second_generator(ec)

    # FIRST PHASE: key pair generation ###################################

    # 1.1 signer one acting as the dealer
    q1, _ = ssa.gen_keys()
    q1_prime, _ = ssa.gen_keys()
    # alpha12 is the share of q1 belonging to signer two, alpha13 the
    # one belonging to signer three; signer one keeps no share of its
    # own, evaluating f1 at 1 below instead
    f1, (alpha12, alpha13) = _deal(q1, q1_prime, [2, 3], m, ec, H, "one")

    # 1.2 signer two acting as the dealer
    q2, _ = ssa.gen_keys()
    q2_prime, _ = ssa.gen_keys()
    f2, (alpha21, alpha23) = _deal(q2, q2_prime, [1, 3], m, ec, H, "two")

    # 1.3 signer three acting as the dealer
    q3, _ = ssa.gen_keys()
    q3_prime, _ = ssa.gen_keys()
    f3, (alpha31, alpha32) = _deal(q3, q3_prime, [1, 2], m, ec, H, "three")

    # shares of the secret key q = q1 + q2 + q3
    alpha1 = (alpha21 + alpha31) % ec.n + _share(f1, 1, ec)
    alpha2 = (alpha12 + alpha32) % ec.n + _share(f2, 2, ec)
    alpha3 = (alpha13 + alpha23) % ec.n + _share(f3, 3, ec)

    # 1.4 it's time to recover the public key
    # each participant i = 1, 2, 3 shares Qi as follows
    # Q = Q1 + Q2 + Q3 = (q1 + q2 + q3) G
    A1 = [mult(f1_i) for f1_i in f1]
    A2 = [mult(f2_i) for f2_i in f2]
    A3 = [mult(f3_i) for f3_i in f3]
    # signer one checks others' values
    assert mult(alpha21) == _commitment(A2, 1, ec), "signer two is cheating"
    assert mult(alpha31) == _commitment(A3, 1, ec), "signer three is cheating"
    # signer two checks others' values
    assert mult(alpha12) == _commitment(A1, 2, ec), "signer one is cheating"
    assert mult(alpha32) == _commitment(A3, 2, ec), "signer three is cheating"
    # signer three checks others' values
    assert mult(alpha13) == _commitment(A1, 3, ec), "signer one is cheating"
    assert mult(alpha23) == _commitment(A2, 3, ec), "signer two is cheating"
    # commitment at the global sharing polynomial
    A = [ec.add_var(A1[i], ec.add_var(A2[i], A3[i])) for i in range(m)]
    # aggregated public key
    Q = A[0]
    # the same coin flip as in test_musig1: fresh keys, random parity
    if Q[1] % 2:
        A[1] = ec.negate(A[1])  # pragma: no cover
        alpha1 = ec.n - alpha1  # pragma: no cover
        alpha2 = ec.n - alpha2  # pragma: no cover
        alpha3 = ec.n - alpha3  # pragma: no cover
        Q = ec.negate(Q)  # pragma: no cover

    # SECOND PHASE: generation of the nonces' pair  ######################
    # Assume signer one and three want to sign

    msg = b"message to sign"
    msg_hash = reduce_to_hlen(msg, hf)

    # 2.1 signer one acting as the dealer
    k1, _, _, _ = bip340_nonce_(msg_hash, q1, None, ec, hf)
    k1_prime, _, _, _ = bip340_nonce_(msg_hash, q1_prime, None, ec, hf)
    # the nonce is shared exactly as the key was, and with only signers
    # one and three signing, each deals to the other alone
    f1, (beta13,) = _deal(k1, k1_prime, [3], m, ec, H, "one")

    # 2.2 signer three acting as the dealer
    k3, _, _, _ = bip340_nonce_(msg_hash, q3, None, ec, hf)
    k3_prime, _, _, _ = bip340_nonce_(msg_hash, q3_prime, None, ec, hf)
    f3, (beta31,) = _deal(k3, k3_prime, [1], m, ec, H, "three")

    # 2.3 shares of the secret nonce
    beta1 = beta31 % ec.n + _share(f1, 1, ec)
    beta3 = beta13 % ec.n + _share(f3, 3, ec)

    # 2.4 it's time to recover the public nonce
    # each participant i = 1, 3 shares Qi as follows
    B1 = [mult(f1_i) for f1_i in f1]
    B3 = [mult(f3_i) for f3_i in f3]

    # signer one checks values from signer three
    assert mult(beta31) == _commitment(B3, 1, ec), "signer three is cheating"

    # signer three checks values from signer one
    assert mult(beta13) == _commitment(B1, 3, ec), "signer one is cheating"

    # commitment at the global sharing polynomial
    B = [ec.add_var(B1[i], B3[i]) for i in range(m)]
    # aggregated public nonce
    K = B[0]
    # the same coin flip again, and here pinning the keys would not
    # even help: k1 and k3 come from bip340_nonce_ with aux=None, i.e.
    # fresh OS randomness, so the aux would need pinning too
    if K[1] % 2:
        B[1] = ec.negate(B[1])  # pragma: no cover
        beta1 = ec.n - beta1  # pragma: no cover
        beta3 = ec.n - beta3  # pragma: no cover
        K = ec.negate(K)  # pragma: no cover

    # PHASE THREE: signature generation ###

    # partial signatures
    e = ssa.challenge_(msg_hash, Q[0], K[0], ec, hf)
    gamma1 = (beta1 + e * alpha1) % ec.n
    gamma3 = (beta3 + e * alpha3) % ec.n

    # each participant verifies the other partial signatures

    # signer one
    RHS3 = _partial_sig_point(3, e, Q, K, A, B, ec)
    assert mult(gamma3) == RHS3, "signer three is cheating"

    # signer three
    RHS1 = _partial_sig_point(1, e, Q, K, A, B, ec)
    assert mult(gamma1) == RHS1, "signer one is cheating"

    # PHASE FOUR: aggregating the signature ###
    omega1 = 3 * mod_inv_var(3 - 1, ec.n) % ec.n
    omega3 = 1 * mod_inv_var(1 - 3, ec.n) % ec.n
    sigma = (gamma1 * omega1 + gamma3 * omega3) % ec.n

    sig = ssa.Sig(K[0], sigma, ec)

    assert ssa.verify_(msg_hash, Q[0], sig)

    # ADDITIONAL PHASE: reconstruction of the private key ###
    secret = (omega1 * alpha1 + omega3 * alpha3) % ec.n
    assert (q1 + q2 + q3) % ec.n in {secret, ec.n - secret}


@needs_bindings
def test_libsecp256k1() -> None:
    """Check btclib's signature is byte-identical to the bindings' own."""
    msg = b"Satoshi Nakamoto"
    prvkey_int, pubkey_int = ssa.gen_keys(0x1)
    aux = b"\x00" * 32
    btclib_sig = ssa.sign(msg, prvkey_int, aux)
    pub_key = pubkey_int.to_bytes(32, "big")
    assert ssa.verify(msg, pub_key, btclib_sig.serialize())
    assert ssa.verify(msg, pub_key, btclib_sig)

    msg_hash = reduce_to_hlen(msg)
    libsecp256k1_sig = libsecp256k1_ssa.sign(msg_hash, prvkey_int, aux)
    assert len(btclib_sig.serialize()) == 64
    assert btclib_sig.serialize() == libsecp256k1_sig
    assert ssa.verify(msg, pub_key, libsecp256k1_sig)


@needs_bindings
def test_a_plain_sign_reaches_the_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default call signs a secret key through libsecp256k1, not Python.

    `sign_`'s guard -- `_libsecp256k1_serves(ec, hf) and commit_hash is
    None` -- is what every caller with no commitment keeps by default,
    and both arms it chooses between reach the same signature from the
    same secret key: nothing about the result says which one produced it
    (issue 975, asked in general of every guard a computed value could
    disable rather than of this one, which has none). `ssa.sign` for
    secp256k1 with sha256, any message size and no commitment is one
    call SECURITY.md names as crossing the boundary whole; the Python
    arm below composes the same signature from `bip340_nonce_` and a
    linear combination instead, its own two point multiplications still
    reaching libsecp256k1 while it serves. This records the call into
    `libsecp256k1_ssa.sign_custom` instead of the answer it returns, so
    a change that silently stopped taking it would fail here rather
    than reproduce the same signature from the arm it stands in for.
    """
    calls: list[int] = []
    real_sign_custom = libsecp256k1_ssa.sign_custom

    def record(msg: bytes, prvkey: int, *args: Any, **kwargs: Any) -> bytes:
        calls.append(prvkey)
        return real_sign_custom(msg, prvkey, *args, **kwargs)

    monkeypatch.setattr(libsecp256k1_ssa, "sign_custom", record)

    q, _x_Q = ssa.gen_keys(0x1234567890ABCDEF)
    ssa.sign_(b"Satoshi Nakamoto", q)
    assert calls == [q]


@needs_bindings
def test_libsecp256k1_x_only_conversion() -> None:
    """The x-only key handed to the bindings is btclib's to derive.

    The bindings' x-only surface takes 32 bytes and nothing else: a
    compressed key there is a ValueError.
    point_from_bip340pub_key normalizes first, so the odd-y key below
    verifies through the same even-y point in whatever representation
    it is handed in. This test is what keeps that true: a refactor that
    starts passing a compressed key straight through would fail here
    rather than at the cffi boundary, where ssa_verify swallows the
    ValueError and only a failed script is left to read.
    """
    msg = b"Satoshi Nakamoto"
    q = 6  # gen_keys negates it, so mult(q) is the odd-y point
    q_fixed, x_Q = ssa.gen_keys(q)
    assert q_fixed != q
    sig = ssa.sign(msg, q, b"\x00" * 32)

    x_only = x_Q.to_bytes(32, "big")
    assert len(x_only) == 32  # what assert_as_valid_ passes to the bindings
    assert ssa.verify(msg, x_only, sig)

    Q = mult(q)
    assert Q[1] % 2  # y is odd, so the parity byte is the one dropped
    for pub_key in (bytes_from_point(Q), bytes_from_point(Q, compressed=False)):
        assert len(pub_key) in {33, 65}
        assert ssa.verify(msg, pub_key, sig)


def test_sign_aux_size() -> None:
    """Nonce entropy is 32 bytes, or omitted.

    bytes_from_octets enforces it at btclib's own boundary, ahead of the
    bindings' own ValueError, so callers get a BTClibValueError, and
    b"" is a size error rather than a request for fresh randomness.
    """
    msg_hash = reduce_to_hlen(b"Satoshi Nakamoto")
    q, x_Q = ssa.gen_keys(0x1)

    assert ssa.verify_(msg_hash, x_Q, ssa.sign_(msg_hash, q))  # aux omitted
    assert ssa.verify_(msg_hash, x_Q, ssa.sign_(msg_hash, q, b"\x00" * 32))

    for aux in (b"", b"\x00" * 31, b"\x00" * 33):
        err_msg = f"invalid size: {len(aux)} bytes instead of 32"
        with pytest.raises(BTClibValueError, match=err_msg):
            ssa.sign_(msg_hash, q, aux)


def test_zero_challenge() -> None:
    """A tagged hash that is zero mod n must raise.

    For secp256k1 that is a 2**-256 accident; on ec13_11 one msg_hash
    in eleven does it, and this one is the first big-endian counter
    value that does (x_Q = x_K = 1, the generator).
    """
    ec = low_card_curves["ec13_11"]
    msg_hash = (11).to_bytes(32, "big")
    with pytest.raises(BTClibRuntimeError, match="invalid zero challenge"):
        ssa.challenge_(msg_hash, 1, 1, ec, hf)


def test_recover_infinity_pub_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The recovered Q = e1*(s*G - K) is INF whenever s*G equals K.

    G's y-coordinate is even, so r = G.x picks K = G, and s = 1 then
    makes the recovered key INF whatever the challenge. The
    low-cardinality loop can never get here: its s comes from a real
    signature, hence s*G - K = c*q*G with c and q both nonzero.

    Both arithmetics answer it, which is what the delegated double_mult_var of
    issue 286 turns on: a libsecp256k1 pubkey is never the identity, so
    the sum is recognized from the coordinates in curves.curve and handed
    back as the z == 0 this function tests -- u*H + v*Q with v*Q == -u*H
    is exactly the case, u being n - e1 and v being e1 here.
    """
    err_msg = r"invalid \(INF\) key"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        ssa._recover_pub_key_(1, secp256k1.G[0], 1, secp256k1)

    no_bindings(monkeypatch)
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        ssa._recover_pub_key_(1, secp256k1.G[0], 1, secp256k1)


def test_recovery_multiplies_in_libsecp256k1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """x-only recovery on both point arithmetics (issue 286).

    Nothing in libsecp256k1 recovers an x-only key: its recovery module is
    ECDSA -- `recover(msg, signature, recid)` -- and its xonly module has
    no recovery in it, so the double_mult_var under this function is the whole
    of what there is to delegate, and the Python arithmetic is reachable
    only by patching the dispatch off. What this catches is the two
    disagreeing about the recovered x_Q.

    The low-cardinality loop asserts the same equality exhaustively, and
    on the Python arithmetic alone: those curves are not secp256k1, so
    nothing there reaches the bindings this compares against.
    """
    ec = secp256k1
    for i in range(1, 5):
        msg_hash = reduce_to_hlen(bytes([i]) * 32)
        q, x_Q = ssa.gen_keys(i)
        sig = ssa.sign_(msg_hash, q)
        c = ssa.challenge_(msg_hash, x_Q, sig.r, ec, hf)

        assert ssa._recover_pub_key_(c, sig.r, sig.s, ec) == x_Q
        with monkeypatch.context() as patch:
            no_bindings(patch)
            assert ssa._recover_pub_key_(c, sig.r, sig.s, ec) == x_Q


def test_a_bad_hf_raises_rather_than_answering_about_the_signature() -> None:
    """As `ecc.dsa`'s twin of this test, and for `batch_verify_` as well.

    The batch is the one that has to be checked on its own: it validates
    its own lengths before delegating, so an hf refused only inside
    `assert_as_valid_` would be reported as an invalid batch for every
    size but one (issue #745).
    """
    msg = b"Satoshi Nakamoto"
    q, x_Q = ssa.gen_keys(0x1)
    sig = ssa.sign(msg, q)
    msg_hash = reduce_to_hlen(msg, hf)
    assert ssa.verify_(msg_hash, x_Q, sig)

    err_msg = "not a hash function"
    with pytest.raises(BTClibTypeError, match=err_msg):
        ssa.verify_(msg_hash, x_Q, sig, hf())  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match=err_msg):
        ssa.assert_as_valid_(msg_hash, x_Q, sig, hf())  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match=err_msg):
        ssa.verify(msg, x_Q, sig, hf())  # type: ignore[arg-type]

    # the batch, at both sizes: one signature shortcuts to assert_as_valid_
    # and two or more take the multi-scalar equation
    assert ssa.batch_verify_([msg_hash], [x_Q], [sig])
    for size in (1, 2):
        with pytest.raises(BTClibTypeError, match=err_msg):
            ssa.batch_verify_([msg_hash] * size, [x_Q] * size, [sig] * size, hf())  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match=err_msg):
            ssa.assert_batch_as_valid_(
                [msg_hash] * size,
                [x_Q] * size,
                [sig] * size,
                hf(),  # type: ignore[arg-type]
            )


def test_verification_under_a_prepared_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """BIP340 takes a prepared key too, and both lifts of it are the key.

    An x-only key names two points and BIP340 means the even-y one, so a
    caller preparing the odd-y twin has prepared this same key: the
    verification lifts as it always did, and the tables answer because
    `PreparedPoint` puts the negation in its set beside the point --
    which is the reason `Curve.__init__` puts the generator's there.

    So the assertion is that all three spellings verify the same
    signature and agree with each other, on both arithmetics.
    """
    prv_key = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
    _, x_Q = ssa.gen_keys(prv_key)
    msg = b"Satoshi Nakamoto"
    sig = ssa.sign(msg, prv_key)

    even = ssa.point_from_bip340pub_key(x_Q)
    odd = even[0], secp256k1.p - even[1]
    for _ in range(2):
        for key in (x_Q, PreparedPoint(even), PreparedPoint(odd)):
            ssa.assert_as_valid(msg, key, sig)
            assert ssa.verify(msg, key, sig)
            assert not ssa.verify(b"another message", key, sig)
        no_bindings(monkeypatch)


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_a_key_that_is_no_x_coordinate_is_refused_in_the_lift_s_words(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both arithmetics refuse a bad x as `ec.y_var` refuses it.

    The delegated path never lifts the key -- the verification's own parse
    is that square root (issue 887) -- so the two messages are written in
    two places and would drift apart unnoticed but for this: what would
    notice is a caller matching on the text.

    Four x, for both messages in both renderings: `ec.p` and above it are
    the range refusal, `0xDEADBEEF00000000` an x no point of the curve
    has, and 7 the same refusal below `HEX_THRESHOLD`, where the value
    renders in decimal rather than as grouped hex.
    """
    if not bindings:
        no_bindings(monkeypatch)

    ec = secp256k1
    q, x_Q = ssa.gen_keys(0x1234567890ABCDEF)
    msg = b"a message"
    sig = ssa.sign_(msg, q)
    assert ssa.verify_(msg, x_Q, sig)

    for x in (ec.p, ec.p + 1, 0xDEADBEEF00000000, 7):
        with pytest.raises(BTClibValueError) as verified:
            ssa.assert_as_valid_(msg, x, sig)
        with pytest.raises(BTClibValueError) as lifted:
            ec.y_var(x)
        assert str(verified.value) == str(lifted.value)


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
@needs_bindings
def test_signer_signs_what_sign_signs(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A held keypair changes what a signature costs and not what it is.

    `Signer.sign_` is `sign_` over a keypair built once, so the two have
    to answer the same octets: asserted over a spread of messages, with
    the aux named so that the comparison is of the derivation and not of
    two draws. And over the arm that holds no keypair at all -- a curve
    or a hash function the bindings decline -- where `sign_` is the whole
    of the implementation.
    """
    if not bindings:
        no_bindings(monkeypatch)

    prv_key, x_Q = ssa.gen_keys(0x1234567890ABCDEF)
    aux = bytes(32)

    # where a keypair was built it holds the secret in memory that can be
    # overwritten, so the scalar is not kept beside it; where there is no
    # keypair the scalar is the whole of what signs, and is
    held = ssa.Signer(prv_key)
    assert bool(held._q) is not bindings
    held.wipe()

    with ssa.Signer(prv_key) as signer:
        for msg in (b"", b"a message", bytes(32), bytes(1000)):
            msg_hash = reduce_to_hlen(msg)
            assert (
                signer.sign_(msg_hash, aux)
                == ssa.sign_(msg_hash, prv_key, aux).serialize()
            )
            # and the unprepared spelling reduces with hf, as `sign` does
            assert signer.sign(msg, aux) == ssa.sign(msg, prv_key, aux).serialize()
            assert ssa.verify_(msg_hash, x_Q, signer.sign_(msg_hash))

        # a *prepared* message of any size, which is the whole of what
        # the trailing underscore promises and what the bindings' 32-byte
        # entry point would take away again (issue 169): signing through
        # that one would leave the two arms of this class disagreeing,
        # the python one signing what the delegated one refused
        for size in (0, 1, 31, 33, 64, 1000):
            of_that_size = bytes(size)
            assert (
                signer.sign_(of_that_size, aux)
                == ssa.sign_(of_that_size, prv_key, aux).serialize()
            )
            assert ssa.verify_(of_that_size, x_Q, signer.sign_(of_that_size, aux))


def test_a_wiped_signer_refuses_rather_than_signing_with_the_zeros() -> None:
    """The lifetime a signer hands its caller, and how it is given back.

    `wipe` is the instruction and the `with` block is how to give it
    without having to remember; both leave a signer that refuses, and
    neither can be undone -- what the signer held it no longer holds.
    """
    prv_key, _ = ssa.gen_keys(0x1234567890ABCDEF)
    msg_hash = reduce_to_hlen(b"a message")

    signer = ssa.Signer(prv_key)
    assert signer.sign_(msg_hash)
    signer.wipe()
    with pytest.raises(BTClibValueError, match="the signer is wiped"):
        signer.sign_(msg_hash)
    # idempotent, as `close` is on the signer contract
    signer.wipe()
    # the scalar is let go of and not only the keypair: an int cannot be
    # overwritten, so dropping the reference is the whole of what `wipe`
    # can do about it -- but leaving it bound would make "cannot be
    # revived" false, this being where the key is held on both arms
    assert not signer._q

    with ssa.Signer(prv_key) as block_signer:
        assert block_signer.sign_(msg_hash)
    with pytest.raises(BTClibValueError, match="the signer is wiped"):
        block_signer.sign_(msg_hash)

    # and the block wipes on the way out of an exception too
    raising = ssa.Signer(prv_key)
    with pytest.raises(ZeroDivisionError), raising:
        _ = 1 / 0
    with pytest.raises(BTClibValueError, match="the signer is wiped"):
        raising.sign_(msg_hash)


def test_a_signer_refuses_what_sign_refuses() -> None:
    """The key and the hash function are read at the constructor.

    A public constructor, so the refusal belongs at it rather than at the
    first signature -- which is the only place a caller could hear it,
    the keypair being built here.
    """
    with pytest.raises(BTClibValueError, match="private key not in 1..n-1"):
        ssa.Signer(0)
    with pytest.raises(BTClibValueError, match="private key not in 1..n-1"):
        ssa.Signer(secp256k1.n)
    with pytest.raises(BTClibTypeError):
        ssa.Signer(0x1234567890ABCDEF, secp256k1, "not a hash function")  # type: ignore[arg-type]


_ARMS = [
    pytest.param(True, marks=needs_bindings, id="bindings"),
    pytest.param(False, id="python"),
]


@pytest.mark.parametrize("bindings", _ARMS)
def test_the_check_changes_no_signature(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`verify` is a truth: what it turns on reads, and writes nothing.

    Every spelling answers the same octets, which is what puts the flag
    in `_TRUTHS` rather than beside the kinds, and what makes declining
    the check a decision about time and not about which signature a key
    and a message make. `aux` is fixed because BIP340 draws it at random
    otherwise, and two signatures of one message would differ for a
    reason that has nothing to do with the flag.
    """
    if not bindings:
        no_bindings(monkeypatch)

    prv_key = 0x1234567890ABCDEF
    msg = b"a message signed twice"
    aux = bytes(32)

    checked = ssa.sign(msg, prv_key, aux)
    assert checked == ssa.sign(msg, prv_key, aux, verify=False)
    assert checked == ssa.sign_(reduce_to_hlen(msg, hf), prv_key, aux)
    assert checked == ssa.sign_(reduce_to_hlen(msg, hf), prv_key, aux, verify=False)

    # the commitment path answers the same pair either way, and its check
    # is of the signature and not of the receipt
    committed = ssa.sign(msg, prv_key, aux, commit=b"a commitment")
    assert committed == ssa.sign(
        msg, prv_key, aux, commit=b"a commitment", verify=False
    )


@pytest.mark.parametrize("bindings", _ARMS)
def test_a_signer_answers_what_the_free_function_answers(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The flag reaches the call it was exposed for.

    A `Signer` holds the keypair, so the signature is the cheap part and
    the check is not -- which is why this is the signing call a caller
    would most plausibly decline. Both of its spellings take the keyword
    and both answer the free function's signature.
    """
    if not bindings:
        no_bindings(monkeypatch)

    prv_key = 0x1234567890ABCDEF
    msg = b"a message signed by a signer"
    aux = bytes(32)
    expected = ssa.sign(msg, prv_key, aux).serialize()

    with ssa.Signer(prv_key) as signer:
        assert signer.sign(msg, aux) == expected
        assert signer.sign(msg, aux, verify=False) == expected
        assert signer.sign_(reduce_to_hlen(msg, hf), aux) == expected
        assert signer.sign_(reduce_to_hlen(msg, hf), aux, verify=False) == expected


def test_the_python_arm_refuses_a_signature_that_does_not_verify() -> None:
    """The check is wired to the raise, not merely written near it.

    No input reaches it -- a fresh signature verifies under the key that
    made it -- so what says the branch is live is a substituted
    verification, as `tests/ecc/dsa_test.py` does for the same reason.
    Read in both directions: with the check refusing everything the
    signature is not answered with, and with `verify=False` the
    substitution is never reached at all, which is what says the flag is
    honoured rather than ignored on a path whose output does not change.

    What comes back is the signing sentence and not the check's own
    words, which are a verifier's; the check's are kept as the cause, so
    what the verification saw is still in hand.
    """

    def refuse(*_: Any, **__: Any) -> None:
        raise BTClibRuntimeError("signature verification failed")

    prv_key = 0x1234567890ABCDEF
    msg = b"a message whose check is made to fail"
    aux = bytes(32)

    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(ssa, "_libsecp256k1_serves", lambda *_: False)
        unchecked = ssa.sign(msg, prv_key, aux, verify=False)
        patched.setattr(ssa, "_assert_as_valid_", refuse)
        with pytest.raises(BTClibRuntimeError, match="does not verify") as plain:
            ssa.sign(msg, prv_key, aux)
        assert str(plain.value.__cause__) == "signature verification failed"
        with pytest.raises(BTClibRuntimeError, match="does not verify") as committed:
            ssa.sign(msg, prv_key, aux, commit=b"a commitment")
        assert str(committed.value.__cause__) == "signature verification failed"
        # and the flag is read: the same substitution is not reached,
        # and the signature that comes back is the one the checked call
        # would have answered had its check not been made to fail
        assert ssa.sign(msg, prv_key, aux, verify=False) == unchecked


@needs_bindings
def test_the_two_arms_answer_the_same_signature_and_the_same_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One contract, two implementations, checked or not.

    A fallback answering differently from the arm it stands in for would
    be two libraries wearing one name, and how it refuses is half of
    what it answers: the signatures, the exception type and the message
    are all held equal here, as `tests/ecc/dsa_test.py`'s namesake holds
    them. `verify` adds no failure an argument can reach -- BIP340's
    check is a bare verification under a point the keypair already
    holds, so there is no key to hand in and no second reason to fail --
    so each arm is driven into its real failing branch instead.

    The fault is installed in a different place per arm because that is
    where each arm's check lives: the bindings' own verification for the
    delegated one, and for the Python one a signature that is not the
    one the nonce and the key make, which its own `_assert_as_valid_`
    then refuses. Nothing about either refusal is fabricated, so the two
    rows are the words each implementation really says.

    Twice on the Python arm, because its check refuses in two
    hierarchies: a signature that simply does not verify, and one whose
    K lands on the point at infinity -- what a nonce zeroed after its
    point was computed leaves behind -- which has no y to answer with
    and comes back as a `ValueError`. Both have to arrive as the one
    sentence, and the second is the one a clause naming only
    `BTClibRuntimeError` lets through.

    Marked for the bindings because the delegated row is what the Python
    one is compared against; without them both rows would be the Python
    arm.
    """
    prv_key = 0x1234567890ABCDEF
    msg = b"a message both arms sign"
    aux = bytes(32)

    def signatures() -> tuple[Any, ...]:
        return (
            ssa.sign(msg, prv_key, aux),
            ssa.sign(msg, prv_key, aux, verify=False),
            ssa.sign(msg, prv_key, aux, commit=b"a commitment"),
        )

    def refusal() -> tuple[Any, ...]:
        with pytest.raises(BTClibRuntimeError) as refused:
            ssa.sign(msg, prv_key, aux)
        return type(refused.value), str(refused.value)

    delegated = signatures()
    with monkeypatch.context() as faulted:
        # their `_abort_unless_verified` reads this and raises, so the
        # words this row contributes are the bindings' own
        faulted.setattr(libsecp256k1_ssa, "_verify_", lambda *_, **__: False)
        delegated_refusal = refusal()

    signed = ssa._sign_
    with monkeypatch.context() as python:
        python.setattr(ssa, "_libsecp256k1_serves", lambda *_: False)
        assert signatures() == delegated

        def a_signature_that_cannot_verify(*args: Any) -> ssa.Sig:
            signature = signed(*args)
            return ssa.Sig(signature.r, signature.s + 1, signature.ec)

        python.setattr(ssa, "_sign_", a_signature_that_cannot_verify)
        assert refusal() == delegated_refusal

        def a_signature_whose_point_is_at_infinity(
            c: int, q: int, k: int, x_K: int, ec: Curve
        ) -> ssa.Sig:
            # s = c*q is what a zeroed nonce leaves, and sG - cQ is then
            # the point at infinity: the same check, refusing in the
            # other hierarchy
            return ssa.Sig(x_K, c * q % ec.n, ec)

        python.setattr(ssa, "_sign_", a_signature_whose_point_is_at_infinity)
        assert refusal() == delegated_refusal


@needs_bindings
def test_a_signer_refuses_under_the_same_sentence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other crossing into the bindings, translated as the first is.

    `Signer.sign_` calls them rather than going through `sign_`, so the
    two calls are two chances for a bare RuntimeError to reach a caller
    who wrote the hierarchy this package publishes. Driven into the
    bindings' own failing branch the way the test above drives it.
    """
    monkeypatch.setattr(libsecp256k1_ssa, "_verify_", lambda *_, **__: False)

    with (
        ssa.Signer(0x1234567890ABCDEF) as signer,
        pytest.raises(BTClibRuntimeError, match="does not verify"),
    ):
        signer.sign(b"a message whose check is made to fail")
