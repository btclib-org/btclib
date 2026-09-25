# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.der` module."""

import pytest

from btclib._libsecp256k1 import dsa as libsecp256k1_dsa
from btclib.curves import secp256k1
from btclib.curves.curve import CURVES
from btclib.ecc import dsa
from btclib.ecc.dsa import Sig
from btclib.exceptions import BTClibValueError
from tests import load, needs_bindings

ec = secp256k1


def test_der_size() -> None:
    """Round-trip DER serializations of every size from 8 to 72 bytes."""
    sig8 = 1, 1
    sig72 = ec.n - 2, ec.n - 1
    sig71 = 2**255 - 4, ec.n - 1
    sig70 = 2**255 - 4, 2**255 - 1
    sig70b = 2**255 - 4, 2**248 - 1
    sig69 = 2**255 - 4, 2**247 - 1
    sig68 = 2**247 - 1, 2**247 - 1
    sigs = [sig8, sig72, sig71, sig70, sig70b, sig69, sig68]
    lengths = [8, 72, 71, 70, 70, 69, 68]

    for length, (r, s) in zip(lengths, sigs, strict=True):
        sig = Sig(r, s)
        assert r == sig.r
        assert s == sig.s
        assert ec == sig.ec
        sig_bin = sig.serialize()
        assert len(sig_bin) == length
        assert sig == Sig.parse(sig_bin)


def _der_length(n: int) -> bytes:
    """Return the X.690 8.1.3 length octets for a body of n octets.

    A second, redundant reading of the rule `dsa._der_length` writes,
    used only to check that `Sig.serialize`'s own length octets are
    internally consistent (short form below 128, `0x80 | k` at and
    above it). It shares its author with `dsa._der_length`, so it is not
    what stands as the independent oracle for whether that rule is
    itself correct DER -- `test_der_matches_a_vendored_der_oracle`
    below, held to bytes `cryptography` produced outside this tree, is
    (issue 2130).
    """
    if n < 0x80:
        return bytes([n])
    length_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def _read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    """Return (length, offset past it), read by X.690 8.1.3 alone."""
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    size = first & 0x7F
    return int.from_bytes(
        data[offset + 1 : offset + 1 + size], "big"
    ), offset + 1 + size


def _independent_parse(der: bytes) -> tuple[int, int]:
    """Return (r, s), read by X.690 alone rather than as CompactSize.

    `Sig.parse` reads a length as CompactSize, which is X.690 only below
    0x80, so it cannot read back what `Sig.serialize` writes at and above
    it (issue 2130). This re-derives every length octet with
    `_der_length` and refuses trailing data instead -- a self-consistency
    check on `serialize`'s output, not a check that the rule it and
    `_der_length` share is the right one.
    """
    assert der[0] == 0x30
    seq_len, offset = _read_der_length(der, 1)
    assert der[1:offset] == _der_length(seq_len)
    assert offset + seq_len == len(der)

    values = []
    for _ in range(2):
        assert der[offset] == 0x02
        length, value_offset = _read_der_length(der, offset + 1)
        assert der[offset + 1 : value_offset] == _der_length(length)
        values.append(int.from_bytes(der[value_offset : value_offset + length], "big"))
        offset = value_offset + length
    assert offset == len(der)
    r, s = values
    return r, s


def test_der_sequence_length_is_der_for_every_curve() -> None:
    """Every catalogued curve's sequence length is X.690, not CompactSize.

    secp256k1 and every other bitcoin curve stay under the 128-octet
    threshold where the two agree; `bpp512r1`, `nistp521` and
    `secp521r1` do not (issue 2130). A self-consistency check across the
    whole catalogue, not the oracle: see
    `test_der_matches_a_vendored_der_oracle` for that.
    """
    for name, curve in sorted(CURVES.items()):
        sig = dsa.sign(b"msg", 0x1234567890ABCDEF, ec=curve)
        raw = sig.serialize()
        assert _independent_parse(raw) == (sig.r, sig.s), name


def test_der_matches_a_vendored_der_oracle() -> None:
    """`serialize` matches bytes an outside DER encoder wrote, per curve.

    Outside means written by nobody in this change: `_der_length` above
    and `dsa._der_length` share an author and an afternoon, so a decoder
    or a copy of the encoder written beside the fix could share a
    misreading of X.690 and prove nothing (issue 2130). This asserts
    against `tests/ecc/_data/der_length_vectors.json` alone --
    `cryptography`'s `encode_dss_signature`, run once outside this tree
    and vendored rather than imported live, since `cryptography` is not
    a dependency any group the suite installs resolves. See
    `tests/_data/README.md` for the producing command.
    """
    for vector in load("ecc", "_data", "der_length_vectors.json"):
        curve = CURVES[vector["curve"]]
        r, s = int(vector["r"], 16), int(vector["s"], 16)
        check_validity = vector["check_validity"]
        sig = Sig(r, s, curve, check_validity=check_validity)
        raw = sig.serialize(check_validity=check_validity)
        assert raw == bytes.fromhex(vector["der"]), vector["curve"]


def test_der_sequence_length_refuses_the_long_form() -> None:
    """BIP66 fixes the length at one octet; `Sig.parse` still refuses more.

    `81 44` is the DER long form of 0x44 = 68, an encoding no shorter
    DER ever needs and no secp256k1 signature reaches. Core's
    `IsValidSignatureEncoding` accepts only the short form, and
    accepting both would be new malleability (issue 2130).
    """
    sig = Sig(2**247 - 1, 2**247 - 1)
    good = sig.serialize()
    assert good[1] < 0x80
    long_form = good[:1] + bytes([0x81, good[1]]) + good[2:]
    err_msg = "invalid DER length"
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig.parse(long_form)


def test_der_deserialize() -> None:
    """Refuse each malformed DER field with its own message."""
    err_msg = "invalid hex string: non-hexadecimal number found "
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig.parse("not a sig")

    sig = Sig(2**255 - 4, 2**247 - 1)
    sig_bin = sig.serialize()
    r_size = sig_bin[3]

    bad_sig_bin = b"\x31" + sig_bin[1:]
    err_msg = "invalid compound header: "
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig.parse(bad_sig_bin)

    # a length overrunning the buffer is the DER being malformed, so it
    # is a BTClibValueError: var_bytes calls it a BTClibRuntimeError, and
    # a caller filtering parse failures on BTClibValueError -- as
    # psbt_in._assert_valid_partial_sigs does -- would not have caught it
    bad_sig_bin = sig_bin[:1] + b"\x41" + sig_bin[2:]
    err_msg = "invalid DER length: not enough binary data"
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig.parse(bad_sig_bin)

    # r and s scalars
    for offset in (4, 6 + r_size):
        bad_sig_bin = sig_bin[: offset - 2] + b"\x00" + sig_bin[offset - 1 :]
        err_msg = "invalid value header: "
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

        bad_sig_bin = sig_bin[: offset - 1] + b"\x00" + sig_bin[offset:]
        err_msg = "invalid DER length: zero size"
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

        bad_sig_bin = sig_bin[: offset - 1] + b"\x80" + sig_bin[offset:]
        err_msg = "invalid DER length: not enough binary data"
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

        bad_sig_bin = sig_bin[:offset] + b"\x80" + sig_bin[offset + 1 :]
        err_msg = "invalid negative scalar"
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

        # 0x80 itself is not the only negative first byte: `>= 0x80`
        # weakened to `== 0x80` would miss every byte above it
        bad_sig_bin = sig_bin[:offset] + b"\xff" + sig_bin[offset + 1 :]
        err_msg = "invalid negative scalar"
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

        bad_sig_bin = sig_bin[:offset] + b"\x00\x7f" + sig_bin[offset + 2 :]
        err_msg = "invalid 'highest bit set' padding"
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse(bad_sig_bin)

    data_size = sig_bin[1]
    malleated_size = (data_size + 1).to_bytes(1, byteorder="big", signed=False)
    bad_sig_bin = sig_bin[:1] + malleated_size + sig_bin[2:] + b"\x01"
    err_msg = "invalid DER sequence length"
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig.parse(bad_sig_bin)


def test_der_one_byte_scalar() -> None:
    """Guard against a one-byte DER scalar indexing past its buffer.

    3006020100020100 is r = s = 0, each written in the one byte that is
    minimal DER for zero. A 'highest bit set' test that reads the second
    byte of a value having none lets IndexError escape Sig.parse
    whatever the flags -- strict, the last of its three conditions, does
    not spare it -- and IndexError is not what a caller filtering parse
    failures catches.
    """
    for strict in (True, False):
        err_msg = "scalar r not in 1..n-1: "
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig.parse("3006020100020100", strict=strict)

        # check_validity=False asks for the numbers those bytes spell,
        # whatever they are, and what they spell is zero
        sig = Sig.parse("3006020100020100", check_validity=False, strict=strict)
        assert (sig.r, sig.s) == (0, 0)

    # a single byte with the highest bit set is still a negative scalar
    err_msg = "invalid negative scalar"
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig.parse("3006020180020180")
    sig = Sig.parse("3006020180020180", check_validity=False, strict=False)
    assert (sig.r, sig.s) == (0x80, 0x80)


def test_der_serialize() -> None:
    """Refuse out-of-range scalars and an r that fits no x-coordinate."""
    r = 2**247 - 1
    s = 2**247 - 1
    Sig(r, s)

    err_msg = "scalar r not in 1..n-1: "
    for bad_r in (0, ec.n):
        _ = Sig(bad_r, s, check_validity=False)
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig(bad_r, s)

    err_msg = "scalar s not in 1..n-1: "
    for bad_s in (0, ec.n):
        _ = Sig(r, bad_s, check_validity=False)
        with pytest.raises(BTClibValueError, match=err_msg):
            Sig(r, bad_s)

    err_msg = r"r is not \(congruent to\) a valid x-coordinate: "
    with pytest.raises(BTClibValueError, match=err_msg):
        Sig(5, s)


def _element(value: bytes) -> bytes:
    """Return the [0x02][size][value] element DER writes a scalar as."""
    return b"\x02" + len(value).to_bytes(1, "big") + value


def _sequence(*elements: bytes) -> bytes:
    """Return the [0x30][size] sequence of already-encoded elements."""
    body = b"".join(elements)
    return b"\x30" + len(body).to_bytes(1, "big") + body


def _malformed(good: bytes) -> list[tuple[str, bytes]]:
    """One malformed DER per rule the strict parser above enforces.

    Every scalar rule twice, on r and on s. The two are one code path --
    `_deserialize_scalar` is called for each -- so what the second half
    of each pair guards is the order of those two calls rather than the
    rule itself: an s reached through an r that had to parse first.

    Assembled from the elements rather than by patching `good` in place,
    so that a case fires the rule it is named for: an s whose size byte
    is edited where it lies leaves the sequence length disagreeing, and
    what refuses it is that disagreement and not the scalar rule.
    """
    r_value = good[4 : 4 + good[3]]
    s_value = good[4 + good[3] + 2 :]
    r, s = _element(r_value), _element(s_value)
    data_size = good[1]
    return [
        ("compound header", b"\x31" + good[1:]),
        ("sequence length overruns", good[:1] + b"\x41" + good[2:]),
        (
            "sequence length short",
            good[:1] + (data_size + 1).to_bytes(1, "big") + good[2:] + b"\x01",
        ),
        ("r is no integer element", _sequence(b"\x03" + r[1:], s)),
        ("r of zero size", _sequence(b"\x02\x00", s)),
        ("r padded twice", _sequence(_element(b"\x00\x00" + r_value[1:]), s)),
        ("s is no integer element", _sequence(r, b"\x03" + s[1:])),
        ("s of zero size", _sequence(r, b"\x02\x00")),
        ("s padded twice", _sequence(r, _element(b"\x00\x00" + s_value[1:]))),
        ("empty", b""),
        ("truncated", good[:-1]),
        ("trailing octet", good + b"\x00"),
    ]


@needs_bindings
def test_der_agrees_with_libsecp256k1_except_where_it_is_stricter() -> None:
    """libsecp256k1 as the oracle on a DER encoding, and where it is not one.

    Nothing here asks the bindings whether an encoding is well formed,
    the strict DER of BIP66 being written in python and validated against
    the BIP's own rules alone -- which is the pairing that bites others:
    https://github.com/btclib-org/btclib/issues/680 is embit parsing
    high-s DER differently per backend, and
    https://github.com/btclib-org/btclib/issues/667 is electrum-ecc
    normalizing s inside a documented pure conversion. So the corpus
    above is put to `dsa.signature_verify` as well, which is
    secp256k1_ecdsa_signature_parse_der and a verdict.

    The two agree on every rule but one, and the exception is not a
    disagreement about DER: `secp256k1_der_parse_integer` treats an
    integer whose high bit is set as an *overflow* rather than as a
    malformed encoding, zeroes the scalar and reports success, so the
    signature it hands back is r = 0 -- which no verification accepts.
    btclib refuses the encoding instead, in BIP66's words, and this is
    what says so out loud rather than leaving the difference to be found
    by a caller who used `to_compact` as a validator.
    """
    sig = Sig(2**255 - 4, 2**247 - 1)
    good = sig.serialize()
    compact = sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")

    # the well-formed encoding first, both ways round
    assert libsecp256k1_dsa.signature_verify(good)
    assert libsecp256k1_dsa.to_der(compact) == good
    assert libsecp256k1_dsa.to_compact(good) == compact

    for name, bad in _malformed(good):
        with pytest.raises(BTClibValueError):
            Sig.parse(bad, check_validity=False)
        assert not libsecp256k1_dsa.signature_verify(bad), name

    # and the one rule libsecp256k1 answers otherwise, on each scalar:
    # a high bit set with no 0x00 in front of it is a negative integer,
    # which BIP66 refuses and `secp256k1_der_parse_integer` reports as an
    # overflow -- zeroing the scalar and answering success
    r_value = good[4 : 4 + good[3]]
    s_value = good[4 + good[3] + 2 :]
    r, s = _element(r_value), _element(s_value)
    for name, bad, zeroed in (
        ("r", _sequence(_element(b"\x80" + r_value[1:]), s), slice(0, 32)),
        ("s", _sequence(r, _element(b"\x80" + s_value[1:])), slice(32, 64)),
    ):
        with pytest.raises(BTClibValueError, match="invalid negative scalar"):
            Sig.parse(bad, check_validity=False)
        assert libsecp256k1_dsa.signature_verify(bad), name
        # what it read is the zero scalar, not the value those octets spell
        assert libsecp256k1_dsa.to_compact(bad)[zeroed] == bytes(32), name


@needs_bindings
def test_der_low_s_agrees_with_libsecp256k1() -> None:
    """The low-s verdict and the normalization, against their C twins.

    `lower_s` is one comparison against n // 2 here, and libsecp256k1 has
    the same two answers as `is_low_s` and `normalize`. Nothing delegates
    to them -- an order of magnitude under `is_low_s`, a comparison
    against a parse and a call -- so this is where the two are held
    together instead.
    """
    for s in (1, ec.n // 2, ec.n // 2 + 1, ec.n - 1):
        sig = Sig(2**255 - 4, s)
        der = sig.serialize()
        assert libsecp256k1_dsa.is_low_s(der) == (s <= ec.n // 2)

        normalized = Sig.parse(libsecp256k1_dsa.normalize(der))
        assert normalized.r == sig.r
        assert normalized.s == min(s, ec.n - s)
