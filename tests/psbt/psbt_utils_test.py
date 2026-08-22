# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.psbt.psbt_utils` module."""

from io import BytesIO

import pytest

from btclib.bip32 import BIP32KeyOrigin
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.psbt.psbt_utils import (
    deserialize_map,
    deserialize_tx,
    parse_taproot_bip32,
    serialize_hd_key_paths,
    serialize_taproot_bip32,
)
from btclib.script import Witness
from btclib.tx import Tx, TxIn, TxOut
from btclib.tx.out_point import OutPoint


def test_invalid_serialize_hd_key_paths() -> None:
    """Refuse a type marker that is not a single byte."""
    with pytest.raises(BTClibValueError, match="invalid type marker length: "):
        serialize_hd_key_paths(b"\x01\x01", [])  # type: ignore[arg-type]


def test_parse_taproot_bip32() -> None:
    """A leaf hash is 32 bytes, not 4 (BIP371)."""
    leaf_hashes = [bytes(range(32)), bytes(range(32, 64))]
    key_origin = BIP32KeyOrigin(b"\xde\xad\xbe\xef", "m/86h/1h/0h/0/0")
    v = b"\x02" + b"".join(leaf_hashes) + key_origin.serialize()

    assert parse_taproot_bip32(v) == (leaf_hashes, key_origin)

    # a 4-byte read would have left 60 bytes of leaf hash to be taken as
    # the master fingerprint and the derivation path
    pub_key = b"\x02" * 32
    dict_ = {pub_key: (leaf_hashes, key_origin)}
    assert serialize_taproot_bip32(b"\x16", dict_)[-len(v) :] == v


def test_parse_taproot_bip32_hostile_count() -> None:
    """A count is bounded by the data, not trusted (issue #133)."""
    # 0xfe0000_0400 is a count of 262144: without the bound, five bytes
    # cost a 262144-element list, and nine bytes never terminate
    for v in (b"\xfe\x00\x00\x04\x00", b"\xfe\x00\x00\x10\x00"):
        with pytest.raises(BTClibValueError, match="invalid number of leaf hashes: "):
            parse_taproot_bip32(v)

    with pytest.raises(BTClibValueError, match="var_int too big: "):
        parse_taproot_bip32(b"\xff" + b"\xff" * 8)

    # one leaf hash announced, one byte short of it
    with pytest.raises(BTClibValueError, match="invalid number of leaf hashes: "):
        parse_taproot_bip32(b"\x01" + b"\x00" * 31 + b"\xde\xad\xbe\xef")


def test_deserialize_map_short_read() -> None:
    """An announced size is bounded by the data, not taken on trust.

    BytesIO.read hands back whatever is left rather than what was asked
    for, so an unchecked read deserializes every buffer below to the very
    same map -- {b"A": b"B"} -- which serializes back to only one of them.
    """
    assert deserialize_map(b"\x01A\x01B\x00") == {b"A": b"B"}

    err_msg = "not enough data for the psbt map value: "
    for announced_size in (b"\x02", b"\x05", b"\x09"):
        with pytest.raises(BTClibValueError, match=err_msg):
            deserialize_map(b"\x01A" + announced_size + b"B")

    err_msg = "not enough data for the psbt map key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        deserialize_map(b"\x05AB")


def test_deserialize_map_reads_one_map() -> None:
    """The separator is consumed and nothing beyond it is.

    A psbt is a sequence of maps with no count in front of it, so one
    stream threaded through is the only thing that reads them in order:
    each call has to leave the next one where the next map starts.
    """
    stream = BytesIO(b"\x01A\x01B\x00\x01C\x01D\x00 the psbt ends here")
    assert deserialize_map(stream) == {b"A": b"B"}
    assert deserialize_map(stream) == {b"C": b"D"}
    assert stream.read() == b" the psbt ends here"


def test_deserialize_map_unterminated() -> None:
    """Running out of buffer is not the 0x00 that ends a map.

    Reading the separator without checking that there is one to read
    answers a truncated psbt with an IndexError.
    """
    err_msg = "malformed psbt: unterminated map"
    with pytest.raises(BTClibValueError, match=err_msg):
        deserialize_map(b"\x01A\x01B")


def test_deserialize_tx_reads_include_witness_for_its_truth() -> None:
    """`True` accepts either encoding, `False` demands the round trip.

    Two values and two behaviours, which is what issue #1190 settled:
    the flag is read as a truth, `not include_witness` being false for
    `True` alone, so `True` is the one that does not ask for the round
    trip and `False` is the one that refuses a witness serialization.
    `None` used to be declared here too, documented as "either encoding"
    and doing what `False` does, and is now a `BTClibTypeError` like any
    other non-bool.

    Asserted rather than described, and asserted on octets that tell the
    two encodings apart: a legacy serialization is accepted by every
    value of the flag, so a test that fed only one could not have seen
    which arm ran.
    """
    tx = Tx(
        1,
        0,
        [TxIn(OutPoint(b"\x01" * 32, 0), script_witness=Witness([b"\x01"]))],
        [TxOut(1, "")],
    )
    witness = tx.serialize(include_witness=True, check_validity=False)
    legacy = tx.serialize(include_witness=False, check_validity=False)
    assert witness != legacy
    # the same transaction with the witness dropped, which is what the
    # legacy octets parse to whatever the flag says
    stripped = Tx.parse(legacy, check_validity=False)

    # True: the round trip is not asked for, so either encoding is read
    assert deserialize_tx(b"\x00", witness, "tx", True) == tx
    assert deserialize_tx(b"\x00", legacy, "tx", True) == stripped

    # False: the round trip is the check, and the witness form fails it
    assert deserialize_tx(b"\x00", legacy, "tx", False) == stripped
    with pytest.raises(BTClibValueError, match="wrong tx serialization format"):
        deserialize_tx(b"\x00", witness, "tx", False)

    # None is no longer a third spelling of False; it is a wrong type
    with pytest.raises(BTClibTypeError):
        deserialize_tx(b"\x00", legacy, "tx", None)  # type: ignore[arg-type]
