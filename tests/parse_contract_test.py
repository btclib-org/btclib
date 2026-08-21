# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the parse contract every `parse` in btclib owes its caller.

One file rather than a case per module, because the rule is one and
`btclib/utils.py` states it: a field is as long as its encoding says, a
complete octet string is one whole object, and a caller's stream is the
caller's. What the tests hold every parser to is that none of the three
depends on `check_validity`, which is an opinion about what the bytes
mean and not about where they end.

The inventory at the top is what those tests run over, and the last test
is what makes it a promise rather than a list: it walks the package for
every public class carrying a `parse` and fails unless each one is either
in the inventory or in a table of exclusions naming its reason. A parser
added to btclib and forgotten here would otherwise be held to nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from btclib.bip32 import BIP32KeyData, BIP32KeyOrigin
from btclib.block import Block, BlockHeader
from btclib.ecc import bms, ssa
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.p2p import (
    Addr,
    GetBlocks,
    GetData,
    GetHeaders,
    Headers,
    Inv,
    Inventory,
    InventoryType,
    Message,
    NetworkAddress,
    NotFound,
    Ping,
    Pong,
    TimestampedNetworkAddress,
    Verack,
)
from btclib.psbt import Psbt, PsbtIn, PsbtOut
from btclib.script import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests import public_classes_with

# what btclib promises to raise, and the whole of it: a truncated buffer
# has to be refused as one of these three, and never as an IndexError or a
# struct error from underneath the library
_CONTRACT_EXCEPTIONS = (BTClibValueError, BTClibRuntimeError, BTClibTypeError)

_TX_ID = "01" * 32
_XPRV = (
    "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFo"
    "CMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"
)


def _block_1() -> bytes:
    """Return the consensus bytes of the block after genesis."""
    filename = Path(__file__).parent / "block" / "_data" / "block_1.bin"
    with filename.open("rb") as file_:
        return file_.read()


def _tx() -> Tx:
    return Tx(
        1,
        0x12345678,
        [TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF)],
        [TxOut(1, b"")],
    )


def _addr() -> Addr:
    """Return an `addr` of one entry, which is the wiki's captured one."""
    address = NetworkAddress(1, "10.0.0.1", 8333)
    return Addr([TimestampedNetworkAddress(0x4D1015E2, address)])


def _inventory() -> Inventory:
    """Return one inventory entry, announcing the block after genesis."""
    return Inventory(InventoryType.MSG_BLOCK, BlockHeader.parse(_block_1()[:80]).hash)


def _psbt() -> Psbt:
    """Return the psbt of the transaction above, maps and all."""
    return Psbt.from_tx(_tx())


# every object with a fixed-width field in it or a length of its own,
# with the class whose `parse` reads it back: (name, class, serialization).
# The class and not the bound method, so that the inventory says which
# parsers are covered -- see the completeness test at the end of this file
_CASES: list[tuple[str, type[Any], bytes]] = [
    ("outpoint", OutPoint, OutPoint(_TX_ID, 0).serialize()),
    ("tx_in", TxIn, TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF).serialize()),
    ("tx_out", TxOut, TxOut(1, b"").serialize()),
    ("tx", Tx, _tx().serialize(include_witness=True)),
    ("block_header", BlockHeader, _block_1()[:80]),
    ("block", Block, _block_1()),
    ("bip32_key", BIP32KeyData, BIP32KeyData.b58decode(_XPRV).serialize()),
    ("ssa_sig", ssa.Sig, ssa.sign(b"parse contract", 1).serialize()),
    ("bms_sig", bms.Sig, bms.sign(b"parse contract", 1).serialize()),
    ("witness", Witness, Witness([b"\x51", b"\x52\x53"]).serialize()),
    ("psbt", Psbt, _psbt().serialize()),
    ("psbt_in", PsbtIn, PsbtIn(redeem_script=b"\x51").serialize()),
    ("psbt_out", PsbtOut, PsbtOut(redeem_script=b"\x51").serialize()),
    ("p2p_message", Message, Message("f9beb4d9", "ping", bytes(8)).serialize()),
    (
        "p2p_network_address",
        NetworkAddress,
        NetworkAddress(1, "10.0.0.1", 8333).serialize(),
    ),
    (
        "p2p_timestamped_address",
        TimestampedNetworkAddress,
        _addr().addresses[0].serialize(),
    ),
    ("p2p_addr", Addr, _addr().serialize()),
    ("p2p_verack", Verack, Verack().serialize()),
    ("p2p_ping", Ping, Ping(1).serialize()),
    ("p2p_pong", Pong, Pong(1).serialize()),
    ("p2p_inventory", Inventory, _inventory().serialize()),
    ("p2p_inv", Inv, Inv([_inventory()]).serialize()),
    ("p2p_getdata", GetData, GetData([_inventory()]).serialize()),
    ("p2p_notfound", NotFound, NotFound([_inventory()]).serialize()),
    (
        "p2p_getblocks",
        GetBlocks,
        GetBlocks(70016, [_inventory().hash], _inventory().hash).serialize(),
    ),
    (
        "p2p_getheaders",
        GetHeaders,
        GetHeaders(70016, [_inventory().hash], _inventory().hash).serialize(),
    ),
    (
        "p2p_headers",
        Headers,
        Headers([BlockHeader.parse(_block_1()[:80])]).serialize(),
    ),
]

_IDS = [case[0] for case in _CASES]
_PARSE_AND_BYTES = [(case[1].parse, case[2]) for case in _CASES]


@pytest.mark.parametrize("parse, serialization", _PARSE_AND_BYTES, ids=_IDS)
@pytest.mark.parametrize("check_validity", [True, False], ids=["checked", "unchecked"])
def test_no_prefix_of_an_encoding_is_an_object(
    parse: Callable[..., Any], serialization: bytes, *, check_validity: bool
) -> None:
    """Every truncation is refused, at every offset and either way.

    `BytesIO.read` answers with what is left rather than raising, and
    `int.from_bytes` takes a short answer, so an unchecked parser turns
    each of these prefixes into an object that serializes back longer
    than the buffer it came from: distinct buffers, including malformed
    ones, mapping to one canonical object.
    """
    for size in range(len(serialization)):
        with pytest.raises(_CONTRACT_EXCEPTIONS):
            parse(serialization[:size], check_validity=check_validity)


@pytest.mark.parametrize("parse, serialization", _PARSE_AND_BYTES, ids=_IDS)
@pytest.mark.parametrize("check_validity", [True, False], ids=["checked", "unchecked"])
def test_octets_are_one_whole_object(
    parse: Callable[..., Any], serialization: bytes, *, check_validity: bool
) -> None:
    """Bytes after the object are refused, hex-string included."""
    assert parse(serialization, check_validity=check_validity)

    for trailing in (b"\x00", b"junk"):
        with pytest.raises(BTClibValueError, match="bytes after the"):
            parse(serialization + trailing, check_validity=check_validity)
        with pytest.raises(BTClibValueError, match="bytes after the"):
            parse((serialization + trailing).hex(), check_validity=check_validity)


@pytest.mark.parametrize("parse, serialization", _PARSE_AND_BYTES, ids=_IDS)
def test_a_stream_is_the_callers(
    parse: Callable[..., Any], serialization: bytes
) -> None:
    """A stream may carry more, and is left on the byte after the object.

    This is the half of the contract that makes the other half safe to
    enforce: a transaction is read out of the very stream its block is
    read from, so what follows the object in a stream is not the parser's
    to complain about -- or to consume.
    """
    stream = BytesIO(serialization + b"junk")
    assert parse(stream)
    assert stream.read() == b"junk"


def test_a_truncated_field_names_itself() -> None:
    """The diagnosis is the truncation, not whatever the short read meant.

    Without the length check the missing bytes are reported by whichever
    field they happen to fall in, or not at all: three bytes off a lock
    time read as a lock time three bytes smaller, which is a valid one.
    """
    tx_bytes = _tx().serialize(include_witness=True)
    out_point_bytes = OutPoint(_TX_ID, 0).serialize()

    with pytest.raises(
        BTClibValueError, match="not enough data for the outpoint tx_id"
    ):
        OutPoint.parse(out_point_bytes[:20])
    with pytest.raises(BTClibValueError, match="not enough data for the outpoint vout"):
        OutPoint.parse(out_point_bytes[:34])
    with pytest.raises(
        BTClibValueError, match="not enough data for the transaction version"
    ):
        Tx.parse(tx_bytes[:3])
    with pytest.raises(BTClibValueError, match="not enough data for the lock time"):
        Tx.parse(tx_bytes[:-1])
    with pytest.raises(BTClibValueError, match="not enough data for the sequence"):
        TxIn.parse(TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF).serialize()[:-1])
    with pytest.raises(BTClibValueError, match="not enough data for the output value"):
        TxOut.parse(TxOut(1, b"").serialize()[:4])


def test_a_fixed_size_object_reports_its_own_length() -> None:
    """A buffer that is the object reports the buffer, not a field of it.

    The three fixed-size encodings agree on the message -- and on saying
    it whatever `check_validity` says, which is what a semantic check
    would have gated.
    """
    header_bytes = _block_1()[:80]
    key_bytes = BIP32KeyData.b58decode(_XPRV).serialize()

    err_msg = "invalid decoded length: 70 instead of 80"
    with pytest.raises(BTClibValueError, match=err_msg):
        BlockHeader.parse(header_bytes[:70], check_validity=False)

    err_msg = "invalid decoded length: 70 instead of 78"
    with pytest.raises(BTClibValueError, match=err_msg):
        BIP32KeyData.parse(key_bytes[:70], check_validity=False)


def test_a_truncation_does_not_round_trip() -> None:
    """The property behind the contract, on the case issue 322 reported.

    A transaction one to three bytes short of its lock time used to parse
    into a transaction whose serialization is longer than what was
    parsed: two buffers, one object, and only one of them written back.
    """
    tx = _tx()
    tx_bytes = tx.serialize(include_witness=True)

    for cut in (1, 2, 3):
        with pytest.raises(BTClibValueError, match="not enough data for the lock time"):
            Tx.parse(tx_bytes[:-cut])

    assert Tx.parse(tx_bytes) == tx
    with pytest.raises(BTClibValueError, match="4 bytes after the transaction"):
        Tx.parse(tx_bytes + b"junk")


def test_a_key_origin_is_a_fingerprint_and_then_indexes() -> None:
    """The fingerprint is four octets wide, whatever the origin means.

    Deferred to `check_validity`, a slice of a shorter buffer answered with
    whatever was there and the object serialized back longer than what it
    was parsed from. The remainder was already unconditional:
    `indexes_from_der_path` refuses what is not a whole number of 4-octet
    indexes, whatever `check_validity` says, so this is the other half of
    one boundary.

    Its own test rather than a line in the inventory above, because none of
    the three generic properties applies to a key origin, and that is worth
    saying once: four octets are a valid key origin with an empty path, so
    a prefix of a longer encoding *is* an object; the record carries no
    length and consumes the whole buffer, so nothing can trail it -- four
    junk octets are one more index; and `parse` takes `Octets` rather than
    `BinaryData`, so there is no stream to leave alone.
    """
    for check_validity in (True, False):
        for raw in (b"", b"\x00", b"\x00\x00\x00"):
            err_msg = "not enough data for the master fingerprint"
            with pytest.raises(BTClibValueError, match=err_msg):
                BIP32KeyOrigin.parse(raw, check_validity=check_validity)

    # and what the refusal must not take with it: the shortest key origin
    # there is, and one with a path
    assert BIP32KeyOrigin.parse(b"\xde\xad\xbe\xef").description == "deadbeef"
    key_origin = BIP32KeyOrigin("deadbeef", "m/44h/0h")
    assert BIP32KeyOrigin.parse(key_origin.serialize()) == key_origin


# what a parser of this library is *not* held to, and why. A name here is
# a decision, which is the difference between an exclusion and an
# oversight -- the test below fails on either
_EXCLUDED = {
    "btclib.bip21.Bip21": (
        "a bitcoin: URI is text and not octets: it has no fixed-width"
        " field, nothing can follow it in a stream, and its own grammar"
        " is what tests/bip21_test.py holds it to"
    ),
    "btclib.bip32.key_origin.BIP32KeyOrigin": (
        "a four-octet prefix of it is a valid key origin with an empty"
        " path, and the record has no length of its own, so two of the"
        " three properties are false of it by design; the boundary it does"
        " owe its caller is the test above"
    ),
    "btclib.block.block_filter.BasicBlockFilter": (
        "a Golomb-coded set has no length of its own, only the count of the"
        " values coded in it, so a filter is the whole of the octets it is"
        " given: nothing can trail it -- a further octet is a delta the"
        " count does not admit, which assert_valid refuses -- and there is"
        " no stream left for a caller to read on from. What the three"
        " properties protect is kept by construction all the same: the set"
        " is held as the octets it was parsed from, so a truncated buffer"
        " and a padded one are two objects, each serializing back to the"
        " buffer it came from"
    ),
    "btclib.ecc.borromean.BorromeanSig": (
        "the wire format has no length of its own for the ring structure:"
        " e0 || s... is only as long as the caller's rsizes says it is,"
        " the same reason zkp's secp256k1_borromean_verify takes rsizes as"
        " an argument rather than reading it from the proof. The three"
        " generic properties assume a self-contained encoding, and driving"
        " them with rsizes defaulting to empty would test that default's"
        " artifact rather than a real signature's boundary; the real one is"
        " tests/ecc/borromean_test.py's own"
        " test_borromean_sig_parse_refuses_short_and_trailing_data, driven"
        " with the rsizes an actual pubk_rings carries"
    ),
    "btclib.ecc.dsa.Sig": (
        "the one parser here with a flag in front of the rule, and the flag"
        " is Bitcoin Core's: trailing octets are refused under `strict`"
        " alone, where IsValidSignatureEncoding is called, and refused in a"
        " stream as well -- no caller in this library reads a signature out"
        " of the middle of one. Sig.parse says so where it does it"
    ),
    "btclib.p2p.handshake.Version": (
        "BIP37's relay flag is the last field of a `version` and may not"
        " be on the wire at all, so the hundred-octet payload a pre-BIP37"
        " peer sends is a prefix of the hundred-and-one-octet one a modern"
        " peer sends: a prefix of an encoding *is* an object here, by"
        " construction. What that property protects is kept all the same,"
        " and that is the difference from an oversight -- the two buffers"
        " are two objects, each serializing back to the buffer it came"
        " from, where the property exists to refuse two buffers decoding"
        " to one. `parse` takes `Octets` for the same reason, a stream"
        " being unable to say whether the next octet is the flag or the"
        " next message, so the third property has no stream to be about"
        " either. btclib/p2p/handshake.py states both, and"
        " tests/p2p/handshake_test.py drives what is true instead"
    ),
    "btclib.ecc.ecies.Envelope": (
        "BIE1 writes the ciphertext between fixed offsets with no length in"
        " front of it, so what would trail the envelope is ciphertext and a"
        " truncation of it is a shorter message: the size rule it can be"
        " held to is the minimum one it checks"
    ),
}


def test_every_parser_is_covered_or_named_an_exclusion() -> None:
    """The inventory is a promise only if omission is what fails.

    A parser added to btclib and forgotten here is the failure this
    catches: the tests above would go on passing on the parsers they were
    given, and the new one would be held to nothing.

    `public_classes_with` is the walk, and it is `tests/__init__.py`'s
    because `serialization_boundary_test.py` holds these same parsers to
    a different contract -- where the bytes end is not what type the
    argument is. A private class is skipped there, which is what leaves
    `_BIP32KeyData` out here; its public subclass is in the inventory.
    """
    covered = {f"{cls.__module__}.{cls.__qualname__}" for _, cls, _ in _CASES}
    assert not covered & _EXCLUDED.keys()
    assert public_classes_with("parse") == covered | _EXCLUDED.keys()
