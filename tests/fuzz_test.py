# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every parser, on input nobody wrote down.

The rest of the suite is fixed vectors: exactly what conformance needs,
and blind to the malformed bytes that never make it into a
specification's test section. This file is the converse. It does not
assert that a parser accepts the right things -- the vectors do that --
but that it *fails the way the library says it fails*, whatever it is
handed.

Issues #133, #135 and #138 were all one bug: a parser answering hostile
input with IndexError, or OverflowError, or a silent short read, where
the caller was catching BTClibValueError to reject it. A fuzzer finds
that class in seconds, which is the argument for keeping this file
green rather than for having written it once.
"""

import contextlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from btclib import b32, b58, base58, bech32, bip322, descriptors, var_bytes, var_int
from btclib.bip32.bip32 import BIP32KeyData
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.block.block import Block
from btclib.block.block_header import BlockHeader
from btclib.curves.sec_point import point_from_octets
from btclib.descriptors import miniscript
from btclib.ecc import bms, dsa, ecies, ssa
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.p2p.address import Addr, NetworkAddress, TimestampedNetworkAddress
from btclib.p2p.addrv2 import AddrV2, NetworkAddressV2, SendAddrV2
from btclib.p2p.data import BlockPayload, TxPayload
from btclib.p2p.handshake import Verack, Version
from btclib.p2p.inventory import (
    GetBlocks,
    GetData,
    GetHeaders,
    Headers,
    Inv,
    Inventory,
    InventoryType,
    NotFound,
)
from btclib.p2p.keepalive import Ping, Pong
from btclib.p2p.message import Message
from btclib.psbt import psbt_utils
from btclib.psbt.psbt import Psbt
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.script import script, sig_hash, taproot
from btclib.script.engine import verify_input, verify_transaction
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut

# What a btclib parser is allowed to raise. Anything else -- an
# IndexError off a short slice, an OverflowError off an unchecked size,
# a KeyError, a UnicodeDecodeError -- leaves the contract that
# btclib/exceptions.py documents, and reaches a caller who wrote
# `except BTClibValueError` to reject bad input and has no reason to
# expect anything else
CONTRACT = (BTClibValueError, BTClibTypeError, BTClibRuntimeError)

# Bounded because these are parsers, not benchmarks: what a length field
# does with the bytes behind it is decided in the first few of them, and
# an input long enough to be interesting to a parser is one this
# strategy cannot stumble on anyway. The mutation tests below are what
# reaches past the outermost check
MAX_INPUT = 512

BINARY_PARSERS: dict[str, Callable[[bytes], Any]] = {
    "var_int.parse": var_int.parse,
    "var_bytes.parse": var_bytes.parse,
    "script.parse": script.parse,
    "taproot.parse": taproot.parse,
    "Witness.parse": Witness.parse,
    "OutPoint.parse": OutPoint.parse,
    "TxIn.parse": TxIn.parse,
    "TxOut.parse": TxOut.parse,
    "Tx.parse": Tx.parse,
    "BlockHeader.parse": BlockHeader.parse,
    "Block.parse": Block.parse,
    "Psbt.parse": Psbt.parse,
    "PsbtIn.parse": PsbtIn.parse,
    "PsbtOut.parse": PsbtOut.parse,
    "psbt_utils.deserialize_map": psbt_utils.deserialize_map,
    "psbt_utils.parse_leaf_script": psbt_utils.parse_leaf_script,
    "psbt_utils.parse_taproot_tree": psbt_utils.parse_taproot_tree,
    "psbt_utils.parse_taproot_bip32": psbt_utils.parse_taproot_bip32,
    "Message.parse": Message.parse,
    "NetworkAddress.parse": NetworkAddress.parse,
    "TimestampedNetworkAddress.parse": TimestampedNetworkAddress.parse,
    "Addr.parse": Addr.parse,
    "NetworkAddressV2.parse": NetworkAddressV2.parse,
    "AddrV2.parse": AddrV2.parse,
    "SendAddrV2.parse": SendAddrV2.parse,
    "Version.parse": Version.parse,
    "Verack.parse": Verack.parse,
    "Ping.parse": Ping.parse,
    "Pong.parse": Pong.parse,
    "Inventory.parse": Inventory.parse,
    "Inv.parse": Inv.parse,
    "GetData.parse": GetData.parse,
    "NotFound.parse": NotFound.parse,
    "GetBlocks.parse": GetBlocks.parse,
    "GetHeaders.parse": GetHeaders.parse,
    "Headers.parse": Headers.parse,
    # the two payloads that are a transaction and a block: their own
    # mutation samples are `Tx.parse`'s and `Block.parse`'s below, the
    # wrapper adding no octets of its own to flip
    "TxPayload.parse": TxPayload.parse,
    "BlockPayload.parse": BlockPayload.parse,
    "BIP32KeyData.parse": BIP32KeyData.parse,
    "BIP32KeyOrigin.parse": BIP32KeyOrigin.parse,
    "dsa.Sig.parse": dsa.Sig.parse,
    "ssa.Sig.parse": ssa.Sig.parse,
    "bms.Sig.parse": bms.Sig.parse,
    # no bip322.Sig.parse: that class has none, its three payloads being
    # three unrelated serializations told apart by the prefix of the text
    # form alone, so the text entry point below is where it is read
    "ecies.Envelope.parse": ecies.Envelope.parse,
    "point_from_octets": point_from_octets,
    "base58.decode": base58.decode,
    "bech32.decode": bech32.decode,
}

# The same contract, for what a user pastes rather than what a peer
# sends: an address, a WIF, an extended key, a descriptor.
#
# The base64 wrappers are here rather than above, and each is a parser of
# its own: `b64decode` decodes and then hands the bytes to `parse`, so
# what it adds is the decoding -- a str that is not ascii, padding that
# is not canonical, a length no multiple of four -- and that is a layer
# the binary entry point never sees
TEXT_PARSERS: dict[str, Callable[[str], Any]] = {
    "base58.decode": base58.decode,
    "bech32.decode": bech32.decode,
    "b32.witness_from_address": b32.witness_from_address,
    "b58.h160_from_address": b58.h160_from_address,
    "BIP32KeyData.b58decode": BIP32KeyData.b58decode,
    "bms.Sig.b64decode": bms.Sig.b64decode,
    "bip322.Sig.b64decode": bip322.Sig.b64decode,
    "Psbt.b64decode": Psbt.b64decode,
    "ecies.Envelope.b64decode": ecies.Envelope.b64decode,
    "descriptors.checksum": descriptors.checksum,
    "descriptors.parse": descriptors.parse,
    "miniscript.parse": miniscript.parse,
}


def _assert_contract(parse: Callable[[Any], Any], data: Any) -> None:
    """Call parse, and let anything outside the contract propagate.

    Rejecting the input is the expected answer to almost all of what
    these strategies generate, so there is nothing to assert about it.
    What the test is for is the third outcome, neither a value nor a
    refusal: hypothesis reports the exception, and the input it shrank
    to reach it.
    """
    with contextlib.suppress(*CONTRACT):
        parse(data)


@pytest.mark.parametrize(
    "parse", BINARY_PARSERS.values(), ids=list(BINARY_PARSERS.keys())
)
@given(data=st.binary(max_size=MAX_INPUT))
def test_binary_parser_honors_the_exception_contract(
    parse: Callable[[bytes], Any], data: bytes
) -> None:
    """Fuzz every binary parser: refusals stay within the contract."""
    _assert_contract(parse, data)


@pytest.mark.parametrize("parse", TEXT_PARSERS.values(), ids=list(TEXT_PARSERS.keys()))
@given(data=st.text(max_size=MAX_INPUT))
def test_text_parser_honors_the_exception_contract(
    parse: Callable[[str], Any], data: str
) -> None:
    """Fuzz every text parser: refusals stay within the contract."""
    _assert_contract(parse, data)


def _load(*parts: str) -> bytes:
    """Return the bytes of a file vendored under tests/."""
    with Path(__file__).parent.joinpath(*parts).open("rb") as file_:
        return file_.read()


def _first_valid_psbt() -> bytes:
    """Return BIP174's first valid psbt, re-serialized to bytes."""
    filename = Path("psbt") / "_data" / "bip174_test_vectors.json"
    with (Path(__file__).parent / filename).open(encoding="ascii") as file_:
        vectors = json.load(file_)
    return Psbt.b64decode(vectors["valid psbts"][0]["encoded psbt"]).serialize()


# Block 1, the smallest there is at 215 bytes: what the mutations below
# cost is paid once per example, so the sample is chosen for being the
# shortest thing that still has a header, a transaction, and the two
# var_int counts between them
BLOCK_BIN = _load("block", "_data", "block_1.bin")
BLOCK_HEADER_BIN = BLOCK_BIN[:80]
# a segwit transaction, so that the marker, the flag and the witness
# stack are in the bytes being mutated and not only the legacy fields
TX_BIN = bytes.fromhex(
    "010000000001019bdea7abb2fa14dead47dd14d03cf82212a25b6096a8da6b14feec"
    "3658dbcf9d0100000000ffffffff02a02526000000000017a914f987c321394968be"
    "164053d352fc49763b2be55c874361610000000000220020701a8d401c84fb13e6ba"
    "f169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220421fbbedf2"
    "ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57"
    "e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d01473044022039"
    "8f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204e"
    "a405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f44016952"
    "210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c"
    "2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff"
    "2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f880"
    "53ae00000000"
)
PSBT_BIN = _first_valid_psbt()
# a p2p envelope carrying a payload, so that the mutations reach the
# checksum and the length field with octets behind them rather than a
# header alone
MESSAGE_BIN = Message("f9beb4d9", "ping", bytes(8)).serialize()
# the two p2p payloads with structure behind their first field: a
# `version`'s two embedded addresses and its var_int-prefixed user agent,
# and an `addr`'s count. Both are the captured messages of
# tests/p2p/handshake_test.py and tests/p2p/address_test.py
VERSION_BIN = bytes.fromhex(
    "62ea000001000000000000001"
    "1b2d05000000000"
    "010000000000000000000000000000000000ffff000000000000"
    "010000000000000000000000000000000000ffff000000000000"
    "3b2eb35d8ce617650f2f5361746f7368693a302e372e322fc03e0300"
)
ADDR_BIN = bytes.fromhex(
    "01e215104d010000000000000000000000000000000000ffff0a000001208d"
)
# and the BIP155 form of the same idea, whose fields a mutation reaches
# that an `addr`'s cannot: the count, then a CompactSize of service flags,
# a network id and a var_bytes length in front of the address. Core's
# `stream_addrv2_hex`, which is tests/p2p/addrv2_test.py's sample
ADDRV2_BIN = bytes.fromhex(
    "03"
    "61bc6649000210000000000000000000000000000000010000"
    "796276830102100000000000000000000000000000000100f1"
    "fffffffffd4804021000000000000000000000000000000001f1f2"
)
# an `inv` of one entry and a `headers` of one header, which are the
# inventory payloads with a count in front of a fixed-width record: a
# flipped octet lands in the count, in a type code or inside the header,
# and the octet after each header is the transaction count that has to be
# zero. The hash is block 1's, so the sample is the vendored block above
INV_BIN = Inv(
    [Inventory(InventoryType.MSG_BLOCK, BLOCK_HEADER_BIN[4:36][::-1])]
).serialize()
HEADERS_BIN = b"\x01" + BLOCK_HEADER_BIN + b"\x00"


def _mutations(sample: bytes) -> st.SearchStrategy[bytes]:
    """Return the near-misses of a valid serialization.

    Uniform random bytes are rejected by the first field of a parser and
    so exercise the outermost check and nothing beneath it. What reaches
    the code underneath is a serialization valid right up to the point
    where it is not: the truncation, the flipped length prefix, the
    trailing junk that must not be taken for a second record.
    """
    truncated = st.integers(min_value=0, max_value=len(sample)).map(
        lambda i: sample[:i]
    )
    flipped = st.builds(
        lambda i, byte: sample[:i] + bytes([byte]) + sample[i + 1 :],
        st.integers(min_value=0, max_value=len(sample) - 1),
        st.integers(min_value=0, max_value=0xFF),
    )
    extended = st.binary(max_size=32).map(lambda tail: sample + tail)
    return st.one_of(truncated, flipped, extended)


MUTATED_PARSERS: dict[str, tuple[Callable[[bytes], Any], bytes]] = {
    # a p2p envelope is the one sample here whose mutations are all
    # reachable: 24 octets of header, so a flipped bit lands in the magic,
    # the command, the length or the checksum rather than deep inside a
    # structure the outermost check has already refused
    "Message.parse": (Message.parse, MESSAGE_BIN),
    # and the two payloads whose own fields a mutation can reach: a
    # length in front of the user agent, a count in front of the
    # addresses, and the relay flag a `version` may or may not carry
    "Version.parse": (Version.parse, VERSION_BIN),
    "Addr.parse": (Addr.parse, ADDR_BIN),
    # and the BIP155 payload beside it, where a flipped octet lands in a
    # network id, in the CompactSize of the services or in the length in
    # front of a variable-width address
    "AddrV2.parse": (AddrV2.parse, ADDRV2_BIN),
    # and the two inventory payloads of the same shape, where a mutation
    # reaches a count, a four-octet type code and the zero after a header
    "Inv.parse": (Inv.parse, INV_BIN),
    "Headers.parse": (Headers.parse, HEADERS_BIN),
    "Tx.parse": (Tx.parse, TX_BIN),
    "BlockHeader.parse": (BlockHeader.parse, BLOCK_HEADER_BIN),
    "Block.parse": (Block.parse, BLOCK_BIN),
    "Psbt.parse": (Psbt.parse, PSBT_BIN),
}


@pytest.mark.parametrize(
    "parse, sample",
    MUTATED_PARSERS.values(),
    ids=list(MUTATED_PARSERS.keys()),
)
@given(data=st.data())
def test_mutated_serialization_honors_the_exception_contract(
    parse: Callable[[bytes], Any], sample: bytes, data: st.DataObject
) -> None:
    """Fuzz near-miss serializations: refusals stay within the contract."""
    _assert_contract(parse, data.draw(_mutations(sample)))


# The consumers, not the parsers. Everything above hands bytes to
# something that turns them into an object; what follows hands an object
# that parsed *cleanly* to the code that reads it, which is a surface no
# parser strategy reaches. The guarded case:
# `sig_hash.taproot_annex_and_ext` and `engine.taproot_get_annex` both
# read `stack[-1][0]` to test for the annex, and an empty witness element
# is legal on the wire and has no first byte -- so a 186-byte transaction
# `Tx.parse` accepts would answer a caller catching BTClibValueError with
# an IndexError, out of the public `sig_hash.from_tx`. Bitcoin Core's
# `spendpath/truncshortcontrol` vectors carry the case, and a
# fixed-vector test can take that crash for the refusal it asked for.
#
# The witness is the whole of what a peer chooses here, the rest of the
# transaction being fixed: it is the one field of a valid spend that the
# consensus code indexes into before it has validated anything
_P2TR_PRV_KEY = 0x4242424242424242424242424242424242424242424242424242424242424242
_P2TR_SCRIPT_PUB_KEY = ScriptPubKey.p2tr(_P2TR_PRV_KEY)
_P2TR_PREVOUTS = [TxOut(100_000, _P2TR_SCRIPT_PUB_KEY)]


def _p2tr_spend(stack: list[bytes]) -> Tx:
    """Return a one-input spend of a p2tr output, `stack` as witness."""
    vin = TxIn(OutPoint(b"\x11" * 32, 0))
    vin.script_witness = Witness(stack)
    return Tx(vin=[vin], vout=[TxOut(90_000, _P2TR_SCRIPT_PUB_KEY)])


# up to five elements, empty ones included and on purpose: two is what
# turns a key path spend into a script path one, three is what puts a
# control block where the leaf version is read, and an annex is
# recognized by the first byte of the last element, which an empty
# element does not have
WITNESS_STACKS = st.lists(st.binary(max_size=64), max_size=5)

WITNESS_CONSUMERS: dict[str, Callable[[list[bytes]], Any]] = {
    "sig_hash.from_tx": lambda stack: sig_hash.from_tx(
        _P2TR_PREVOUTS, _p2tr_spend(stack), 0, sig_hash.DEFAULT
    ),
    "engine.verify_input": lambda stack: verify_input(
        _P2TR_PREVOUTS, _p2tr_spend(stack), 0
    ),
    "engine.verify_transaction": lambda stack: verify_transaction(
        _P2TR_PREVOUTS, _p2tr_spend(stack)
    ),
}


@pytest.mark.parametrize(
    "consume", WITNESS_CONSUMERS.values(), ids=list(WITNESS_CONSUMERS.keys())
)
@given(stack=WITNESS_STACKS)
def test_witness_consumer_honors_the_exception_contract(
    consume: Callable[[list[bytes]], Any], stack: list[bytes]
) -> None:
    """Fuzz witness stacks: consumers keep the exception contract."""
    _assert_contract(consume, stack)
