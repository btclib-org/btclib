# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Fuzz corpora of Bitcoin Core and rust-bitcoin, replayed through btclib.

`bitcoin-core/qa-assets` holds, per Core fuzz target, the inputs that
target's fuzzers found interesting. `rust-bitcoin/qa-assets` does the
same for rust-bitcoin's targets. Where the input is the raw bytes of a
format btclib parses, the same bytes go to the btclib parser. A parser
may refuse them with a `BTClibException`; any other exception is a
defect, because the parsers' contract is that malformed octets are
refused in that one family.

A source is skipped where its variable is unset or empty:
`BTCLIB_QA_ASSETS` for Core's checkout, `BTCLIB_RUST_BITCOIN_QA_ASSETS`
for rust-bitcoin's.

    BTCLIB_QA_ASSETS=/path/to/qa-assets uv run pytest \
        tests/integration/qa_assets_test.py

`qa-assets.yml` runs it weekly against both repositories' default
branch, sparse-checking out the directories `TARGETS` names.

`TARGETS` is the table from a qa-assets directory to the parser that
reads its bytes. `reading` says how the source's own target reads them:
a file of `src/test/fuzz/` in `bitcoin/bitcoin`, or of
`fuzz/fuzz_targets/` in `rust-bitcoin/rust-bitcoin`. Core's
targets read an object off the front of the input and ignore what
follows (`SpanReader{buffer} >> obj`), while `parse` on bytes refuses
trailing bytes before it builds the object. So a Core row hands `parse` a
`BytesIO`, which it reads from and leaves where the object ends, and
reaches the code a refused-at-the-end input would never reach. The rows
whose source consumes the whole input (`decode_tx`, which needs the hex
of the whole input to decode, and the rust-bitcoin rows that decode the
whole input with `decode_from_slice` or `from_bytes`) hand it the bytes. The
rust-bitcoin rows whose decoder stops at the end of one value
(`consensus_encoding_decode_compact_size` and
`consensus_encoding_decode_byte_vec`) hand it a stream, as Core's do.

Each parser that takes `check_validity` is replayed with it on and off,
the second reaching the code that runs on a structure the first would
have refused.

A directory gets a row only where its target reads the input as the
octets of one format btclib parses: the same fields, in the same widths
and with the same framing. So these are not replayed:

- a target that builds its values from the input, as Core's
  `FuzzedDataProvider` does (`script`, `primitives_transaction`) and
  rust-bitcoin's typed `fuzz_target!` does (`bitcoin_arbitrary_block`):
  the bytes are choices, not a format;
- a text target (`key_io`, `parse_script`, `bitcoin_parse_address`):
  not octets of a format;
- PSBT and descriptors (`psbt`, `descriptor_parse`,
  `bitcoin_0_32_deserialize_psbt`): btclib reads neither;
  `btclib-wallet` does;
- a target that reads no format (`hashes_sha256`), or tries one input as
  many (`bitcoin_compare_consensus_encoding`), or decodes a fixed-width
  array (`consensus_encoding_decode_array`);
- a format whose last field btclib makes optional where the target
  requires it: `Version.relay` and the hash of `Reject`, which the BIPs
  leave out of some messages and rust-bitcoin's decoders always read
  (`bitcoin_encoding_roundtrip_p2p_message_network_version_message`,
  `bitcoin_encoding_roundtrip_p2p_message_network_reject`);
- a format whose count field is a different width: rust-bitcoin's
  `NetworkHeader` ends in one octet, where `Headers` ends each header in a
  `CompactSize` (`bitcoin_encoding_roundtrip_p2p_message_headers_message`
  and `bitcoin_encoding_roundtrip_p2p_message_network_header`);
- a format btclib reads only inside a larger one: the 24-octet header of
  a message (`messageheader_deserialize` and
  `bitcoin_encoding_roundtrip_p2p_message_v1_message_header`) and its
  command (`bitcoin_encoding_roundtrip_p2p_message_command_string`) are read
  by `Message.parse` together with the payload whose checksum the header
  holds; a block locator (`blocklocator_deserialize` and
  `bitcoin_encoding_roundtrip_p2p_message_blockdata_block_locator`) is read
  by `GetBlocks` and `GetHeaders` with the stop hash after it; an `AddrV2`
  address (`p2p_deserialize_addrv2` and
  `bitcoin_encoding_roundtrip_p2p_address_addr_v2`) is read by
  `NetworkAddressV2` with the time, the services and the port around it;
- a format btclib has no parser for: bloom filters (`bloomfilter_deserialize`
  and the `bitcoin_encoding_roundtrip_p2p_message_bloom_*` directories),
  the `alert` payload, and the fixed-width scalars such as amounts,
  hashes, versions, service flags and the magic.

rust-bitcoin builds its fuzz binaries with `--cfg=hashes_fuzz`
(`fuzz/rustflags.sh`), under which SHA256 is an XOR of its input. So the
checksum of a frame in the corpora is not SHA256d's, and the `Message`
rows rewrite it, where the length field fits the input, before parsing.
No other row reads a hash the corpus computed.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

import pytest

from btclib import compressor, script, var_bytes, var_int
from btclib.alias import BinaryData
from btclib.block.block import Block
from btclib.block.block_filter import BasicBlockFilter
from btclib.block.block_header import BlockHeader
from btclib.block.partial_merkle_tree import PartialMerkleTree
from btclib.exceptions import BTClibException
from btclib.hashes import hash256
from btclib.p2p.address import Addr, NetworkAddress, TimestampedNetworkAddress
from btclib.p2p.addrv2 import AddrV2, NetworkAddressV2
from btclib.p2p.block_filters import (
    CFCheckpt,
    CFHeaders,
    CFilter,
    GetCFCheckpt,
    GetCFHeaders,
    GetCFilters,
)
from btclib.p2p.compact_blocks import (
    BlockTxn,
    CmpctBlock,
    GetBlockTxn,
    PrefilledTransaction,
    SendCmpct,
)
from btclib.p2p.inventory import GetBlocks, GetHeaders, Inv, Inventory
from btclib.p2p.keepalive import Ping, Pong
from btclib.p2p.merkleblock import MerkleBlock
from btclib.p2p.message import Message
from btclib.p2p.negotiation import Feature, FeeFilter, SendTxRcncl
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from btclib.utils import assert_no_trailing, bytesio_from_binarydata

pytestmark = pytest.mark.integration

# a parser and the way to ask it: (octets or a stream, check_validity)
Parser = Callable[[BinaryData, bool], object]


@dataclass(frozen=True)
class Target:
    """A qa-assets directory, how its source reads it, and btclib's readings."""

    directory: str
    reading: str
    parsers: tuple[Parser, ...]
    source: str = "bitcoin-core"
    # whether the source reads an object off the front of the input and
    # ignores the rest, so the parser is given a stream and not the bytes
    front: bool = True
    # the values of `check_validity` to replay with
    validity: tuple[bool, ...] = (True, False)


def _parser(parse: Callable[..., object]) -> Parser:
    """Return `parse`, called with `check_validity` by keyword."""
    return lambda data, check_validity: parse(data, check_validity=check_validity)


def _script_deserialize(data: BinaryData, check_validity: bool) -> object:
    """Return the script a CompactSize-prefixed byte vector holds."""
    return script.parse(_var_bytes(data, check_validity))


def _script(data: BinaryData, check_validity: bool) -> object:
    """Return the script the octets are, with no length prefix."""
    return script.parse(data)


# the magic, the command, the length and the checksum of a v1 frame
_FRAME_HEADER = 24


def _block_filter(data: BinaryData, check_validity: bool) -> object:
    """Return the filter `BlockFilter::Unserialize` builds.

    It reads the type, the block hash and the encoded filter, then decodes
    the Golomb-coded set and refuses a type other than the basic one.
    """
    return CFilter.parse(data, check_validity=check_validity).basic_filter


def _basic_filter(data: BinaryData, check_validity: bool) -> object:
    """Return the filter `BasicFilter::from_bytes` builds from the octets.

    Parsing does not read the block hash, which only keys matching: any 32
    octets do.
    """
    octets = bytesio_from_binarydata(data).getvalue()
    return BasicBlockFilter.parse(octets, b"\x00" * 32, check_validity=check_validity)


def _message_with_real_checksum(data: BinaryData, check_validity: bool) -> object:
    """Return the message, its checksum made that of SHA256d of the payload.

    rust-bitcoin's fuzz binaries are built with `--cfg=hashes_fuzz`, under
    which SHA256 is an XOR of its input, so the checksums in the corpora
    are not SHA256d's and every frame fails `Message.parse` at the
    checksum. Where the length field fits the input, the checksum is
    rewritten before parsing, so that the frame passes the checksum and
    reaches the trailing-octet check and the constructor; the payload stays
    opaque octets, and no payload parser runs.
    """
    octets = bytesio_from_binarydata(data).getvalue()
    if len(octets) >= _FRAME_HEADER:
        length = int.from_bytes(octets[16:20], byteorder="little")
        end = _FRAME_HEADER + length
        if end <= len(octets):
            checksum = hash256(octets[_FRAME_HEADER:end])[:4]
            octets = octets[:20] + checksum + octets[24:]
    return Message.parse(octets, check_validity=check_validity)


def _compact_size(data: BinaryData, check_validity: bool) -> object:
    """Return the number a CompactSize is."""
    return var_int.parse(data)


def _var_bytes(data: BinaryData, check_validity: bool) -> bytes:
    """Return the octets a CompactSize length and its bytes hold.

    `var_bytes.parse` leaves what follows unread, so a byte string with
    octets after it is refused here, as `parse` refuses them in every other
    format.
    """
    stream = bytesio_from_binarydata(data)
    octets = var_bytes.parse(stream)
    assert_no_trailing(data, stream, "byte vector")
    return octets


def _tx_out_compression(data: BinaryData, check_validity: bool) -> object:
    """Return the amount and script `TxOutCompression` reads."""
    stream = bytesio_from_binarydata(data)
    amount = compressor.decompress_amount(compressor.parse_varint(stream))
    return amount, compressor.parse_script(stream)


def _coin(data: BinaryData, check_validity: bool) -> object:
    """Return the code, the amount and the script `Coin::Unserialize` reads."""
    stream = bytesio_from_binarydata(data)
    code = compressor.parse_varint(stream, 32)
    return code, _tx_out_compression(stream, check_validity)


def _decode_hex_tx_without_witness(data: BinaryData, check_validity: bool) -> object:
    """Return the transaction read as `DecodeHexTx` reads it with no witness."""
    return Tx.parse_without_witness(data, check_validity=check_validity)


def _roundtrip(directory: str, rust_type: str, parse: Callable[..., object]) -> Target:
    """Return the row of `check_roundtrip::<rust_type>`."""
    return Target(
        f"bitcoin_encoding_roundtrip_{directory}",
        f"bitcoin/encoding_roundtrip/{directory}.rs: {rust_type}",
        (_parser(parse),),
        source="rust-bitcoin",
        front=False,
    )


def _script_roundtrip(directory: str, rust_type: str) -> Target:
    """Return the row of `check_script_roundtrip::<rust_type>`."""
    return Target(
        f"bitcoin_encoding_roundtrip_{directory}",
        f"bitcoin/encoding_roundtrip/{directory}.rs: {rust_type},"
        " a CompactSize length and its bytes",
        (_script_deserialize,),
        source="rust-bitcoin",
        front=False,
        validity=(True,),
    )


def _var_bytes_roundtrip(directory: str, rust_type: str) -> Target:
    """Return the row of a `check_roundtrip` type that is a ByteVecDecoder."""
    return Target(
        f"bitcoin_encoding_roundtrip_{directory}",
        f"bitcoin/encoding_roundtrip/{directory}.rs: {rust_type},"
        " a CompactSize length and its bytes",
        (_var_bytes,),
        source="rust-bitcoin",
        front=False,
        validity=(True,),
    )


_WITH_WITNESS = "CBlock, TX_WITH_WITNESS"

TARGETS = (
    Target(
        "block_deserialize",
        f"deserialize.cpp: {_WITH_WITNESS}",
        (_parser(Block.parse),),
    ),
    Target(
        "block", f"block.cpp: {_WITH_WITNESS}, then CheckBlock", (_parser(Block.parse),)
    ),
    Target(
        "blockheader_deserialize",
        "deserialize.cpp: CBlockHeader",
        (_parser(BlockHeader.parse),),
    ),
    Target(
        "script_deserialize",
        "deserialize.cpp: CScript, a CompactSize length and its bytes",
        (_script_deserialize,),
        validity=(True,),
    ),
    Target(
        "tx_in_deserialize",
        "deserialize.cpp: CTxIn, which carries no witness",
        (_parser(TxIn.parse),),
    ),
    Target("tx_in", "tx_in.cpp: CTxIn", (_parser(TxIn.parse),)),
    Target("tx_out", "tx_out.cpp: CTxOut", (_parser(TxOut.parse),)),
    Target(
        "out_point_deserialize",
        "deserialize.cpp: COutPoint",
        (_parser(OutPoint.parse),),
    ),
    Target(
        "transaction",
        "transaction.cpp: CTransaction, TX_WITH_WITNESS",
        (_parser(Tx.parse),),
    ),
    Target(
        "decode_tx",
        "decode_tx.cpp: DecodeHexTx on the hex of the input, which neither"
        " runs CheckTransaction nor requires a witness",
        (_parser(Tx.parse), _decode_hex_tx_without_witness),
        front=False,
    ),
    Target(
        "prefilled_transaction_deserialize",
        "deserialize.cpp: PrefilledTransaction",
        (_parser(PrefilledTransaction.parse),),
    ),
    Target(
        "blocktransactions_deserialize",
        "deserialize.cpp: BlockTransactions, `blocktxn`",
        (_parser(BlockTxn.parse),),
    ),
    Target(
        "blocktransactionsrequest_deserialize",
        "deserialize.cpp: BlockTransactionsRequest, `getblocktxn`",
        (_parser(GetBlockTxn.parse),),
    ),
    Target(
        "block_header_and_short_txids_deserialize",
        "deserialize.cpp: CBlockHeaderAndShortTxIDs, `cmpctblock`",
        (_parser(CmpctBlock.parse),),
    ),
    Target(
        "merkle_block_deserialize",
        "deserialize.cpp: CMerkleBlock, `merkleblock`",
        (_parser(MerkleBlock.parse),),
    ),
    Target(
        "partial_merkle_tree_deserialize",
        "deserialize.cpp: CPartialMerkleTree",
        (_parser(PartialMerkleTree.parse),),
    ),
    Target(
        "inv_deserialize",
        "deserialize.cpp: CInv, an inventory entry",
        (_parser(Inventory.parse),),
    ),
    Target(
        "block_filter_deserialize",
        "deserialize.cpp: BlockFilter, `cfilter`, whose filter it decodes",
        (_block_filter,),
    ),
    Target(
        "blockmerkleroot",
        f"deserialize.cpp: {_WITH_WITNESS}, then BlockMerkleRoot",
        (_parser(Block.parse),),
    ),
    Target(
        "txoutcompressor_deserialize",
        "deserialize.cpp: CTxOut under TxOutCompression",
        (_tx_out_compression,),
        validity=(True,),
    ),
    Target(
        "coins_deserialize",
        "deserialize.cpp: Coin, a VARINT code then a TxOutCompression",
        (_coin,),
        validity=(True,),
    ),
    Target(
        "bitcoin_deserialize_transaction",
        "bitcoin/deserialize_transaction.rs: bitcoin::Transaction",
        (_parser(Tx.parse),),
        source="rust-bitcoin",
        front=False,
    ),
    Target(
        "bitcoin_deserialize_block",
        "bitcoin/deserialize_block.rs: bitcoin::Block",
        (_parser(Block.parse),),
        source="rust-bitcoin",
        front=False,
    ),
    Target(
        "bitcoin_deserialize_prefilled_transaction",
        "bitcoin/deserialize_prefilled_transaction.rs: p2p::bip152::PrefilledTransaction",
        (_parser(PrefilledTransaction.parse),),
        source="rust-bitcoin",
        front=False,
    ),
    Target(
        "bitcoin_deserialize_script",
        "bitcoin/deserialize_script.rs: bitcoin::ScriptPubKeyBuf,"
        " a CompactSize length and its bytes",
        (_script_deserialize,),
        source="rust-bitcoin",
        front=False,
        validity=(True,),
    ),
    Target(
        "bitcoin_deserialize_witness",
        "bitcoin/deserialize_witness.rs: bitcoin::Witness",
        (_parser(Witness.parse),),
        source="rust-bitcoin",
        front=False,
    ),
    Target(
        "bitcoin_script_bytes_to_asm_fmt",
        "bitcoin/script_bytes_to_asm_fmt.rs: bitcoin::WitnessScript::from_bytes",
        (_script,),
        source="rust-bitcoin",
        front=False,
        validity=(True,),
    ),
    Target(
        "bip158_parse_filter",
        "bip158/parse_filter.rs: bitcoin_bip158::BasicFilter::from_bytes",
        (_basic_filter,),
        source="rust-bitcoin",
        front=False,
    ),
    Target(
        "consensus_encoding_decode_compact_size",
        "consensus_encoding/decode_compact_size.rs: CompactSizeDecoder,"
        " which stops at the end of the number",
        (_compact_size,),
        source="rust-bitcoin",
        validity=(True,),
    ),
    Target(
        "consensus_encoding_decode_byte_vec",
        "consensus_encoding/decode_byte_vec.rs: ByteVecDecoder,"
        " which stops at the end of the bytes",
        (_var_bytes,),
        source="rust-bitcoin",
        validity=(True,),
    ),
    Target(
        "p2p_deserialize_raw_net_msg",
        "p2p/deserialize_raw_net_msg.rs: p2p::message::V1NetworkMessage,"
        " with the checksum made SHA256d's (hashes_fuzz)",
        (_message_with_real_checksum,),
        source="rust-bitcoin",
        front=False,
    ),
    Target(
        "bitcoin_0_32_deser_net_msg",
        "bitcoin_0_32/deser_net_msg.rs: bitcoin 0.32's RawNetworkMessage,"
        " one v1 frame, with the checksum made SHA256d's (hashes_fuzz)",
        (_message_with_real_checksum,),
        source="rust-bitcoin",
        front=False,
    ),
    _roundtrip("block", "bitcoin::Block", Block.parse),
    _roundtrip("block_header", "bitcoin::block::Header", BlockHeader.parse),
    _roundtrip("transaction", "bitcoin::Transaction", Tx.parse),
    _roundtrip("tx_in", "bitcoin::TxIn", TxIn.parse),
    _roundtrip("tx_out", "bitcoin::TxOut", TxOut.parse),
    _roundtrip("out_point", "bitcoin::OutPoint", OutPoint.parse),
    _roundtrip("witness", "bitcoin::Witness", Witness.parse),
    _script_roundtrip("redeem_script_buf", "bitcoin::RedeemScriptBuf"),
    _script_roundtrip("script_pub_key_buf", "bitcoin::ScriptPubKeyBuf"),
    _script_roundtrip("script_sig_buf", "bitcoin::ScriptSigBuf"),
    _script_roundtrip("tap_script_buf", "bitcoin::TapScriptBuf"),
    _script_roundtrip("witness_script_buf", "bitcoin::WitnessScriptBuf"),
    _roundtrip(
        "p2p_bip152_prefilled_transaction",
        "p2p::bip152::PrefilledTransaction",
        PrefilledTransaction.parse,
    ),
    _roundtrip(
        "p2p_bip152_header_and_short_ids",
        "p2p::bip152::HeaderAndShortIds, `cmpctblock`",
        CmpctBlock.parse,
    ),
    _roundtrip(
        "p2p_bip152_block_transactions",
        "p2p::bip152::BlockTransactions, `blocktxn`",
        BlockTxn.parse,
    ),
    _roundtrip(
        "p2p_bip152_block_transactions_request",
        "p2p::bip152::BlockTransactionsRequest, `getblocktxn`",
        GetBlockTxn.parse,
    ),
    _roundtrip(
        "p2p_merkle_tree_merkle_block",
        "p2p::merkle_tree::MerkleBlock, `merkleblock`",
        MerkleBlock.parse,
    ),
    _roundtrip(
        "p2p_merkle_tree_partial_merkle_tree",
        "p2p::merkle_tree::PartialMerkleTree",
        PartialMerkleTree.parse,
    ),
    _roundtrip(
        "p2p_message_blockdata_inventory",
        "p2p::message_blockdata::Inventory",
        Inventory.parse,
    ),
    _roundtrip(
        "p2p_message_inventory_payload",
        "p2p::message::InventoryPayload, `inv`",
        Inv.parse,
    ),
    _roundtrip(
        "p2p_message_blockdata_get_blocks_message",
        "p2p::message_blockdata::GetBlocksMessage, `getblocks`",
        GetBlocks.parse,
    ),
    _roundtrip(
        "p2p_message_blockdata_get_headers_message",
        "p2p::message_blockdata::GetHeadersMessage, `getheaders`",
        GetHeaders.parse,
    ),
    _roundtrip(
        "p2p_address_address",
        "p2p::address::Address, a services field, an IP and a port",
        NetworkAddress.parse,
    ),
    _roundtrip(
        "p2p_address_addr_v1_message",
        "p2p::address::AddrV1Message, a time and an Address",
        TimestampedNetworkAddress.parse,
    ),
    _roundtrip(
        "p2p_address_addr_v2_message",
        "p2p::address::AddrV2Message, an `addrv2` entry",
        NetworkAddressV2.parse,
    ),
    _roundtrip(
        "p2p_message_addr_payload", "p2p::message::AddrPayload, `addr`", Addr.parse
    ),
    _roundtrip(
        "p2p_message_addr_v2_payload",
        "p2p::message::AddrV2Payload, `addrv2`",
        AddrV2.parse,
    ),
    _roundtrip(
        "p2p_message_fee_filter",
        "p2p::message::FeeFilter, `feefilter`",
        FeeFilter.parse,
    ),
    _roundtrip("p2p_message_ping", "p2p::message::Ping, `ping`", Ping.parse),
    _roundtrip("p2p_message_pong", "p2p::message::Pong, `pong`", Pong.parse),
    _roundtrip(
        "p2p_message_compact_blocks_send_cmpct",
        "p2p::message_compact_blocks::SendCmpct, `sendcmpct`",
        SendCmpct.parse,
    ),
    _roundtrip(
        "p2p_message_erlay_send_tx_rcn_cl",
        "p2p::message_erlay::SendTxRcnCl, `sendtxrcncl`",
        SendTxRcncl.parse,
    ),
    _roundtrip(
        "p2p_message_filter_get_c_filters",
        "p2p::message_filter::GetCFilters, `getcfilters`",
        GetCFilters.parse,
    ),
    _roundtrip(
        "p2p_message_filter_c_filter",
        "p2p::message_filter::CFilter, `cfilter`",
        CFilter.parse,
    ),
    _roundtrip(
        "p2p_message_filter_get_c_f_headers",
        "p2p::message_filter::GetCFHeaders, `getcfheaders`",
        GetCFHeaders.parse,
    ),
    _roundtrip(
        "p2p_message_filter_c_f_headers",
        "p2p::message_filter::CFHeaders, `cfheaders`",
        CFHeaders.parse,
    ),
    _roundtrip(
        "p2p_message_filter_get_c_f_checkpt",
        "p2p::message_filter::GetCFCheckpt, `getcfcheckpt`",
        GetCFCheckpt.parse,
    ),
    _roundtrip(
        "p2p_message_filter_c_f_checkpt",
        "p2p::message_filter::CFCheckpt, `cfcheckpt`",
        CFCheckpt.parse,
    ),
    _roundtrip("p2p_bip434_feature", "p2p::bip434::Feature, `feature`", Feature.parse),
    Target(
        "bitcoin_encoding_roundtrip_p2p_message_v1_network_message",
        "bitcoin/encoding_roundtrip/p2p_message_v1_network_message.rs:"
        " p2p::message::V1NetworkMessage, one v1 frame, with the checksum"
        " made SHA256d's (hashes_fuzz)",
        (_message_with_real_checksum,),
        source="rust-bitcoin",
        front=False,
    ),
    _var_bytes_roundtrip("p2p_bip434_feature_id", "p2p::bip434::FeatureId"),
    _var_bytes_roundtrip("p2p_bip434_feature_data", "p2p::bip434::FeatureData"),
    _var_bytes_roundtrip(
        "p2p_message_network_user_agent", "p2p::message_network::UserAgent"
    ),
)

# the environment variable that names a checkout, per source
_CHECKOUTS = {
    "bitcoin-core": "BTCLIB_QA_ASSETS",
    "rust-bitcoin": "BTCLIB_RUST_BITCOIN_QA_ASSETS",
}


@pytest.mark.parametrize(
    "target", TARGETS, ids=lambda target: f"{target.source}-{target.directory}"
)
def test_corpus_is_refused_in_btclibs_own_exception(target: Target) -> None:
    """Every input is parsed, or refused with `BTClibException`."""
    variable = _CHECKOUTS[target.source]
    checkout = os.environ.get(variable)
    if not checkout:
        # the prefix is what integration-bitcoind.yml exempts from its
        # check that the tests ran
        pytest.skip(
            f"qa-assets: set {variable} to a {target.source} qa-assets checkout"
        )
    inputs = sorted((Path(checkout) / "fuzz_corpora" / target.directory).iterdir())
    # a renamed or emptied directory would otherwise pass by replaying nothing
    assert inputs, f"{target.directory} holds no input"

    defects = []
    for path in inputs:
        data = path.read_bytes()
        for parse in target.parsers:
            for check_validity in target.validity:
                # a stream per call: a parse leaves it where the object ends
                subject = BytesIO(data) if target.front else data
                try:
                    parse(subject, check_validity)
                except BTClibException:
                    pass
                except Exception as exc:  # noqa: BLE001 -- any other is the finding
                    defects.append(
                        f"{path.name} ({len(data)} octets),"
                        f" check_validity={check_validity}: {exc!r}"
                    )
    assert not defects, "\n".join([target.reading, *defects])
