# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A value is tested by its own class, not by the class it claims.

`unittest.mock.Mock(spec=T)` sets its `__class__` to `T`, and
`isinstance` reads `__class__`, so a type test asking `isinstance` takes
the Mock for a `T`. `btclib.utils._has_type` reads `type()` instead, and
every type test of btclib asks it. Each case below drives a public
function with a Mock claiming the type its type test expects, and the
value is read as the object it is (issue #3080).
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from btclib import bms
from btclib.amount import valid_btc_amount, valid_sats_amount
from btclib.b58 import p2pkh, prv_key_data_from_wif, wif_from_prv_key
from btclib.block import Block, BlockHeader, PartialMerkleTree
from btclib.block.proof_of_work import chain_work, hash_rate
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate
from btclib.key import PrvKeyData
from btclib.network import Network, normalized_network_name, validated_network_name
from btclib.p2p.address import Addr, NetworkAddress, TimestampedNetworkAddress
from btclib.p2p.addrv2 import AddrV2, NetworkAddressV2
from btclib.p2p.compact_blocks import CmpctBlock, PrefilledTransaction, reconstruct
from btclib.p2p.data import BlockPayload, TxPayload
from btclib.p2p.handshake import Version
from btclib.p2p.headers_sync import ChainStart
from btclib.p2p.inventory import GetHeaders, Headers, Inv, Inventory
from btclib.p2p.keepalive import Ping
from btclib.p2p.merkleblock import MerkleBlock
from btclib.p2p.reject import Reject
from btclib.script import taproot
from btclib.script.engine.flags import NO_FLAGS, ScriptFlag, to_script_flags
from btclib.script.script import Script, serialize
from btclib.script.script_pub_key import ScriptPubKey, script_from_script_pub_key
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.utreexo import Proof, Stump

_TIME = datetime(2009, 1, 9, tzinfo=UTC)
_HEADER = BlockHeader(1, "00" * 32, "11" * 32, _TIME, "1d00ffff", 1)
_TX = Tx(1, 0, [TxIn(OutPoint("01" * 32, 0), b"", 0xFFFFFFFF)], [TxOut(1, b"")])
_ADDR = p2pkh(PrvKeyData(1).pub)


def _serialized_header(version: Any) -> bytes:
    """Serialize a header whose version was set after it was built."""
    header = BlockHeader(1, "00" * 32, "11" * 32, _TIME, "1d00ffff", 1)
    header.version = version
    return header.serialize(check_validity=False)


# (the module whose type test decides the refusal, a public call that
# reaches it, the type the argument claims through `__class__`, what the
# call raises): put `isinstance` back in that test and the case fails
_REFUSED: tuple[tuple[str, Callable[[Any], object], type, type[Exception]], ...] = (
    ("amount", lambda v: valid_btc_amount(1, v), Decimal, BTClibTypeError),
    # an amount is Any, read through its text, so a Mock is a bad value
    ("amount", valid_btc_amount, int, BTClibValueError),
    ("amount", valid_sats_amount, str, BTClibTypeError),
    ("network", lambda v: wif_from_prv_key(1, v), Network, BTClibTypeError),
    ("network", lambda v: wif_from_prv_key(1, v), str, BTClibTypeError),
    ("block_header", _serialized_header, int, BTClibTypeError),
    ("proof_of_work", chain_work, list, BTClibTypeError),
    ("proof_of_work", lambda v: hash_rate(v, 1), int, BTClibTypeError),
    ("proof_of_work", lambda v: hash_rate(1, v), float, BTClibTypeError),
    ("bms", lambda v: bms.assert_as_valid(b"", _ADDR, v), bms.Sig, BTClibTypeError),
    # a fee rate is Any, read through its text, as an amount is
    ("fee", FeeRate.from_sats_per_vbyte, int, BTClibValueError),
    ("amount", FeeRate.from_btc_per_kvbyte, int, BTClibValueError),
    ("network", lambda v: PrvKeyData(1, v), Network, BTClibTypeError),
    ("network", lambda v: PrvKeyData(1, v), str, BTClibTypeError),
    ("network", validated_network_name, str, BTClibTypeError),
    ("address", lambda v: NetworkAddress(ip=v), IPv6Address, BTClibTypeError),
    ("address", lambda v: NetworkAddress(ip=v), IPv4Address, BTClibTypeError),
    ("address", lambda v: NetworkAddress(ip=v), bytes, BTClibTypeError),
    ("address", lambda v: NetworkAddress(ip=v), str, BTClibTypeError),
    (
        "address",
        lambda v: TimestampedNetworkAddress(0, v),
        NetworkAddress,
        BTClibTypeError,
    ),
    ("address", Addr, list, BTClibTypeError),
    ("address", lambda v: Addr([v]), TimestampedNetworkAddress, BTClibTypeError),
    ("addrv2", AddrV2, list, BTClibTypeError),
    ("addrv2", lambda v: AddrV2([v]), NetworkAddressV2, BTClibTypeError),
    ("compact_blocks", lambda v: PrefilledTransaction(v, _TX), int, BTClibTypeError),
    ("compact_blocks", lambda v: PrefilledTransaction(0, v), Tx, BTClibTypeError),
    ("compact_blocks", CmpctBlock, BlockHeader, BTClibTypeError),
    (
        "compact_blocks",
        lambda v: CmpctBlock(_HEADER, prefilled_txns=[v]),
        PrefilledTransaction,
        BTClibTypeError,
    ),
    ("compact_blocks", reconstruct, CmpctBlock, BTClibTypeError),
    (
        "compact_blocks",
        lambda v: reconstruct(CmpctBlock(_HEADER), [v]),
        Tx,
        BTClibTypeError,
    ),
    ("data", lambda v: TxPayload(v, True), Tx, BTClibTypeError),
    ("data", lambda v: BlockPayload(v, True), Block, BTClibTypeError),
    ("handshake", lambda v: Version(addr_recv=v), NetworkAddress, BTClibTypeError),
    ("handshake", lambda v: Version(relay=v), bool, BTClibTypeError),
    ("headers_sync", lambda v: ChainStart(_HEADER, 0, 0, 0, v), list, BTClibTypeError),
    ("inventory", Inv, list, BTClibTypeError),
    ("inventory", lambda v: Inv([v]), Inventory, BTClibTypeError),
    ("inventory", lambda v: Headers([v]), BlockHeader, BTClibTypeError),
    ("inventory", lambda v: GetHeaders(locator=v), list, BTClibTypeError),
    (
        "merkleblock",
        lambda v: MerkleBlock(_HEADER, v),
        PartialMerkleTree,
        BTClibTypeError,
    ),
    # `payload._assert_valid_int` is what `Ping` asks of its nonce
    ("payload", Ping, int, BTClibTypeError),
    ("reject", Reject, str, BTClibTypeError),
    ("reject", lambda v: Reject(reason=v), str, BTClibTypeError),
    ("script", serialize, list, BTClibTypeError),
    ("script", lambda v: serialize([v]), int, BTClibTypeError),
    ("script", lambda v: serialize([v]), str, BTClibTypeError),
    ("script", lambda v: serialize([v]), bytes, BTClibTypeError),
    ("script_pub_key", lambda v: ScriptPubKey(b"", v), Network, BTClibTypeError),
    ("script_pub_key", ScriptPubKey.nulldata, str, BTClibTypeError),
    ("script_pub_key", script_from_script_pub_key, ScriptPubKey, BTClibTypeError),
    ("script_pub_key", script_from_script_pub_key, bytes, BTClibTypeError),
    ("taproot", lambda v: taproot.serialize([v]), int, BTClibTypeError),
    ("taproot", lambda v: taproot.serialize([v]), str, BTClibTypeError),
    # what follows OP_SUCCESS is no bytes command, as for any other object
    (
        "taproot",
        lambda v: taproot.serialize(["OP_SUCCESS80", v]),
        bytes,
        BTClibValueError,
    ),
    ("taproot", lambda v: taproot.tree_helper([v]), tuple, BTClibTypeError),
    ("taproot", lambda v: taproot.tree_from_weights([v]), tuple, BTClibTypeError),
    ("tx_out", lambda v: TxOut(1, v), ScriptPubKey, BTClibTypeError),
    ("utreexo", Stump, int, BTClibTypeError),
    ("utreexo", lambda v: Proof([v]), int, BTClibTypeError),
)


@pytest.mark.parametrize(
    "call, claimed, refusal",
    [case[1:] for case in _REFUSED],
    ids=[f"{i}-{case[0]}-{case[2].__name__}" for i, case in enumerate(_REFUSED)],
)
@pytest.mark.parametrize("mock", [Mock, MagicMock])
def test_a_value_that_claims_a_type_is_refused(
    call: Callable[[Any], object],
    claimed: type,
    refusal: type[Exception],
    mock: type[Mock],
) -> None:
    """The Mock is refused as the object it is, never read as `claimed`."""
    with pytest.raises(refusal):
        call(mock(spec=claimed))


@pytest.mark.parametrize("mock", [Mock, MagicMock])
def test_a_value_that_claims_a_type_is_answered_as_its_own(mock: type[Mock]) -> None:
    """What answers rather than refuses answers for the object it is."""
    assert Script(b"").__add__(mock(spec=Script)) is NotImplemented
    assert ScriptPubKey(b"").__eq__(mock(spec=ScriptPubKey)) is NotImplemented
    assert _TX.__eq__(mock(spec=Tx)) is NotImplemented

    claimed_bool = mock(spec=bool)
    key = PrvKeyData(1, compressed=claimed_bool, check_validity=False)
    assert "compressed=...)" in repr(key)

    claimed_str = mock(spec=str)
    assert normalized_network_name(claimed_str) is claimed_str


@pytest.mark.parametrize("mock", [Mock, MagicMock])
def test_a_value_that_claims_a_network_is_no_name_to_b58(mock: type[Mock]) -> None:
    """`b58` refuses the Mock as no network name, not as a bad Network."""
    wif = wif_from_prv_key(1)
    with pytest.raises(BTClibTypeError, match="not a network name"):
        prv_key_data_from_wif(wif, mock(spec=Network))


def test_a_value_that_claims_a_flag_set_is_read_as_its_own() -> None:
    """A MagicMock is an empty iterable of names by its own class."""
    assert to_script_flags(MagicMock(spec=ScriptFlag)) == NO_FLAGS


def test_btclib_tests_a_type_only_through_has_type() -> None:
    """No module of btclib calls `isinstance`, and `utils` calls `_has_type`."""
    src = Path(__file__).parents[1] / "src" / "btclib"
    calls = {
        path: [
            node.func.id
            for node in ast.walk(ast.parse(path.read_text()))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        for path in src.rglob("*.py")
    }
    assert "_has_type" in calls[src / "utils.py"]
    offenders = [path for path, names in calls.items() if "isinstance" in names]
    assert not offenders
