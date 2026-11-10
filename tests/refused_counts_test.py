# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a refusal prints no number decoded from the octets it refuses.

Section 7 of the organization's standard, *A refusal carries no secret*: a
value refused as a public type may be a key passed in its place, and a
count, a length or a script number read from its octets is bytes of it.
Each case below puts a fixed random key's bytes where such a number is
read, and checks the exact text and every exception of the chain (issue
#3005). `tests/refused_octets_test.py` is the same check for the bytes
themselves.
"""

from __future__ import annotations

from collections.abc import Callable
from io import BytesIO

import pytest

from btclib import var_int
from btclib.block.block_filter import BasicBlockFilter
from btclib.block.partial_merkle_tree import PartialMerkleTree
from btclib.exceptions import BTClibValueError
from btclib.p2p.address import Addr
from btclib.p2p.addrv2 import AddrV2, NetworkAddressV2
from btclib.p2p.block_filters import CFHeaders
from btclib.p2p.inventory import GetBlocks, Headers, Inv
from btclib.p2p.limits import MAX_ADDR_TO_SEND
from btclib.p2p.message import Message
from btclib.script import serialize
from btclib.script.engine import ScriptFlag
from btclib.script.engine.script import (
    assert_pub_key_num,
    assert_signature_num,
    script_op_count,
    verify_script,
)
from btclib.script.engine.script_op_codes import read_push_data
from btclib.script.script import script_from_dict
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.utils import decode_num
from tests.secret_free import assert_secret_free, chained, text_of

# a fixed random key, as `assert_secret_free` asks
_KEY = bytes.fromhex("9ed7f12938cd646f2866d454cc247f688b857424cc4ee6bec49c16f1200bd5b9")

# the key's bytes 0 and 1 after a two-byte var_int prefix: 55198, which
# is below var_int's own cap and above every count bound below
_TWO_KEY_BYTES = b"\xfd" + _KEY[:2]

# the mainnet genesis header, for a `headers` payload
_HEADER = bytes.fromhex(
    "01000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "29ab5f49ffff001d1dac2b7c"
)


def _script(
    commands: list[object], flags: ScriptFlag, *, lock_time: int = 0, sequence: int = 0
) -> Callable[[], object]:
    """Return a call running the script against a one-input transaction."""
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0), b"", sequence)
    tx = Tx(2, lock_time, [tx_in], [TxOut(1, b"")], check_validity=False)
    script = serialize(commands)  # type: ignore[arg-type]
    return lambda: verify_script(script, [], 0, tx, 0, flags, False)


def _push(op_code: int, octets: bytes) -> Callable[[], object]:
    """Return a call reading a push of `op_code` from the octets after it."""
    return lambda: read_push_data(
        op_code, BytesIO(octets), [], False, ScriptFlag(0), serialize
    )


_CLTV = ScriptFlag.CHECKLOCKTIMEVERIFY
_CSV = ScriptFlag.CHECKSEQUENCEVERIFY

_CASES: list[tuple[str, Callable[[], object], str]] = [
    (
        "addr count",
        lambda: Addr.parse(_TWO_KEY_BYTES),
        "invalid addresses count: at most 1000 expected",
    ),
    (
        "addrv2 count",
        lambda: AddrV2.parse(_TWO_KEY_BYTES),
        "invalid addresses count: at most 1000 expected",
    ),
    (
        "addrv2 address length",
        lambda: NetworkAddressV2.parse(bytes(4) + b"\x00\x01" + _TWO_KEY_BYTES),
        "invalid address length: at most 512 bytes expected",
    ),
    (
        "cfheaders count",
        lambda: CFHeaders.parse(bytes(65) + _TWO_KEY_BYTES),
        "invalid filter_hashes count: at most 2000 expected",
    ),
    (
        "inv count",
        lambda: Inv.parse(_TWO_KEY_BYTES),
        "invalid items count: at most 50000 expected",
    ),
    (
        "locator count",
        lambda: GetBlocks.parse(bytes(4) + _TWO_KEY_BYTES),
        "invalid locator count: at most 101 expected",
    ),
    (
        "headers count",
        lambda: Headers.parse(_TWO_KEY_BYTES),
        "invalid headers count: at most 2000 expected",
    ),
    # the key's bytes 0 to 3, little-endian, are above var_int's cap
    (
        "headers transaction count",
        lambda: Headers.parse(b"\x01" + _HEADER + b"\xfe" + _KEY[:4]),
        "var_int too big: max is 02000000",
    ),
    (
        "headers transaction count with round_trip",
        lambda: Headers.parse(b"\x01" + _HEADER + _KEY[:1], round_trip=True),
        "invalid transaction count: 0 expected",
    ),
    (
        "message payload length",
        lambda: Message.parse(bytes(4) + b"ping".ljust(12, b"\x00") + _KEY[:8]),
        "invalid payload length: at most 4000000 bytes expected",
    ),
    # eight one bits make a quotient no bound of one element admits
    (
        "block filter element",
        lambda: BasicBlockFilter(bytes(32), 1, b"\xff" + _KEY),
        "block filter element out of range",
    ),
    (
        "partial merkle tree transactions",
        lambda: PartialMerkleTree(_KEY[0], [bytes(32)] * (_KEY[0] + 1), b"\xff"),
        f"partial merkle tree: {_KEY[0] + 1} hashes for fewer transactions",
    ),
    (
        "multisig public keys",
        lambda: assert_pub_key_num(decode_num(_KEY[:4])),
        "invalid number of public keys: 0 to 20 expected",
    ),
    (
        "multisig signatures",
        lambda: assert_signature_num(decode_num(_KEY[:4]), 3),
        "invalid number of signatures: 0 to the number of public keys expected",
    ),
    (
        "op code count",
        lambda: script_op_count(int.from_bytes(_KEY, "big"), 0),
        "more than 201 op codes",
    ),
    (
        "op code count increment",
        lambda: script_op_count(1, int.from_bytes(_KEY, "big")),
        "more than 201 op codes",
    ),
    # 0x38, the key's byte 4, leaves the sign bit clear: the zero after
    # it is a byte no minimal number has
    (
        "non-minimal number",
        _script([_KEY[3:5] + b"\x00", "OP_1ADD"], ScriptFlag.MINIMALDATA),
        "non-minimal number encoding of 3 bytes (command 1, stack depth 1)",
    ),
    (
        "pushdata past the script",
        _push(0x4D, _KEY[:2] + _KEY),
        "pushdata longer than the 32 bytes left in the script",
    ),
    (
        "pushdata past the element size",
        _push(0x4D, _KEY[:2] + bytes(0xD79E)),
        "pushdata longer than 520 bytes",
    ),
    # 0xf1, the key's byte 2, sets the sign bit of a three-byte number
    (
        "negative OP_PICK depth",
        _script(["OP_1", _KEY[:3], "OP_PICK"], ScriptFlag(0)),
        "negative OP_PICK depth (command 2, stack depth 1)",
    ),
    (
        "negative OP_ROLL depth",
        _script(["OP_1", _KEY[:3], "OP_ROLL"], ScriptFlag(0)),
        "negative OP_ROLL depth (command 2, stack depth 1)",
    ),
    (
        "OP_ROLL depth past the stack",
        _script(["OP_1", _KEY[3:5], "OP_ROLL"], ScriptFlag(0)),
        "OP_ROLL depth past a stack of 1 elements (command 2, stack depth 1)",
    ),
    (
        "negative lock time",
        _script([_KEY[:3], "OP_CHECKLOCKTIMEVERIFY"], _CLTV),
        "negative lock time (command 1, stack depth 1)",
    ),
    (
        "block height lock time",
        _script([_KEY[3:5], "OP_CHECKLOCKTIMEVERIFY"], _CLTV, lock_time=500_000_000),
        (
            "block height lock time against the timestamp lock time 500000000 of "
            "the transaction (command 1, stack depth 1)"
        ),
    ),
    (
        "timestamp lock time",
        _script([_KEY[3:7], "OP_CHECKLOCKTIMEVERIFY"], _CLTV),
        (
            "timestamp lock time against the block height lock time 0 of "
            "the transaction (command 1, stack depth 1)"
        ),
    ),
    (
        "lock time not reached",
        _script([_KEY[3:7], "OP_CHECKLOCKTIMEVERIFY"], _CLTV, lock_time=500_000_000),
        "lock time > 500000000 (command 1, stack depth 1)",
    ),
    (
        "negative sequence",
        _script([_KEY[:3], "OP_CHECKSEQUENCEVERIFY"], _CSV),
        "negative sequence (command 1, stack depth 1)",
    ),
    # 0x64cd3829, the key's bytes 3 to 6, sets the time type flag
    (
        "relative lock time unit",
        _script([_KEY[3:7], "OP_CHECKSEQUENCEVERIFY"], _CSV),
        (
            "relative lock time unit mismatch against the sequence 0x0 of input 0 "
            "(command 1, stack depth 1)"
        ),
    ),
    (
        "relative lock time not reached",
        _script([_KEY[3:7], "OP_CHECKSEQUENCEVERIFY"], _CSV, sequence=0x400000),
        "relative lock time > 0 (command 1, stack depth 1)",
    ),
    (
        "asm against hex",
        lambda: script_from_dict({"asm": "OP_RETURN", "hex": _KEY.hex()}),
        "asm does not match hex",
    ),
]


@pytest.mark.parametrize(
    "call, err_msg",
    [case[1:] for case in _CASES],
    ids=[case[0] for case in _CASES],
)
def test_a_refusal_prints_no_number_of_the_octets(
    call: Callable[[], object], err_msg: str
) -> None:
    """The refusal names the bound, the width or the field, never the value.

    `assert_secret_free` looks for pieces whose length `WINDOW` gives
    (`tests/secret_free/__init__.py`), so each byte of the key is also
    looked for as `0x` and its hex, and the text is compared whole, which
    is what finds a number written in decimal or bare hex.
    """
    with pytest.raises(BTClibValueError) as refusal:
        call()
    assert str(refusal.value) == err_msg
    # a cause or a context would be text the whole comparison does not see:
    # the one the script engine chains is the same refusal before it is
    # placed at its command
    assert all(err_msg.startswith(str(e)) for e in chained(refusal.value))
    assert_secret_free(refusal.value, [_KEY, str(int.from_bytes(_KEY, "big"))])
    for e in chained(refusal.value):
        text = text_of(e)
        assert all(f"0x{byte:02x}" not in text for byte in _KEY)


def test_a_bound_is_refused_one_past_it_and_not_at_it() -> None:
    """The count and the depth the refusals above name are bounded exactly.

    At the bound the parse goes on to what follows the count, and the
    depth reaches the bottom of the stack; one past it, each is refused.
    """
    at_most = var_int.serialize(MAX_ADDR_TO_SEND)
    with pytest.raises(BTClibValueError, match="^not enough data for the address"):
        AddrV2.parse(at_most)
    one_past = var_int.serialize(MAX_ADDR_TO_SEND + 1)
    err_msg = f"^invalid addresses count: at most {MAX_ADDR_TO_SEND} expected$"
    with pytest.raises(BTClibValueError, match=err_msg):
        AddrV2.parse(one_past)

    # two elements under the depth: 1 rolls the bottom one up, 2 is past it
    _script(["OP_1", "OP_2", "OP_1", "OP_ROLL"], ScriptFlag(0))()
    err_msg = r"^OP_ROLL depth past a stack of 2 elements \("
    with pytest.raises(BTClibValueError, match=err_msg):
        _script(["OP_1", "OP_2", "OP_2", "OP_ROLL"], ScriptFlag(0))()
