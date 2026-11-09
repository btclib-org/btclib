# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a refusal prints no byte of the octets it refuses.

Section 7 of the btclib-org standard, *A refusal carries no secret*: a
value refused as a public type may be a key passed in its place. Such a
refusal may print a version or prefix field only where the value has
its format's size and the field holds a value the format defines. Each
case below feeds a fixed random key where the refused field is read,
and checks the exact text and every exception of the chain (issue
#3005).
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from btclib import var_int
from btclib.exceptions import BTClibValueError
from btclib.key import PubKeyData
from btclib.p2p.compact_blocks import SendCmpct
from btclib.p2p.handshake import Version
from btclib.script import script_pub_key as spk
from btclib.script.engine import validate_push_only
from btclib.script.engine.script import op_code_name
from btclib.script.taproot import output_pubkey
from btclib.utreexo import Proof, Stump
from tests.secret_free import assert_secret_free, chained, text_of

# a fixed random key, as `assert_secret_free` asks
_KEY = bytes.fromhex("9ed7f12938cd646f2866d454cc247f688b857424cc4ee6bec49c16f1200bd5b9")

_ONE = (1).to_bytes(8, "little")

_CASES: list[tuple[str, Callable[[], object], str]] = [
    (
        "p2pk compressed marker",
        lambda: spk.assert_p2pk_var(_KEY[:1] + b"\x00" + _KEY + b"\xac"),
        "invalid pub_key length marker: 33 expected",
    ),
    (
        "p2pk uncompressed marker",
        lambda: spk.assert_p2pk_var(_KEY[:1] + b"\x04" + _KEY + _KEY + b"\xac"),
        "invalid pub_key length marker: 65 expected",
    ),
    (
        "p2pkh marker",
        lambda: spk.assert_p2pkh(b"\x76\xa9" + _KEY[:21] + b"\x88\xac"),
        "invalid pub_key hash length marker: 20 expected",
    ),
    (
        "p2sh marker",
        lambda: spk.assert_p2sh(b"\xa9" + _KEY[:21] + b"\x87"),
        "invalid redeem script hash length marker: 20 expected",
    ),
    (
        "nulldata marker",
        lambda: spk.assert_nulldata(b"\x6a" + _KEY),
        "invalid data length marker: 31 expected",
    ),
    (
        "nulldata OP_PUSHDATA1",
        lambda: spk.assert_nulldata(b"\x6a" + _KEY + _KEY + _KEY[:16]),
        "invalid data length marker: OP_PUSHDATA1 78 expected",
    ),
    (
        "nulldata OP_PUSHDATA1 marker",
        lambda: spk.assert_nulldata(b"\x6a\x4c" + _KEY + _KEY + _KEY[:15]),
        "invalid data length marker: OP_PUSHDATA1 78 expected",
    ),
    (
        "segwit version",
        lambda: spk.assert_segwit(_KEY),
        "invalid witness version: OP_0 or OP_1 to OP_16 expected",
    ),
    # 0x28, the key's byte 8, is a program length marker of 40
    (
        "segwit length",
        lambda: spk.assert_segwit(b"\x00" + _KEY[8:]),
        "invalid segwit script length: 25 bytes against its program length marker",
    ),
    (
        "p2wpkh version",
        lambda: spk.assert_p2wpkh(_KEY[:22]),
        "invalid witness version op code: OP_0 (0x00) expected",
    ),
    (
        "p2wpkh marker",
        lambda: spk.assert_p2wpkh(b"\x00" + _KEY[:21]),
        "invalid pub_key hash length marker: 20 expected",
    ),
    (
        "p2wsh version",
        lambda: spk.assert_p2wsh(_KEY + _KEY[:2]),
        "invalid witness version op code: OP_0 (0x00) expected",
    ),
    (
        "p2wsh marker",
        lambda: spk.assert_p2wsh(b"\x00" + _KEY + _KEY[:1]),
        "invalid redeem script hash length marker: 32 expected",
    ),
    (
        "p2tr version",
        lambda: spk.assert_p2tr(_KEY + _KEY[:2]),
        "invalid witness version op code: OP_1 (0x51) expected",
    ),
    (
        "p2tr marker",
        lambda: spk.assert_p2tr(b"\x51" + _KEY + _KEY[:1]),
        "invalid redeem script hash length marker: 32 expected",
    ),
    (
        "p2ms m",
        lambda: spk.assert_p2ms_var(_KEY + _KEY[:4] + b"\xae"),
        "invalid m in m-of-n",
    ),
    (
        "p2ms n above m",
        lambda: spk.assert_p2ms_var(b"\x51" + _KEY + _KEY[:3] + b"\xae"),
        "invalid n in m-of-n",
    ),
    # 0x29, the key's byte 3, is no count and is below OP_16's m
    (
        "p2ms n invalid and below m",
        lambda: spk.assert_p2ms_var(b"\x60" + _KEY + _KEY[:4] + b"\xae"),
        "invalid n in m-of-n",
    ),
    # 0x54, the key's byte 11, is OP_4, below OP_16's m
    (
        "p2ms n below m",
        lambda: spk.assert_p2ms_var(b"\x60" + _KEY + _KEY[:12] + b"\xae"),
        "invalid m-of-n: n below m",
    ),
    (
        "compressed SEC prefix",
        lambda: PubKeyData(b"\x00" + _KEY),
        "invalid compressed SEC prefix: 0x02 or 0x03 expected",
    ),
    (
        "uncompressed SEC prefix",
        lambda: PubKeyData(_KEY[:1] + _KEY + _KEY),
        "invalid uncompressed SEC prefix: 0x04 expected",
    ),
    (
        "hybrid SEC prefix",
        lambda: output_pubkey(PubKeyData(b"\x06" + _KEY, check_validity=False)),
        "invalid internal public key: hybrid SEC prefix",
    ),
    (
        "utreexo hash tag",
        lambda: Stump.parse(_ONE + _ONE + _KEY),
        "stump: invalid hash tag",
    ),
    (
        "utreexo target count",
        lambda: Proof.parse(_KEY),
        "proof: target count does not fit the data",
    ),
    (
        "utreexo hash count",
        lambda: Proof.parse(bytes(8) + _KEY),
        "proof: hash count does not fit the data",
    ),
    (
        "utreexo root count",
        lambda: Stump.parse(_KEY),
        "stump: root count does not match the leaf count",
    ),
    (
        "sendcmpct announce",
        lambda: SendCmpct.parse(_KEY[:9]),
        "invalid announce octet: 0 or 1 expected",
    ),
    (
        "version relay flag",
        lambda: Version.parse(Version().serialize() + _KEY[:1]),
        "invalid relay flag: 0 or 1 expected",
    ),
    # the module needs the `bip324` extra, and a run without it skips the row
    (
        "bip324 short id",
        lambda: pytest.importorskip("btclib.p2p.bip324").message_from_contents(_KEY),
        "unknown short message id",
    ),
    # 0x9e, the key's byte 0, is OP_NUMNOTEQUAL
    (
        "non-push op code",
        lambda: validate_push_only(_KEY),
        "non-push op code in the script_sig at byte 0",
    ),
    # 0xd7, the key's byte 1, is a byte OP_CODE_NAME_FROM_INT does not name
    (
        "unnamed non-push op code",
        lambda: validate_push_only(_KEY[1:]),
        "non-push op code in the script_sig at byte 0",
    ),
    (
        "unknown op code",
        lambda: op_code_name(_KEY[1]),
        "unknown op code",
    ),
    (
        "var_int too big",
        lambda: var_int.parse(b"\xff" + _KEY[:8]),
        "var_int too big: max is 02000000",
    ),
    (
        "var_int too big in one byte",
        lambda: var_int.parse(_KEY[:1], max_size=100),
        "var_int too big: max is 64",
    ),
    (
        "var_int non-canonical in 3 bytes",
        lambda: var_int.parse(b"\xfd" + _KEY[:1] + b"\x00"),
        "non-canonical var_int of 3 bytes",
    ),
    (
        "var_int non-canonical in 5 bytes",
        lambda: var_int.parse(b"\xfe" + _KEY[:2] + bytes(2)),
        "non-canonical var_int of 5 bytes",
    ),
    (
        "var_int non-canonical in 9 bytes",
        lambda: var_int.parse(b"\xff" + _KEY[:4] + bytes(4)),
        "non-canonical var_int of 9 bytes",
    ),
]


@pytest.mark.parametrize(
    "call, err_msg",
    [case[1:] for case in _CASES],
    ids=[case[0] for case in _CASES],
)
def test_a_refusal_prints_no_byte_of_the_octets(
    call: Callable[[], object], err_msg: str
) -> None:
    """The refusal names the field or what it expected, never the value.

    `assert_secret_free` looks for pieces whose length `WINDOW` gives
    (`tests/secret_free/__init__.py`), so each byte of the key is also
    looked for as `0x` and its hex, and the text is compared whole, which
    is what finds a byte or a number written in decimal or bare hex.
    """
    with pytest.raises(BTClibValueError) as refusal:
        call()
    assert str(refusal.value) == err_msg
    # a cause or a context would be text the whole comparison does not see
    assert list(chained(refusal.value)) == [refusal.value]
    assert_secret_free(refusal.value, [_KEY, str(int.from_bytes(_KEY, "big"))])
    for e in chained(refusal.value):
        text = text_of(e)
        assert all(f"0x{byte:02x}" not in text for byte in _KEY)
