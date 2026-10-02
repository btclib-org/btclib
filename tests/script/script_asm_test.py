# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `script_to_asm`, which is Bitcoin Core's `ScriptToAsmStr`.

Every row of `CASES` was put to bitcoind v31.1.0: `decodescript` gives
the second column, and `decoderawtransaction` on a transaction whose
`scriptSig` is the script gives the third, the one Core asks the sighash
decode for. `tests/integration/script_asm_test.py` puts the same rows,
and a generated corpus, to a live node.
"""

from __future__ import annotations

import pytest

from btclib.script import script_to_asm

# the signature and the key of Core's own `script_GetScriptAsm` test
# (src/test/script_tests.cpp); a hash type byte follows the signature
DER_SIG = (
    "304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a"
    "022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c5090"
)
PUB_KEY = "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2"
G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def _push(data: bytes) -> str:
    """Return the minimal push of data, as hex."""
    n = len(data)
    if n < 76:
        return bytes([n]).hex() + data.hex()
    if n < 256:
        return "4c" + bytes([n]).hex() + data.hex()
    return "4d" + n.to_bytes(2, "little").hex() + data.hex()


def _sig(hash_type: int) -> bytes:
    return bytes.fromhex(DER_SIG) + bytes([hash_type])


def _sighash_cases() -> list[tuple[str, str, str]]:
    """Return the six hash types Core names, and the ones it leaves as hex."""
    names = {
        0x01: "ALL",
        0x02: "NONE",
        0x03: "SINGLE",
        0x81: "ALL|ANYONECANPAY",
        0x82: "NONE|ANYONECANPAY",
        0x83: "SINGLE|ANYONECANPAY",
    }
    rows = []
    for hash_type in (0x00, 0x01, 0x02, 0x03, 0x04, 0x80, 0x81, 0x82, 0x83, 0x84):
        script = _push(_sig(hash_type)) + _push(bytes.fromhex(PUB_KEY))
        plain = DER_SIG + f"{hash_type:02x}" + " " + PUB_KEY
        name = names.get(hash_type)
        decoded = plain if name is None else f"{DER_SIG}[{name}] {PUB_KEY}"
        rows.append((script, plain, decoded))
    return rows


def _der(r: str, s: str) -> str:
    """Return a signature of the given R and S, hash type ALL included."""
    body = f"02{len(r) // 2:02x}{r}02{len(s) // 2:02x}{s}"
    return f"30{len(body) // 2:02x}{body}01"


def _set(sig: str, byte_index: int, value: int) -> str:
    """Return sig with one byte replaced."""
    return sig[: 2 * byte_index] + f"{value:02x}" + sig[2 * byte_index + 2 :]


def _der_cases() -> list[tuple[str, str, str]]:
    """Return signatures that break each rule of IsValidSignatureEncoding.

    One rule each, from the 9-byte signature of R = S = 1.
    """
    small = _der("01", "01")
    accepted = [
        small,  # the shortest
        _der("00ff", "01"),  # a zero before a high bit
        _der("01", "00ff"),
        _der("7f" * 32, "7f" * 32),
        _der("00" + "ff" * 32, "00" + "ff" * 32),  # the longest, 73 bytes
    ]
    refused = [
        _der("7f" * 34, "7f" * 33),  # 74 bytes
        "30" + "00" * 8,  # 9 bytes, none of the rules met
        small[:-2],  # 8 bytes
        _set(small, 0, 0x31),  # not a sequence
        _set(small, 1, 0x07),  # a total length one too long
        _set(small, 1, 0x05),  # and one too short
        _set(small, 2, 0x03),  # R not an integer
        _set(small, 3, 0x00),  # R empty
        _set(small, 3, 0x7F),  # R's length runs past the end
        _set(small, 3, 0x03),  # R's length reaches S's
        _set(small, 4, 0x80),  # R negative
        _der("0001", "01"),  # R padded for nothing
        _set(small, 4 + 1, 0x03),  # S not an integer
        _set(small, 6, 0x00),  # S empty
        _set(small, 6, 0x02),  # S's length too long
        _set(small, 7, 0x80),  # S negative
        _der("01", "0001"),  # S padded for nothing
    ]
    rows = [(_push(bytes.fromhex(sig)), sig, sig[:-2] + "[ALL]") for sig in accepted]
    rows += [(_push(bytes.fromhex(sig)), sig, sig) for sig in refused]
    return rows


def _row(script: str, asm: str, asm_decoded: str | None = None) -> tuple[str, str, str]:
    return script, asm, asm if asm_decoded is None else asm_decoded


def _sized_cases() -> list[tuple[str, str, str]]:
    """Return a signature and padding of MAX_SCRIPT_SIZE bytes, and one more."""
    sig = _push(_sig(0x01))
    rows = []
    for size in (10000, 10001):
        pad = size - len(sig) // 2
        script = sig + "61" * pad
        plain = " ".join([DER_SIG + "01"] + ["OP_NOP"] * pad)
        decoded = plain if size > 10000 else plain.replace("01 ", "[ALL] ", 1)
        rows.append((script, plain, decoded))
    return rows


CASES: list[tuple[str, str, str]] = [
    # the table of the issue that asked for this function
    _row("0151", "81"),
    _row("4c0101", "1"),
    _row("6a026869", "OP_RETURN 26984"),
    _row("21" + G[:66] + "ac", G[:66] + " OP_CHECKSIG"),
    _row("ff", "OP_INVALIDOPCODE"),
    # the empty script is the empty string
    _row("", ""),
    # the op codes that are numbers, and those named by a mistake
    _row("00", "0"),
    _row("4f", "-1"),
    _row("50", "OP_RESERVED"),
    _row("51", "1"),
    _row("60", "16"),
    _row("61", "OP_NOP"),
    _row("b0", "OP_NOP1"),
    _row("b1", "OP_CHECKLOCKTIMEVERIFY"),
    _row("b2", "OP_CHECKSEQUENCEVERIFY"),
    _row(f"{0xBA:02x}51", "OP_CHECKSIGADD 1"),
    _row("bb", "OP_UNKNOWN"),
    _row("fe", "OP_UNKNOWN"),
    _row("7e", "OP_CAT"),
    _row(
        "76a914" + "ab" * 20 + "88ac",
        "OP_DUP OP_HASH160 " + "ab" * 20 + " OP_EQUALVERIFY OP_CHECKSIG",
    ),
    # a push of up to four bytes is a number, whatever its width or its sign
    _row("0100", "0"),
    _row("0180", "0"),
    _row("0181", "-1"),
    _row("01ff", "-127"),
    _row("0200ff", "-32512"),
    _row("0201ff", "-32513"),
    _row("0281ff", "-32641"),
    _row("0300000000", "0 0"),  # a push of three bytes, then OP_0
    _row("04ffffff7f", "2147483647"),
    _row("04ffffffff", "-2147483647"),
    _row("0400000080", "0"),
    _row("4c0100", "0"),
    _row("4d010081", "-1"),
    _row("4e0100000081", "-1"),
    # five bytes and longer is hex
    _row("05" + "0000000001", "0000000001"),
    _row("05ffffffffff", "ffffffffff"),
    _row("4c05" + "00" * 5, "00" * 5),
    _row("4d0500" + "01" * 5, "01" * 5),
    _row("4e05000000" + "02" * 5, "02" * 5),
    _row(_push(b"\xab" * 75), "ab" * 75),
    _row(_push(b"\xab" * 76), "ab" * 76),
    _row(_push(b"\xab" * 255), "ab" * 255),
    _row(_push(b"\xab" * 256), "ab" * 256),
    _row(_push(b"\xab" * 521), "ab" * 521),
    # a push cut short ends the string, and whatever came before stays
    _row("01", "[error]"),
    _row("02aa", "[error]"),
    _row("4c", "[error]"),
    _row("4c05aa", "[error]"),
    _row("4d01", "[error]"),
    _row("4d0500aa", "[error]"),
    _row("4e010000", "[error]"),
    _row("4eaaaaaaff", "[error]"),
    _row("51" + "02ff", "1 [error]"),
    _row("5151" + "4c", "1 1 [error]"),
    # OP_RETURN data
    _row("6a4c05" + "68656c6c6f", "OP_RETURN 68656c6c6f"),
    _row("6a" + _push(_sig(0x01)), "OP_RETURN " + DER_SIG + "01"),
    # a push of five bytes or more that is a signature, and what follows it
    *_sighash_cases(),
    *((script, plain, decoded) for script, plain, decoded in _der_cases()),
    # decoded in the middle of a script, and up to MAX_SCRIPT_SIZE bytes
    _row(
        "61" + _push(_sig(0x01)),
        "OP_NOP " + DER_SIG + "01",
        "OP_NOP " + DER_SIG + "[ALL]",
    ),
    *_sized_cases(),
]


@pytest.mark.parametrize(
    "script, asm, asm_decoded", CASES, ids=[row[0][:24] for row in CASES]
)
def test_script_to_asm(script: str, asm: str, asm_decoded: str) -> None:
    """Match Core with and without the sighash decode."""
    assert script_to_asm(bytes.fromhex(script)) == asm
    assert (
        script_to_asm(bytes.fromhex(script), attempt_sighash_decode=True) == asm_decoded
    )
