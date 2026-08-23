# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.script.script` module."""

from __future__ import annotations

from typing import Any

import pytest
from typing_extensions import override

from btclib.alias import ScriptList
from btclib.exceptions import BTClibValueError
from btclib.script import (
    Script,
    op_int,
    parse,
    push_int,
    script_from_dict,
    script_to_dict,
    serialize,
)
from btclib.script.script import (
    BYTE_FROM_OP_CODE_NAME,
    ERROR_COMMAND,
    OP_CODE_NAME_FROM_INT,
    op_code_spans,
    read_op_code,
)
from btclib.utils import encode_num, hex_string
from tests import load, vector_id
from tests.script import serialize_non_canonical


def test_operators() -> None:
    """Verify the two op code tables agree, aliases and gaps aside."""
    for i, name in OP_CODE_NAME_FROM_INT.items():
        b = BYTE_FROM_OP_CODE_NAME[name]
        assert i == b[0]
    for name, code in BYTE_FROM_OP_CODE_NAME.items():
        # skip duplicated
        if name in {"OP_FALSE", "OP_TRUE", "OP_NOP2", "OP_NOP3"}:
            continue
        i = code[0]
        assert name == OP_CODE_NAME_FROM_INT[i]
    for i in range(76, 186):
        # skip disabled 'splice' opcodes
        if i in {126, 127, 128, 129}:
            continue
        # skip disabled 'bitwise logic' opcodes
        if i in {131, 132, 133, 134}:
            continue
        # skip disabled 'splice' opcodes
        if i in {141, 142, 149, 150, 151, 152, 153}:
            continue
        # skip 'reserved' opcodes
        if i in {80, 98, 101, 102, 137, 138}:
            continue
        assert i in OP_CODE_NAME_FROM_INT


def test_op_int() -> None:
    """Verify op_int names -1 to 16 and refuses 17."""
    assert op_int(-1) == "OP_1NEGATE"
    for i in range(17):
        assert op_int(i) == f"OP_{i}"

    err_msg = "invalid OP_INT: "
    with pytest.raises(BTClibValueError, match=err_msg):
        op_int(17)


def test_push_int_is_the_shortest_command_that_pushes_a_number() -> None:
    """The op code where there is one, the CScriptNum encoding above it.

    One byte from -1 to 16 and the push of the encoded number after
    that, which is the choice `op_int` refuses to make and `encode_num`
    knows nothing about. Minimal at the boundary, 16 against 17 being
    where a caller writing it by hand goes wrong, and minimal is what
    the consumers require: `parse` reads back what was written, and
    nothing is warned about, a warning being what `serialize` answers
    the caller who passed the integer instead.
    """
    for i in range(-1, 17):
        assert push_int(i) == op_int(i)
        assert len(serialize([push_int(i)])) == 1

    assert push_int(17) == "11"
    assert serialize([push_int(17)]) == b"\x01\x11"
    assert push_int(144) == encode_num(144).hex()
    # the numbers a script writes as a push, sign included, read back as
    # the very bytes `encode_num` writes -- `parse` spelling its hex in
    # upper case, which is the one difference between the two spellings
    for i in (-2, 127, 128, 255, 256, 2**31 - 1):
        assert parse(serialize([push_int(i)])) == [encode_num(i).hex().upper()]


def test_serialize_bytes_command() -> None:
    """Verify the push overhead grows at the 76- and 256-byte thresholds."""
    length = 75
    b = b"\x0a" * length
    assert len(serialize([b])) == length + 1
    b = b"\x0a" * (length + 1)
    assert len(serialize([b])) == (length + 1) + 2

    length = 255
    b = b"\x0a" * length
    assert len(serialize([b])) == length + 2
    b = b"\x0a" * (length + 1)
    assert len(serialize([b])) == (length + 1) + 3


def test_a_data_command_is_never_a_numeric_op_code() -> None:
    """Verify the values with an op code are still pushed as data.

    The set Core's `CheckMinimalPush` names -- the empty push, 1 to 16
    and 0x81 -- is the set with a one-byte op code of its own, and
    `serialize` reaches for none of them from a bytes command, a hex
    string or an integer: data is data, and `push_int` is where a caller
    that means a number says so (issue #646). The empty push is the one
    place the two spellings are the same byte, a zero-length push being
    OP_0 already.
    """
    assert serialize([b""]) == BYTE_FROM_OP_CODE_NAME["OP_0"]
    for i in range(1, 17):
        assert serialize([bytes([i])]) == bytes([1, i])
        assert serialize([bytes([i]).hex()]) == bytes([1, i])
        assert serialize_non_canonical([i]) == bytes([1, i])
        assert serialize([push_int(i)]) == BYTE_FROM_OP_CODE_NAME[f"OP_{i}"]
    assert serialize([b"\x81"]) == b"\x01\x81"
    assert serialize_non_canonical([-1]) == b"\x01\x81"
    assert serialize([push_int(-1)]) == BYTE_FROM_OP_CODE_NAME["OP_1NEGATE"]

    # a push of one zero byte is data of one byte, which is what Core's
    # CheckMinimalPush measures it as: OP_0 pushes no bytes at all, so
    # the two are not the same push and this one is minimal already --
    # the only value in the set for which reaching for the op code would
    # change what lands on the stack, and not merely how it is spelled
    assert serialize([b"\x00"]) == b"\x01\x00"

    # the integer zero is not that push: its encoding is the empty
    # vector, whose push is OP_0, so the data and the op code coincide
    # and the warning the rest of the range gets has nothing to say
    assert serialize([0]) == BYTE_FROM_OP_CODE_NAME["OP_0"]

    # what parse hands back for such a push is its hex, and serializing
    # that writes the push it read: the round trip is what a substitution
    # would break, silently and for every one-byte push in a script
    assert parse(b"\x01\x01") == ["01"]
    assert serialize(parse(b"\x01\x01")) == b"\x01\x01"


def test_add_and_eq() -> None:
    """Verify Script + Script concatenates and refuses raw bytes."""
    script_1 = serialize(["OP_2", "OP_3", "OP_ADD", "OP_5"])
    script_2 = serialize(["OP_EQUAL"])
    assert Script(script_1) + Script(script_2) == Script(script_1 + script_2)

    with pytest.raises(TypeError):
        _ = Script(script_1) + script_2  # type: ignore[operator]


def test_simple_scripts() -> None:
    """Round-trip a sample of scripts through serialize and parse."""
    script_list: list[ScriptList] = [
        ["OP_2", "OP_3", "OP_ADD", "OP_5", "OP_EQUAL"],
        [0x1ADD, "OP_1ADD", 0x1ADE, "OP_EQUAL"],
        [26, "OP_1NEGATE", "OP_ADD", 26, "OP_EQUAL"],
        [0x7FFFFFFF, "OP_1NEGATE", "OP_ADD", 0x7FFFFFFF, "OP_EQUAL"],
        [0x80000000, "OP_1NEGATE", "OP_ADD", 0x7FFFFFFF, "OP_EQUAL"],
        [0xFFFFFFFF - 1, "OP_1NEGATE", "OP_ADD", 0x7FFFFFFF, "OP_EQUAL"],
        [0xFFFFFFFF, "OP_1NEGATE", "OP_ADD", 0x7FFFFFFF, "OP_EQUAL"],
        ["1F" * 250, "OP_DROP"],
        ["1F" * 520, "OP_DROP"],
    ]
    for script_pub_key in script_list:
        serialized_script = serialize(script_pub_key)
        assert serialized_script == serialize(parse(serialized_script))
        assert serialized_script == serialize(parse(serialized_script.hex()))


def test_exceptions() -> None:
    """Refuse an unknown OP_ string and a command of the wrong type."""
    script_pub_key: ScriptList = ["OP_2", "OP_3", "OP_ADD", "OP_5", "OP_RETURN_244"]
    err_msg = "invalid string command: OP_RETURN_244"
    with pytest.raises(BTClibValueError, match=err_msg):
        serialize(script_pub_key)

    with pytest.raises(TypeError):
        serialize(["OP_2", "OP_3", "OP_ADD", "OP_5", serialize])  # type: ignore[list-item]


def test_pushdata4_and_the_only_length_left_to_refuse() -> None:
    """All four push widths are written, and read back.

    A push over 520 bytes is one the stack cannot hold, i.e. a script
    nobody can spend, and there are such scripts on chain (issue #123):
    unspendable is not unencodable, so what serialize refuses is only a
    length no length field can carry.
    """
    for length, op_code, head in ((65535, 0x4D, 3), (65536, 0x4E, 5)):
        data = b"\x0a" * length
        script = serialize([data])
        assert script[0] == op_code
        assert len(script) == length + head
        assert parse(script) == [data.hex().upper()]

    # __len__ lies rather than have the test allocate four gibibytes
    class TooLong(bytes):
        @override
        def __len__(self) -> int:
            return 4294967296

    err_msg = "too many bytes for OP_PUSHDATA: "
    with pytest.raises(BTClibValueError, match=err_msg):
        serialize([TooLong()])


def test_nulldata() -> None:
    """Round-trip OP_RETURN scripts carrying 79-byte payloads."""
    scripts: list[ScriptList] = [["OP_RETURN", "1A" * 79], ["OP_RETURN", "0A" * 79]]
    for script_pub_key in scripts:
        assert script_pub_key == parse(serialize(script_pub_key))
        assert script_pub_key == parse(serialize(script_pub_key).hex())


def test_encoding() -> None:
    """Round-trip the BIP141 'Hello SegWit' bytes through parse."""
    script_bytes = b"jKBIP141 \\o/ Hello SegWit :-) keep it strong! LLAP Bitcoin twitter.com/khs9ne"
    assert serialize(parse(script_bytes)) == script_bytes


def test_truncated_push_ends_the_parse() -> None:
    """A push running past the end stops the walk, and marks the place.

    Core's GetOp returns false there and its ScriptToAsmStr appends the
    literal "[error]"; both are the only refusal a decode has, and this
    is that refusal. What follows the mark is not decoded, because there
    is nothing to decode it as -- and Esplora prints "<push past end>"
    at the same offset for the very scripts of issue #123.
    """
    # a length field cut short, and data short of its length
    assert parse(b"\x4e\x00") == [ERROR_COMMAND]
    assert parse(b"\x40\x00") == [ERROR_COMMAND]

    # what came before it is kept, and the mark is terminal
    assert parse(b"\x51\x4c\x05\xaa\xbb") == ["OP_1", ERROR_COMMAND]

    # the mark cannot be serialized back: it is a place, not a command,
    # where UNKNOWN_OP_CODE_n is a byte of an executable script and must
    # round-trip
    with pytest.raises(BTClibValueError, match=r"invalid string command: \[ERROR\]"):
        serialize([ERROR_COMMAND])

    # 0xff, Core's OP_INVALIDOPCODE, which no soft fork can name: an op
    # code all the same, refused by the interpreter that executes it and
    # named here so that serialize writes it back unchanged
    assert parse(b"\x01\x00\xff") == ["00", "UNKNOWN_OP_CODE_255"]
    assert serialize(parse(b"\x01\x00\xff")) == b"\x01\x00\xff"


def unspendable_script_pub_key_vectors() -> list[Any]:
    """Return the twelve script_pub_keys of issue #123, one case each.

    tests/_data/README.md records where they come from. Real ones and not
    a synthetic equivalent: what the issue reports is that these could
    not be read, so anything else would exercise the code without closing
    the report.
    """
    data = load("script", "_data", "unspendable_script_pub_keys.json")
    return [
        pytest.param(v, id=vector_id(v["height"], v["txid"][:8], f"vout{v['vout']}"))
        for v in data
    ]


@pytest.mark.parametrize("vector", unspendable_script_pub_key_vectors())
def test_an_unspendable_script_pub_key_still_decodes(vector: dict[str, Any]) -> None:
    """A script no one can spend is a script all the same.

    Five transactions in blocks 251718 to 299571 carry one, and every
    Script built from them used to raise: two push more than the stack
    can hold, ten declare a push longer than the bytes that follow it
    (issue #123). Bitcoin Core reads all twelve, and so does btclib now
    -- byte for byte where nothing is missing, and up to the place it
    stops where something is.
    """
    script = bytes.fromhex(vector["script"])
    asm = Script(script).asm

    assert len(asm) == vector["commands"]
    if vector["truncated"]:
        # the mark is terminal, and it is the only one
        assert asm[-1] == ERROR_COMMAND
        assert asm.count(ERROR_COMMAND) == 1
    else:
        # nothing was lost, which for an oversized push means that
        # serialize wrote the same OP_PUSHDATA back
        assert ERROR_COMMAND not in asm
        assert serialize(asm) == script


def test_regressions() -> None:
    """Round-trip past regressions, the warned non-canonical ones apart."""
    script_list: list[ScriptList] = [
        ["OP_1"],
        [51],
        [b"\x01"],
        ["01"],
        ["AA"],
        ["aa"],
        ["AAAA"],
        [""],
        [b""],
        [0],
        ["OP_0"],
        ["OP_1NEGATE"],
        [0x81],
        ["81"],
    ]
    for s in script_list:
        serialized = serialize(s)
        assert serialize(parse(serialized)) == serialized

    # the two regressions that serialize() warns about, kept apart from
    # the others so that the warning is asserted rather than ignored: a
    # simplefilter("ignore") around the loop above would hide it, and
    # with it any other warning the loop raises. Zero is not one of them
    # any more, OP_0 being what its empty encoding is pushed as
    non_canonical: list[ScriptList] = [[1], [-1]]
    for s in non_canonical:
        serialized = serialize_non_canonical(s)
        assert serialize(parse(serialized)) == serialized


def test_null_serialization() -> None:
    """Verify empty pushes read back as OP_0, and the 0/16 borderline."""
    empty_script: ScriptList = []
    assert empty_script == parse(b"")
    assert serialize(empty_script) == b""

    assert parse(serialize([""])) == ["OP_0"]
    assert parse(serialize([" "])) == ["OP_0"]
    assert parse(serialize([b""])) == ["OP_0"]
    assert parse(serialize([b" "])) == ["20"]

    # zero is the empty vector, so pushing it as data is OP_0 and warns
    # not: the op code and the push are the same byte
    assert serialize([0]) == b"\x00"
    assert parse(serialize([0])) == ["OP_0"]

    # 16 has a one-byte op code the data push is not, so it warns
    assert serialize_non_canonical([16]) == b"\x01\x10"
    assert parse(serialize_non_canonical([16])) == ["10"]

    # 17 has none, and warns not
    assert serialize([17]) == b"\x01\x11"
    assert parse(serialize([17])) == ["11"]

    assert serialize(["10"]) == b"\x01\x10"
    assert serialize(["11"]) == b"\x01\x11"

    assert serialize(["OP_16"]) == b"\x60"
    assert parse(serialize(["OP_16"])) == ["OP_16"]


def test_op_int_serialization() -> None:
    """Round-trip OP_1NEGATE to OP_16 through one-byte serializations."""
    for i in range(-1, 17):
        op_int_str = f"OP_{i}" if i > -1 else "OP_1NEGATE"
        serialized_op_int = serialize([op_int_str])
        assert len(serialized_op_int) == 1
        assert [op_int_str] == parse(serialized_op_int)


def test_integer_serialization() -> None:
    """Verify integers parse back as data, warned only in [0, 16]."""
    assert parse(b"\x00") == ["OP_0"]

    # [1, 16] is exactly the range with a shorter op code form, so every
    # serialize() below warns; from 17 on, none does, and zero is the op
    # code itself
    assert serialize([0]) == b"\x00"
    for i in range(1, 17):
        serialized_int = serialize_non_canonical([i])
        assert [hex_string(i)] == parse(serialized_int)

    for i in range(17, 128):
        serialized_int = serialize([i])  # e.g., i = 26
        assert [hex_string(i)] == parse(serialized_int)

    for i in range(128, 256):
        serialized_int = serialize([i])


def test_serialize_refuses_a_number_wider_than_an_int64() -> None:
    """Serialize writes only the script numbers Core's int64_t can hold.

    A number reaches a script through `CScript::operator<<(int64_t)`,
    which has no wider parameter, so an unbounded Python int writes a
    push no node can have built -- 13 octets for 2**100, 26 for 2**200
    -- and one the interpreter cannot read back either, capping every
    operand at four bytes (issue #406).

    Both extremes serialize: the eight-octet largest, and the nine-octet
    most negative.
    """
    assert serialize([2**63 - 1]) == bytes.fromhex("08ffffffffffffff7f")
    assert serialize([-(2**63)]) == bytes.fromhex("09000000000000008080")

    for i in (2**63, -(2**63) - 1, 2**100, 2**200, -(2**100)):
        with pytest.raises(BTClibValueError, match="script number out of range: "):
            serialize([i])


def test_single_byte_serialization() -> None:
    """Round-trip every single-byte hex string as a two-byte push."""
    for i in range(256):
        hex_str = hex_string(i)  # e.g., "1A"
        serialized_byte = serialize([hex_str])
        assert len(serialized_byte) == 2
        assert serialized_byte[0] == 1
        assert [hex_str] == parse(serialized_byte)


def test_read_op_code() -> None:
    """The walk agrees with parse on where each op code ends.

    Which is all that is asked of it, and what makes a script code a
    slice: parse says what the op codes are, this says where they are.
    """
    for script, expected in (
        (b"", []),
        (b"\xac", [(0xAC, 0, 1)]),
        (b"\x00\x51", [(0x00, 0, 1), (0x51, 1, 2)]),  # OP_0 is not a push
        (b"\x01\xff\xac", [(0x01, 0, 2), (0xAC, 2, 3)]),
        (b"\x4c\x01\xff", [(0x4C, 0, 3)]),  # OP_PUSHDATA1 of the same byte
        (b"\x4d\x01\x00\xff", [(0x4D, 0, 4)]),  # OP_PUSHDATA2
        (b"\x4e\x01\x00\x00\x00\xff", [(0x4E, 0, 6)]),  # OP_PUSHDATA4
    ):
        spans = list(op_code_spans(script))
        assert spans == expected
        # the spans tile the script, and there are as many of them as
        # parse finds commands
        assert b"".join(script[start:stop] for _, start, stop in spans) == script
        assert len(spans) == len(parse(script))

    # nothing whole to read: past the end, and three ways to be truncated
    assert read_op_code(b"\xac", 1) is None
    assert read_op_code(b"\x02\xff", 0) is None  # data short of its length
    assert read_op_code(b"\x4c", 0) is None  # no length byte at all
    assert read_op_code(b"\x4d\x01", 0) is None  # half a length
    # a push over 520 bytes is not this walk's to refuse, as it is not
    # Core's GetOp's: the limit is on what reaches the stack
    assert read_op_code(b"\x4d\x09\x02" + b"\x00" * 521, 0) == (0x4D, 524)


P2PKH = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
P2PKH_ASM = (
    "OP_DUP OP_HASH160 751E76E8199196D454941C45D1B3A323F1433BD6 "
    "OP_EQUALVERIFY OP_CHECKSIG"
)


def test_script_to_dict() -> None:
    """The two renderings Bitcoin Core's RPC gives of one script."""
    assert script_to_dict(bytes.fromhex(P2PKH)) == {"asm": P2PKH_ASM, "hex": P2PKH}

    # the empty script is empty in both, where Core omits the key: every
    # btclib to_dict emits every field
    assert script_to_dict(b"") == {"asm": "", "hex": ""}

    # asm is Script.asm with a space between its commands, and nothing
    # else, so the sentinel of a script that stops being one reaches it
    assert script_to_dict(b"\x51\x02\xff") == {
        "asm": f"OP_1 {ERROR_COMMAND}",
        "hex": "5102ff",
    }


def test_script_from_dict() -> None:
    """Take the script from hex; asm is checked against it, not believed."""
    script = bytes.fromhex(P2PKH)

    # the round trip, and the same answer with no asm to check
    assert script_from_dict({"asm": P2PKH_ASM, "hex": P2PKH}) == script
    assert script_from_dict({"hex": P2PKH}) == script

    # the shape to_dict emitted before this one, still read: a stored
    # dict from an older btclib carries the hex alone
    assert script_from_dict(P2PKH) == script
    assert script_from_dict(script) == script
    assert script_from_dict("") == b""


def test_script_from_dict_refuses_a_disagreeing_asm() -> None:
    """A hand-edited asm is refused rather than ignored.

    Ignoring it would leave a stored dict whose human-readable field
    describes a script the bytes do not hold -- and every consumer of
    that field, a diff or a review among them, reading it as if it did.
    """
    with pytest.raises(BTClibValueError, match="asm does not match hex: "):
        script_from_dict({"asm": "OP_DUP OP_HASH160", "hex": P2PKH})

    # the empty asm of a non-empty script is a disagreement too, and not
    # an absent field: what is absent is what `to_dict` never wrote
    with pytest.raises(BTClibValueError, match="asm does not match hex: "):
        script_from_dict({"asm": "", "hex": P2PKH})

    # and the message names both, the one given and the one hex decodes to
    with pytest.raises(BTClibValueError, match=P2PKH_ASM):
        script_from_dict({"asm": "OP_RETURN", "hex": P2PKH})
