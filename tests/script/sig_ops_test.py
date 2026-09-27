# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.script.sig_ops` module.

Bitcoin Core's `CScript::GetSigOpCount`, both overloads, and
`CountWitnessSigOps`. Every case here is a script or an input, because
that is what the functions read: the legacy sums over a transaction are
asserted where they live, `Tx.sig_op_count` in `tests/tx/tx_test.py` and
`Block.sig_op_count` in `tests/block/block_test.py` and
`tests/block/blockfilters_test.py`, and the whole cost in
`tests/script_engine/sig_op_cost_test.py`.

The cases named `core-` are Core's `GetSigOpCount` test case in
src/test/sigopcount_tests.cpp, re-expressed; the others are read off
Core's source, the functions each test's docstring names.
"""

import pytest

from btclib.exceptions import BTClibTypeError
from btclib.hashes import hash160, sha256
from btclib.script import (
    Witness,
    p2sh_sig_op_count,
    serialize,
    sig_op_count,
    witness_sig_op_count,
)
from btclib.script.limits import MAX_PUBKEYS_PER_MULTISIG

_KEY = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)

_MAX = MAX_PUBKEYS_PER_MULTISIG


@pytest.mark.parametrize(
    "count, script",
    [
        pytest.param(0, b"", id="an-empty-script-announces-nothing"),
        pytest.param(1, serialize([_KEY, "OP_CHECKSIG"]), id="p2pk"),
        pytest.param(1, serialize([_KEY, "OP_CHECKSIGVERIFY"]), id="the-verify-form"),
        pytest.param(
            2,
            serialize([_KEY, "OP_CHECKSIG", _KEY, "OP_CHECKSIG"]),
            id="one-each",
        ),
        pytest.param(
            _MAX,
            serialize(["OP_1", _KEY, _KEY, "OP_2", "OP_CHECKMULTISIG"]),
            id="a-1-of-2-costs-twenty-not-two",
        ),
        pytest.param(
            _MAX,
            serialize(["OP_1", _KEY, "OP_1", "OP_CHECKMULTISIGVERIFY"]),
            id="and-so-does-the-verify-form",
        ),
        pytest.param(
            2 * _MAX + 1,
            serialize(["OP_CHECKMULTISIG", "OP_CHECKMULTISIGVERIFY", "OP_CHECKSIG"]),
            id="the-op-codes-alone-are-what-is-counted",
        ),
        pytest.param(0, bytes.fromhex("01ac"), id="an-op-code-byte-pushed-is-data"),
        pytest.param(
            1, bytes.fromhex("01acac"), id="and-the-byte-after-the-push-is-not"
        ),
        pytest.param(0, bytes.fromhex("4bac"), id="a-truncated-push-ends-the-walk"),
        pytest.param(
            1, bytes.fromhex("ac4bac"), id="what-was-read-before-it-is-counted"
        ),
    ],
)
def test_sig_op_count(count: int, script: bytes) -> None:
    """The four op codes that count, and the three things that do not.

    Data is not an op code; a truncated push ends the walk without an
    exception, Core's loop `break`ing where `GetOp` returns false; and the
    keys a multisig pushes do not change its cost, `fAccurate` being false
    here, so every `OP_CHECKMULTISIG` costs `MAX_PUBKEYS_PER_MULTISIG`
    whatever it would actually check.

    An `OP_CHECKSIG` with nothing to check is still an `OP_CHECKSIG`: the
    count is what the bytes announce, which is what makes it computable
    without the outputs being spent.
    """
    assert sig_op_count(script) == count
    # Octets, as the rest of the public surface takes them
    assert sig_op_count(script.hex()) == count


# what Core's test case builds: a 1-of-2 multisig over two 20-byte dummies,
# with a conditional OP_CHECKSIG after it, and a 1-of-3 over three keys
_DUMMY = b"\x00" * 20
_S1 = serialize(
    [
        "OP_1",
        _DUMMY,
        _DUMMY,
        "OP_2",
        "OP_CHECKMULTISIG",
        "OP_IF",
        "OP_CHECKSIG",
        "OP_ENDIF",
    ]
)
_S2 = serialize(["OP_1", _KEY, _KEY, _KEY, "OP_3", "OP_CHECKMULTISIG"])


def _p2sh(redeem_script: bytes) -> bytes:
    return serialize(["OP_HASH160", hash160(redeem_script), "OP_EQUAL"])


def _p2wsh(witness_script: bytes) -> bytes:
    return serialize(["OP_0", sha256(witness_script)])


_P2WPKH = serialize(["OP_0", hash160(_KEY)])


@pytest.mark.parametrize(
    "legacy, accurate, script",
    [
        pytest.param(0, 0, b"", id="core-an-empty-script"),
        pytest.param(
            _MAX,
            2,
            serialize(["OP_1", _DUMMY, _DUMMY, "OP_2", "OP_CHECKMULTISIG"]),
            id="core-a-1-of-2",
        ),
        pytest.param(_MAX + 1, 3, _S1, id="core-and-an-op-checksig"),
        pytest.param(_MAX, 3, _S2, id="core-a-1-of-3"),
        pytest.param(0, 0, _p2sh(_S2), id="core-its-p2sh-script-pub-key"),
        pytest.param(
            _MAX,
            16,
            serialize(["OP_16", "OP_CHECKMULTISIGVERIFY"]),
            id="op-16-is-sixteen",
        ),
        pytest.param(
            _MAX,
            _MAX,
            serialize(["OP_0", "OP_CHECKMULTISIG"]),
            id="op-0-is-no-op-n",
        ),
        pytest.param(
            _MAX,
            _MAX,
            serialize(["OP_1NEGATE", "OP_CHECKMULTISIG"]),
            id="nor-is-op-1negate",
        ),
        pytest.param(
            _MAX, _MAX, serialize(["OP_CHECKMULTISIG"]), id="nor-is-nothing-at-all"
        ),
        pytest.param(
            _MAX, _MAX, bytes.fromhex("0160ae"), id="nor-is-an-op-16-byte-pushed"
        ),
        pytest.param(
            2 * _MAX,
            2 + _MAX,
            serialize(["OP_2", "OP_CHECKMULTISIG", "OP_CHECKMULTISIG"]),
            id="only-the-op-code-right-before-counts",
        ),
    ],
)
def test_accurate_sig_op_count(legacy: int, accurate: int, script: bytes) -> None:
    """`accurate` is Core's `fAccurate`, of `CScript::GetSigOpCount(bool)`.

    An `OP_CHECKMULTISIG` costs the number of the `OP_1` to `OP_16` right
    before it, and `MAX_PUBKEYS_PER_MULTISIG` after any other op code:
    `OP_0` and `OP_1NEGATE` are outside the range Core tests, a byte
    pushed as data is not an op code, and Core's `lastOpcode` starts as
    `OP_INVALIDOPCODE`, no `OP_n`, before the first op code is read.
    """
    assert sig_op_count(script) == legacy
    assert sig_op_count(script, accurate=False) == legacy
    assert sig_op_count(script, accurate=True) == accurate
    assert sig_op_count(script.hex(), accurate=True) == accurate


@pytest.mark.parametrize(
    "count, script_sig, script_pub_key",
    [
        pytest.param(3, serialize(["OP_0", _S1]), _p2sh(_S1), id="core-p2sh-of-s1"),
        pytest.param(
            3,
            serialize(["OP_1", _DUMMY, _DUMMY, _S2]),
            _p2sh(_S2),
            id="core-p2sh-of-s2",
        ),
        pytest.param(
            3,
            b"\x4c" + len(_S1).to_bytes(1, "little") + _S1,
            _p2sh(_S1),
            id="pushed-by-op-pushdata1",
        ),
        pytest.param(
            3,
            b"\x4d" + len(_S1).to_bytes(2, "little") + _S1,
            _p2sh(_S1),
            id="pushed-by-op-pushdata2",
        ),
        pytest.param(
            3,
            b"\x4e" + len(_S1).to_bytes(4, "little") + _S1,
            _p2sh(_S1),
            id="pushed-by-op-pushdata4",
        ),
        pytest.param(
            0,
            serialize([_S1, "OP_NOP"]),
            _p2sh(_S1),
            id="a-script-sig-not-push-only-counts-nothing",
        ),
        pytest.param(
            0,
            serialize([_S1]) + b"\x4b",
            _p2sh(_S1),
            id="nor-does-one-that-stops-parsing",
        ),
        pytest.param(
            0,
            serialize([_S1, "OP_1"]),
            _p2sh(_S1),
            id="the-last-op-code-is-read-and-op-1-pushes-no-data",
        ),
        pytest.param(
            0,
            serialize([_S1]) + b"\x50",
            _p2sh(_S1),
            id="nor-does-op-reserved-which-is-push-only",
        ),
        pytest.param(0, b"", _p2sh(_S1), id="an-empty-script-sig-pushes-nothing"),
        pytest.param(
            3, serialize(["OP_0", _S1]), _S1, id="any-other-script-pub-key-is-counted"
        ),
    ],
)
def test_p2sh_sig_op_count(
    count: int, script_sig: bytes, script_pub_key: bytes
) -> None:
    """Core's `CScript::GetSigOpCount(const CScript& scriptSig)`.

    The accurate count of the last push, where the script_sig is push
    only and parses to its end, and zero where it is not or does not.
    The hash in the p2sh script_pub_key is not checked against the redeem
    script: Core's count reads the script_sig and not the hash.
    """
    assert p2sh_sig_op_count(script_sig, script_pub_key) == count
    assert p2sh_sig_op_count(script_sig.hex(), script_pub_key.hex()) == count


_WITNESS_SCRIPT = serialize(["OP_2", _KEY, _KEY, _KEY, "OP_3", "OP_CHECKMULTISIG"])


@pytest.mark.parametrize(
    "count, script_sig, script_pub_key, stack",
    [
        pytest.param(1, b"", _P2WPKH, [b"", b""], id="p2wpkh"),
        pytest.param(1, b"", _P2WPKH, [], id="whatever-its-witness"),
        pytest.param(
            3, b"", _p2wsh(_WITNESS_SCRIPT), [b"", _WITNESS_SCRIPT], id="p2wsh"
        ),
        pytest.param(
            0, b"", _p2wsh(_WITNESS_SCRIPT), [], id="p2wsh-with-no-witness-script"
        ),
        pytest.param(
            3,
            b"",
            _p2wsh(b"\x00"),
            [_WITNESS_SCRIPT],
            id="the-script-hash-is-not-checked",
        ),
        pytest.param(
            0,
            b"",
            serialize(["OP_1", b"\x02" * 32]),
            [_WITNESS_SCRIPT],
            id="a-version-1-program-counts-nothing",
        ),
        pytest.param(
            0,
            b"",
            serialize(["OP_0", b"\x02" * 25]),
            [_WITNESS_SCRIPT],
            id="nor-a-version-0-program-of-another-size",
        ),
        pytest.param(
            1,
            serialize([_P2WPKH]),
            _p2sh(_P2WPKH),
            [b"", b""],
            id="p2wpkh-nested-in-p2sh",
        ),
        pytest.param(
            3,
            serialize([_p2wsh(_WITNESS_SCRIPT)]),
            _p2sh(_p2wsh(_WITNESS_SCRIPT)),
            [b"", _WITNESS_SCRIPT],
            id="p2wsh-nested-in-p2sh",
        ),
        pytest.param(
            0,
            serialize([_P2WPKH, "OP_NOP"]),
            _p2sh(_P2WPKH),
            [b"", b""],
            id="nested-under-a-script-sig-not-push-only",
        ),
        pytest.param(
            0,
            serialize([_P2WPKH, b"\x01"]),
            _p2sh(_P2WPKH),
            [b"", b""],
            id="nested-but-not-last",
        ),
        pytest.param(
            0,
            serialize([_WITNESS_SCRIPT]),
            _p2sh(_WITNESS_SCRIPT),
            [b"", _WITNESS_SCRIPT],
            id="p2sh-of-no-witness-program",
        ),
        pytest.param(
            0,
            b"",
            serialize(["OP_DUP", "OP_HASH160", hash160(_KEY), "OP_EQUALVERIFY"])
            + serialize(["OP_CHECKSIG"]),
            [_WITNESS_SCRIPT],
            id="p2pkh",
        ),
    ],
)
def test_witness_sig_op_count(
    count: int, script_sig: bytes, script_pub_key: bytes, stack: list[bytes]
) -> None:
    """Core's `CountWitnessSigOps`, with the `WitnessSigOps` it calls.

    A version-0 key hash program costs one whatever its witness, a
    version-0 script hash program the accurate count of its last witness
    element, and any other program nothing; the program is the
    script_pub_key, or the last push of a push-only script_sig where that
    is p2sh. Neither hash is checked against what is counted.
    """
    witness = Witness(stack)
    assert witness_sig_op_count(script_sig, script_pub_key, witness) == count
    assert (
        witness_sig_op_count(script_sig.hex(), script_pub_key.hex(), witness) == count
    )


def test_witness_sig_op_count_takes_a_witness() -> None:
    """A list of stack elements is refused rather than read as a stack."""
    with pytest.raises(BTClibTypeError, match="invalid witness type: list"):
        witness_sig_op_count(b"", _P2WPKH, [b"", b""])  # type: ignore[arg-type]
