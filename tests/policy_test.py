# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.policy` module.

Core's own cases come first, read at bitcoin/bitcoin@9be056a8a7: from
src/test/transaction_tests.cpp `test_Get`, `test_IsStandard`,
`max_standard_legacy_sigops` and `spends_witness_prog`; from
src/test/script_p2sh_tests.cpp `AreInputsStandard`; and from
test/functional/p2p_segwit.py `test_non_standard_witness` and
test/functional/mempool_accept.py's witness on a pay-to-anchor spend.
Keys are fixed where Core generates them, and a signature nothing
verifies is a placeholder of the same size. The rest are the edges of
the port.
"""

from __future__ import annotations

from typing import Any

import pytest
from btclib_ecc.ecc import dsa

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.fee import FeeRate
from btclib.hashes import hash160, sha256
from btclib.policy import (
    DEFAULT_ACCEPT_DATACARRIER,
    DEFAULT_BYTES_PER_SIGOP,
    DEFAULT_PERMIT_BAREMULTISIG,
    MAX_DUST_OUTPUTS_PER_TX,
    MAX_OP_RETURN_RELAY,
    MAX_P2SH_SIGOPS,
    MAX_STANDARD_TX_SIGOPS_COST,
    MAX_TX_LEGACY_SIGOPS,
    MIN_STANDARD_TX_NONWITNESS_SIZE,
    TX_MAX_STANDARD_VERSION,
    are_inputs_standard,
    assert_standard_tx,
    dust_outputs,
    is_dust,
    is_witness_standard,
    sig_ops_adjusted_weight,
    spends_non_anchor_witness_prog,
    virtual_size,
)
from btclib.script import serialize
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn, input_weight
from btclib.tx.tx_out import TxOut

# compressed G, 2G and 3G, and G uncompressed
KEY_1 = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
KEY_2 = bytes.fromhex(
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)
KEY_3 = bytes.fromhex(
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
)
KEY_1_UNCOMPRESSED = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817"
    "98483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
X_ONLY = KEY_1[1:]
# the size of a DER signature with its hash type, which nothing here verifies
SIG = b"\x30" + b"\x00" * 70
# a well-formed one, by the key of KEY_1: what a signature check reaches
DER_SIG = dsa.sign(b"btclib", 1).serialize() + b"\x01"

CENT = 1_000_000
MAX_MONEY = 21_000_000 * 100_000_000

OP_0 = b"\x00"
OP_1 = b"\x51"
OP_RETURN = b"\x6a"
ANCHOR = b"\x51\x02\x4e\x73"


def _p2pk(key: bytes) -> bytes:
    return serialize([key, "OP_CHECKSIG"])


def _p2pkh(key: bytes) -> bytes:
    return serialize(
        ["OP_DUP", "OP_HASH160", hash160(key), "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )


def _p2sh(redeem_script: bytes) -> bytes:
    return serialize(["OP_HASH160", hash160(redeem_script), "OP_EQUAL"])


def _p2wpkh(key: bytes) -> bytes:
    return serialize(["OP_0", hash160(key)])


def _p2wsh(witness_script: bytes) -> bytes:
    return serialize(["OP_0", sha256(witness_script)])


def _p2tr(x_only: bytes) -> bytes:
    return serialize(["OP_1", x_only])


def _multisig(m: int, keys: list[bytes]) -> bytes:
    return serialize([f"OP_{m}", *keys, f"OP_{len(keys)}", "OP_CHECKMULTISIG"])


def _outpoint(n: int) -> OutPoint:
    return OutPoint(b"\x01" * 32, n)


def _spend(
    prevouts: list[TxOut],
    script_sigs: list[bytes] | None = None,
    witnesses: list[list[bytes]] | None = None,
) -> Tx:
    """Return a transaction spending the outputs, one input each."""
    script_sigs = script_sigs or [b""] * len(prevouts)
    witnesses = witnesses or [[]] * len(prevouts)
    vin = [
        TxIn(_outpoint(i), script_sig, 0xFFFFFFFF, Witness(witness))
        for i, (script_sig, witness) in enumerate(
            zip(script_sigs, witnesses, strict=True)
        )
    ]
    return Tx(2, 0, vin, [TxOut(1000, _p2pkh(KEY_2))])


def _assert_standard(tx: Tx, **kwargs: Any) -> None:
    assert_standard_tx(tx, **kwargs)


def _assert_not_standard(tx: Tx, reason: str, **kwargs: Any) -> None:
    with pytest.raises(BTClibValueError, match=f"^{reason}$"):
        assert_standard_tx(tx, **kwargs)


def test_get() -> None:
    """Core's `test_Get`: p2pk and p2pkh prevouts are standard inputs."""
    prevouts = [
        TxOut(50 * CENT, _p2pk(KEY_2)),
        TxOut(21 * CENT, _p2pkh(KEY_3)),
        TxOut(22 * CENT, _p2pkh(KEY_1)),
    ]
    tx = _spend(
        prevouts,
        [
            serialize([b"\x00" * 65]),
            serialize([b"\x00" * 65, b"\x04" * 33]),
            serialize([b"\x00" * 65, b"\x04" * 33]),
        ],
    )
    assert are_inputs_standard(prevouts, tx)


def _is_standard_base() -> Tx:
    vin = [TxIn(_outpoint(1), serialize([b"\x00" * 65]), 0xFFFFFFFF)]
    return Tx(2, 0, vin, [TxOut(90 * CENT, _p2pkh(KEY_1))])


def test_is_standard_dust_and_version() -> None:
    """Core's `test_IsStandard`, its dust and version half."""
    tx = _is_standard_base()
    _assert_standard(tx)

    # up to the dust outputs allowed, still standard
    for _ in range(MAX_DUST_OUTPUTS_PER_TX):
        tx.vout.append(TxOut(0, tx.vout[0].script_pub_key.script))
        _assert_standard(tx)

    # 182 * 3000 / 1000
    dust_threshold = 546
    tx.vout[0] = TxOut(dust_threshold - 1, _p2pkh(KEY_1))
    _assert_not_standard(tx, "dust")
    tx.vout[0] = TxOut(dust_threshold, _p2pkh(KEY_1))
    _assert_standard(tx)

    for version in (0xFFFFFFFF, 0, TX_MAX_STANDARD_VERSION + 1):
        tx.version = version
        _assert_not_standard(tx, "version")
    for version in (1, 2):
        tx.version = version
        _assert_standard(tx)

    # 182 * 3702 / 1000, rounded up
    odd = FeeRate(sats_per_kvbyte=3702)
    tx.vout[0] = TxOut(674 - 1, _p2pkh(KEY_1))
    _assert_not_standard(tx, "dust", dust_relay_fee=odd)
    tx.vout[0] = TxOut(674, _p2pkh(KEY_1))
    _assert_standard(tx, dust_relay_fee=odd)


DATA_40 = bytes.fromhex(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38"
)


def test_is_standard_nulldata() -> None:
    """Core's `test_IsStandard`, its nulldata half."""
    tx = _is_standard_base()
    tx.vout.append(TxOut(0, _p2pkh(KEY_1)))

    tx.vout[0] = TxOut(674, OP_1)
    _assert_not_standard(tx, "scriptpubkey")

    # 83 bytes, standard with a max_datacarrier_bytes of 83 and not of 82
    tx.vout[0] = TxOut(674, OP_RETURN + serialize([DATA_40 * 2]))
    assert len(tx.vout[0].script_pub_key.script) == 83
    _assert_standard(tx, max_datacarrier_bytes=83)
    _assert_not_standard(tx, "datacarrier", max_datacarrier_bytes=82)

    # the payload can be encoded in any way, OP_RESERVED included...
    for script in (
        OP_RETURN + serialize([b""]),
        OP_RETURN + serialize([b"\x00", b"\x01"]),
        OP_RETURN
        + serialize(["OP_RESERVED", "OP_1NEGATE", "OP_0", b"\x01"])
        + serialize([f"OP_{i}" for i in range(2, 17)]),
        OP_RETURN + serialize(["OP_0", b"\x01", "OP_2", b"\xff" * 36]),
    ):
        tx.vout[0] = TxOut(674, script)
        _assert_standard(tx)

    # ...so long as it is only pushes
    tx.vout[0] = TxOut(674, OP_RETURN + OP_RETURN)
    _assert_not_standard(tx, "scriptpubkey")

    tx.vout = [TxOut(674, OP_RETURN)]
    _assert_standard(tx)

    # several nulldata outputs
    pushed = OP_RETURN + serialize([DATA_40])
    for first, second in ((pushed, pushed), (pushed, OP_RETURN)):
        tx.vout = [TxOut(0, first), TxOut(0, second)]
        _assert_standard(tx)
    tx.vout = [TxOut(0, OP_RETURN), TxOut(0, OP_RETURN)]
    _assert_standard(tx)

    # the bound is on the outputs taken together
    big = OP_RETURN + serialize([DATA_40 * 2])
    tx.vout = [TxOut(0, big), TxOut(0, big)]
    datacarrier_size = 2 * len(big)
    _assert_standard(tx)
    _assert_standard(tx, max_datacarrier_bytes=datacarrier_size)
    _assert_not_standard(tx, "datacarrier", max_datacarrier_bytes=datacarrier_size - 1)


def test_is_standard_script_sig() -> None:
    """Core's `test_IsStandard`, its script_sig half."""
    tx = _is_standard_base()
    tx.vout = [TxOut(MAX_MONEY, _p2pkh(KEY_1))]

    # OP_PUSHDATA2, its two length bytes and 1647 bytes: 1650 in all
    tx.vin[0].script_sig = serialize([b"\x00" * 1647])
    _assert_standard(tx)
    tx.vin[0].script_sig = serialize([b"\x00" * 1648])
    _assert_not_standard(tx, "scriptsig-size")

    pushes = serialize(
        [
            "OP_1",
            "OP_0",
            "OP_1NEGATE",
            "OP_16",
            b"\x00" * 75,
            b"\x00" * 235,
            b"\x00" * 1234,
            "OP_9",
        ]
    )
    tx.vin[0].script_sig = pushes
    _assert_standard(tx)

    non_push_op_codes = serialize(
        [
            "OP_NOP",
            "OP_VERIFY",
            "OP_IF",
            "OP_ROT",
            "OP_3DUP",
            "OP_SIZE",
            "OP_EQUAL",
            "OP_ADD",
            "OP_SUB",
            "OP_HASH256",
            "OP_CODESEPARATOR",
            "OP_CHECKSIG",
            "OP_CHECKLOCKTIMEVERIFY",
        ]
    )
    # each single-byte push replaced by each non-push op code
    single_byte_pushes = [0, 1, 2, 3, len(pushes) - 1]
    for index in single_byte_pushes:
        for op_code in non_push_op_codes:
            script_sig = bytearray(pushes)
            script_sig[index] = op_code
            tx.vin[0].script_sig = bytes(script_sig)
            _assert_not_standard(tx, "scriptsig-not-pushonly")
    tx.vin[0].script_sig = pushes
    _assert_standard(tx)


def test_is_standard_tx_size() -> None:
    """Core's `test_IsStandard`, its weight half."""
    # 41 bytes each with an empty script_sig
    vin = [TxIn(_outpoint(i), b"", 0xFFFFFFFF) for i in range(2438)]
    # 30 bytes, and 12 of header: 400000 weight units in all
    tx = Tx(2, 0, vin, [TxOut(MAX_MONEY, OP_RETURN + serialize([b"\x00" * 19]))])
    assert tx.weight == 400_000
    _assert_standard(tx)

    tx.vout[0] = TxOut(MAX_MONEY, OP_RETURN + serialize([b"\x00" * 20]))
    assert tx.weight == 400_004
    _assert_not_standard(tx, "tx-size")


def test_is_standard_bare_multisig_and_dust() -> None:
    """Core's `test_IsStandard`, its bare multisig and dust half."""
    tx = _is_standard_base()
    tx.vout = [TxOut(MAX_MONEY, _multisig(1, [KEY_1]))]
    _assert_standard(tx, permit_bare_multisig=True)
    _assert_not_standard(tx, "bare-multisig", permit_bare_multisig=False)

    tx.vout.extend([TxOut(0, _multisig(1, [KEY_1]))] * MAX_DUST_OUTPUTS_PER_TX)
    cases = [
        (serialize([b"\x02" * 33, "OP_CHECKSIG"]), 576),
        (serialize([b"\x04" * 65, "OP_CHECKSIG"]), 672),
        (
            serialize(
                ["OP_DUP", "OP_HASH160", b"\x00" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]
            ),
            546,
        ),
        (serialize(["OP_HASH160", b"\x00" * 20, "OP_EQUAL"]), 540),
        (serialize(["OP_0", b"\x00" * 20]), 294),
        (serialize(["OP_0", b"\x00" * 32]), 330),
        # an x-only key that is no point is fine
        (serialize(["OP_1", b"\x00" * 32]), 330),
        # future witness versions, of a program length v1 leaves undefined
        *((serialize([f"OP_{n}", b"\x00" * 2]), 240) for n in range(1, 17)),
        (ANCHOR, 240),
    ]
    for script_pub_key, threshold in cases:
        tx.vout[0] = TxOut(threshold, script_pub_key)
        _assert_standard(tx)
        tx.vout[0] = TxOut(threshold - 1, script_pub_key)
        _assert_not_standard(tx, "dust")


def test_is_standard_order() -> None:
    """The first rule a transaction breaks is the reason, in Core's order."""
    tx = _is_standard_base()
    tx.version = 0
    tx.vin[0].script_sig = serialize(["OP_NOP"])
    tx.vout = [TxOut(0, OP_1), TxOut(0, _p2pkh(KEY_1))]
    _assert_not_standard(tx, "version")
    tx.version = 2
    _assert_not_standard(tx, "scriptsig-not-pushonly")
    tx.vin[0].script_sig = b""
    _assert_not_standard(tx, "scriptpubkey")
    tx.vout[0] = TxOut(0, _multisig(1, [KEY_1]))
    _assert_not_standard(tx, "bare-multisig", permit_bare_multisig=False)
    _assert_not_standard(tx, "dust")


def test_is_standard_order_of_the_size_rules() -> None:
    """Version before weight, and script_sig size before push-only."""
    tx = _is_standard_base()
    tx.version = 0
    tx.vin[0].script_sig = serialize([b"\x00" * 100_001])
    assert tx.weight > 400_000
    _assert_not_standard(tx, "version")
    tx.version = 2
    _assert_not_standard(tx, "tx-size")

    # 1651 bytes, the last of them OP_NOP
    tx.vin[0].script_sig = serialize([b"\x00" * 1647, "OP_NOP"])
    assert len(tx.vin[0].script_sig) == 1651
    _assert_not_standard(tx, "scriptsig-size")


def test_is_standard_datacarrier_off() -> None:
    """None is -datacarrier=0: no nulldata output, however small."""
    tx = _is_standard_base()
    tx.vout.append(TxOut(0, OP_RETURN))
    _assert_standard(tx, max_datacarrier_bytes=1)
    _assert_not_standard(tx, "datacarrier", max_datacarrier_bytes=None)
    _assert_not_standard(tx, "datacarrier", max_datacarrier_bytes=0)


@pytest.mark.parametrize(
    "script_pub_key, standard",
    [
        (_multisig(1, [KEY_1, KEY_2, KEY_3]), True),
        (_multisig(3, [KEY_1, KEY_2, KEY_3]), True),
        (_multisig(1, [KEY_1, KEY_2, KEY_3, KEY_1]), False),
        (_multisig(2, [KEY_1_UNCOMPRESSED, KEY_2]), True),
    ],
)
def test_bare_multisig_up_to_three_keys(script_pub_key: bytes, standard: bool) -> None:
    """Core's `IsStandard`: m-of-n with n up to 3."""
    tx = _is_standard_base()
    tx.vout = [TxOut(MAX_MONEY, script_pub_key)]
    if standard:
        _assert_standard(tx)
    else:
        _assert_not_standard(tx, "scriptpubkey")


def _max_sigops_redeem_script() -> bytes:
    """Core's pathological redeem script of exactly MAX_P2SH_SIGOPS."""
    commands: list[Any] = [b"", KEY_1]
    commands += ["OP_2DUP", "OP_CHECKSIG", "OP_DROP"] * (MAX_P2SH_SIGOPS - 1)
    commands += ["OP_CHECKSIG", "OP_NOT"]
    return serialize(commands)


def test_max_standard_legacy_sigops() -> None:
    """Core's `max_standard_legacy_sigops`: BIP54's cap of 2500."""
    redeem_script = _max_sigops_redeem_script()
    script_sig = serialize([redeem_script])
    p2sh_count = MAX_TX_LEGACY_SIGOPS // MAX_P2SH_SIGOPS
    assert p2sh_count * MAX_P2SH_SIGOPS < MAX_TX_LEGACY_SIGOPS

    prevouts = [TxOut(424242 + i, _p2sh(redeem_script)) for i in range(p2sh_count)]
    # 2490 sigops
    assert are_inputs_standard(prevouts, _spend(prevouts, [script_sig] * p2sh_count))
    # 2505
    prevouts.append(TxOut(424242, _p2sh(redeem_script)))
    script_sigs = [script_sig] * len(prevouts)
    assert not are_inputs_standard(prevouts, _spend(prevouts, script_sigs))

    # the limit reached with p2pk outputs too: 2490 + 10
    prevouts = prevouts[:p2sh_count] + [
        TxOut(212121 + i, _p2pk(KEY_1)) for i in range(10)
    ]
    script_sigs = [script_sig] * p2sh_count + [b""] * 10
    assert are_inputs_standard(prevouts, _spend(prevouts, script_sigs))

    # witness sigops are not legacy ones
    witness_script = _p2pk(KEY_1)
    prevouts += [
        TxOut(121212, _p2wpkh(KEY_1)),
        TxOut(131313, _p2wsh(witness_script)),
        TxOut(141414, _p2tr(X_ONLY)),
    ]
    script_sigs += [b""] * 3
    assert are_inputs_standard(prevouts, _spend(prevouts, script_sigs))

    # one p2pk more: 2501
    prevouts.append(TxOut(212121, _p2pk(KEY_1)))
    script_sigs.append(b"")
    assert not are_inputs_standard(prevouts, _spend(prevouts, script_sigs))


def test_bip54_counts_the_script_sig() -> None:
    """The script_sig's own sigops count, accurately, toward the cap."""
    prevouts = [TxOut(1000, _p2pk(KEY_1))] * (MAX_TX_LEGACY_SIGOPS - 2)
    prevouts.append(TxOut(1000, _p2pkh(KEY_1)))
    # one for OP_1 OP_CHECKMULTISIG, which would be 20 counted roughly
    script_sigs = [b""] * (len(prevouts) - 1) + [
        serialize(["OP_1", "OP_CHECKMULTISIG"])
    ]
    assert are_inputs_standard(prevouts, _spend(prevouts, script_sigs))

    script_sigs[-1] = serialize(["OP_2", "OP_CHECKMULTISIG"])
    assert not are_inputs_standard(prevouts, _spend(prevouts, script_sigs))


def test_are_inputs_standard_p2sh() -> None:
    """Core's `AreInputsStandard` of script_p2sh_tests.cpp."""
    keys = [KEY_1, KEY_2, KEY_3]
    pay_1 = _p2pkh(KEY_1)
    # 1-of-3 and 2-of-3, standard only inside p2sh
    one_and_two = serialize(
        [
            "OP_1",
            *keys,
            "OP_3",
            "OP_CHECKMULTISIGVERIFY",
            "OP_2",
            KEY_1_UNCOMPRESSED,
            KEY_2,
            KEY_3,
            "OP_3",
            "OP_CHECKMULTISIG",
        ]
    )
    fifteen_sigops = serialize(
        ["OP_1"]
        + [keys[i % 3] for i in range(MAX_P2SH_SIGOPS)]
        + ["OP_15", "OP_CHECKMULTISIG"]
    )
    sixteen_sigops = serialize(["OP_16", "OP_CHECKMULTISIG"])
    twenty_sigops = serialize(["OP_CHECKMULTISIG"])

    prevouts = [
        TxOut(1000, _p2sh(pay_1)),
        TxOut(2000, pay_1),
        TxOut(3000, _multisig(1, keys)),
        TxOut(4000, _p2sh(one_and_two)),
        TxOut(5000, _p2sh(fifteen_sigops)),
    ]
    script_sigs = [
        serialize([SIG, KEY_1, pay_1]),
        serialize([SIG, KEY_1]),
        serialize(["OP_0", SIG]),
        serialize(["OP_11", "OP_11", one_and_two]),
        serialize([fifteen_sigops]),
    ]
    assert are_inputs_standard(prevouts, _spend(prevouts, script_sigs))

    for redeem_script in (sixteen_sigops, twenty_sigops):
        prevouts = [TxOut(5000, _p2sh(redeem_script))]
        tx = _spend(prevouts, [serialize([redeem_script])])
        assert not are_inputs_standard(prevouts, tx)


@pytest.mark.parametrize(
    "script_pub_key, script_sig, standard",
    [
        # Solver's nonstandard and witness_unknown are refused
        (OP_1, b"", False),
        (serialize(["OP_2", b"\x00" * 32]), b"", False),
        (serialize(["OP_0", b"\x00" * 21]), b"", False),
        # the anchor is a type of its own, and standard
        (ANCHOR, b"", True),
        (serialize(["OP_RETURN"]), b"", True),
        # a p2sh spend whose script_sig leaves nothing, or fails
        (_p2sh(b""), b"", False),
        (_p2sh(OP_1), serialize(["OP_RETURN"]), False),
        (_p2sh(OP_1), serialize(["OP_0", "OP_DROP"]), False),
        # a script_sig need not be push-only to leave a redeem script
        (_p2sh(OP_1), serialize(["OP_0", "OP_DROP", OP_1]), True),
    ],
)
def test_are_inputs_standard_edges(
    script_pub_key: bytes, script_sig: bytes, standard: bool
) -> None:
    """What Core's cases leave out: each refusal on its own."""
    prevouts = [TxOut(1000, script_pub_key)]
    tx = _spend(prevouts, [script_sig])
    assert are_inputs_standard(prevouts, tx) is standard


@pytest.mark.parametrize(
    "check",
    [
        serialize([DER_SIG, KEY_1, "OP_CHECKSIG"]),
        serialize(["OP_0", DER_SIG, "OP_1", KEY_1, "OP_1", "OP_CHECKMULTISIG"]),
    ],
)
def test_the_script_sig_checks_no_signature(check: bytes) -> None:
    """Every signature check fails, as with Core's BaseSignatureChecker.

    The script_sig goes on to OP_RETURN unless its check pushed false.
    The signature is well formed and the key valid, so a check that ran
    would reach the signature hash.
    """
    script_sig = check + serialize(["OP_IF", "OP_RETURN", "OP_ENDIF", OP_1])
    prevouts = [TxOut(1000, _p2sh(OP_1))]
    tx = _spend(prevouts, [script_sig])
    assert are_inputs_standard(prevouts, tx)


def test_coinbase() -> None:
    """A coinbase spends nothing: standard inputs, and no program spent."""
    coinbase = Tx(
        2,
        0,
        [TxIn(OutPoint(), b"\x01\x01", 0xFFFFFFFF, Witness([b"\x00" * 32]))],
        [TxOut(50, OP_1)],
    )
    assert are_inputs_standard([], coinbase)
    assert is_witness_standard([], coinbase)
    assert not spends_non_anchor_witness_prog([], coinbase)


def _spend_one(prevout: bytes, script_sig: bytes = b"") -> tuple[list[TxOut], Tx]:
    prevouts = [TxOut(1000, prevout)]
    return prevouts, _spend(prevouts, [script_sig])


def test_spends_witness_prog() -> None:
    """Core's `spends_witness_prog`, output type by output type."""
    redeem_script = serialize(["OP_1", "OP_CHECKSIG"])
    witness_script = serialize(["OP_12", "OP_HASH160", "OP_DUP", "OP_EQUAL"])
    cases = [
        (_p2pk(KEY_1), b"", False),
        (_p2pkh(KEY_1), b"", False),
        (_p2sh(redeem_script), serialize(["OP_0", redeem_script]), False),
        (ANCHOR, b"", False),
    ]
    programs = [
        _p2wsh(witness_script),
        _p2wpkh(KEY_1),
        _p2tr(X_ONLY),
        # an undefined version 1 program, and undefined versions 2 to 16
        serialize(["OP_1", b"\x42\x42"]),
        *(serialize([f"OP_{i}", X_ONLY]) for i in range(2, 17)),
    ]
    for program in programs:
        cases += [
            (program, b"", True),
            # detected inside p2sh, and not without the redeem script
            (_p2sh(program), serialize([program]), True),
            (_p2sh(program), b"", False),
        ]
    # the anchor, undefined inside p2sh, is a witness program there
    cases.append((_p2sh(ANCHOR), serialize([ANCHOR]), True))

    for prevout, script_sig, expected in cases:
        prevouts, tx = _spend_one(prevout, script_sig)
        assert spends_non_anchor_witness_prog(prevouts, tx) is expected


def _p2wsh_cases() -> list[tuple[list[bytes], bytes, bool]]:
    """p2p_segwit.py's `test_non_standard_witness` stacks."""
    pad = b"\x01"
    scripts = [
        serialize(["OP_DROP"] * 100),
        serialize(["OP_DROP"] * 99),
        serialize([pad * 59] * 59 + ["OP_DROP"] * 60),
        serialize([pad * 59] * 59 + ["OP_DROP"] * 61),
    ]
    assert len(scripts[2]) == 3600
    assert len(scripts[3]) == 3601
    return [
        # more than 100 items besides the witness script
        ([pad] * 101 + [scripts[0]], scripts[0], False),
        # an item over 80 bytes
        ([pad * 81] * 100 + [scripts[1]], scripts[1], False),
        ([pad * 80] * 100 + [scripts[1]], scripts[1], True),
        # a witness script of 3600 bytes, and of 3601
        ([pad, pad, scripts[2]], scripts[2], True),
        ([pad, pad, pad, scripts[3]], scripts[3], False),
    ]


@pytest.mark.parametrize("stack, witness_script, standard", _p2wsh_cases())
def test_non_standard_witness(
    stack: list[bytes], witness_script: bytes, standard: bool
) -> None:
    """Core's p2wsh limits, native and nested in p2sh."""
    program = _p2wsh(witness_script)
    for prevout, script_sig in ((program, b""), (_p2sh(program), serialize([program]))):
        prevouts = [TxOut(1000, prevout)]
        tx = _spend(prevouts, [script_sig], [stack])
        assert is_witness_standard(prevouts, tx) is standard


TAPSCRIPT = serialize(["OP_DROP", "OP_1"])
CONTROL_BLOCK = b"\xc0" + X_ONLY


@pytest.mark.parametrize(
    "prevout, script_sig, stack, standard",
    [
        # no witness, nothing to judge
        (_p2pkh(KEY_1), b"", [], True),
        # a witness for a script that is no witness program
        (_p2pkh(KEY_1), b"", [b"\x01"], False),
        # witness stuffing: an anchor spend takes no witness
        (ANCHOR, b"", [b"\x01"], False),
        # nested in p2sh, an anchor is a version 1 program like any other
        (_p2sh(ANCHOR), serialize([ANCHOR]), [b"\x01"], True),
        # a p2sh script_sig that fails, or leaves nothing
        (_p2sh(_p2wpkh(KEY_1)), serialize(["OP_RETURN"]), [b"\x01"], False),
        (_p2sh(_p2wpkh(KEY_1)), b"", [b"\x01"], False),
        (_p2sh(OP_1), serialize([OP_1]), [b"\x01"], False),
        # p2wpkh and undefined versions have no limits here
        (_p2wpkh(KEY_1), b"", [b"\x01" * 81, KEY_1], True),
        (serialize(["OP_2", X_ONLY]), b"", [b"\x01" * 1000], True),
        (serialize(["OP_2", X_ONLY]), b"", [b"\x01", b"\x50"], True),
        # taproot: a key path spend, the annex, the control block
        (_p2tr(X_ONLY), b"", [b"\x01" * 64], True),
        (_p2tr(X_ONLY), b"", [b"\x01" * 64, b"\x50"], False),
        (_p2tr(X_ONLY), b"", [TAPSCRIPT, CONTROL_BLOCK, b"\x50\x01"], False),
        (_p2tr(X_ONLY), b"", [TAPSCRIPT, b""], False),
        # tapscript items up to 80 bytes, the script and control block apart
        (_p2tr(X_ONLY), b"", [b"\x01" * 80, TAPSCRIPT, CONTROL_BLOCK], True),
        (_p2tr(X_ONLY), b"", [b"\x01" * 81, TAPSCRIPT, CONTROL_BLOCK], False),
        (_p2tr(X_ONLY), b"", [b"\x01" * 81, b"\x01" * 81, CONTROL_BLOCK], False),
        (_p2tr(X_ONLY), b"", [TAPSCRIPT * 50, CONTROL_BLOCK + b"\x01" * 32], True),
        # a leaf version other than tapscript's has no item limit
        (_p2tr(X_ONLY), b"", [b"\x01" * 81, TAPSCRIPT, b"\xc2" + X_ONLY], True),
        (_p2tr(X_ONLY), b"", [b"\x01" * 81, TAPSCRIPT, b"\xc1" + X_ONLY], False),
        # a key path signature is not read for an annex
        (_p2tr(X_ONLY), b"", [b"\x50" + b"\x01" * 63], True),
        # nested in p2sh, taproot is undefined and has no limits
        (_p2sh(_p2tr(X_ONLY)), serialize([_p2tr(X_ONLY)]), [b"\x01", b"\x50"], True),
        (_p2sh(_p2tr(X_ONLY)), serialize([_p2tr(X_ONLY)]), [b"\x01" * 81] * 3, True),
    ],
)
def test_is_witness_standard_edges(
    prevout: bytes, script_sig: bytes, stack: list[bytes], standard: bool
) -> None:
    """Each witness rule on its own, and what none of them reads."""
    prevouts = [TxOut(1000, prevout)]
    tx = _spend(prevouts, [script_sig], [stack])
    assert is_witness_standard(prevouts, tx) is standard


def test_is_witness_standard_reads_every_input() -> None:
    """One input out of standard is the transaction out of standard."""
    prevouts = [TxOut(1000, _p2wpkh(KEY_1)), TxOut(1000, ANCHOR)]
    tx = _spend(prevouts, witnesses=[[SIG, KEY_1], [b"\x01"]])
    assert not is_witness_standard(prevouts, tx)
    tx.vin[1].script_witness = Witness()
    assert is_witness_standard(prevouts, tx)


def test_dust_outputs() -> None:
    """The dust outputs by index, at the default rate and at a zero one."""
    tx = _is_standard_base()
    tx.vout = [
        TxOut(545, _p2pkh(KEY_1)),
        TxOut(546, _p2pkh(KEY_1)),
        TxOut(0, OP_RETURN),
        TxOut(293, _p2wpkh(KEY_1)),
    ]
    assert dust_outputs(tx) == [0, 3]
    assert [is_dust(tx_out) for tx_out in tx.vout] == [True, False, False, True]
    assert dust_outputs(tx, dust_relay_fee=FeeRate(sats_per_kvbyte=0)) == []


def test_virtual_size() -> None:
    """The weight over four rounded up, or the sigop cost where more."""
    tx = _is_standard_base()
    assert virtual_size(tx.weight) == tx.vsize
    # 32 + 4 + 1 + 66 + 4 bytes, none of them witness
    assert virtual_size(input_weight(tx.vin[0].script_sig)) == 107
    # the weight, or the sigop cost at 20 bytes each where that is more
    assert sig_ops_adjusted_weight(400, sig_op_cost=20, bytes_per_sigop=20) == 400
    assert sig_ops_adjusted_weight(400, sig_op_cost=21, bytes_per_sigop=20) == 420
    assert virtual_size(401) == 101
    assert virtual_size(400, sig_op_cost=25) == 125
    assert virtual_size(400, sig_op_cost=25, bytes_per_sigop=0) == 100


def test_constants() -> None:
    """The values policy.h states at bitcoin/bitcoin@9be056a8a7."""
    assert (MIN_STANDARD_TX_NONWITNESS_SIZE, MAX_STANDARD_TX_SIGOPS_COST) == (
        65,
        16_000,
    )
    assert (MAX_OP_RETURN_RELAY, DEFAULT_ACCEPT_DATACARRIER) == (100_000, True)
    assert (DEFAULT_BYTES_PER_SIGOP, DEFAULT_PERMIT_BAREMULTISIG) == (20, True)


def test_invalid_arguments() -> None:
    """A wrong type is a BTClibTypeError, a wrong value a BTClibValueError."""
    tx = _is_standard_base()
    prevouts = [TxOut(1000, _p2pkh(KEY_1))]
    for function in (are_inputs_standard, is_witness_standard):
        with pytest.raises(BTClibTypeError, match="invalid tx type"):
            function(prevouts, "tx")  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="invalid prevouts type"):
            function(None, tx)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="invalid prevout type"):
            function(["prevout"], tx)  # type: ignore[list-item]
        with pytest.raises(BTClibValueError, match="2 prevouts for 1 transaction"):
            function(prevouts * 2, tx)
    with pytest.raises(BTClibTypeError, match="invalid tx type"):
        spends_non_anchor_witness_prog(prevouts, None)  # type: ignore[arg-type]

    with pytest.raises(BTClibTypeError, match="invalid tx type"):
        assert_standard_tx(None)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid max_datacarrier_bytes type"):
        assert_standard_tx(tx, max_datacarrier_bytes=True)
    with pytest.raises(BTClibValueError, match="negative max_datacarrier_bytes"):
        assert_standard_tx(tx, max_datacarrier_bytes=-1)
    with pytest.raises(BTClibTypeError, match="invalid permit_bare_multisig type"):
        assert_standard_tx(tx, permit_bare_multisig=1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid dust_relay_fee type"):
        assert_standard_tx(tx, dust_relay_fee=3000)  # type: ignore[arg-type]
    # refused before any rule is read, a nonstandard version included
    tx.version = 0
    with pytest.raises(BTClibTypeError, match="invalid dust_relay_fee type"):
        assert_standard_tx(tx, dust_relay_fee=3000)  # type: ignore[arg-type]
    tx.version = 2

    with pytest.raises(BTClibTypeError, match="invalid tx_out type"):
        is_dust(None)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid tx type"):
        dust_outputs(None)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid dust_relay_fee type"):
        is_dust(prevouts[0], dust_relay_fee=3000)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid dust_relay_fee type"):
        dust_outputs(Tx(check_validity=False), dust_relay_fee=3000)  # type: ignore[arg-type]

    with pytest.raises(BTClibTypeError, match="invalid weight type"):
        virtual_size(1.5)  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="negative sig_op_cost"):
        virtual_size(1, sig_op_cost=-1)
    with pytest.raises(BTClibValueError, match="negative bytes_per_sigop"):
        sig_ops_adjusted_weight(1, sig_op_cost=1, bytes_per_sigop=-1)
