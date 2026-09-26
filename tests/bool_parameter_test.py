# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every `bool` parameter of the library, classified and held to its class.

CONTRIBUTING.md's "A `bool` parameter is a kind or a truth, and only the
first is type-checked", which is `musig2._flag`'s reasoning: a kind
written down and read back -- json, a configuration file, a coordinator's
message -- arrives as whatever it was written as, and `"false"` is true.
Issue #868 asked for the census this file is.

## The line, and the shape that makes it decidable

A **truth** only decides whether the call refuses: `check_validity=False`
says do not check now, and the object handed back is the same one. So a
value read for its truth runs a check or skips one and changes no answer,
which is why nothing is refused there.

A **kind** decides what a non-refusing call computes, returns or writes.
`"no"` is true, so a kind read for its truth quietly computes the other
answer -- the other signature, the other address, the other script code --
and that is what the refusal is for.

## The polarity a truth has to have

`"no"` is true, and so is every other wrong value, so the misreading is
never "the flag was off": it is always the one the flag's `True` stands
for. That is what makes a truth safe rather than the fact that it changes
no answer -- `verify_checksum="no"` checks the checksum, `strict="no"` is
strict, `forbid_zero_size="no"` forbids. The wrong value falls on the side
that refuses more, which is the side that cannot accept what was to be
refused.

So a truth's `True` has to be its conservative value, and a flag whose
`True` is the permissive one is a kind however little it computes.
`verified` and `hybrid` are, each waiving the very refusal it was written
to make, and `btclib_wallet`'s `allow_partial` is the same case. The two
are in `_KINDS` under a comment of their own, and issue #884 is the one
that asked, over `verified` and over `verify_script`'s `final` beside it
-- which stays a truth, its `True` being the one that demands the true
stack.

The two tests below are that line, one each:

- a kind refuses `"no"`, `0`, `1` and (where the annotation does not
  declare it) `None`, with a `BTClibTypeError`
- a truth **accepts** them, on a fixture the flag's `True` accepts. It is
  the ratchet `input_validation_test._ANSWERS_FALSE` is: a truth that
  starts refusing fails here, and the entry has to move rather than the
  test being edited

## What the census found

Every kind below was ungated when this file was written, `include_witness`
excepted -- `Block.serialize` and `Tx.serialize` were gated with
`utils.assert_type` as the serialization boundary was -- and so were
`musig2.apply_tweak`'s `is_xonly`, which `_flag` refuses, and
`btclib_wallet`'s `KeyGroup(verify=)`. The two the issue names are the sharpest:

```text
dsa.sign(msg, q, lower_s="no")        -> a low-s signature, "no" being true
PrvKeyData(q, compressed="no")        -> the compressed key, and its address
```

## The walk, and the one name it subtracts

`_bool_parameters` reads every public function of the package and every
`bool`-annotated parameter of one, so a flag added anywhere is either in a
table here or the run is red -- there is no third table, and that is the
state to keep.

`check_validity` is subtracted by name, with one reason for its many
signatures: it is a convention rather than a parameter, and
`check_validity_test.py` owns it, holding every class to the same two
answers. Being a truth is what that file is about.

## Where a fixture is not what it looks like

The engine's five and `read_push_data` take the interpreter's own state,
and what they are handed here is the smallest *valid* call of each: an
empty signature is a False `op_checksig` answers rather than raises, an
empty script is a script code of nothing, and OP_1 is a script that leaves
a true stack.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from btclib import b32, b58, var_bytes
from btclib.block.block import Block
from btclib.curves import bytes_from_point, bytes_from_prv_key_int
from btclib.ecc import bms, dsa
from btclib.exceptions import BTClibTypeError
from btclib.fee import FeeRate
from btclib.key import PrvKeyData, PubKeyData
from btclib.p2p import BlockPayload, SendCmpct, TxPayload, Version
from btclib.script.engine import script as engine
from btclib.script.engine import script_op_codes, verify_transaction
from btclib.script.engine.flags import NO_FLAGS, ScriptFlag
from btclib.script.script import serialize as serialize_script
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.taproot import parse as taproot_parse
from btclib.tx.coin import Coin
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx import join as tx_join
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut

_LIBRARY = Path(__file__).parents[1] / "src" / "btclib"

# `check_validity` is the one name the walk subtracts, and this is the
# reason it may: it is a convention over many signatures rather than a
# parameter of one, and `check_validity_test.py` is the file that holds
# every class to it -- being a truth is what that whole file is about
_OWNED_BY_ITS_OWN_FILE = "check_validity"

# a value of no bool type: a truthy string, and the two integers `bool`
# inherits from. Every one of them is a call mypy refuses
_WRONG_TYPES: tuple[Any, ...] = ("no", 0, 1)

_PRV_KEY = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
_PUB_KEY = dsa.gen_keys(_PRV_KEY)[1]
_SEC = bytes_from_point(_PUB_KEY)
_SEC_2 = bytes_from_prv_key_int(_PRV_KEY + 1)
_MSG = b"Satoshi Nakamoto"
_MSG_HASH = sha256(_MSG).digest()
_DER_SIG = dsa.sign(_MSG, _PRV_KEY).serialize()

# a transaction with an input, which is what the engine refuses to work
# without
_TX = Tx(vin=[TxIn(OutPoint(b"\x00" * 32, 0))], vout=[TxOut(1000, b"\x51")])
# a second one spending another outpoint: what `join` refuses is two
# transactions with an input in common, so one twice is no fixture
_TX_2 = Tx(vin=[TxIn(OutPoint(b"\x11" * 32, 1))], vout=[TxOut(900, b"\x51")])
_TX_BYTES = _TX.serialize(include_witness=False, check_validity=False)
# OP_1 as the output being spent: a script anyone can satisfy, so the one
# verification below is about `check_amounts` and not about a signature
_PREVOUTS = [TxOut(2000, b"\x51")]

_BLOCK = Block.parse(
    (Path(__file__).parent / "block" / "_data" / "block_1.bin").read_bytes()
)


@dataclass(frozen=True)
class _Case:
    """One `bool` parameter, and a call of its function that works."""

    dotted: str
    flag: str
    function: Any
    # every argument but the flag, by keyword
    args: dict[str, Any] = field(default_factory=dict)
    # the flag value the working call is made with: `True` unless the
    # fixture is one only `False` accepts
    valid: bool = True
    # `bool | None` declares None, so it is not a wrong value there. Read
    # off the annotation, not an exemption from anything
    optional: bool = False
    # the classification, which is prose because it is a judgement: for a
    # truth what the flag turns on and what it therefore cannot change,
    # and for a kind only where the kind is the polarity rather than the
    # answer -- the flags carrying one below are those
    reason: str = ""


_KINDS = (
    # `compressed` chooses which public key is computed, and therefore
    # which address
    _Case(
        "btclib.key.PrvKeyData.__init__",
        "compressed",
        PrvKeyData,
        {"q": _PRV_KEY},
    ),
    _Case(
        "btclib.b58.wif_from_prv_key",
        "compressed",
        b58.wif_from_prv_key,
        {"prv_key": _PRV_KEY},
    ),
    _Case(
        "btclib.b58.prv_key_data_from_wif",
        "compressed",
        b58.prv_key_data_from_wif,
        {"wif": b58.wif_from_prv_key(_PRV_KEY)},
        optional=True,
    ),
    _Case(
        "btclib.ecc.bms.gen_keys",
        "compressed",
        bms.gen_keys,
    ),
    _Case(
        "btclib.script.script_pub_key.ScriptPubKey.p2ms",
        "lexicographic_sorting",
        ScriptPubKey.p2ms,
        {"m": 1, "keys": [PubKeyData(_SEC), PubKeyData(_SEC_2)]},
    ),
    # the script engine: `segwit` says which digest a signature commits
    # to and which script code it is checked against, so it is a
    # consensus answer and not a check
    _Case(
        "btclib.script.engine.script.check_pub_key",
        "segwit",
        engine.check_pub_key,
        {"pub_key": _SEC, "flags": NO_FLAGS},
    ),
    _Case(
        "btclib.script.engine.script.calculate_script_code",
        "segwit",
        engine.calculate_script_code,
        {
            "script_bytes": b"",
            "codesep_offset": 0,
            "signatures": [],
            "const_scriptcode": False,
        },
    ),
    _Case(
        "btclib.script.engine.script.calculate_script_code",
        "const_scriptcode",
        engine.calculate_script_code,
        {"script_bytes": b"", "codesep_offset": 0, "signatures": [], "segwit": True},
        valid=False,
    ),
    _Case(
        "btclib.script.engine.script.op_checksig",
        "segwit",
        engine.op_checksig,
        {
            "signature": b"",
            "signatures": [],
            "pub_key": _SEC,
            "script_bytes": b"",
            "codesep_offset": 0,
            "prevout_value": 0,
            "tx": _TX,
            "i": 0,
            "flags": NO_FLAGS,
        },
    ),
    _Case(
        "btclib.script.engine.script.prepare_script",
        "segwit",
        engine.prepare_script,
        {"script": [], "flags": NO_FLAGS},
    ),
    _Case(
        "btclib.script.engine.script.verify_script",
        "segwit",
        engine.verify_script,
        {
            "script_bytes": b"\x51",
            "stack": [],
            "prevout_value": 0,
            "tx": _TX,
            "i": 0,
            "flags": NO_FLAGS,
        },
        valid=False,
    ),
    _Case(
        "btclib.script.engine.script_op_codes.read_push_data",
        "skip_execution",
        script_op_codes.read_push_data,
        {
            "op_code": 1,
            "s": BytesIO(b"\x01"),
            "stack": [],
            "flags": NO_FLAGS,
            "serialize": serialize_script,
        },
    ),
    _Case(
        "btclib.script.taproot.parse",
        "exit_on_op_success",
        taproot_parse,
        {"stream": b"\x51"},
    ),
    _Case(
        "btclib.block.block.Block.serialize",
        "include_witness",
        _BLOCK.serialize,
        {},
    ),
    _Case("btclib.tx.tx.Tx.serialize", "include_witness", _TX.serialize, {}),
    # and the two p2p payloads that hold the same flag rather than take
    # it, which is `btclib.p2p.data`'s decision: a `tx` message written
    # for a peer that negotiated no witness is the stripped encoding, so
    # the flag chooses which of two messages is sent
    _Case(
        "btclib.p2p.data.TxPayload.__init__",
        "include_witness",
        TxPayload,
        {"tx": _TX},
    ),
    _Case(
        "btclib.p2p.data.BlockPayload.__init__",
        "include_witness",
        BlockPayload,
        {"block": _BLOCK},
    ),
    # a stored fact rather than a switch: `is_coinbase` is not read to
    # decide how `Coin.__init__` behaves, it is the value `assert_
    # coinbase_maturity` later branches on for the coin it is handed, so
    # a misread "no" would carry a wrong fact into a rule miles from here
    _Case(
        "btclib.tx.coin.Coin.__init__",
        "is_coinbase",
        Coin,
        {"tx_out": TxOut(1_000, b"\x51"), "height": 100},
    ),
    _Case(
        "btclib.b32.power_of_2_base_conversion",
        "pad",
        b32.power_of_2_base_conversion,
        {"data": [1, 2, 3], "from_bits": 8, "to_bits": 5},
    ),
    _Case(
        "btclib.tx.tx.join",
        "shuffle_inp",
        tx_join,
        {
            "txs": [_TX, _TX_2],
            "enforce_same_version": True,
            "enforce_same_lock_time": True,
            "shuffle_out": False,
        },
        valid=False,
    ),
    _Case(
        "btclib.tx.tx.join",
        "shuffle_out",
        tx_join,
        {
            "txs": [_TX, _TX_2],
            "enforce_same_version": True,
            "enforce_same_lock_time": True,
            "shuffle_inp": False,
        },
        valid=False,
    ),
    # The ones below decide no answer, which every kind above does, and
    # are here for the other half of the line: their `True` is the
    # permissive value. A truth is safe because a non-bool is true and
    # its `True` is the conservative one -- `verify_checksum="no"` checks
    # the checksum, `forbid_zero_size="no"` forbids, `final="no"` demands
    # the true stack -- so the one misreading a non-bool can make is the
    # one that refuses more. These read the other way, and each is the
    # refusal it was written to make, waived
    _Case(
        "btclib.script.engine.script.assert_nullfail",
        "verified",
        engine.assert_nullfail,
        {
            "flags": ScriptFlag.NULLFAIL,
            "signatures": [b""],
            "op": "OP_CHECKSIG",
        },
        reason="`True` suppresses the NULLFAIL refusal, so a non-bool lets"
        " a non-empty signature that failed to verify through a consensus"
        " rule; `verify_script`'s `final` beside it tightens instead",
    ),
    _Case(
        "btclib.fee.FeeRate.from_sats_per_vbyte",
        "round_up",
        FeeRate.from_sats_per_vbyte,
        {"sats_per_vbyte": "0.0001"},
        reason="`True` waives the refusal of a quote finer than a"
        " millisatoshi per virtual byte, so a non-bool rounds one up"
        " silently where a caller stating an exact price meant it refused",
    ),
    _Case(
        "btclib.fee.FeeRate.from_btc_per_kvbyte",
        "round_up",
        FeeRate.from_btc_per_kvbyte,
        {"btc_per_kvbyte": "0.000000001"},
        reason="`True` waives the refusal of a quote finer than a"
        " satoshi per kvB, the same way `from_sats_per_vbyte`'s does",
    ),
    _Case(
        "btclib.p2p.compact_blocks.SendCmpct.__init__",
        "announce",
        SendCmpct,
        {},
        reason="BIP152's high-bandwidth mode, and the octet written is"
        " `int(announce)`: a non-bool writes the one that asks a peer to"
        " push every new block unasked, where the message it was given"
        " said not to",
    ),
    _Case(
        "btclib.p2p.handshake.Version.__init__",
        "relay",
        Version,
        {},
        optional=True,
        reason="BIP37's flag, and what is written is a function of its"
        " value: one octet for True or False and none for None, so a"
        " non-bool would serialize as the True a peer reading it takes"
        " for a request to relay transactions",
    ),
)

_TRUTHS = (
    _Case(
        "btclib.var_bytes.parse",
        "forbid_zero_size",
        var_bytes.parse,
        {"stream": b"\x01\x00"},
        reason="whether a zero-size field is refused",
    ),
    _Case(
        "btclib.tx.tx.join",
        "enforce_same_version",
        tx_join,
        {
            "txs": [_TX, _TX_2],
            "enforce_same_lock_time": True,
            "shuffle_inp": False,
            "shuffle_out": False,
        },
        reason="whether a version the others do not share is refused; the"
        " joined transaction takes the highest either way",
    ),
    _Case(
        "btclib.tx.tx.join",
        "enforce_same_lock_time",
        tx_join,
        {
            "txs": [_TX, _TX_2],
            "enforce_same_version": True,
            "shuffle_inp": False,
            "shuffle_out": False,
        },
        reason="whether a lock time the others do not share is refused",
    ),
    _Case(
        "btclib.script.engine.__init__.verify_transaction",
        "check_amounts",
        verify_transaction,
        {"prevouts": _PREVOUTS, "tx": _TX},
        reason="whether the outputs are required to be worth no more than"
        " the inputs; the scripts run either way",
    ),
    _Case(
        "btclib.tx.tx.Tx.assert_valid",
        "unsigned_template",
        _TX.assert_valid,
        {},
        reason="whether the inputs are required to carry no signature,"
        " which is a rule about a template and not a field of the tx",
    ),
    _Case(
        "btclib.script.engine.script.verify_script",
        "final",
        engine.verify_script,
        {
            "script_bytes": b"\x51",
            "stack": [],
            "prevout_value": 0,
            "tx": _TX,
            "i": 0,
            "flags": NO_FLAGS,
            "segwit": False,
        },
        reason="whether the script is required to end on a true stack,"
        " which is the caller saying no script runs after this one; it"
        " stays here where `verified` did not, being the flag whose"
        " `True` refuses more -- a non-bool fails a script instead of"
        " passing one, and that is nobody's money",
    ),
)

_KIND_IDS = tuple(f"{case.dotted}({case.flag})" for case in _KINDS)
_TRUTH_IDS = tuple(f"{case.dotted}({case.flag})" for case in _TRUTHS)


def _flags_of(function: ast.FunctionDef) -> set[str]:
    """Return the `bool`-annotated parameters of one public function."""
    if function.name.startswith("_") and not function.name.startswith("__"):
        return set()
    arguments = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    return {
        argument.arg
        for argument in arguments
        if argument.annotation is not None
        and ast.unparse(argument.annotation) in {"bool", "bool | None"}
        and argument.arg != _OWNED_BY_ITS_OWN_FILE
    }


def _bool_parameters() -> set[tuple[str, str]]:
    """Return every (function, `bool` parameter) pair of the public API.

    Keyed on the annotation, `bool` and `bool | None`: what a flag is
    called says nothing, and `include_witness` is spelled both ways.

    A method counts and a private function does not, as in
    `curve_parameter_test.py`; and a function nested in another is a closure
    rather than API, a parameter no caller can pass.
    """
    found: set[tuple[str, str]] = set()

    def walk(node: ast.Module | ast.ClassDef, module: str, prefix: str) -> None:
        for child in node.body:
            if isinstance(child, ast.ClassDef):
                walk(child, module, f"{prefix}{child.name}.")
            elif isinstance(child, ast.FunctionDef):
                dotted = f"{module}.{prefix}{child.name}"
                found.update((dotted, flag) for flag in _flags_of(child))

    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        walk(ast.parse(path.read_text(encoding="utf-8")), module, "")
    return found


@pytest.mark.parametrize("case", [*_KINDS, *_TRUTHS], ids=[*_KIND_IDS, *_TRUTH_IDS])
def test_the_call_works(case: _Case) -> None:
    """The fixture is valid, which is what makes a refusal below a finding.

    Without this a case whose arguments had gone stale would pass every
    test in the file by refusing everything it is handed.
    """
    case.function(**case.args, **{case.flag: case.valid})


@pytest.mark.parametrize("case", _KINDS, ids=_KIND_IDS)
def test_a_kind_refuses_a_non_bool(case: _Case) -> None:
    """A kind decides what is computed, so it is not read for its truth.

    `"no"` is the value that makes the point -- it is true, so the flag
    would be on -- and `0` and `1` are the two `bool` inherits from, which
    is what makes `isinstance(value, int)` no check at all here.
    """
    wrong = _WRONG_TYPES if case.optional else (*_WRONG_TYPES, None)
    for value in wrong:
        with pytest.raises(BTClibTypeError, match=f"invalid {case.flag} type"):
            case.function(**case.args, **{case.flag: value})


@pytest.mark.parametrize("case", _TRUTHS, ids=_TRUTH_IDS)
def test_a_truth_is_read_for_its_truth(case: _Case) -> None:
    """The other half of the line, and the ratchet under this file.

    A truth turns a check on or off and changes no answer, so a value of
    another type is read for whether it is true and refused by nothing.
    An entry that starts refusing fails here rather than passing quietly:
    the fix is to move it to `_KINDS`, which is a decision about the
    parameter and not about this test.
    """
    for value in _WRONG_TYPES:
        case.function(**case.args, **{case.flag: value})


def test_every_bool_parameter_is_classified() -> None:
    """No third table: a flag is a kind or a truth, and the walk says so.

    A parameter added anywhere under `src/btclib/` fails here until somebody
    decides which of the two it is -- which is the decision this file
    exists to keep from being made by default.
    """
    classified = {(case.dotted, case.flag) for case in (*_KINDS, *_TRUTHS)}
    found = _bool_parameters()
    assert classified == found, (
        f"unclassified: {sorted(found - classified)};"
        f" gone from the tree: {sorted(classified - found)}"
    )


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes it must find, and the ones it must not.

    A walk that found nothing would pass the test above.
    """
    found = _bool_parameters()
    # a defaulted flag, a required one, an optional annotation, a method
    assert ("btclib.ecc.bms.gen_keys", "compressed") in found
    assert ("btclib.tx.tx.join", "shuffle_inp") in found
    assert ("btclib.b58.prv_key_data_from_wif", "compressed") in found
    assert ("btclib.tx.tx.Tx.serialize", "include_witness") in found

    # the convention with a file of its own
    assert not [pair for pair in found if pair[1] == "check_validity"]
    # a private function, and a parameter of another type
    assert ("btclib.block.block.Block._serialized_size", "include_witness") not in found
    assert ("btclib.hashes.merkle_root", "hf") not in found
    # and nothing of what btclib re-exports of ellipticcurves: the walk
    # reads btclib's own files, where those names are imports and no def
    assert not [pair for pair in found if pair[0].startswith("btclib.ecc.dsa.")]
