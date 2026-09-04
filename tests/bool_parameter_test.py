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
`True` is the permissive one is a kind however little it computes. Three
were: `verified`, `allow_partial` and `hybrid`, each waiving the very
refusal it was written to make. They are in `_KINDS` under a comment of
their own, and issue #884 is the one that asked, over `verified` and over
`verify_script`'s `final` beside it -- which stays a truth, its `True`
being the one that demands the true stack.

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
`KeyGroup(verify=)`. The two the issue names are the sharpest:

```text
dsa.sign(msg, q, lower_s="no")        -> a low-s signature, "no" being true
pub_keyinfo_from_prv_key(q, "no")     -> the compressed key, and its address
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
a true stack. `hwi.enumerate_devices` runs a command line, so its stand-in
is `python -c "print('[]')"` -- a device list of none, which is what an
`emulators` of the wrong type must be refused in front of.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from btclib import b32, b58, bip38, bip322, core_import, slip132, var_bytes
from btclib._libsecp256k1 import INSTALLED
from btclib.bip32.bip32 import (
    _PythonPubKeyTweakChain,
    derive,
    derive_from_account,
    derive_from_account_,
    derive_from_account_range,
    derive_from_account_range_,
    prv_keyinfo_from_xprv,
    pub_keyinfo_from_xpub,
    rootxprv_from_seed,
    xpub_from_xprv,
)
from btclib.bip32.der_path import (
    hardenings_from_der_path,
    indexes_from_der_path,
    int_from_index_str,
)
from btclib.block.block import Block
from btclib.curves.curve import (
    Curve,
    SEC2v1_params2,
    set_libsecp256k1_serving,
)
from btclib.curves.sec_point import (
    bytes_from_point,
    bytes_from_prv_key_int,
    point_from_octets,
)
from btclib.descriptors.descriptors import parse as descriptor_from_string
from btclib.ecc import bms, dsa, musig2, ssa
from btclib.exceptions import BTClibTypeError
from btclib.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib.fetch.bitcoin_core_rest import BitcoinCoreRestClient, BitcoinCoreRestFetcher
from btclib.fetch.electrum import ElectrumFetcher
from btclib.fetch.esplora import EsploraFetcher
from btclib.hwi import HwiSigner, enumerate_devices
from btclib.key import PrvKeyData
from btclib.mnemonic import bip39, slip39
from btclib.mnemonic.entropy import (
    bin_str_entropy_from_random,
    bin_str_entropy_from_rolls,
)
from btclib.mnemonic.mnemonic import WordLists
from btclib.p2p import BlockPayload, SendCmpct, TxPayload, Version
from btclib.psbt import musig2 as psbt_musig2
from btclib.psbt.psbt import Psbt, assert_signed
from btclib.psbt.psbt import join as psbt_join
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_utils import (
    deserialize_sized_int,
    deserialize_tx,
    serialize_sized_int,
)
from btclib.psbt_signer import SoftwareSigner
from btclib.script.engine import script as engine
from btclib.script.engine import script_op_codes, verify_transaction
from btclib.script.engine.flags import NO_FLAGS, ScriptFlag
from btclib.script.script import serialize as serialize_script
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.taproot import parse as taproot_parse
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from btclib.to_pub_key import (
    pub_keyinfo_from_key,
    pub_keyinfo_from_prv_key,
    pub_keyinfo_from_pub_key,
)
from btclib.tx.coin import Coin
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx import join as tx_join
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from btclib.wallet.script_wallet import KeyGroup
from tests.fetch import Recorded
from tests.fetch.bitcoin_core_test import client
from tests.fetch.electrum_test import LineRecorded
from tests.psbt import psbt_cases


def _is_signed(psbt: Psbt) -> bool:
    """Return whether every input of the psbt is signed through."""
    try:
        assert_signed(psbt)
    except Exception:  # noqa: BLE001
        return False
    return True


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

_ROOT_XPRV = rootxprv_from_seed("00" * 32)
_ACCOUNT_XPRV = derive(_ROOT_XPRV, "m/44h/0h/0h")


# a block cipher this file never has to get right: `bip38.encrypt` and
# `new_key_pair` need one to reach `compressed` at all, and what happens
# to the plaintext is not this file's question, only whether the flag it
# is refusing was read for its type. A 16-byte block in, the same 16
# bytes out, is a cipher no BIP38 record could be decrypted with and a
# perfectly good fixture
def _block_cipher(key: bytes, block: bytes) -> bytes:
    return block


_INT_CODE = bip38.intermediate_code("test password")

# the cheapest catalogued curve, and the point of it is that both
# construction-time checks pass on it: a low-cardinality one is MOV-weak,
# which is what `weakness_check=True` is there to refuse
_SMALL_CURVE = dict(
    zip(
        ("p", "a", "b", "G", "n", "cofactor"),
        SEC2v1_params2["secp112r1"][:6],
        strict=True,
    )
)
_XPUB = xpub_from_xprv(_ROOT_XPRV)
_DESCRIPTOR = descriptor_from_string(f"wpkh({_XPUB}/0/*)")
_ADDRESS = b58.p2pkh(_PUB_KEY)
_BIP322_SIG = bip322.sign(_MSG, PrvKeyData(_PRV_KEY), _ADDRESS)

# a transaction with an input, which is what the engine and the psbt
# boundary both refuse to work without
_TX = Tx(vin=[TxIn(OutPoint(b"\x00" * 32, 0))], vout=[TxOut(1000, b"\x51")])
# a second one spending another outpoint: what `join` refuses is two
# transactions with an input in common, so one twice is no fixture
_TX_2 = Tx(vin=[TxIn(OutPoint(b"\x11" * 32, 1))], vout=[TxOut(900, b"\x51")])
_PSBTS = [Psbt.from_tx(_TX), Psbt.from_tx(_TX_2)]
_TX_BYTES = _TX.serialize(include_witness=False, check_validity=False)
# OP_1 as the output being spent: a script anyone can satisfy, so the one
# verification below is about `check_amounts` and not about a signature
_PREVOUTS = [TxOut(2000, b"\x51")]

_BLOCK = Block.parse(
    (Path(__file__).parent / "block" / "_data" / "block_1.bin").read_bytes()
)

# the first BIP174 vector that is signed through, which is what makes
# `allow_partial` a flag both of whose values accept it
_SIGNED_PSBT = next(
    psbt
    for psbt in (
        Psbt.b64decode(case["encoded psbt"])
        for case in psbt_cases("bip174_test_vectors.json", "valid psbts")
    )
    if _is_signed(psbt)
)

# a device that answers HWI's own shape and needs no device: the flag is
# read in front of the command line, which is where it has to be
_STAND_IN = [sys.executable, "-c", "print('[]')"]

_KEY_AGG = musig2.key_agg([_SEC, _SEC_2])


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
    # which address: a handful of checks, the rest of the `compressed`
    # parameters reaching one of them
    _Case(
        "btclib.curves.sec_point.bytes_from_point",
        "compressed",
        bytes_from_point,
        {"Q": _PUB_KEY},
    ),
    _Case(
        "btclib.curves.sec_point.bytes_from_prv_key_int",
        "compressed",
        bytes_from_prv_key_int,
        {"prv_key_int": _PRV_KEY},
    ),
    _Case(
        "btclib.key.PrvKeyData.__init__",
        "compressed",
        PrvKeyData,
        {"q": _PRV_KEY},
    ),
    _Case(
        "btclib.to_prv_key.prv_keyinfo_from_prv_key",
        "compressed",
        prv_keyinfo_from_prv_key,
        {"prv_key": _PRV_KEY},
        optional=True,
    ),
    _Case(
        "btclib.to_pub_key.pub_keyinfo_from_key",
        "compressed",
        pub_keyinfo_from_key,
        {"key": _SEC},
        optional=True,
    ),
    _Case(
        "btclib.to_pub_key.pub_keyinfo_from_pub_key",
        "compressed",
        pub_keyinfo_from_pub_key,
        {"pub_key": _SEC},
        optional=True,
    ),
    _Case(
        "btclib.to_pub_key.pub_keyinfo_from_prv_key",
        "compressed",
        pub_keyinfo_from_prv_key,
        {"prv_key": _PRV_KEY},
        optional=True,
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
    _Case("btclib.b58.p2pkh", "compressed", b58.p2pkh, {"key": _SEC}, optional=True),
    _Case(
        "btclib.bip38.encrypt",
        "compressed",
        bip38.encrypt,
        {
            "prv_key": _PRV_KEY,
            "password": "pw",  # pragma: allowlist secret
            "encrypt_block": _block_cipher,
        },
    ),
    _Case(
        "btclib.bip38.new_key_pair",
        "compressed",
        bip38.new_key_pair,
        {"int_code": _INT_CODE, "encrypt_block": _block_cipher},
    ),
    # the one that is a bound method: a chain holds the point it steps,
    # so the instance is built here and `bytes_from_point` above is the
    # check this one reaches. A refused call must not step it, which is
    # why the serialization happens before the step rather than after
    _Case(
        "btclib.bip32.bip32._PythonPubKeyTweakChain.tweak_add",
        "compressed",
        _PythonPubKeyTweakChain(_SEC).tweak_add,
        {"tweak": _PRV_KEY.to_bytes(32, byteorder="big", signed=False)},
    ),
    _Case(
        "btclib.ecc.bms.gen_keys",
        "compressed",
        bms.gen_keys,
    ),
    _Case(
        "btclib.script.script_pub_key.ScriptPubKey.p2pkh",
        "compressed",
        ScriptPubKey.p2pkh,
        {"key": _SEC},
        optional=True,
    ),
    _Case(
        "btclib.script.script_pub_key.ScriptPubKey.p2ms",
        "compressed",
        ScriptPubKey.p2ms,
        {"m": 1, "keys": [_SEC, _SEC_2]},
        optional=True,
    ),
    _Case(
        "btclib.script.script_pub_key.ScriptPubKey.p2ms",
        "lexicographic_sorting",
        ScriptPubKey.p2ms,
        {"m": 1, "keys": [_SEC, _SEC_2]},
    ),
    # `lower_s` chooses which of the two signatures is returned, `grind`
    # whether the nonce is searched until r is short
    _Case(
        "btclib.ecc.dsa.sign_",
        "lower_s",
        dsa.sign_,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY},
    ),
    _Case(
        "btclib.ecc.dsa.sign", "lower_s", dsa.sign, {"msg": _MSG, "prv_key": _PRV_KEY}
    ),
    _Case(
        "btclib.ecc.dsa.sign_recoverable_",
        "lower_s",
        dsa.sign_recoverable_,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY},
    ),
    _Case(
        "btclib.ecc.dsa.sign_recoverable",
        "lower_s",
        dsa.sign_recoverable,
        {"msg": _MSG, "prv_key": _PRV_KEY},
    ),
    _Case(
        "btclib.ecc.dsa.anti_exfil_sign",
        "lower_s",
        dsa.anti_exfil_sign,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY, "rho": _MSG_HASH},
    ),
    _Case(
        "btclib.ecc.dsa.sign_",
        "grind",
        dsa.sign_,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY},
    ),
    _Case("btclib.ecc.dsa.sign", "grind", dsa.sign, {"msg": _MSG, "prv_key": _PRV_KEY}),
    _Case(
        "btclib.ecc.dsa.Signer.sign_",
        "grind",
        dsa.Signer(_PRV_KEY).sign_,
        {"msg_hash": _MSG_HASH},
    ),
    _Case(
        "btclib.ecc.dsa.Signer.sign", "grind", dsa.Signer(_PRV_KEY).sign, {"msg": _MSG}
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
    # the psbt boundary: which integer encoding, and which transaction
    _Case(
        "btclib.psbt.psbt_utils.deserialize_sized_int",
        "signed",
        deserialize_sized_int,
        {"k": b"\x00", "v": b"\x01\x00\x00\x00", "type_": "field", "size": 4},
        valid=False,
    ),
    _Case(
        "btclib.psbt.psbt_utils.serialize_sized_int",
        "signed",
        serialize_sized_int,
        {"type_": b"\x00", "value": 1, "size": 4},
        valid=False,
    ),
    _Case(
        "btclib.psbt.psbt_utils.deserialize_tx",
        "include_witness",
        deserialize_tx,
        {"k": b"\x00", "v": _TX_BYTES, "type_": "field"},
        valid=False,
    ),
    _Case(
        "btclib.psbt.psbt_utils.deserialize_tx",
        "unsigned_template",
        deserialize_tx,
        {"k": b"\x00", "v": _TX_BYTES, "type_": "field", "include_witness": False},
        valid=False,
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
        "btclib.psbt.musig2.add_participant_pub_keys",
        "sort",
        psbt_musig2.add_participant_pub_keys,
        {"psbt_map": PsbtIn(), "participant_pub_keys": [_SEC, _SEC_2]},
        valid=False,
    ),
    _Case(
        "btclib.mnemonic.entropy.bin_str_entropy_from_rolls",
        "shuffle",
        bin_str_entropy_from_rolls,
        {"bits": 8, "dice_sides": 6, "rolls": [1, 2, 3, 4, 5, 6, 1, 2]},
    ),
    _Case(
        "btclib.mnemonic.entropy.bin_str_entropy_from_random",
        "to_be_hashed",
        bin_str_entropy_from_random,
        {"bits": 128},
    ),
    _Case(
        "btclib.psbt.psbt.join",
        "shuffle_inp",
        psbt_join,
        {
            "psbts": _PSBTS,
            "enforce_same_tx_version": True,
            "enforce_same_tx_lock_time": True,
            "shuffle_out": False,
        },
        valid=False,
    ),
    _Case(
        "btclib.psbt.psbt.join",
        "shuffle_out",
        psbt_join,
        {
            "psbts": _PSBTS,
            "enforce_same_tx_version": True,
            "enforce_same_tx_lock_time": True,
            "shuffle_inp": False,
        },
        valid=False,
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
    # which verification runs: a BMS signature over the message, or
    # BIP322's own
    _Case(
        "btclib.bip322.assert_as_valid",
        "legacy",
        bip322.assert_as_valid,
        {"msg": _MSG, "addr": _ADDRESS, "sig": _BIP322_SIG},
    ),
    _Case(
        "btclib.bip322.verify",
        "legacy",
        bip322.verify,
        {"msg": _MSG, "addr": _ADDRESS, "sig": _BIP322_SIG},
    ),
    _Case(
        "btclib.hwi.enumerate_devices",
        "emulators",
        enumerate_devices,
        {"executable": _STAND_IN},
        valid=False,
    ),
    _Case(
        "btclib.hwi.HwiSigner.__init__",
        "emulators",
        HwiSigner,
        {"fingerprint": "00" * 4, "executable": _STAND_IN},
        valid=False,
    ),
    _Case(
        "btclib.psbt_signer.SoftwareSigner.__init__",
        "musig2",
        SoftwareSigner,
        {"xkey": _ROOT_XPRV},
        valid=False,
    ),
    _Case(
        "btclib.psbt_signer.SoftwareSigner.from_accounts",
        "musig2",
        SoftwareSigner.from_accounts,
        {"master_fingerprint": "00" * 4, "accounts": {"m/0h": _XPUB}},
        valid=False,
    ),
    _Case(
        "btclib.core_import.import_request",
        "internal",
        core_import.import_request,
        {"descriptor": _DESCRIPTOR, "timestamp": 0},
        valid=False,
    ),
    _Case(
        "btclib.core_import.import_request",
        "active",
        core_import.import_request,
        {"descriptor": _DESCRIPTOR, "timestamp": 0},
    ),
    _Case(
        "btclib.core_import.account_import_requests",
        "active",
        core_import.account_import_requests,
        {"receive": _DESCRIPTOR, "change": _DESCRIPTOR, "timestamp": 0},
    ),
    _Case(
        "btclib.mnemonic.slip39.mnemonics_from_master_secret",
        "extendable",
        slip39.mnemonics_from_master_secret,
        {"master_secret": "00" * 16},
    ),
    _Case(
        "btclib.ecc.musig2.apply_tweak",
        "is_xonly",
        musig2.apply_tweak,
        {"key_agg_ctx": _KEY_AGG, "tweak": b"\x01" * 32},
    ),
    _Case(
        "btclib.wallet.script_wallet.KeyGroup.__init__",
        "verify",
        KeyGroup,
        {"threshold": 2, "keys": [_XPUB, _XPUB]},
        valid=False,
    ),
    # `serving` chooses which implementation every later call reaches, so
    # it is as much a kind as `compressed` is: a value read for its truth
    # would let `serving="no"` ask for C and `serving=0` for Python, and
    # a caller that asked for one and got the other would be timing the
    # other and calling it the one. `valid=True` and not False, so that
    # the call this file makes leaves the state an installation with the
    # bindings is normally in
    _Case(
        "btclib.curves.curve.set_libsecp256k1_serving",
        "serving",
        set_libsecp256k1_serving,
        {},
        valid=INSTALLED,
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
        "btclib.psbt.psbt.assert_signed",
        "allow_partial",
        assert_signed,
        {"psbt": _SIGNED_PSBT},
        reason="`True` accepts an input still unsigned, so a non-bool"
        " stores as complete a psbt nobody finished signing",
    ),
    _Case(
        "btclib.curves.sec_point.point_from_octets",
        "hybrid",
        point_from_octets,
        {"pub_key": _SEC},
        reason="`True` accepts the 0x06 and 0x07 prefixes, so a non-bool"
        " parses the very forms it was written down to keep out",
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
    # the two extended-key parses. Their `compressed` computes nothing --
    # a BIP32 key is compressed, so the flag is a check on a key that has
    # already answered the question -- and it is the polarity that makes
    # each a kind
    _Case(
        "btclib.bip32.bip32.prv_keyinfo_from_xprv",
        "compressed",
        prv_keyinfo_from_xprv,
        {"xprv": _ROOT_XPRV},
        optional=True,
        reason="`True` is the value an extended key already has, so a"
        " non-bool passes the check a False was written down to fail and"
        " an uncompressed key is reported as this compressed one",
    ),
    _Case(
        "btclib.bip32.bip32.pub_keyinfo_from_xpub",
        "compressed",
        pub_keyinfo_from_xpub,
        {"xpub": _XPUB},
        optional=True,
        reason="`prv_keyinfo_from_xprv`'s above, on the public half",
    ),
)

_TRUTHS = (
    _Case(
        "btclib.slip132.p2pkh_xkey",
        "check_root_xkey",
        slip132.p2pkh_xkey,
        {"xkey": _ROOT_XPRV},
        reason="whether the xkey is required to be a root one",
    ),
    _Case(
        "btclib.slip132.p2wpkh_xkey",
        "check_root_xkey",
        slip132.p2wpkh_xkey,
        {"xkey": _ROOT_XPRV},
        reason="whether the xkey is required to be a root one",
    ),
    _Case(
        "btclib.slip132.p2wpkh_p2sh_xkey",
        "check_root_xkey",
        slip132.p2wpkh_p2sh_xkey,
        {"xkey": _ROOT_XPRV},
        reason="whether the xkey is required to be a root one",
    ),
    _Case(
        "btclib.mnemonic.bip39.seed_from_mnemonic",
        "verify_checksum",
        bip39.seed_from_mnemonic,
        {"mnemonic": "abandon " * 11 + "about", "passphrase": ""},
        reason="whether the mnemonic's checksum is checked; the seed is the"
        " same either way, being a PBKDF2 of the words",
    ),
    _Case(
        "btclib.mnemonic.bip39.mxprv_from_mnemonic",
        "verify_checksum",
        bip39.mxprv_from_mnemonic,
        {"mnemonic": "abandon " * 11 + "about"},
        reason="whether the mnemonic's checksum is checked",
    ),
    _Case(
        "btclib.curves.curve.Curve.__init__",
        "weakness_check",
        Curve,
        _SMALL_CURVE,
        reason="whether the embedding degree is derived; a construction-time"
        " check, and no parameter of the curve built",
    ),
    _Case(
        "btclib.curves.curve.Curve.__init__",
        "order_check",
        Curve,
        _SMALL_CURVE,
        reason="whether n*G is verified to be the point at infinity",
    ),
    _Case(
        "btclib.bip32.der_path.int_from_index_str",
        "bip380_enforced",
        int_from_index_str,
        {"s": "0"},
        reason="whether BIP380's spelling rules are enforced; an index both"
        " accept is the same integer",
    ),
    _Case(
        "btclib.bip32.der_path.indexes_from_der_path",
        "bip380_enforced",
        indexes_from_der_path,
        {"der_path": "0/1"},
        reason="whether BIP380's spelling rules are enforced",
    ),
    _Case(
        "btclib.bip32.der_path.hardenings_from_der_path",
        "bip380_enforced",
        hardenings_from_der_path,
        {"der_path": "0/1"},
        reason="whether BIP380's spelling rules are enforced",
    ),
    _Case(
        "btclib.ecc.dsa.Sig.parse",
        "strict",
        dsa.Sig.parse,
        {"data": _DER_SIG},
        reason="whether the encoding must be Bitcoin Core's canonical one,"
        " trailing bytes and non-minimal scalars alike; the signature"
        " parsed out of what both readings accept is one signature",
    ),
    _Case(
        "btclib.ecc.dsa.sign_",
        "verify",
        dsa.sign_,
        {"msg_hash": _MSG_HASH, "prv_key": _PRV_KEY},
        reason="whether the signature is checked before it is answered with;"
        " the signature is the same either way, the check being a"
        " verification of what has already been computed",
    ),
    _Case(
        "btclib.ecc.dsa.sign",
        "verify",
        dsa.sign,
        {"msg": _MSG, "prv_key": _PRV_KEY},
        reason="whether the signature is checked before it is answered with",
    ),
    _Case(
        "btclib.ecc.dsa.Signer.sign_",
        "verify",
        dsa.Signer(_PRV_KEY).sign_,
        {"msg_hash": _MSG_HASH},
        reason="whether the signature is checked before it is answered with",
    ),
    _Case(
        "btclib.ecc.dsa.Signer.sign",
        "verify",
        dsa.Signer(_PRV_KEY).sign,
        {"msg": _MSG},
        reason="whether the signature is checked before it is answered with",
    ),
    _Case(
        "btclib.ecc.ssa.sign_",
        "verify",
        ssa.sign_,
        {"msg": _MSG, "prv_key": _PRV_KEY},
        reason="whether the signature is checked before it is answered with;"
        " the signature is the same either way, the check being a"
        " verification of what has already been computed",
    ),
    _Case(
        "btclib.ecc.ssa.sign",
        "verify",
        ssa.sign,
        {"msg": _MSG, "prv_key": _PRV_KEY},
        reason="whether the signature is checked before it is answered with",
    ),
    _Case(
        "btclib.ecc.ssa.Signer.sign_",
        "verify",
        ssa.Signer(_PRV_KEY).sign_,
        {"msg": _MSG},
        reason="whether the signature is checked before it is answered with",
    ),
    _Case(
        "btclib.ecc.ssa.Signer.sign",
        "verify",
        ssa.Signer(_PRV_KEY).sign,
        {"msg": _MSG},
        reason="whether the signature is checked before it is answered with",
    ),
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
        "btclib.psbt.psbt.join",
        "enforce_same_tx_version",
        psbt_join,
        {
            "psbts": _PSBTS,
            "enforce_same_tx_lock_time": True,
            "shuffle_inp": False,
            "shuffle_out": False,
        },
        reason="whether a transaction version the others do not share is refused",
    ),
    _Case(
        "btclib.psbt.psbt.join",
        "enforce_same_tx_lock_time",
        psbt_join,
        {
            "psbts": _PSBTS,
            "enforce_same_tx_version": True,
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
        "btclib.fetch.bitcoin_core.BitcoinCoreFetcher.__init__",
        "verify_network",
        BitcoinCoreFetcher,
        {"client": client()},
        reason="whether the node is asked which chain it serves; a check,"
        " and the one the fetcher makes before its first fetch",
    ),
    _Case(
        "btclib.fetch.bitcoin_core_rest.BitcoinCoreRestFetcher.__init__",
        "verify_network",
        BitcoinCoreRestFetcher,
        {
            "client": BitcoinCoreRestClient(
                "http://127.0.0.1:8332", transport=Recorded()
            )
        },
        reason="whether the node is asked which chain it serves, the same"
        " check over -rest, `/chaininfo.json` carrying the same `chain`",
    ),
    _Case(
        "btclib.fetch.esplora.EsploraFetcher.__init__",
        "verify_network",
        EsploraFetcher,
        {"base_url": "https://esplora.example/api", "transport": Recorded()},
        reason="whether the explorer is asked which chain it serves; the"
        " same check under the same name, made before its first fetch",
    ),
    _Case(
        "btclib.fetch.electrum.ElectrumFetcher.__init__",
        "verify_network",
        ElectrumFetcher,
        {"transport": LineRecorded()},
        reason="whether the server is asked which chain it serves; the"
        " same check again, over the header at height 0 this backend"
        " hashes rather than a chain name it would be told",
    ),
    _Case(
        "btclib.bip32.bip32.derive_from_account",
        "branches_0_1_only",
        derive_from_account,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_index": 0},
        reason="whether a branch other than 0 and 1 is refused; the key"
        " derived at a branch both accept is the same key",
    ),
    _Case(
        "btclib.bip32.bip32.derive_from_account_",
        "branches_0_1_only",
        derive_from_account_,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_index": 0},
        reason="the flag of `derive_from_account` above, in the spelling"
        " that answers the key rather than its Base58Check text",
    ),
    _Case(
        "btclib.bip32.bip32.derive_from_account_range",
        "branches_0_1_only",
        derive_from_account_range,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_indexes": [0]},
        reason="the flag of `derive_from_account` above, over many"
        " addresses of one branch rather than over one",
    ),
    _Case(
        "btclib.bip32.bip32.derive_from_account_range_",
        "branches_0_1_only",
        derive_from_account_range_,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_indexes": [0]},
        reason="the flag of `derive_from_account_range` above, in the"
        " spelling that answers the keys rather than their text",
    ),
    _Case(
        "btclib.mnemonic.mnemonic.WordLists.__init__",
        "power_of_two",
        WordLists,
        {},
        reason="whether a word list whose length is not a power of two is"
        " refused, which is what Electrum's 1626 words need off",
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
    if any(ast.unparse(d) == "overload" for d in function.decorator_list):
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
    `curve_parameter_test.py`; an `@overload` stub is not a function to
    drive; and a function nested in another is a closure rather than API --
    `Miniscript.to_script`'s `up` takes a `verify` that no caller can pass.
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
    """The shapes it must find, and the four it must not.

    A walk that found nothing would pass the test above.
    """
    found = _bool_parameters()
    # a defaulted flag, a required one, an optional annotation, a method
    assert ("btclib.ecc.dsa.sign", "lower_s") in found
    assert ("btclib.tx.tx.join", "shuffle_inp") in found
    assert ("btclib.b58.p2pkh", "compressed") in found
    assert ("btclib.tx.tx.Tx.serialize", "include_witness") in found

    # the convention with a file of its own
    assert not [pair for pair in found if pair[1] == "check_validity"]
    # a private function, a closure, and a parameter of another type
    assert ("btclib.ecc.musig2._flag", "is_xonly") not in found
    assert ("btclib.descriptors.miniscript.up", "verify") not in found
    assert ("btclib.hashes.reduce_to_hlen", "hf") not in found
