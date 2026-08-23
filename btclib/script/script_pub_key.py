# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""ScriptPubKey and the classification of the standard script shapes.

Every standard shape has an assert_* function, raising
BTClibValueError on bytes that are not it, and an is_* companion
answering the same test as a bool: False means "not this shape", while
a caller error -- None, a list, anything no bytes can be read from --
raises through both, a TypeError not being an answer to "is this a
p2sh". The assert functions test shape, not spendability: any 20 bytes
are a pub_key hash to assert_p2pkh, and only assert_p2pk parses its
key, the script being the one place the key itself sits.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from typing_extensions import override

from btclib import b32, b58, var_bytes
from btclib.alias import Octets, ScriptList, ScriptType, String, TaprootScriptTree
from btclib.curves import point_from_octets
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.network import NETWORKS, network_type_from_network
from btclib.script.script import Script, op_int, serialize
from btclib.script.taproot import output_pubkey
from btclib.to_pub_key import Key, pub_keyinfo_from_key
from btclib.utils import assert_type, bytes_from_octets, bytesio_from_binarydata

__all__ = [
    "ScriptPubKey",
    "address",
    "addresses",
    "assert_nulldata",
    "assert_p2ms",
    "assert_p2pk",
    "assert_p2pkh",
    "assert_p2sh",
    "assert_p2tr",
    "assert_p2wpkh",
    "assert_p2wsh",
    "assert_segwit",
    "is_nulldata",
    "is_p2ms",
    "is_p2pk",
    "is_p2pkh",
    "is_p2sh",
    "is_p2tr",
    "is_p2wpkh",
    "is_p2wsh",
    "is_segwit",
    "p2ms_m_and_keys",
    "type_and_payload",
]


def address(script_pub_key: Octets, network: str = "mainnet") -> str:
    """Return the bech32/base58 address from a script_pub_key.

    A witness program of version 2 or higher has an address as much as
    a p2tr one does -- bech32m spells it, `b32.address_from_witness`
    writes it, and Bitcoin Core renders it, `EncodeDestination` having
    a `WitnessUnknown` case. Answering "" for one would be
    indistinguishable from "this script has no address", which is the
    right answer for a nulldata output and the wrong one where btclib
    can read the address back into the very script it came from
    (issue #251).
    """
    # the coercion before the truthiness, which is what tells an empty
    # script from a script that has no address: `None` is falsy just as
    # `b""` is, so a caller passing one was answered "" -- the answer a
    # nulldata output has, and not a word about the argument
    script_pub_key = bytes_from_octets(script_pub_key)

    if script_pub_key:
        script_type, payload = type_and_payload(script_pub_key)
        if script_type in {"p2pkh", "p2sh"}:
            return b58.address_from_h160(script_type, payload, network)
        if script_type in {"p2wsh", "p2wpkh"}:
            return b32.address_from_witness(0, payload, network)
        if script_type == "p2tr":
            return b32.address_from_witness(1, payload, network)
        if script_type == "witness_unknown":
            # the one type whose version the answer does not imply: it is
            # the op code the program follows, OP_2..OP_16 being 0x52..0x60
            version = script_pub_key[0] - 0x50
            return b32.address_from_witness(version, payload, network)

    # not script_pub_key
    # or
    # a script_pub_key of type p2pk, p2ms, nulldata or unknown
    return ""


def p2ms_m_and_keys(script_pub_key: Octets) -> tuple[int, list[bytes]]:
    """Return the threshold and the pub keys of a p2ms script_pub_key.

    The bounds are checked -- 0 < m <= n < 17 -- and each key is read as
    a push of the declared length and then parsed as a public key: a
    push that is not one is what makes the bytes not a p2ms, which is the
    answer `is_p2ms` gives.

    The keys come back as the script holds them, uncompressed ones
    included, and not as the parse normalized them: BIP174 keys a partial
    signature by the key "as it appears in the scriptPubKey or
    redeemScript", so the Finalizer below matches these bytes.

    Three callers ask this one question, which is why it is asked in one
    place: `addresses` wants a p2pkh address per key, `assert_p2ms` the
    exception alone, and the psbt Finalizer both halves of the answer --
    OP_CHECKMULTISIG takes m signatures, in the order the script lists
    the keys they belong to.
    """
    script_pub_key = bytes_from_octets(script_pub_key)
    # p2ms: m pub_keys n OP_CHECKMULTISIG
    length = len(script_pub_key)
    if length < 37:
        raise BTClibValueError(f"invalid p2ms length {length}")
    if script_pub_key[-1] != 0xAE:
        raise BTClibValueError("missing final OP_CHECKMULTISIG")
    m = script_pub_key[0] - 80
    if not 0 < m < 17:
        raise BTClibValueError(f"invalid m in m-of-n: {m}")
    n = script_pub_key[-2] - 80
    if not m <= n < 17:
        raise BTClibValueError(f"invalid m-of-n: {m}-of-{n}")

    stream = bytesio_from_binarydata(script_pub_key[1:-2])
    pub_keys = [var_bytes.parse(stream) for _ in range(n)]

    if stream.read(1):
        raise BTClibValueError("invalid p2ms script_pub_key size")

    for pub_key in pub_keys:
        pub_keyinfo_from_key(pub_key)

    return m, pub_keys


def addresses(script_pub_key: Octets, network: str = "mainnet") -> list[str]:
    """Return the p2pkh addresses of the pub_keys in a p2ms script_pub_key."""
    _, pub_keys = p2ms_m_and_keys(script_pub_key)
    return [b58.p2pkh(pub_key, network) for pub_key in pub_keys]


def _is_funct(assert_funct: Callable[[Octets], None], script_pub_key: Octets) -> bool:
    try:
        # if the assert function detects a problem, it must raise
        assert_funct(script_pub_key)
    # ValueError, not Exception: these bool functions answer "are these
    # bytes a p2sh script", so bytes that are not are False. A TypeError is
    # a different answer -- is_p2sh(None) is not a p2sh script the way
    # b"\x00" is not one, it is a caller passing the wrong thing -- and so
    # are AttributeError, RecursionError and MemoryError. Catching Exception
    # would make every one of them a plausible False.
    # BTClibValueError is a ValueError, and so is what bytes.fromhex raises
    # on a bad hex-string, which is why plain ValueError is the catch
    except ValueError:
        return False
    return True


def assert_p2pk(script_pub_key: Octets) -> None:
    """Refuse bytes that are not p2pk: a pushed pub_key, OP_CHECKSIG.

    The key must parse as a curve point, so a well-shaped script
    pushing 33 or 65 bytes that are not one is refused too.
    """
    script_pub_key = bytes_from_octets(script_pub_key, (35, 67))
    # p2pk: pub_key OP_CHECKSIG
    # 0x41{65-byte pub_key}AC
    # or
    # 0x21{33-byte pub_key}AC
    if script_pub_key[-1] != 0xAC:
        raise BTClibValueError("missing final OP_CHECKSIG")

    len_marker = script_pub_key[0]
    length = len(script_pub_key)
    if length == 35:
        if len_marker != 0x21:
            err_msg = f"invalid pub_key length marker: {len_marker}"
            err_msg += " instead of 33"
            raise BTClibValueError(err_msg)
    elif length == 67 and len_marker != 0x41:
        err_msg = f"invalid pub_key length marker: {len_marker}"
        err_msg += " instead of 65"
        raise BTClibValueError(err_msg)

    pub_key = script_pub_key[1:-1]
    point_from_octets(pub_key)


def is_p2pk(script_pub_key: Octets) -> bool:
    """Answer whether the bytes are a p2pk script_pub_key."""
    return _is_funct(assert_p2pk, script_pub_key)


def assert_p2pkh(script_pub_key: Octets) -> None:
    """Refuse bytes that are not p2pkh.

    The shape is OP_DUP OP_HASH160, a 20-byte push, OP_EQUALVERIFY
    OP_CHECKSIG; the hash is any 20 bytes.
    """
    script_pub_key = bytes_from_octets(script_pub_key, 25)
    # p2pkh [OP_DUP, OP_HASH160, pub_key hash, OP_EQUALVERIFY, OP_CHECKSIG]
    # 0x76A914{20-byte pub_key_hash}88AC
    if script_pub_key[-2:] != b"\x88\xac":
        raise BTClibValueError("missing final OP_EQUALVERIFY, OP_CHECKSIG")
    if script_pub_key[:2] != b"\x76\xa9":
        raise BTClibValueError("missing leading OP_DUP, OP_HASH160")
    if script_pub_key[2] != 0x14:
        err_msg = f"invalid pub_key hash length marker: {script_pub_key[2]}"
        err_msg += " instead of 20"
        raise BTClibValueError(err_msg)


def is_p2pkh(script_pub_key: Octets) -> bool:
    """Answer whether the bytes are a p2pkh script_pub_key."""
    return _is_funct(assert_p2pkh, script_pub_key)


def assert_p2sh(script_pub_key: Octets) -> None:
    """Refuse bytes that are not p2sh, per BIP16.

    The shape is OP_HASH160, a 20-byte push, OP_EQUAL; the hash is any
    20 bytes.
    """
    script_pub_key = bytes_from_octets(script_pub_key, 23)
    # p2sh [OP_HASH160, redeem_script hash, OP_EQUAL]
    # 0xA914{20-byte redeem_script hash}87
    if script_pub_key[-1] != 0x87:
        raise BTClibValueError("missing final OP_EQUAL")
    if script_pub_key[0] != 0xA9:
        raise BTClibValueError("missing leading OP_HASH160")
    if script_pub_key[1] != 0x14:
        err_msg = f"invalid redeem script hash length marker: {script_pub_key[1]}"
        err_msg += " instead of 20"
        raise BTClibValueError(err_msg)


def is_p2sh(script_pub_key: Octets) -> bool:
    """Answer whether the bytes are a p2sh script_pub_key."""
    return _is_funct(assert_p2sh, script_pub_key)


def assert_p2ms(script_pub_key: Octets) -> None:
    """Refuse bytes that are not p2ms: m, the pushed keys, n, OP_CHECKMULTISIG.

    `p2ms_m_and_keys` is the whole of the check, and says what it is.
    """
    p2ms_m_and_keys(script_pub_key)


def is_p2ms(script_pub_key: Octets) -> bool:
    """Answer whether the bytes are a p2ms script_pub_key."""
    return _is_funct(assert_p2ms, script_pub_key)


def assert_nulldata(script_pub_key: Octets) -> None:
    """Assert the standard nulldata shape: OP_RETURN and one minimal push.

    A policy, and narrower than Bitcoin Core's classification on every
    count. Core's `Solver` answers NULL_DATA for an OP_RETURN whose
    remaining bytes pass `IsPushOnly`, which refuses only an op code above
    OP_16: any number of pushes qualifies, OP_1..OP_16 among them, and so
    does the empty remainder of a bare OP_RETURN. The 83-byte bound is a
    third thing again, `MAX_OP_RETURN_RELAY` being relay policy tested by
    `IsStandardTx` and not by the classifier, and the length 78 refused
    below is the non-minimal push of 75 bytes through OP_PUSHDATA1, which
    consensus allows. So `6a`, `6a51`, `6a0101010102` and a nulldata of
    any size are NULL_DATA there and unknown here (issue #211).

    The narrowness is what lets `type_and_payload` answer at all: it
    returns one payload, and OP_RETURN followed by push-only bytes has
    none for a bare OP_RETURN and two for two pushes. It is also the one
    shape `ScriptPubKey.nulldata` builds, so the classifier agrees with
    the constructor. A caller wanting Core's answer wants a different
    function, returning a list of payloads.

    `6a00` is accepted, and by arithmetic rather than by Core's rule: the
    `00` is read here as the length marker of a zero-length push, where
    Core reads it as OP_0, a push like any other.
    """
    script_pub_key = bytes_from_octets(script_pub_key)
    # nulldata: OP_RETURN data
    length = len(script_pub_key)
    if length == 0:
        raise BTClibValueError("null length")
    if script_pub_key[0] != 0x6A:
        raise BTClibValueError("missing leading OP_RETURN")

    # a lone OP_RETURN has no data length marker to read: script_pub_key[1]
    # below would answer it with an IndexError, from outside the library's
    # exception contract and not the ValueError _is_funct catches, so
    # is_nulldata would raise rather than answer False
    if length == 1:
        raise BTClibValueError("missing data length marker")

    if length == 78 or length >= 84:
        raise BTClibValueError(f"invalid length {length}")

    # OP_RETURN, data length, data up to 75 bytes max
    # 0x6A{1 byte data-length}{data (0-75 bytes)}
    if length < 78:
        if script_pub_key[1] != length - 2:
            raise BTClibValueError(f"invalid data length marker {script_pub_key[1]}")
    # OP_RETURN, OP_PUSHDATA1, data length, data min 76 bytes up to 80
    # 0x6A4C{1-byte data-length}{data (76-80 bytes)}
    elif script_pub_key[1] != 0x4C or script_pub_key[2] != length - 3:
        err_msg = f"invalid data length marker {script_pub_key[1:2].hex()}"
        raise BTClibValueError(err_msg)


def is_nulldata(script_pub_key: Octets) -> bool:
    """Answer whether the bytes are a standard nulldata script_pub_key."""
    return _is_funct(assert_nulldata, script_pub_key)


def assert_segwit(script_pub_key: Octets) -> None:
    """Refuse bytes that are not a witness program, per BIP141.

    The shape every segwit output shares, whatever its version: one
    version op code -- OP_0 or OP_1..OP_16 -- and one push of 2 to 40
    bytes. Shape only; the program is not interpreted.
    """
    script_pub_key = bytes_from_octets(script_pub_key)
    # an empty script has no version byte to read: script_pub_key[0] would
    # answer it with an IndexError, from outside the exception contract
    # and not the ValueError _is_funct catches
    if not script_pub_key:
        raise BTClibValueError("null length")
    if not (script_pub_key[0] == 0 or 0x51 <= script_pub_key[0] <= 0x60):
        raise BTClibValueError(f"invalid witness version: {hex(script_pub_key[0])}")
    if len(script_pub_key) == 1 or not 2 <= script_pub_key[1] <= 40:
        raise BTClibValueError("invalid witness program length")
    if len(script_pub_key) != script_pub_key[1] + 2:
        raise BTClibValueError(
            f"invalid segwit script length: {len(script_pub_key)}, "
            f"{script_pub_key[1] + 2} expected"
        )


def is_segwit(script_pub_key: Octets) -> bool:
    """Answer whether the bytes are a witness program of any version."""
    return _is_funct(assert_segwit, script_pub_key)


def assert_p2wpkh(script_pub_key: Octets) -> None:
    """Refuse bytes that are not p2wpkh: OP_0, a 20-byte push, per BIP141."""
    script_pub_key = bytes_from_octets(script_pub_key, 22)
    # p2wpkh [OP_0, pub_key hash]
    # 0x0014{20-byte pub_key hash}
    if script_pub_key[0] != 0:
        err_msg = f"invalid witness version: {script_pub_key[0]}"
        err_msg += " instead of 0"
        raise BTClibValueError(err_msg)
    if script_pub_key[1] != 0x14:
        err_msg = f"invalid pub_key hash length marker: {script_pub_key[1]}"
        err_msg += " instead of 20"
        raise BTClibValueError(err_msg)


def is_p2wpkh(script_pub_key: Octets) -> bool:
    """Answer whether the bytes are a p2wpkh script_pub_key."""
    return _is_funct(assert_p2wpkh, script_pub_key)


def assert_p2wsh(script_pub_key: Octets) -> None:
    """Refuse bytes that are not p2wsh: OP_0, a 32-byte push, per BIP141."""
    script_pub_key = bytes_from_octets(script_pub_key, 34)
    # p2wsh [OP_0, redeem_script hash]
    # 0x0020{32-byte redeem_script hash}
    if script_pub_key[0] != 0:
        err_msg = f"invalid witness version: {script_pub_key[0]}"
        err_msg += " instead of 0"
        raise BTClibValueError(err_msg)
    if script_pub_key[1] != 0x20:
        err_msg = f"invalid redeem script hash length marker: {script_pub_key[1]}"
        err_msg += " instead of 32"
        raise BTClibValueError(err_msg)


def is_p2wsh(script_pub_key: Octets) -> bool:
    """Answer whether the bytes are a p2wsh script_pub_key."""
    return _is_funct(assert_p2wsh, script_pub_key)


def assert_p2tr(script_pub_key: Octets) -> None:
    """Refuse bytes that are not p2tr: OP_1, a 32-byte push, per BIP341.

    The 32 bytes are not checked to be a valid x-only key: the shape is
    the classification, and an output key off the curve is found by the
    spender, not by the classifier.
    """
    script_pub_key = bytes_from_octets(script_pub_key, 34)
    # p2wtr [OP_1, redeem_script hash]
    # 0x0120{32-byte redeem_script hash}
    if script_pub_key[0] != 0x51:  # OP_1 = b"\x51",
        err_msg = f"invalid witness version: {script_pub_key[0]}"
        err_msg += " instead of 0"
        raise BTClibValueError(err_msg)
    if script_pub_key[1] != 0x20:
        err_msg = f"invalid redeem script hash length marker: {script_pub_key[1]}"
        err_msg += " instead of 32"
        raise BTClibValueError(err_msg)


def is_p2tr(script_pub_key: Octets) -> bool:
    """Answer whether the bytes are a p2tr script_pub_key."""
    return _is_funct(assert_p2tr, script_pub_key)


def _witness_type_and_payload(
    script_pub_key: bytes,
) -> tuple[ScriptType, bytes] | None:
    """Name the witness program, or None if these bytes are not one.

    One function for the family, because the version is what tells them
    apart and the four answers are one decision: v0 of 20 bytes is
    p2wpkh and of 32 bytes p2wsh, a 32-byte v1 is p2tr, and any other
    version is a program this library cannot spend -- which is still a
    type, and still has an address. A v0 program of any other length is
    none of the four: v0 is defined, so a length it does not define is
    not upgrade room, and Bitcoin Core's Solver calls it NONSTANDARD.

    The payload is the witness program throughout. For the three named
    types the version is implied by the answer; for the fourth it is
    not, and stays in the script, which is where `address` reads it.
    """
    if is_p2wpkh(script_pub_key):
        # p2wpkh: OP_0 pub_key_hash
        # 0x0014{20-byte pub_key_hash}
        return "p2wpkh", script_pub_key[2:]

    if is_p2wsh(script_pub_key):
        # p2wsh: OP_0 script_hash
        # 0x0020{32-byte script_hash}
        return "p2wsh", script_pub_key[2:]

    if is_p2tr(script_pub_key):
        # p2tr: OP_1 output_key
        # 0x5120{32-byte output key}
        return "p2tr", script_pub_key[2:]

    if is_segwit(script_pub_key) and script_pub_key[0] != 0:
        # witness_unknown: Bitcoin Core's own name for the type,
        # TxoutType::WITNESS_UNKNOWN, and Solver draws the line in the
        # same place -- any version but 0 that is not p2tr, so a v1
        # program that is not 32 bytes lands here too
        return "witness_unknown", script_pub_key[2:]

    return None


def type_and_payload(script_pub_key: Octets) -> tuple[ScriptType, bytes]:  # noqa: PLR0911
    """Return (script_pub_key type, payload) from the input script_pub_key.

    The returns here and in _witness_type_and_payload are the whole of
    ScriptType between them, mypy checking each one against it: an
    eleventh shape classified in either is a member added there.
    """
    script_pub_key = bytes_from_octets(script_pub_key)

    if is_p2pk(script_pub_key):
        # p2pk: pub_key OP_CHECKSIG
        # 0x41{65-byte pub_key}AC or 0x21{33-byte pub_key}AC
        return "p2pk", script_pub_key[1:-1]

    if is_p2ms(script_pub_key):
        # p2ms: m pub_keys n OP_CHECKMULTISIG
        return "p2ms", script_pub_key[:-1]

    if is_p2pkh(script_pub_key):
        # p2pkh: OP_DUP OP_HASH160 pub_key_hash OP_EQUALVERIFY OP_CHECKSIG
        # 0x76A914{20-byte pub_key_hash}88AC
        return "p2pkh", script_pub_key[3:-2]

    if is_p2sh(script_pub_key):
        # p2sh: OP_HASH160 script_hash OP_EQUAL
        # 0xA914{20-byte script_hash}87
        return "p2sh", script_pub_key[2:-1]

    if witness := _witness_type_and_payload(script_pub_key):
        return witness

    if is_nulldata(script_pub_key):
        # nulldata: OP_RETURN data
        if len(script_pub_key) < 78:
            # OP_RETURN, data length, data up to 75 bytes max
            # 0x6A{1 byte data-length}{data (0-75 bytes)}
            return "nulldata", script_pub_key[2:]

        # OP_RETURN, OP_PUSHDATA1, data length, data min 76 bytes up to 80
        # 0x6A4C{1-byte data-length}{data (76-80 bytes)}
        return "nulldata", script_pub_key[3:]

    return "unknown", script_pub_key


# a dataclass, like the Script it extends, so that network is a *field*
# and not merely an annotation on a plain subclass: with the latter,
# dataclasses.fields(ScriptPubKey) reports only script, and
# dataclasses.replace(testnet_spk) rebuilds it through ScriptPubKey(script=)
# alone -- returning a mainnet ScriptPubKey, silently.
#
# init=False and eq=False keep the two written out below: __init__ takes
# Octets and a check_validity flag the generated one would not, and __eq__
# answers NotImplemented for a non-ScriptPubKey where the generated one
# compares by exact class.
#
# frozen because Script is: a dataclass cannot inherit frozen as non-frozen,
# and Script is frozen so that `tx_out.script_pub_key.script = b""` cannot
# reach through a frozen TxOut. So __init__ assigns through
# object.__setattr__, as Network's and the three Sig classes' do
#
# __hash__ is written out below because __eq__ is: a class defining __eq__
# without __hash__ gets __hash__ = None, and an unhashable ScriptPubKey
# takes TxOut with it -- TxOut is frozen, so it has a generated __hash__,
# which raises TypeError on the field that cannot hash. Frozen is what
# makes hashing safe here, and every other frozen value class of the
# library is hashable: OutPoint keys the dict an utxo set is, and TxOut
# is the other half of it (issue #416)
@dataclass(init=False, eq=False, frozen=True)
class ScriptPubKey(Script):
    """A Script with the network its addresses render on.

    The script bytes and their validation are Script's; the network
    enters `address`, `addresses`, the equality test and the hash, two
    ScriptPubKey being equal when their scripts match and their
    networks are of one type -- mainnet against the rest -- rather
    than of one name. Frozen and hashable on that same pair, so a
    ScriptPubKey can be a set member or a dict key. The classmethods
    build the standard shapes, one per type the classifier names.
    """

    network: str

    @property
    def type(self) -> ScriptType:
        """Return the script type, as type_and_payload names it."""
        return type_and_payload(self.script)[0]

    @property
    def address(self) -> str:
        """Return the bech32/base58 address.

        An address is a shortened notation for a particular script. As a
        transaction output contains exactly one script, it has at most
        one address (it is possible that the script does not correspond
        to a particular address, though).
        """
        return address(self.script, self.network)

    @property
    def addresses(self) -> list[str]:
        """Return the address, if any, or the p2pkh addresses for p2ms.

        Historically, a p2pkh address has been used to refer to a key.
        For a p2ms multisig script, the keys it pays to are returned,
        expressed in p2pkh-address notation.

        https://bitcoin.stackexchange.com/questions/30442/multiple-addresses-in-one-utxo
        """
        try:
            return addresses(self.script, self.network)
        except BTClibValueError:
            return [self.address]

    @override
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ScriptPubKey):
            return NotImplemented

        # the network *type*, not the name. Four test networks share one
        # set of address prefixes, so from_address answers "testnet" for
        # a signet address too -- and comparing names made a signet
        # ScriptPubKey unequal to the very address it renders, identical
        # script bytes and all. Types keep the distinction that matters,
        # mainnet against the rest, and drop the one the address cannot
        # carry: issue #207.
        #
        # Two ScriptPubKey are still not equal across types, so this is
        # not a loosening of the funds-relevant check. __hash__ below is
        # over the same pair this compares, and moves with it
        if network_type_from_network(self.network) != network_type_from_network(
            other.network
        ):
            return False
        return super().__eq__(other)

    @override
    def __hash__(self) -> int:
        # the script and the network *type*, which is what __eq__ above
        # compares: hashing the network *name* would put a signet
        # ScriptPubKey and the equal testnet one in different buckets.
        # Script hashes its bytes alone, and a Script never equals a
        # ScriptPubKey -- the generated __eq__ it inherits compares by
        # exact class -- so the two need not agree
        return hash((self.script, network_type_from_network(self.network)))

    def __init__(
        self,
        script: Octets,
        network: str = "mainnet",
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "network", network)
        # network first, then super(): Script.__init__ calls
        # self.assert_valid(), which dispatches to the override below and
        # so needs the field set. That call is also the whole validation,
        # the override running Script's checks and the network one, which
        # is why there is no second assert_valid() here -- it would parse
        # the script a second time
        super().__init__(script, check_validity=check_validity)

    @override
    def assert_valid(self) -> None:
        """Run Script's checks, then refuse a network name not in NETWORKS."""
        super().assert_valid()
        if self.network not in NETWORKS:
            raise BTClibValueError(f"unknown network: {self.network}")

    @classmethod
    def from_address(cls, addr: String, *, check_validity: bool = True) -> ScriptPubKey:
        """Return the ScriptPubKey of the input bech32/base58 address."""
        if b32.is_segwit_prefixed(addr):
            wit_ver, wit_prg, network = b32.witness_from_address(addr)
            return cls(
                serialize([op_int(wit_ver), wit_prg]),
                network,
                check_validity=check_validity,
            )

        script_type, h160, network = b58.h160_from_address(addr)
        if script_type == "p2sh":
            commands: ScriptList = ["OP_HASH160", h160, "OP_EQUAL"]
        else:  # it must be "p2pkh"
            commands = [
                "OP_DUP",
                "OP_HASH160",
                h160,
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        return cls(serialize(commands), network, check_validity=check_validity)

    @classmethod
    def p2pk(
        cls,
        key: Key,
        network: str | None = None,
        *,
        check_validity: bool = True,
    ) -> ScriptPubKey:
        """Return the p2pk ScriptPubKey of the provided Key."""
        payload, network = pub_keyinfo_from_key(key, network)
        script = serialize([payload, "OP_CHECKSIG"])
        return cls(script, network, check_validity=check_validity)

    @classmethod
    def p2ms(
        cls,
        m: int,
        keys: Sequence[Key],
        network: str | None = None,
        compressed: bool | None = None,
        lexicographic_sorting: bool = True,
        *,
        check_validity: bool = True,
    ) -> ScriptPubKey:
        """Return the m-of-n multi-sig ScriptPubKey of the provided keys.

        BIP67 endorses lexicographic sorting of compressed public keys.

        Sorting uncompressed keys (leading 0x04 byte) would
        result in a different order. An uncompressed key is not refused
        here even when lexicographic_sorting is True: BIP67's own
        compatibility note calls such a key a sign of a non-conforming
        counterparty, not something to reject, and Bitcoin Core's
        sortedmulti() accepts the mix and sorts it the same way -- see
        #299.

        https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki
        """
        assert_type(lexicographic_sorting, bool, "lexicographic_sorting")

        n = len(keys)
        if not 0 < n < 17:
            raise BTClibValueError(f"invalid n in m-of-n: {n}")
        if not 0 < m <= n:
            raise BTClibValueError(f"invalid m in m-of-n: {m}-of-{n}")

        # if network is None, then first key sets the network
        pub_key, network = pub_keyinfo_from_key(keys[0], network, compressed)
        pub_keys = [pub_key] + [
            pub_keyinfo_from_key(k, network, compressed)[0] for k in keys[1:]
        ]
        if lexicographic_sorting:
            # btclib_secp256k1's keys.pubkey_sort is not called here:
            # on compressed keys it gives the identical order, byte for
            # byte, at 11.0 us against sorted()'s 0.062 on three keys --
            # 180 times the cost for the same answer -- and it re-
            # serializes an uncompressed key to a compressed one, which
            # a drop-in delegation cannot do without rewriting the
            # script. sorted() is also what Bitcoin Core's own
            # sortedmulti() computes, CPubKey::operator< (src/pubkey.h)
            # comparing the serialization as received on any input,
            # compressed or not -- see #267.
            pub_keys = sorted(pub_keys)

        script = serialize([op_int(m), *pub_keys, op_int(n), "OP_CHECKMULTISIG"])
        return cls(script, network, check_validity=check_validity)

    @classmethod
    def nulldata(
        cls,
        data: String,
        *,
        check_validity: bool = True,
    ) -> ScriptPubKey:
        """Return the nulldata ScriptPubKey of the provided data."""
        if isinstance(data, str):
            # do not strip spaces
            data = data.encode()

        if len(data) > 80:
            err_msg = f"invalid nulldata payload length: {len(data)} bytes "
            raise BTClibValueError(err_msg)

        script = serialize(["OP_RETURN", data])
        return cls(script, check_validity=check_validity)

    @classmethod
    def p2pkh(
        cls,
        key: Key,
        compressed: bool | None = None,
        network: str | None = None,
        *,
        check_validity: bool = True,
    ) -> ScriptPubKey:
        """Return the p2pkh ScriptPubKey of the provided key."""
        pub_key, network = pub_keyinfo_from_key(key, network, compressed=compressed)
        script = serialize(
            ["OP_DUP", "OP_HASH160", hash160(pub_key), "OP_EQUALVERIFY", "OP_CHECKSIG"]
        )
        return cls(script, network, check_validity=check_validity)

    @classmethod
    def p2sh(
        cls,
        redeem_script: Octets,
        network: str = "mainnet",
        *,
        check_validity: bool = True,
    ) -> ScriptPubKey:
        """Return the p2sh ScriptPubKey of the provided redeem script."""
        script_h160 = hash160(redeem_script)
        script = serialize(["OP_HASH160", script_h160, "OP_EQUAL"])
        return cls(script, network, check_validity=check_validity)

    @classmethod
    def p2wpkh(
        cls,
        key: Key,
        *,
        check_validity: bool = True,
    ) -> ScriptPubKey:
        """Return the p2wpkh ScriptPubKey of the provided key.

        If the provided key is a public one, it must be compressed.
        """
        pub_key, network = pub_keyinfo_from_key(key, compressed=True)
        script = serialize(["OP_0", hash160(pub_key)])
        return cls(script, network, check_validity=check_validity)

    @classmethod
    def p2wsh(
        cls,
        redeem_script: Octets,
        network: str = "mainnet",
        *,
        check_validity: bool = True,
    ) -> ScriptPubKey:
        """Return the p2wsh ScriptPubKey of the provided redeem script."""
        script_h256 = sha256(redeem_script)
        script = serialize(["OP_0", script_h256])
        return cls(script, network, check_validity=check_validity)

    @classmethod
    def p2tr(
        cls,
        internal_key: Key | None = None,
        script_path: TaprootScriptTree | None = None,
        network: str = "mainnet",
        *,
        check_validity: bool = True,
    ) -> ScriptPubKey:
        """Return the p2tr ScriptPubKey of the provided script tree."""
        pub_key = output_pubkey(internal_key, script_path)[0]
        script = serialize(["OP_1", pub_key])
        return cls(script, network, check_validity=check_validity)


def _script_from(script_pub_key: Octets | ScriptPubKey) -> bytes:
    """Return the script bytes of whatever names one output.

    The spellings a caller may hold an output as, and which of them is
    which is not guesswork: a `ScriptPubKey` and `bytes` are what they
    are, and a string is the hex of a script where `bytes.fromhex` reads
    it and an address where it does not. The two alphabets do overlap --
    base58 and bech32 both hold hex digits -- but an address of hex digits
    only, of even length, and carrying a valid checksum is not a string
    anybody has.

    Private, and imported by the two questions that ask "is this output
    mine": `Descriptor.index_of` and `wallet.RangedWallet.position_of`.
    Here rather than in either, because it is about this module's own
    class and this module's own `from_address`, and because a second copy
    of the rule is a second answer to give.

    The empty string is the one refused outright, and for the reason the
    whole function exists: it is what `address` answers where a script has
    none, so `index_of(descriptor.address(i))` on a ``pk()`` would
    otherwise read as the empty script, match nothing, and say that the
    wallet's own output is not the wallet's. Empty `bytes` are the empty
    script and go through: no descriptor derives one, and the caller who
    wrote them meant them.

    `bytes_from_octets` alone cannot do this: it returns anything that is
    not a `str` untouched, so the `ScriptPubKey` that a wallet and a
    descriptor both answer with would travel through to a comparison
    against `bytes` that is False at every index, and the caller would
    read the None it falls off the end with as "not this wallet's".
    """
    if isinstance(script_pub_key, ScriptPubKey):
        return script_pub_key.script
    if isinstance(script_pub_key, (bytes, bytearray, memoryview)):
        # copied, where `bytes_from_octets` deliberately does not copy:
        # this function exists to produce the thing a caller compares and
        # keys a dict by, and a bytearray is unhashable
        return bytes(script_pub_key)
    # unreachable to mypy, the annotation having no fourth case, and the
    # whole point to a caller who is not running it: `Octets` is honoured
    # inside btclib and nowhere else
    assert_type(script_pub_key, str, "script_pub_key")
    if not script_pub_key:
        err_msg = "empty script_pub_key: a script with no address renders as ''"
        raise BTClibValueError(err_msg)
    try:
        return bytes.fromhex(script_pub_key)
    except ValueError:
        pass
    try:
        return ScriptPubKey.from_address(script_pub_key).script
    # ValueError rather than BTClibValueError, which is one: the address
    # codecs raise their own, and a string that reaches them is decoded
    # before it is checked, so it may fail on a plain one from underneath
    except ValueError as e:
        err_msg = f"neither a script nor an address: '{script_pub_key}'"
        raise BTClibValueError(err_msg) from e


def _validated_script_from(script_pub_key: Octets | ScriptPubKey) -> bytes:
    """`_script_from`, having first asked the object whether it is one.

    What the public questions "is this output mine" owe their caller.
    Answering `None` -- or "not what this branch derives" -- for a
    `ScriptPubKey` its own `assert_valid` refuses is the worst shape a
    missing check can take, the answer being a negative rather than an
    error: it is what a caller is told about a perfectly good output
    belonging to somebody else, and nothing in it says the question was
    malformed.

    Here rather than three times over in `Descriptor.index_of`,
    `DescriptorWallet.position_of` and `RangedWallet.position_of`, for the
    reason `_script_from` gives about itself: a second copy of the rule is
    a second answer to give.
    """
    if isinstance(script_pub_key, ScriptPubKey):
        script_pub_key.assert_valid()
    return _script_from(script_pub_key)
