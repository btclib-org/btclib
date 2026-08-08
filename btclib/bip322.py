# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP322 signed messages: a script is satisfied, not a key recovered.

`ecc.bms` signs with a key and lets the verifier recover it, which is why
it can only speak about the addresses that *are* a public key hash --
p2pkh, and by Electrum's extension the two p2wpkh spellings. A taproot
address is a tweaked BIP340 key and a p2wsh address is a hash of a
script, and no recovery flag names either.

BIP322 asks the other question. The address becomes the script_pub_key of
a virtual output, and the signature is whatever spends it: a witness
stack, a whole transaction, or a psbt. Verification is then the script
interpreter -- `script.engine` -- rather than a key comparison, so every
script btclib can run is a script that can sign, multisig and timelocks
included. The signature commits to the public key too, which the compact
ECDSA of BMS does not.

The two virtual transactions are the whole of the construction:

- `to_spend` pays 0 satoshi to the address, and is spendable by nobody:
  its single input is the null outpoint of a coinbase, and its
  script_sig is `OP_0 PUSH32 message_hash`, the BIP340-tagged hash of
  the message under the `BIP0322-signed-message` tag. Message and
  address are therefore both inside its txid
- `to_sign` spends that output and pays 0 satoshi to an `OP_RETURN`.
  Its witness -- or script_sig -- is the signature

A verifier rebuilds `to_spend` from the message and the address it was
given, so a signature made for another message or another address spends
a different output and satisfies nothing. Neither transaction can be
broadcast, `to_spend`'s own input being unspendable.

Three encodings, all base64 with a three-character prefix in front of it,
and `Sig` holds whichever came:

- `smp`, the *simple* variant: the witness stack alone, which is enough
  where the rest of `to_sign` is fixed -- native segwit, i.e. p2wpkh,
  p2wsh and p2tr
- `ful`, the *full* variant: the whole `to_sign` transaction, which is
  what a script_sig (p2pkh, p2sh), a version or a lock time needs
- `pof`, the *proof of funds* variant: a finalized psbt of `to_sign`,
  carrying further inputs the signer also controls, with the utxo of
  each. Whether those outputs exist and are unspent is the chain's
  answer and not this module's

A signature with no prefix is read as *simple*, which BIP322 allows for
compatibility with the implementations that predate the prefixes. The
*legacy* variant is BMS: `assert_as_valid` hands a 65-byte compact
signature to `ecc.bms`, and only for a p2pkh address, the BIP restricting
it to that one.

Verification answers three states, as the BIP does. Valid is a return;
invalid is a `BTClibValueError`, whatever failed being what it says; and
*inconclusive* is `InconclusiveError`, which is the state for a signature
that today's rules cannot judge -- a `to_sign` whose version is neither 0
nor 2, an upgradeable NOP, a witness program of a version this library
does not know. `verify` collapses all three to a boolean, and an
inconclusive signature is not a valid one.

What is enforced is BIP322's list, through the engine's own flags: the
consensus rules, then LOW_S, STRICTENC, NULLFAIL, MINIMALDATA,
CLEANSTACK, MINIMALIF and CONST_SCRIPTCODE for the required ones, and the
``DISCOURAGE_`` family for the upgradeable ones -- the backticks because a
name ending in an underscore is a link reference to docutils, which
sphinx runs with `-W`. One rule of the list is not enforced:
"all signatures MUST use SIGHASH_ALL", because which stack elements were
consumed as signatures is bookkeeping the interpreter does not report,
and picking them out of the witness by shape would refuse a control block
that happens to be 65 bytes long. `sign` here uses SIGHASH_ALL, and
SIGHASH_DEFAULT where taproot has it; issue 514 is what it costs and what
closing it would take.

One field of the BIP is not here either:
`PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE = 0x09`, which a creator puts the
message in so that a signing device shows "signing message m for address
A" rather than "spending 0 satoshi". It belongs to the psbt format
rather than to a signature encoding, and `btclib.psbt` keeps an unknown
global field as it arrives, so such a psbt round-trips through this
library today. Issue 516 is registering it.

https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from btclib.alias import Octets, String
from btclib.curves import bytes_from_prv_key_int
from btclib.ecc import bms, dsa, ssa
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibValueError,
    InconclusiveError,
)
from btclib.hashes import hash160, tagged_hash
from btclib.psbt import Psbt, extract_tx
from btclib.script import serialize
from btclib.script.engine import ALL_FLAGS, ScriptFlag, verify_transaction
from btclib.script.script_pub_key import ScriptPubKey, type_and_payload
from btclib.script.sig_hash import ALL, DEFAULT, from_tx
from btclib.script.sig_hash import taproot as taproot_sig_hash
from btclib.script.taproot import output_prvkey_from_merkle_root, output_pubkey
from btclib.script.witness import Witness
from btclib.to_prv_key import PrvKey, prv_keyinfo_from_prv_key
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from btclib.utils import bytes_from_octets

__all__ = [
    "FULL",
    "PROOF_OF_FUNDS",
    "REQUIRED_RULES",
    "SIMPLE",
    "TAG",
    "UPGRADEABLE_RULES",
    "Sig",
    "assert_as_valid",
    "message_hash",
    "sign",
    "to_sign",
    "to_spend",
    "verify",
]

TAG = b"BIP0322-signed-message"

SIMPLE = "smp"
FULL = "ful"
PROOF_OF_FUNDS = "pof"

_PREFIXES = (SIMPLE, FULL, PROOF_OF_FUNDS)
# every prefix is three characters, so the split of a signature into
# prefix and base64 does not depend on which one it is
_PREFIX_SIZE = 3

# the output of `to_sign`, which is the same for every message and every
# address: an OP_RETURN paying nothing, provably unspendable
_OP_RETURN = b"\x6a"

# BMS is 65 octets, and no witness stack is: the shortest one is a single
# 64-byte BIP340 signature, which the count and the push length make 66.
# So the two encodings do not overlap and a prefixless signature can be
# read as whichever of the two it is
_BMS_SIZE = 65

# the rules of BIP322's "Check the required rules", plus the consensus
# ones every spend is held to. Failing one of these is *invalid*: the
# signature is malleable, or not canonical, or does not spend
REQUIRED_RULES = (
    ALL_FLAGS
    | ScriptFlag.STRICTENC
    | ScriptFlag.LOW_S
    | ScriptFlag.NULLFAIL
    | ScriptFlag.MINIMALDATA
    | ScriptFlag.CLEANSTACK
    | ScriptFlag.MINIMALIF
    | ScriptFlag.CONST_SCRIPTCODE
)

# BIP322's "Check the upgradeable rules". Failing one of these is
# *inconclusive* and not invalid, which is the distinction the two sets
# exist for: a NOP reserved for an upgrade and a witness program of an
# unknown version are anyone-can-spend today and may mean something
# tomorrow, so a validator that judged them valid would be judging a
# script it does not know.
#
# The BIP names the two pre-taproot ones. The three BIP342 added are the
# same rule for tapscript -- an OP_SUCCESS, an unknown public key type
# and an unknown leaf version are each successful *because* nothing
# checks them -- and are here for the reason the BIP gives for the other
# two, rather than because it lists them
UPGRADEABLE_RULES = (
    ScriptFlag.DISCOURAGE_UPGRADABLE_NOPS
    | ScriptFlag.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | ScriptFlag.DISCOURAGE_UPGRADABLE_PUBKEYTYPE
    | ScriptFlag.DISCOURAGE_OP_SUCCESS
    | ScriptFlag.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
)

# BIP322's "The version of to_sign must be 0 or 2": 0 is what a signature
# with no time lock uses, and 2 is what BIP68 relative lock times need
_VERSIONS = (0, 2)


def message_hash(msg: Octets) -> bytes:
    """Return the BIP340-tagged hash of the message, under BIP322's tag.

    The message enters as it is: no magic string around it, no length in
    front of it, and no terminator after it. The tag is what keeps this
    hash from meaning anything under any other protocol, which is the
    job BMS gives to its "Bitcoin Signed Message:" envelope.
    """
    return tagged_hash(TAG, bytes_from_octets(msg))


def to_spend(msg: Octets, script_pub_key: Octets) -> Tx:
    """Return the virtual transaction the message and the script commit to.

    Nobody can spend it and nobody can broadcast it: its one input is
    the null outpoint a coinbase carries, and a coinbase is valid in a
    block and nowhere else. What it is for is its txid, which the
    message hash in its script_sig and the challenge script in its
    output both enter -- so a `to_sign` built on this txid is a
    signature for this message and this address alone.
    """
    script_sig = b"\x00\x20" + message_hash(msg)
    tx_in = TxIn(OutPoint(), script_sig, 0, Witness())
    tx_out = TxOut(0, bytes_from_octets(script_pub_key))
    return Tx(0, 0, [tx_in], [tx_out])


def to_sign(
    to_spend_tx: Tx,
    script_sig: Octets = b"",
    witness: Witness | None = None,
    *,
    version: int = 0,
    lock_time: int = 0,
    sequence: int = 0,
    extra_inputs: list[TxIn] | None = None,
) -> Tx:
    """Return the virtual transaction that spends `to_spend_tx`.

    The signature is `script_sig`, `witness`, or both: what satisfies
    the challenge script, whichever half of an input carries it.

    The three keyword arguments are the fields the *full* variant may
    set and the *simple* variant may not, all three of them 0 there: a
    version of 2 and a lock time for a `CHECKLOCKTIMEVERIFY` script, a
    sequence for a `CHECKSEQUENCEVERIFY` one. `extra_inputs` are the
    outputs a proof of funds shows control of, appended after the one
    input every signature has.
    """
    tx_in = TxIn(OutPoint(to_spend_tx.id, 0), script_sig, sequence, witness)
    vin = [tx_in, *extra_inputs] if extra_inputs else [tx_in]
    return Tx(version, lock_time, vin, [TxOut(0, _OP_RETURN)])


@dataclass(frozen=True)
class Sig:
    """A BIP322 signature: what the variant carries, and nothing beside it.

    One field, because the variant is not a second fact: a witness stack
    *is* a simple signature, a transaction a full one, and a psbt a
    proof of funds, so `variant` reads the payload rather than being
    stored where it could disagree with it.

    There is no `parse`, and that is the format rather than an omission:
    the three payloads are three unrelated serializations and only the
    prefix of the text form says which one follows, so `b64decode` is
    where a signature is read and `b64encode` where it is written.
    """

    payload: Witness | Tx | Psbt

    @property
    def variant(self) -> str:
        """Return the three-character prefix this signature is written with."""
        if isinstance(self.payload, Witness):
            return SIMPLE
        return FULL if isinstance(self.payload, Tx) else PROOF_OF_FUNDS

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the payload's own serialization, without the prefix.

        The transaction is serialized with its witness, that being where
        a full signature keeps the signature.
        """
        if isinstance(self.payload, Tx):
            return self.payload.serialize(
                include_witness=True, check_validity=check_validity
            )
        return self.payload.serialize(check_validity=check_validity)

    def b64encode(self, *, check_validity: bool = True) -> str:
        """Return the signature as BIP322 writes it: prefix, then base64."""
        data = self.serialize(check_validity=check_validity)
        return self.variant + base64.b64encode(data).decode("ascii")

    @classmethod
    def b64decode(cls: type[Sig], data: String, *, check_validity: bool = True) -> Sig:
        """Return the signature the text encodes, whichever variant it is.

        A prefix that is not one of the three is not stripped and not
        guessed at: it is base64 or it is nothing, and the three
        characters are then part of the witness stack, which is what
        refuses it. Absent a prefix the signature is *simple*, which is
        what BIP322 says a verifier may assume of the implementations
        that predate them.
        """
        text = data.decode("ascii") if isinstance(data, bytes) else data
        text = text.strip()
        prefix = text[:_PREFIX_SIZE]
        if prefix not in _PREFIXES:
            prefix = SIMPLE
        else:
            text = text[_PREFIX_SIZE:]
        try:
            payload_bin = base64.b64decode(text.encode("ascii"), validate=True)
        except ValueError as e:  # binascii.Error and UnicodeEncodeError
            raise BTClibValueError(f"invalid base64 encoding: {e}") from e

        if prefix == SIMPLE:
            return cls(Witness.parse(payload_bin, check_validity=check_validity))
        if prefix == FULL:
            return cls(Tx.parse(payload_bin, check_validity=check_validity))
        return cls(Psbt.parse(payload_bin, check_validity=check_validity))


def _psbt_prevouts(psbt: Psbt) -> list[TxOut]:
    """Return the output each input of a proof of funds spends.

    `psbt.prevouts` is the same answer without BIP322's one addition:
    "the Non-Witness UTXO field may be omitted for any input that spends
    an output from the same transaction as an input earlier in the
    list", which is what keeps a proof over many outputs of one
    transaction from carrying that transaction many times.
    """
    transactions: dict[bytes, Tx] = {}
    outs: list[TxOut] = []
    for i, psbt_in in enumerate(psbt.inputs):
        if psbt_in.non_witness_utxo is not None:
            transactions[psbt_in.non_witness_utxo.id] = psbt_in.non_witness_utxo
        vout = psbt_in.output_index or 0
        prev_tx = transactions.get(psbt_in.previous_tx_id or b"")
        if psbt_in.witness_utxo is not None:
            outs.append(psbt_in.witness_utxo)
        elif prev_tx is not None and vout < len(prev_tx.vout):
            outs.append(prev_tx.vout[vout])
        else:
            raise BTClibValueError(f"no utxo for input {i}")
    return outs


def _assert_shape(tx: Tx, spend: Tx, prevouts: list[TxOut]) -> None:
    """Refuse a `to_sign` that is not one, the signature apart.

    BIP322's "confirm all fields are set as specified above", in its
    order: at least one input, the first of them spending the output of
    `to_spend` -- which is where the message and the address are -- a
    utxo for each of the rest, and exactly one output, the OP_RETURN
    that pays nothing. The version is checked by `_assert_upgradeable`,
    which is the state it belongs to.
    """
    if not tx.vin:
        raise BTClibValueError("no input in to_sign")
    if tx.vin[0].prev_out != OutPoint(spend.id, 0):
        err_msg = "the first input does not spend to_spend: "
        err_msg += f"{tx.vin[0].prev_out.tx_id.hex()} instead of {spend.id.hex()}"
        raise BTClibValueError(err_msg)
    if len(prevouts) != len(tx.vin):
        err_msg = f"{len(prevouts)} utxos for {len(tx.vin)} inputs"
        raise BTClibValueError(err_msg)
    if len(tx.vout) != 1:
        raise BTClibValueError(f"{len(tx.vout)} outputs in to_sign instead of one")
    if tx.vout[0].value or tx.vout[0].script_pub_key.script != _OP_RETURN:
        raise BTClibValueError("the output of to_sign is not the OP_RETURN of 0")


def _assert_upgradeable(tx: Tx) -> None:
    """Refuse, as inconclusive, a version no BIP322 signature may have."""
    if tx.version not in _VERSIONS:
        err_msg = f"to_sign version {tx.version}: BIP322 allows 0 and 2"
        raise InconclusiveError(err_msg)


def _assert_scripts(prevouts: list[TxOut], tx: Tx) -> None:
    """Run the engine, telling an invalid signature from an inconclusive one.

    The strict set first, which is the answer in the ordinary case and
    one pass. Only where that fails is the required set run on its own,
    and it is the second run that says which state this is: a script
    that satisfies the required rules and not the upgradeable ones is
    inconclusive, and one that fails the required rules is invalid --
    which is the exception the second run raises by itself.
    """
    try:
        verify_transaction(prevouts, tx, REQUIRED_RULES | UPGRADEABLE_RULES)
    except (ValueError, BTClibRuntimeError) as e:
        verify_transaction(prevouts, tx, REQUIRED_RULES)
        raise InconclusiveError(f"upgradeable rule: {e}") from e


def assert_as_valid(
    msg: Octets, addr: String, sig: Sig | String, *, legacy: bool = True
) -> None:
    """Refuse a signature that does not spend the address's own output.

    The message and the address rebuild `to_spend` here, so what the
    signature is checked against is never what it claims to be: a
    signature for another message, or for another address, satisfies a
    script that is not this one.

    `legacy` accepts a BMS signature -- the 65-byte compact one, with no
    prefix -- for a p2pkh address, which is the compatibility BIP322
    keeps and the only address type it keeps it for. False refuses it,
    for a caller that wants BIP322 proper and nothing else.

    Raises `InconclusiveError` for a signature that is not invalid and
    cannot be judged valid; see the module docstring for that state.
    """
    script_pub_key = ScriptPubKey.from_address(addr).script

    if legacy and isinstance(sig, (str, bytes)) and _is_bms(sig):
        if type_and_payload(script_pub_key)[0] != "p2pkh":
            err_msg = "a legacy signature is for a p2pkh address alone"
            raise BTClibValueError(err_msg)
        bms.assert_as_valid(msg, addr, sig)
        return

    sig = sig if isinstance(sig, Sig) else Sig.b64decode(sig)
    spend = to_spend(msg, script_pub_key)

    payload = sig.payload
    # the psbt's own utxo for the first input is not consulted, whichever
    # variant this is: what binds the signature to the message is the
    # output computed just above, and a psbt disagreeing with it would be
    # answering a different challenge under this message's name
    prevouts = list(spend.vout)
    if isinstance(payload, Witness):
        tx = to_sign(spend, witness=payload)
    elif isinstance(payload, Tx):
        tx = payload
    else:
        tx = extract_tx(payload)
        prevouts += _psbt_prevouts(payload)[1:]

    _assert_shape(tx, spend, prevouts)
    _assert_upgradeable(tx)
    _assert_scripts(prevouts, tx)


def verify(
    msg: Octets, addr: String, sig: Sig | String, *, legacy: bool = True
) -> bool:
    """Verify the BIP322 signature of a message for an address.

    False for an inconclusive signature as well as for an invalid one:
    the two states are worth telling apart, and `assert_as_valid` is
    where they are, but neither of them is a signature that verified.
    """
    # ValueError and BTClibRuntimeError, as `ecc.bms.verify` catches them
    # and for its reasons: malformed input is not a valid signature, and
    # a TypeError is a caller's own mistake rather than an answer
    try:
        assert_as_valid(msg, addr, sig, legacy=legacy)
    except (ValueError, BTClibRuntimeError):
        return False

    return True


def _is_bms(sig: String) -> bool:
    """Whether the text is a BMS compact signature rather than a BIP322 one.

    The size settles it, base64 being the encoding of both: 65 octets is
    a recovery flag and an ECDSA signature, and no witness stack is 65
    octets long -- the shortest is a lone BIP340 signature, which its
    count and push length make 66.
    """
    text = sig.decode("ascii") if isinstance(sig, bytes) else sig
    try:
        return len(base64.b64decode(text.strip(), validate=True)) == _BMS_SIZE
    except ValueError:
        return False


def _redeem_script(pub_key: bytes) -> bytes:
    """Return the p2wpkh script a p2sh-p2wpkh address wraps."""
    return b"\x00\x14" + hash160(pub_key)


def _assert_key_owns(script_type: str, payload: bytes, pub_key: bytes) -> None:
    """Refuse an address that is not this public key's, of any of the four.

    The comparison is against what the key builds, one shape per type,
    so an uncompressed key needs no case of its own: it hashes to a
    p2pkh address and to no other, and the three segwit spellings it is
    offered for fail here rather than after a signature was made.
    """
    owned = {
        "p2pkh": hash160(pub_key),
        "p2wpkh": hash160(pub_key),
        "p2sh": hash160(_redeem_script(pub_key)),
        "p2tr": output_pubkey(pub_key)[0] if len(pub_key) == 33 else b"",
    }
    if owned.get(script_type) != payload:
        raise BTClibValueError("mismatch between private key and address")


def sign(msg: Octets, prv_key: PrvKey, addr: String) -> Sig:
    """Return the BIP322 signature of a message for a single-key address.

    The address is the argument and not something worked out from the
    key, one key owning an address of each type: it is the challenge
    being signed, and BIP322 has no default for it.

    p2pkh, p2wpkh, p2sh-p2wpkh and p2tr are what one private key
    satisfies on its own, so they are what this signs; the taproot case
    is the key path, with no script tree. The variant follows the BIP:
    *simple* where the address is native segwit and the rest of
    `to_sign` is therefore fixed, *full* where a script_sig has to be
    carried.

    Any other script -- multisig, a script path, a time lock -- is a
    `Psbt` of `to_sign` signed and finalized by `btclib.psbt`, or a
    `Descriptor.satisfy` over the signatures it needs, and then a `Sig`
    of what comes out. This function is the case that needs neither.
    """
    script_pub_key = ScriptPubKey.from_address(addr).script
    script_type, payload = type_and_payload(script_pub_key)
    q, _, compressed = prv_keyinfo_from_prv_key(prv_key)
    pub_key = bytes_from_prv_key_int(q, compressed=compressed)
    _assert_key_owns(script_type, payload, pub_key)

    spend = to_spend(msg, script_pub_key)
    # the redeem script goes into the script_sig before the hash is
    # computed: `sig_hash.from_tx` dispatches on it, and the engine
    # checks it against the p2sh hash in the output being spent
    script_sig = serialize([_redeem_script(pub_key)]) if script_type == "p2sh" else b""
    tx = to_sign(spend, script_sig)

    if script_type == "p2tr":
        # `sig_hash.taproot` and not `from_tx`, which reads the annex and
        # the tapleaf commitment off the witness stack: there is no stack
        # yet, this being what is about to build one. A key path spend
        # has neither -- ext_flag 0, no annex, no message extension --
        # so the three are what a signer states rather than reads.
        # DEFAULT and not ALL: BIP341 gives the empty hash type the
        # meaning of SIGHASH_ALL, and a signature spelling it out is the
        # same commitment one byte longer
        msg_hash = taproot_sig_hash(tx, 0, spend.vout, DEFAULT, 0, b"", b"")
        tweaked = output_prvkey_from_merkle_root(q)
        return Sig(Witness([ssa.sign_(msg_hash, tweaked).serialize()]))

    msg_hash = from_tx(spend.vout, tx, 0, ALL)
    signature = dsa.sign_(msg_hash, q).serialize() + ALL.to_bytes(1, "big")

    if script_type == "p2pkh":
        tx.vin[0].script_sig = serialize([signature, pub_key])
        return Sig(tx)

    tx.vin[0].script_witness = Witness([signature, pub_key])
    # native segwit is the whole of what the simple variant may carry:
    # a wrapped one has a script_sig, which only the full variant has
    # somewhere to put
    return Sig(tx.vin[0].script_witness) if script_type == "p2wpkh" else Sig(tx)
