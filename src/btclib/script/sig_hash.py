# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The hashes a transaction signature commits to, one per era.

Three preimages for one question -- what does this input's signature
sign: `legacy` is Satoshi's SignatureHash, `segwit_v0` is BIP143's,
which adds the amount being spent, and `taproot` is BIP341's SigMsg,
which commits to every spent output. The hash types -- ALL, NONE,
SINGLE, each with or without ANYONECANPAY, and taproot's DEFAULT --
choose how much of the transaction each preimage covers, and
`from_tx` dispatches an input to the preimage its script demands.
"""

from __future__ import annotations

from dataclasses import dataclass

from btclib import var_bytes
from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160, hash256, sha256, tagged_hash
from btclib.script.script import (
    BYTE_FROM_OP_CODE_NAME,
    ERROR_COMMAND,
    op_code_spans,
    parse,
    serialize,
)
from btclib.script.script_pub_key import (
    ScriptPubKey,
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
    is_p2wsh,
    type_and_payload,
)
from btclib.tx import OutPoint, Tx, TxIn, TxOut

# the width check `Tx.serialize` runs on its own two fields regardless of
# check_validity, imported rather than written again: it is the same
# field width, and a second spelling of it would be a second place to
# read before believing the two agree
from btclib.tx.tx import _assert_valid_4_byte_field
from btclib.utils import bytes_from_octets, is_integer

__all__ = [
    "ALL",
    "ANYONECANPAY",
    "DEFAULT",
    "NONE",
    "OP_CODESEPARATOR",
    "SIG_HASH_TYPES",
    "SINGLE",
    "PrecomputedTxData",
    "assert_valid_hash_type",
    "from_tx",
    "legacy",
    "redeem_script",
    "segwit_v0",
    "taproot",
    "taproot_annex_and_ext",
]

DEFAULT = 0
ALL = 1
NONE = 2
SINGLE = 3
ANYONECANPAY = 0b10000000

# frozenset, not a public mutable list: it is a membership test
# in all three of its uses, one of them the STRICTENC check of the script
# engine, and a caller that appended to it would widen what the engine
# accepts as a signature (issue #145). ANYONECANPAY with DEFAULT is absent
# on purpose: BIP341 gives 0x00 the meaning of SIGHASH_ALL and does not
# define 0x80
SIG_HASH_TYPES = frozenset(
    {
        DEFAULT,
        ALL,
        NONE,
        SINGLE,
        ANYONECANPAY | ALL,
        ANYONECANPAY | NONE,
        ANYONECANPAY | SINGLE,
    }
)


def assert_valid_hash_type(hash_type: int) -> None:
    """Refuse a hash type outside SIG_HASH_TYPES.

    The set is the seven combinations the BIPs define; ANYONECANPAY
    with DEFAULT is not among them, BIP341 leaving 0x80 undefined.
    """
    if hash_type not in SIG_HASH_TYPES:
        raise BTClibValueError(f"invalid sig_hash type: {hex(hash_type)}")


def _serialized_hash_type(hash_type: int) -> bytes:
    """Return the four bytes the two pre-taproot preimages end with.

    Core's `SignatureHash` takes `int32_t nHashType` and writes it as one,
    so the field is a 32-bit word and -1 is `ffffffff` on the wire. Either
    spelling of that word is taken -- Core's signed -1 and the
    `0xffffffff` of a caller who read the field off a preimage -- because
    the two differ nowhere else either: `-1 & 0x1F` and `0xffffffff & 0x1F`
    are the same 31, Python's `&` reading a negative in the same two's
    complement the wire carries. What does not fit the field is a
    BTClibValueError, where `int.to_bytes` answers with an `OverflowError`
    from underneath the library (issue #405).

    Not assert_valid_hash_type: the seven defined types are what a signer
    chooses, not what a preimage may be computed over. Without STRICTENC
    the script engine hashes whatever byte a signature carries, which is
    consensus and not taste, and Core's sighash.json is nothing but
    undefined hash types with the hash each of them must produce.
    """
    if not -(2**31) <= hash_type < 2**32:
        raise BTClibValueError(
            f"sig_hash type too wide for its four bytes: {hash_type}"
        )
    return (hash_type & 0xFFFFFFFF).to_bytes(4, byteorder="little")


# the op code a script code is measured from, read out of the table so
# that a name that stops existing fails at import rather than leaving a
# rule that quietly stops matching
OP_CODESEPARATOR = BYTE_FROM_OP_CODE_NAME["OP_CODESEPARATOR"][0]


def _script_code_from(script: bytes, codesep_index: int) -> bytes:
    """Return the script from just past the codesep_index-th OP_CODESEPARATOR.

    Core's `pbegincodehash`, which its interpreter advances to `pc` as it
    *executes* an OP_CODESEPARATOR and hands to `CScript
    scriptCode(pbegincodehash, pend)` — a byte pointer, so the script code
    is the script's own bytes from a boundary on, never a re-serialization
    of part of a parse (issue #176).

    Index 0 is the whole script, i.e. no OP_CODESEPARATOR executed, and
    the count is over *occurrences*: which of them will be the last one
    executed when the signature is checked is a property of the run, not
    of the script, and nothing here can know it. The signer does.
    """
    if codesep_index < 0:
        raise BTClibValueError(f"negative OP_CODESEPARATOR index: {codesep_index}")
    if codesep_index == 0:
        return script
    found = 0
    for op_code, _, stop in op_code_spans(script):
        if op_code == OP_CODESEPARATOR:
            found += 1
            # `>=` here is an equivalent mutant: found rises by one and is
            # read at each step, and codesep_index is at least 1 -- 0
            # returned the whole script above -- so the first
            # `found >= codesep_index` is the first `found ==`. A mutation
            # run lists it as a survivor with nothing to add (issue #252)
            if found == codesep_index:
                return script[stop:]
    err_msg = f"OP_CODESEPARATOR index {codesep_index}, but the script has {found}"
    raise BTClibValueError(err_msg)


def _without_op_codeseparators(script_code: bytes) -> bytes:
    """Return the script code with its OP_CODESEPARATORs elided.

    Core's `CTransactionSignatureSerializer::SerializeScriptCode`,
    "Serialize the passed scriptCode, skipping OP_CODESEPARATORs": it
    writes `scriptCode.size() - nCodeSeparators` and then copies the raw
    bytes between the separators. So the elision belongs to the legacy
    *serializer* and not to the script code — segwit v0 serializes the
    same script code whole, which is why this is called by `legacy` and
    not by `segwit_v0`.

    Copying byte ranges is what makes it the same preimage Core signs: a
    parse, a list removal and a re-serialization would rewrite every
    non-minimal push passed over.
    """
    if OP_CODESEPARATOR not in script_code:  # nothing to walk the script for
        return script_code
    kept: list[bytes] = []
    walked = 0
    for op_code, start, stop in op_code_spans(script_code):
        if op_code != OP_CODESEPARATOR:
            kept.append(script_code[start:stop])
        walked = stop
    # whatever no op code could be read from, kept verbatim as Core keeps it
    kept.append(script_code[walked:])
    return b"".join(kept)


def taproot_annex_and_ext(tx: Tx, vin_i: int) -> tuple[bytes, bytes]:
    """Read (annex, sig_hash extension) off one input's witness stack.

    What `taproot` needs beyond the transaction: the annex, per
    BIP341's "last element whose first byte is 0x50", and -- for a
    stack that is a script path -- BIP342's message extension, the
    tapleaf hash with key version 0 and no OP_CODESEPARATOR executed.
    A signer past a separator computes its own extension; the caller's
    transaction is never rewritten.
    """
    _assert_valid_vin_i(tx, vin_i)

    # a local name, never assigned back: computing a hash must not rewrite
    # the caller's Tx, and the annex is dropped by rebinding it below
    stack = tx.vin[vin_i].script_witness.stack
    if len(stack) == 0:
        raise BTClibValueError("Empty stack")

    annex = b""
    # a slice and not stack[-1][0]: an element of the witness may be empty,
    # which is legal on the wire and has no first byte to read -- indexing
    # would answer a caller who catches BTClibValueError with an IndexError,
    # on a transaction 186 bytes long that Tx.parse accepts. BIP341 says
    # the annex is the last element "if its first byte is 0x50", and an
    # empty element does not have one, so this is also what the BIP says
    if len(stack) >= 2 and stack[-1][:1] == b"\x50":
        annex = stack[-1]
        stack = stack[:-1]

    ext = b""
    # `!= 1` here is an equivalent mutant: it differs on an empty stack
    # alone, and there is none to be had -- the raise above refuses one,
    # and the annex comes off a stack of two or more, which leaves at
    # least one element. A mutation run lists it as a survivor with
    # nothing to add (issue #252)
    if len(stack) > 1:
        # the same hole, one element along: with the annex off, stack[-1]
        # is the control block, whose first byte is the leaf version. There
        # is no hash to compute without it, so this raises rather than
        # inventing the 33-byte minimum BIP341 states -- validating the
        # control block is the engine's job, and it does it
        if not stack[-1]:
            raise BTClibValueError("empty taproot control block")
        leaf_version = stack[-1][0] & 0xFE
        preimage = leaf_version.to_bytes(1, "big")
        preimage += var_bytes.serialize(stack[-2])
        tapleaf_hash = tagged_hash(b"TapLeaf", preimage)
        ext = tapleaf_hash + b"\x00\xff\xff\xff\xff"

    return annex, ext


def _legacy_tx_copy(tx: Tx, vin_i: int, script_code: bytes) -> Tx:
    """Copy tx with every script_sig emptied but the signed input's.

    A copy and not the caller's Tx: computing a hash must not rewrite the
    transaction it is computed over, and everything the legacy preimage
    does -- blanking the other inputs' scripts, dropping outputs,
    dropping inputs -- is spelled as a mutation of this copy.
    """
    new_tx = Tx(
        version=tx.version,
        lock_time=tx.lock_time,
        vin=[],
        vout=[],
        check_validity=False,
    )

    for txin in tx.vin:
        new_tx.vin.append(
            TxIn(
                prev_out=txin.prev_out,
                script_sig=b"",
                sequence=txin.sequence,
                check_validity=False,
            )
        )
    for txout in tx.vout:
        new_tx.vout.append(
            TxOut(
                value=txout.value,
                script_pub_key=txout.script_pub_key,
                check_validity=False,
            )
        )
    new_tx.vin[vin_i].script_sig = script_code
    return new_tx


def _zero_other_sequences(new_tx: Tx, vin_i: int) -> None:
    """Zero the sequence of every input but the signed one.

    Both NONE and SINGLE do it, and for the same reason: neither commits
    to the outputs the other inputs pay to, so leaving their sequences
    signed would let them be replaced with no change to this signature.
    """
    for i, txin in enumerate(new_tx.vin):
        if i != vin_i:
            txin.sequence = 0


# Core's CAmount is int64_t and the preimages here commit to the eight bytes
# it serializes to, so what those bytes cannot stand for is what this
# refuses. Not the money range: -1 is a signed CAmount and BIP143 hashes it
# (issue 388), so `valid_sats_amount` would refuse a preimage Core writes
_CAMOUNT = range(-(2**63), 2**63)


def _assert_valid_camount(amount: int, name: str) -> None:
    """Refuse an amount no eight-byte signed field can hold."""
    if amount not in _CAMOUNT:
        raise BTClibValueError(f"invalid {name}: {amount}")


# the two field widths every preimage here is made of, each as the write
# that needs the check rather than as a check a writer has to remember:
# `int.to_bytes` answers a field too wide for it with an OverflowError,
# an ArithmeticError that no `except BTClibValueError` written against
# this library catches (issue #690). `Tx.serialize` checks its own two
# the same way and unconditionally, which is what closed them for
# `legacy` alone -- segwit_v0 and taproot assemble their preimage from
# their own calls and never reach it
def _serialized_4_byte_field(name: str, value: int) -> bytes:
    _assert_valid_4_byte_field(name, value)
    return value.to_bytes(4, byteorder="little", signed=False)


def _serialized_camount(amount: int, name: str) -> bytes:
    # signed, as TxOut.serialize is and for the same reason: this is the
    # same CAmount field, Core's `ss << txout.nValue`, so the two must
    # agree on which integers the eight bytes stand for (issue #388)
    _assert_valid_camount(amount, name)
    return amount.to_bytes(8, byteorder="little", signed=True)


def _serialized_out_point(out_point: OutPoint) -> bytes:
    """Serialize an outpoint, its 4-byte vout checked as a width.

    `check_validity=False` throughout, as everywhere in this module: a
    preimage is computed over transactions the caller has not asked to
    be judged whole. The width is the one part of that judgement
    serializing four bytes cannot skip.
    """
    _assert_valid_4_byte_field("vout", out_point.vout)
    return out_point.serialize(check_validity=False)


def _serialized_output(tx_out: TxOut) -> bytes:
    """Serialize an output, its CAmount checked as a width."""
    _assert_valid_camount(tx_out.value, "output value")
    return tx_out.serialize(check_validity=False)


def _serialized_spend_type(ext_flag: int, annex_present: int) -> bytes:
    """Return BIP341's spend type: `2 * ext_flag + annex_present`.

    One byte, so the extension flag is seven bits: 0 for a key path, 1
    for BIP342's tapscript, and nothing wider has anywhere to go --
    where `to_bytes(1)` answered an OverflowError.
    """
    if not is_integer(ext_flag):
        raise BTClibTypeError(f"invalid extension flag type: {type(ext_flag).__name__}")
    if not 0 <= ext_flag <= 0x7F:
        raise BTClibValueError(f"invalid extension flag: {ext_flag}")
    return (2 * ext_flag + annex_present).to_bytes(1, "little")


def _assert_valid_prevouts(prevouts: list[TxOut]) -> None:
    """Ask every prevout what a preimage committing to all of them needs.

    BIP341 commits to every spent amount and script_pub_key, so all of
    them reach the serialization and not only the one being signed. The
    amount by its field's width and not by the money range, for the reason
    above; the script by what ScriptPubKey asks of itself, which is its
    network name and that the script is bytes.
    """
    for prevout in prevouts:
        _assert_valid_camount(prevout.value, "spent amount")
        prevout.script_pub_key.assert_valid()


def _assert_valid_vin_i(tx: Tx, vin_i: int) -> None:
    """Refuse an index naming no input of the transaction being signed.

    Every sig_hash here is the hash of *one* input's spend, so an index
    outside the vin names nothing to sign. Left to the list it would be
    an `IndexError` on the paths that dereference it -- a `LookupError`,
    which no `except BTClibValueError` catches -- and on the paths that
    only write the index into the preimage it would be no error at all,
    just a 32-byte hash of a transaction position that does not exist.
    """
    if not is_integer(vin_i):
        raise BTClibTypeError(f"invalid input index type: {type(vin_i).__name__}")
    if not 0 <= vin_i < len(tx.vin):
        raise BTClibValueError(f"invalid input index: {vin_i}")


def legacy(script_code: Octets, tx: Tx, vin_i: int, hash_type: int) -> bytes:
    """Return the pre-segwit hash one input's signature commits to.

    Satoshi's SignatureHash: the transaction is copied, every other
    script_sig blanked, the signed input's replaced by the script code
    with its OP_CODESEPARATORs elided, and outputs and sequences
    dropped as NONE, SINGLE and ANYONECANPAY ask; hash256 of that
    serialization and the four hash-type bytes is the answer. The
    SINGLE bug is kept, being consensus: an input with no matching
    output signs the constant 1, not an error.

    `hash_type` is Core's `int32_t nHashType`, and every 32-bit word has a
    preimage: the seven defined types are what a signer picks, and an
    undefined one is what a signature may carry and this must still hash.
    """
    # the field is serialized here, before the transaction is copied, so
    # that a hash type too wide for it is refused rather than met by the
    # SINGLE bug's early return, which answers with the constant 1 and
    # never reaches the serialization at the end
    serialized_hash_type = _serialized_hash_type(hash_type)
    _assert_valid_vin_i(tx, vin_i)

    # the legacy preimage commits to the script code with its
    # OP_CODESEPARATORs elided, and Core does that here rather than to the
    # script code itself: SerializeScriptCode is part of the serializer,
    # and the caller — its interpreter, and `sign.cpp` which truncates
    # nothing at all — passes the script as it stands
    script_code = _without_op_codeseparators(bytes_from_octets(script_code))

    new_tx = _legacy_tx_copy(tx, vin_i, script_code)

    if hash_type & 0x1F == NONE:
        new_tx.vout = []
        _zero_other_sequences(new_tx, vin_i)

    if hash_type & 0x1F == SINGLE:
        # sig_hash single bug
        if vin_i >= len(new_tx.vout):
            return (256**31).to_bytes(32, byteorder="big", signed=False)
        # every output before the signed one is blanked: value -1, Core's
        # own `nValue = -1` on the CAmount it is (issue #388), and an
        # empty script_pub_key. Rebuilt one by one rather than assigned
        # into, TxOut being frozen — and one instance each, a single
        # blanked TxOut repeated being the aliasing that issue #139 was
        # about
        new_tx.vout = [
            TxOut(-1, ScriptPubKey(b""), check_validity=False) for _ in range(vin_i)
        ] + [new_tx.vout[vin_i]]
        _zero_other_sequences(new_tx, vin_i)

    if hash_type & 0x80:
        new_tx.vin = [new_tx.vin[vin_i]]

    # the widths of what is left, and only of what is left: the copy above
    # is what `Tx.serialize` is about to write, and NONE and SINGLE have
    # already dropped the outputs they do not commit to. `Tx.serialize`
    # checks the version and the lock time itself, unconditionally, and
    # these are the fields it hands to TxIn and TxOut, which do not
    for txin in new_tx.vin:
        _assert_valid_4_byte_field("sequence", txin.sequence)
        _assert_valid_4_byte_field("vout", txin.prev_out.vout)
    for txout in new_tx.vout:
        _assert_valid_camount(txout.value, "output value")

    preimage = new_tx.serialize(include_witness=False, check_validity=False)
    preimage += serialized_hash_type

    return hash256(preimage)


# the five transaction-wide serializations the two segwit sig_hash
# flavours commit to. Kept as the serializations and not as their hashes
# because BIP143 hashes them with hash256 and BIP341 with sha256: one
# definition each, applied twice, rather than two lists of five that have
# to be checked against each other. Private, PrecomputedTxData below being
# the supported way to compute them once for a whole transaction
def _serialized_prevouts(tx: Tx) -> bytes:
    return b"".join([_serialized_out_point(vin.prev_out) for vin in tx.vin])


def _serialized_sequences(tx: Tx) -> bytes:
    return b"".join(
        [_serialized_4_byte_field("sequence", vin.sequence) for vin in tx.vin]
    )


def _serialized_outputs(tx: Tx) -> bytes:
    return b"".join([_serialized_output(vout) for vout in tx.vout])


def _serialized_amounts(prevouts: list[TxOut]) -> bytes:
    return b"".join(
        [_serialized_camount(prevout.value, "spent amount") for prevout in prevouts]
    )


def _serialized_script_pub_keys(prevouts: list[TxOut]) -> bytes:
    return b"".join(
        [var_bytes.serialize(prevout.script_pub_key.script) for prevout in prevouts]
    )


@dataclass(frozen=True)
class PrecomputedTxData:
    """The transaction-wide hashes every input of a transaction shares.

    BIP143 and BIP341 commit each input to hashes of the whole
    transaction — its prevouts, its sequences, its outputs — and BIP341
    to the amounts and script_pub_keys being spent as well. None of them
    depends on which input is being signed, so a transaction with N inputs
    needs them once and not N times: rebuilding them per input makes
    signing or verifying Θ(N²) in the number of inputs, and a
    consolidation transaction is the ordinary case there rather than a
    pathological one (issue #164). Bitcoin Core computes the same set into
    its PrecomputedTransactionData and passes it down.

    The `sha_` attributes are the BIP341 hashes, spelled as that BIP
    spells them but for script_pub_keys, which btclib does not write
    `scriptpubkeys`. The `hash_` properties are the three BIP143 ones,
    and they are one further sha256 over the corresponding `sha_`
    attribute rather than a second pass over the transaction: hash256 is
    sha256 twice, and the two BIPs hash the very same serializations.

    Everything is computed here, once, because this must be a snapshot of
    the transaction and not a view onto it: `Tx` is mutable, and a hash
    computed lazily out of the caller's transaction would be issue #140
    again, a sig_hash that changed under the caller between two calls.
    Build one, use it for a loop over the inputs, and throw it away with
    the transaction it describes.
    """

    sha_prevouts: bytes
    sha_amounts: bytes
    sha_script_pub_keys: bytes
    sha_sequences: bytes
    sha_outputs: bytes

    def __init__(self, tx: Tx, prevouts: list[TxOut]) -> None:
        # a mismatch would silently hash the amounts and script_pub_keys of
        # one transaction into the sig_hash of another; the same message as
        # script_engine.verify_transaction, which checks it before this
        if len(prevouts) != len(tx.vin):
            raise BTClibValueError(
                f"{len(prevouts)} prevouts for {len(tx.vin)} transaction inputs"
            )
        object.__setattr__(self, "sha_prevouts", sha256(_serialized_prevouts(tx)))
        object.__setattr__(self, "sha_amounts", sha256(_serialized_amounts(prevouts)))
        object.__setattr__(
            self, "sha_script_pub_keys", sha256(_serialized_script_pub_keys(prevouts))
        )
        object.__setattr__(self, "sha_sequences", sha256(_serialized_sequences(tx)))
        object.__setattr__(self, "sha_outputs", sha256(_serialized_outputs(tx)))

    @property
    def hash_prev_outs(self) -> bytes:
        """Return BIP143's hashPrevouts."""
        return sha256(self.sha_prevouts)

    @property
    def hash_seqs(self) -> bytes:
        """Return BIP143's hashSequence."""
        return sha256(self.sha_sequences)

    @property
    def hash_outputs(self) -> bytes:
        """Return BIP143's hashOutputs, the one that commits to them all."""
        return sha256(self.sha_outputs)


# Core's `SegwitV0SignatureHash`, of
# test/functional/test_framework/script.py; `TF2.md` pins the revision
def segwit_v0(
    script_code: Octets,
    tx: Tx,
    vin_i: int,
    hash_type: int,
    amount: int,
    precomputed: PrecomputedTxData | None = None,
) -> bytes:
    """Return the BIP143 hash one segwit v0 input's signature commits to.

    The preimage commits to the amount being spent -- the point of
    BIP143 -- and to the script code whole, OP_CODESEPARATORs included.
    `precomputed`, when given, must describe this very transaction; a
    single call leaves it None and hashes only what its hash type
    commits to.

    `hash_type` is Core's `int32_t nHashType`, as `legacy`'s is, and every
    32-bit word has a preimage for the same reason.
    """
    # the width of the field and not the money range: BIP143's amount is
    # Core's CAmount, so -1 is what eight `ff` octets mean and the preimage
    # commits to them either way (issue 388). What no reading of eight
    # bytes can stand for is what leaked an OverflowError out of the
    # serialization, where the contract promises a BTClibValueError
    _assert_valid_camount(amount, "amount")
    _assert_valid_vin_i(tx, vin_i)

    script_code = bytes_from_octets(script_code)

    # precomputed, when given, must describe this very tx: it is the
    # caller's business to build it from the transaction being signed and
    # to drop it when that transaction changes. Without it each branch
    # hashes what it needs and nothing else, which is what a single call
    # wants and what a loop over the inputs pays Θ(N²) for
    hash_prev_outs = b"\x00" * 32
    if not hash_type & ANYONECANPAY:
        hash_prev_outs = (
            hash256(_serialized_prevouts(tx))
            if precomputed is None
            else precomputed.hash_prev_outs
        )

    hash_seqs = b"\x00" * 32
    if (
        not (hash_type & ANYONECANPAY)
        and (hash_type & 0x1F) != SINGLE
        and (hash_type & 0x1F) != NONE
    ):
        hash_seqs = (
            hash256(_serialized_sequences(tx))
            if precomputed is None
            else precomputed.hash_seqs
        )

    hash_outputs = b"\x00" * 32
    if hash_type & 0x1F not in {SINGLE, NONE}:
        hash_outputs = (
            hash256(_serialized_outputs(tx))
            if precomputed is None
            else precomputed.hash_outputs
        )
    elif (hash_type & 0x1F) == SINGLE and vin_i < len(tx.vout):
        # this one commits to the signed output alone, so it is per input
        # by definition and no precomputation can serve it
        hash_outputs = hash256(_serialized_output(tx.vout[vin_i]))

    preimage = b"".join(
        [
            _serialized_4_byte_field("version", tx.version),
            hash_prev_outs,
            hash_seqs,
            _serialized_out_point(tx.vin[vin_i].prev_out),
            var_bytes.serialize(script_code),
            # BIP143's `amount` is the spent output's value, and Core
            # writes it with the same serializer TxOut uses (issue #388)
            _serialized_camount(amount, "amount"),
            _serialized_4_byte_field("sequence", tx.vin[vin_i].sequence),
            hash_outputs,
            _serialized_4_byte_field("lock time", tx.lock_time),
            # an int32_t as Core's nHashType is, so that -1 is the
            # `ffffffff` Core writes rather than an OverflowError (#405)
            _serialized_hash_type(hash_type),
        ]
    )
    return hash256(preimage)


def taproot(
    transaction: Tx,
    input_index: int,
    prevouts: list[TxOut],
    hashtype: int,
    ext_flag: int,
    annex: Octets,
    message_extension: Octets,
    precomputed: PrecomputedTxData | None = None,
) -> bytes:
    """Return the BIP341 hash one taproot input's signature commits to.

    BIP341's SigMsg under the TapSighash tag: the whole-transaction
    hashes enter as their single-sha256 forms, the spent amounts and
    script_pub_keys are always committed to, and `ext_flag` with
    `message_extension` carry BIP342's tapleaf commitment for a script
    path -- empty for the key path. SIGHASH_SINGLE with no matching
    output is an error here, per BIP341, where legacy keeps the bug.
    """
    _assert_valid_prevouts(prevouts)
    _assert_valid_vin_i(transaction, input_index)

    if hashtype not in SIG_HASH_TYPES:
        raise BTClibValueError(f"Unknown hash type: {hashtype}")
    if hashtype & 0x03 == SINGLE and input_index >= len(transaction.vout):
        raise BTClibValueError("Sighash single without a corresponding output")

    # the message extension is concatenated raw, so it is the one octets
    # parameter here that no serializer coerces on its way in
    message_extension = bytes_from_octets(message_extension)

    anyone_can_pay = hashtype & 0x80 == ANYONECANPAY
    all_outputs = hashtype & 0x03 not in {NONE, SINGLE}
    annex_present = int(bool(annex))

    # b"".join of the parts, as the rest of the module does, rather than
    # the += of a bytes copied whole at every one of a dozen steps
    parts = [
        b"\x00",
        hashtype.to_bytes(1, "little"),
        _serialized_4_byte_field("version", transaction.nVersion),
        _serialized_4_byte_field("lock time", transaction.nLockTime),
    ]

    # the transaction-wide hashes, and only if this hash type commits to
    # any of them: ANYONECANPAY with NONE or SINGLE commits to no part of
    # the transaction beyond its own input, and building them there would
    # be O(N) work for a sig_hash that hashes none of it
    if not anyone_can_pay or all_outputs:
        if precomputed is None:
            precomputed = PrecomputedTxData(transaction, prevouts)
        if not anyone_can_pay:
            parts += [
                precomputed.sha_prevouts,
                precomputed.sha_amounts,
                precomputed.sha_script_pub_keys,
                precomputed.sha_sequences,
            ]
        if all_outputs:
            parts.append(precomputed.sha_outputs)

    parts.append(_serialized_spend_type(ext_flag, annex_present))

    if anyone_can_pay:
        # check_validity=False, as segwit_v0 and the rest of the library do
        # in an inner loop: re-validating every OutPoint and every TxOut of
        # the transaction once per input is the same waste in miniature
        prevout = prevouts[input_index]
        parts += [
            _serialized_out_point(transaction.vin[input_index].prev_out),
            _serialized_camount(prevout.value, "spent amount"),
            var_bytes.serialize(prevout.script_pub_key.script),
            _serialized_4_byte_field(
                "sequence", transaction.vin[input_index].nSequence
            ),
        ]
    else:
        parts.append(input_index.to_bytes(4, "little"))

    if annex_present:
        parts.append(sha256(var_bytes.serialize(annex)))

    if hashtype & 0x03 == SINGLE:
        parts.append(sha256(_serialized_output(transaction.vout[input_index])))

    parts.append(message_extension)

    return tagged_hash(b"TapSighash", b"".join(parts))


def redeem_script(script_sig: Octets, script_pub_key: Octets) -> bytes:
    """Return the redeem script of a p2sh input, checked against its hash.

    BIP16 has it as the last command of the script_sig, and what the
    sig_hash must dispatch on is the redeem script itself, never the push
    that carries it: serialized, a p2sh-p2wpkh redeem script is 23 bytes
    where p2wpkh wants exactly 22, so every is_p2w* test on the script_sig
    is false and the input would silently take the legacy branch, signing
    a hash that does not commit to the amount.

    The hash is checked here rather than left to the script engine: a
    script_sig disagreeing with the script_pub_key it spends can only give
    a sig_hash for a script no one will ever run.
    """
    commands = parse(script_sig)
    if not commands:
        raise BTClibValueError("empty script_sig for a p2sh input")
    # parse spells op codes as their OP_/UNKNOWN_OP_CODE_ name and data
    # pushes as a hex string: only the latter can be a redeem script.
    # ERROR_COMMAND is a str and neither, so it is named here rather than
    # left to bytes.fromhex, which would answer a script_sig ending in a
    # truncated push with a bare ValueError from outside the exception
    # contract
    command = commands[-1]
    if (
        not isinstance(command, str)
        or command == ERROR_COMMAND
        or command.startswith(("OP_", "UNKNOWN_OP_CODE_"))
    ):
        err_msg = f"missing redeem script in the p2sh script_sig: {command!r}"
        raise BTClibValueError(err_msg)

    script = bytes.fromhex(command)
    _, payload = type_and_payload(script_pub_key)
    if hash160(script) != payload:
        err_msg = "invalid redeem script hash: "
        err_msg += f"{hash160(script).hex()} instead of {payload.hex()}"
        raise BTClibValueError(err_msg)
    return script


def from_tx(
    prevouts: list[TxOut],
    tx: Tx,
    vin_i: int,
    hash_type: int,
    precomputed: PrecomputedTxData | None = None,
    *,
    codesep_index: int = 0,
) -> bytes:
    """Return the hash to be signed for one input of a transaction.

    `precomputed` is what makes a loop over the N inputs of a transaction
    cost O(N) instead of Θ(N²): the transaction-wide hashes a segwit
    sig_hash commits to are the same for every input, so computing them
    once is the caller's to do — `PrecomputedTxData(tx, prevouts)` before
    the loop, dropped with the transaction after it. It must describe this
    very tx, and nothing here can tell whether it does.

    `codesep_index` is which OP_CODESEPARATOR the script code starts
    after: 0, the default, is the whole script, i.e. none executed, and k
    is the k-th *occurrence* in the script being signed for — the redeem
    script of a p2sh input, the witness script of a p2wsh one. Whether
    that occurrence is the one last executed when the signature is checked
    depends on which branches the input takes, which is the signer's to
    know: a script `OP_IF OP_CODESEPARATOR OP_ENDIF OP_CODESEPARATOR` run
    down its false branch executes the second occurrence and not the
    first. A verifier does not need the parameter and does not have the
    problem — the interpreter advances Core's `pbegincodehash` as it goes.
    """
    _assert_valid_prevouts(prevouts)
    _assert_valid_vin_i(tx, vin_i)
    # both lists are indexed at vin_i below, and one prevout per input is
    # what a segwit preimage commits to: the message PrecomputedTxData
    # gives for the same mismatch, and script_engine.verify_transaction
    # before it
    if len(prevouts) != len(tx.vin):
        raise BTClibValueError(
            f"{len(prevouts)} prevouts for {len(tx.vin)} transaction inputs"
        )

    script = prevouts[vin_i].script_pub_key.script

    if is_p2tr(script):
        if codesep_index:
            # BIP341 commits to the *position* of the last executed
            # OP_CODESEPARATOR rather than truncating the script, and
            # taproot_annex_and_ext writes 0xffffffff, "none executed".
            # Core's signer supports that case and no other either:
            # "Only support non-OP_CODESEPARATOR BIP342 signing for now"
            raise BTClibValueError("OP_CODESEPARATOR index for a taproot input")
        annex, ext = taproot_annex_and_ext(tx, vin_i)
        return taproot(
            tx, vin_i, prevouts, hash_type, int(bool(ext)), annex, ext, precomputed
        )

    # handle all p2sh-wrapped scripts
    if is_p2sh(script):
        script = redeem_script(tx.vin[vin_i].script_sig, script)

    if is_p2wpkh(script):
        if codesep_index:
            raise BTClibValueError("OP_CODESEPARATOR index for a p2wpkh input")
        # BIP143 signs a p2wpkh input against the p2pkh script for the
        # same hash, which is built here and is in no transaction
        _, payload = type_and_payload(script)
        script_code = serialize(
            ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]
        )
        return segwit_v0(
            script_code, tx, vin_i, hash_type, prevouts[vin_i].value, precomputed
        )

    if is_p2wsh(script):
        # the witness script is the last element, and there is none: the
        # guard the engine has, Core's WITNESS_PROGRAM_WITNESS_EMPTY.
        # Without it the empty stack was an IndexError out of `stack[-1]`,
        # i.e. malformed input leaving through something other than
        # BTClibValueError
        stack = tx.vin[vin_i].script_witness.stack
        if not stack:
            raise BTClibValueError("empty p2wsh witness stack")
        # the real script is contained in the witness, and it is signed as
        # it stands: BIP143 elides no OP_CODESEPARATOR, where the legacy
        # serializer elides those left after the truncation
        script_code = _script_code_from(stack[-1], codesep_index)
        return segwit_v0(
            script_code, tx, vin_i, hash_type, prevouts[vin_i].value, precomputed
        )

    if is_p2tr(script):
        raise BTClibValueError("Taproot scripts cannot be wrapped in p2sh")

    script_code = _script_code_from(script, codesep_index)
    return legacy(script_code, tx, vin_i, hash_type)
