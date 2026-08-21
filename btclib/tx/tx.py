# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Tx dataclass and join; the class docstring has the contract."""

from __future__ import annotations

import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from io import SEEK_CUR
from math import ceil
from typing import Any

from btclib import var_int
from btclib.alias import BinaryData
from btclib.amount import _MAX_SATOSHI
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256
from btclib.script.sig_ops import sig_op_count as script_sig_op_count
from btclib.script.witness import Witness
from btclib.tx.limits import MAX_TX_IN_COUNT, MAX_TX_OUT_COUNT
from btclib.tx.tx_in import TX_IN_COMPARES_WITNESS, TxIn
from btclib.tx.tx_out import TxOut
from btclib.utils import (
    assert_no_trailing,
    assert_type,
    bytesio_from_binarydata,
    fields_from_json_object,
    is_integer,
    list_from_json_array,
    read_exactly,
)

__all__ = [
    "Tx",
    "join",
]

_SEGWIT_MARKER = b"\x00\x01"

# Core v31.1's policy.h, TX_MIN_STANDARD_VERSION through
# TX_MAX_STANDARD_VERSION: 1 and 2 are what v27.2 and v31.1 agree on, 3
# is v31.1's own addition, BIP431's TRUC (issue #387)
_TX_MIN_STANDARD_VERSION = 1
_TX_MAX_STANDARD_VERSION = 3


def _assert_valid_4_byte_field(name: str, value: int) -> None:
    """Refuse an int no four unsigned bytes can hold.

    Called from `serialize` as well as from `assert_valid`, and
    unconditionally there: `check_validity=False` is what lets
    `legacy` and `merkle_root_and_mutated_from_transactions` copy or
    walk a transaction without judging it whole, and the width is the
    one thing serializing four bytes cannot skip regardless -- the
    alternative is `int.to_bytes`'s own OverflowError, past the
    BTClibValueError every caller here is written to catch (issue
    #690).
    """
    if not 0 <= value <= 0xFFFFFFFF:
        raise BTClibValueError(f"invalid {name}: {value}")


def _assert_valid_coinbase(vin: Sequence[TxIn], *, is_coinbase: bool) -> None:
    """Raise an exception if the inputs disagree with the coinbase rule.

    The two cases are one check because a coinbase input -- the null
    outpoint -- is what makes a transaction a coinbase: either the
    transaction is one, and then its single input carries the block's
    script_sig, whose size consensus bounds; or it is not, and then no
    input may be a coinbase one.

    is_coinbase is passed rather than recomputed: `Tx.is_coinbase` is
    where "one input, and it is the null outpoint" is spelled, and a
    second spelling here is one that can drift from it.
    """
    if is_coinbase:
        if not 2 <= len(vin[0].script_sig) <= 100:
            raise BTClibValueError("Invalid coinbase script size")
        return

    for tx_in in vin:
        if tx_in.is_coinbase:
            raise BTClibValueError("coinbase input in a non-coinbase transaction")


# mutable (a builder and a signer edit it in place), so unhashable is the
# dataclass default: eq=True and frozen=False set __hash__ to None
@dataclass
class Tx:  # noqa: PLW1641
    """A Bitcoin transaction: version, lock time, inputs, outputs.

    Mutable, being what a builder and a signer edit in place; `id` and
    `hash` are computed from the current state on every read, so they
    follow the edits. assert_valid checks what CheckTransaction checks
    of a lone transaction -- field ranges, the inputs and outputs one
    by one, the coinbase script size, no outpoint spent twice, the
    MAX_MONEY bound on the output sum; whether it spends what it claims
    needs the prevouts, which is script.engine.verify_transaction's
    question.
    """

    # 4 bytes, _signed_ little endian
    version: int
    # 0	Not locked
    #  < 500000000	Block number at which this transaction is unlocked
    # >= 500000000	UNIX timestamp at which this transaction is unlocked
    # If all TxIns have final (0xffffffff) sequence numbers then lock_time
    # is irrelevant. Otherwise, the transaction may not be added to a
    # block until after lock_time.
    # Set to the current block to prevent fee sniping.
    lock_time: int
    vin: list[TxIn]
    vout: list[TxOut]

    @property
    def nVersion(self) -> int:
        """Return the nVersion int for compatibility with CTransaction."""
        return self.version

    @property
    def nLockTime(self) -> int:
        """Return the nLockTime int for compatibility with CTransaction."""
        return self.lock_time

    @property
    def id(self) -> bytes:
        """Return the transaction id."""
        serialized_ = self.serialize(include_witness=False, check_validity=False)
        hash256_ = hash256(serialized_)
        return hash256_[::-1]

    @property
    def hash(self) -> bytes:
        """Return the transaction hash.

        It differs from tx_id for witness transactions.
        """
        serialized_ = self.serialize(include_witness=True, check_validity=False)
        hash256_ = hash256(serialized_)
        return hash256_[::-1]

    def _serialized_size(self, include_witness: bool) -> int:
        """Return what serialize writes, without writing it.

        The sum of the widths, field by field, and no bytes built: a
        caller that wants a length gets one, where `len(serialize(...))`
        answered it with a copy of the whole transaction -- of the whole
        block, for the rules that bound a block by its size. It is
        Core's `GetSerializeSize`, which serializes into a
        `SizeComputer`: a stream whose write adds to a counter.

        Two ways of computing one quantity can disagree, and a size that
        is wrong by a byte is a consensus answer that is wrong, so this
        mirrors `serialize` line for line and
        `test_the_size_and_the_serialization_agree` holds the two
        together over every vector the suite carries.
        """
        segwit = include_witness and self.is_segwit

        size = 4 + 4  # version and lock_time
        if segwit:
            size += len(_SEGWIT_MARKER)
        size += var_int._size(len(self.vin))
        size += sum(tx_in._serialized_size() for tx_in in self.vin)
        size += var_int._size(len(self.vout))
        size += sum(tx_out._serialized_size() for tx_out in self.vout)
        if segwit:
            size += sum(tx_in.script_witness._serialized_size() for tx_in in self.vin)
        return size

    @property
    def size(self) -> int:
        """Return the transaction size."""
        return self._serialized_size(include_witness=True)

    @property
    def vsize(self) -> int:
        """Return the virtual transaction size.

        It differs from size for witness transactions.
        """
        return ceil(self.weight / 4)

    @property
    def weight(self) -> int:
        """Return the BIP141 weight: 3x the stripped size plus the size."""
        return 3 * self._serialized_size(include_witness=False) + self._serialized_size(
            include_witness=True
        )

    @property
    def sig_op_count(self) -> int:
        """Return the legacy sigop count, Core's GetLegacySigOpCount.

        Every input's script_sig and every output's script_pub_key,
        counted from the bytes by `script.sig_ops.sig_op_count`: the p2sh
        and witness sigops Core adds in ConnectBlock need the outputs
        being spent, which a transaction does not carry. That module's
        docstring has what the shortfall is; the block rule this feeds,
        `Block.assert_valid_sig_op_count`, is the one it is enough for.
        """
        return sum(script_sig_op_count(tx_in.script_sig) for tx_in in self.vin) + sum(
            script_sig_op_count(tx_out.script_pub_key.script) for tx_out in self.vout
        )

    @property
    def vwitness(self) -> list[Witness]:
        """Return the witnesses, one per input and in input order."""
        return [tx_in.script_witness for tx_in in self.vin]

    @property
    def is_segwit(self) -> bool:
        """Answer whether any input carries a witness.

        The inputs and not the outputs: paying to a segwit script does
        not make the paying transaction segwit, spending one does.
        """
        return any(tx_in.is_segwit for tx_in in self.vin)

    @property
    def is_coinbase(self) -> bool:
        """Answer whether this is a coinbase: one input, spending nothing."""
        return len(self.vin) == 1 and self.vin[0].is_coinbase

    def __init__(
        self,
        version: int = 1,
        lock_time: int = 0,
        vin: Sequence[TxIn] | None = None,
        vout: Sequence[TxOut] | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        self.version = version
        self.lock_time = lock_time
        # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
        self.vin = list(vin) if vin else []
        self.vout = list(vout) if vout else []

        if check_validity:
            self.assert_valid()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Tx):
            return NotImplemented

        if not TX_IN_COMPARES_WITNESS and self.vwitness != other.vwitness:
            return False

        return (self.version, self.lock_time, self.vin, self.vout) == (
            other.version,
            other.lock_time,
            other.vin,
            other.vout,
        )

    def to_dict(
        self, *, check_validity: bool = True
    ) -> dict[str, str | int | list[Any]]:
        """Return the transaction as a dict of json-friendly values.

        The keys are Bitcoin Core's decoderawtransaction ones; txid,
        hash, size, vsize and weight are derived for the reader and
        ignored by from_dict, which recomputes them.
        """
        if check_validity:
            self.assert_valid()

        return {
            "txid": self.id.hex(),
            "hash": self.hash.hex(),
            "version": self.version,
            "size": self.size,
            "vsize": self.vsize,
            "weight": self.weight,
            "locktime": self.lock_time,
            "vin": [tx_in.to_dict(check_validity=False) for tx_in in self.vin],
            "vout": [tx_out.to_dict(check_validity=False) for tx_out in self.vout],
        }

    @classmethod
    def from_dict(
        cls: type[Tx], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> Tx:
        """Build a Tx from the dict shape to_dict writes."""
        dict_ = fields_from_json_object(dict_, "transaction")
        return cls(
            dict_["version"],
            dict_["locktime"],
            [
                TxIn.from_dict(tx_in, check_validity=False)
                for tx_in in list_from_json_array(dict_["vin"], "transaction inputs")
            ],
            [
                TxOut.from_dict(tx_out, check_validity=False)
                for tx_out in list_from_json_array(dict_["vout"], "transaction outputs")
            ],
            check_validity=check_validity,
        )

    def assert_standard(self) -> None:
        """Refuse what assert_valid refuses, plus a non-standard version.

        Core v31.1's relay policy, `TX_MIN_STANDARD_VERSION` through
        `TX_MAX_STANDARD_VERSION`: 1 and 2 both v27.2 and v31.1 relay,
        3 is v31.1's own addition, BIP431's TRUC, and every version
        outside that window fails here and not in assert_valid, whose
        four-byte range takes it.
        """
        self.assert_valid()

        if not _TX_MIN_STANDARD_VERSION <= self.version <= _TX_MAX_STANDARD_VERSION:
            raise BTClibValueError(f"invalid version: {self.version}")

    def assert_valid(self, *, unsigned_template: bool = False) -> None:
        """Assert that this is a valid transaction.

        unsigned_template=True drops the two rules a PSBT's global unsigned
        transaction cannot satisfy, and only those: at least one input and
        at least one output. Everything else still applies -- the version
        and lock time ranges, each input and output on its own, no outpoint
        spent twice, the MAX_MONEY bound on their sum.

        Those two rules are right for a transaction, Core's
        CheckTransaction rejecting an empty vin or vout, and wrong for a
        PSBT's: that one is incomplete by construction, which is the whole
        point of the format. BIP174 lists two zero-input PSBTs as valid
        and btclib refused both (issue 170).
        """
        _assert_valid_coinbase(self.vin, is_coinbase=self.is_coinbase)

        # the type before the range, as BlockHeader.assert_valid checks its
        # own two int fields: a bool passes every comparison below as one or
        # zero, and `to_dict`/`from_dict` is a json boundary -- `true` there
        # would be version 1 rather than a schema error
        for key in ("version", "lock_time"):
            value = getattr(self, key)
            if not is_integer(value):
                err_msg = f"invalid {key} type: {type(value).__name__}"
                raise BTClibTypeError(err_msg)

        _assert_valid_4_byte_field("version", self.version)
        _assert_valid_4_byte_field("lock time", self.lock_time)

        if not unsigned_template and not self.vin:
            raise BTClibValueError("Missing inputs")
        for tx_in in self.vin:
            tx_in.assert_valid()

        # CheckTransaction's `bad-txns-inputs-duplicate` (CVE-2018-17144):
        # an outpoint named twice would be spent twice, and every arithmetic
        # over the inputs -- a fee, a total, an ancestor set -- counts what
        # it names once. `OutPoint` is frozen and hashable for this, so the
        # rule is the set, and the inputs are judged one by one above first,
        # a tx_id of the wrong length being reported as that rather than as
        # a member of a set. Unconditional, unsigned_template or not: the
        # flag drops the two rules a psbt's transaction cannot satisfy while
        # it is being built, and a Constructor adding an input already there
        # builds a transaction no node accepts, incomplete or finished
        outpoints = [tx_in.prev_out for tx_in in self.vin]
        if len(set(outpoints)) != len(outpoints):
            raise BTClibValueError("the same outpoint is spent twice")

        if not unsigned_template and not self.vout:
            raise BTClibValueError("Missing outputs")
        for tx_out in self.vout:
            tx_out.assert_valid()

        # CheckTransaction bounds the outputs one by one and then their
        # sum, and the second check is not implied by the first: every
        # output can be within MoneyRange while the total is above it.
        # Only the sum of the outputs, as there, and not the fee: what
        # the inputs are worth is not in the transaction, and comparing
        # the two is verify_amounts' job, with the prevouts in hand
        total = sum(tx_out.value for tx_out in self.vout)
        if total > _MAX_SATOSHI:
            raise BTClibValueError(f"invalid total output amount: {total}")

    def serialize(self, include_witness: bool, *, check_validity: bool = True) -> bytes:
        """Return the wire serialization, BIP144's where a witness rides.

        `include_witness` False gives the stripped serialization, what
        the txid is computed over; True adds the marker and the
        witnesses only if some input has one, a marker over empty
        witnesses not being what the wire writes.

        A bool and nothing else, which is the line
        `tests/built_object_contract_test.py` draws: this flag decides
        *what is computed* rather than whether a check runs, so a value
        read for its truth would answer a stripped serialization -- a
        different transaction id -- where the wire one was meant.
        """
        assert_type(include_witness, bool, "include_witness")

        if check_validity:
            self.assert_valid()
        else:
            # the width alone, checked here regardless: check_validity=False
            # is what lets a caller copy or walk a transaction without
            # judging it whole (`legacy`'s copy, the merkle root's loop),
            # and int.to_bytes below would otherwise answer a version or
            # lock_time outside it with an OverflowError, past the
            # BTClibValueError every caller here is written to catch
            # (issue #690)
            _assert_valid_4_byte_field("version", self.version)
            _assert_valid_4_byte_field("lock time", self.lock_time)

        segwit = include_witness and self.is_segwit

        return b"".join(
            [
                self.version.to_bytes(4, byteorder="little", signed=False),
                _SEGWIT_MARKER if segwit else b"",
                var_int.serialize(len(self.vin)),
                b"".join(
                    tx_in.serialize(check_validity=check_validity) for tx_in in self.vin
                ),
                var_int.serialize(len(self.vout)),
                b"".join(
                    tx_out.serialize(check_validity=check_validity)
                    for tx_out in self.vout
                ),
                b"".join(
                    tx_in.script_witness.serialize(check_validity=check_validity)
                    for tx_in in self.vin
                )
                if segwit
                else b"",
                self.lock_time.to_bytes(4, byteorder="little", signed=False),
            ]
        )

    @classmethod
    def parse(
        cls: type[Tx],
        data: BinaryData,
        *,
        check_validity: bool = True,
    ) -> Tx:
        """Return a Tx by parsing binary data.

        A BIP144 marker and flag over witnesses that are all empty is
        refused, which is Core's "Superfluous witness record" of
        `UnserializeTransaction` in src/primitives/transaction.h. The
        refusal is what keeps the property this library holds every wire
        class to -- `btclib.p2p.inventory`'s module docstring states it,
        `Headers.parse` and `Verack.parse` refuse for it: `serialize`
        writes the marker only when some input carries a witness, so
        those octets are ones this class could not write back.

        It does not answer to `check_validity`, and `assert_no_trailing`
        beside it is the shape being copied: that flag gates
        `assert_valid`, which asks about the transaction, and the
        transaction here is valid -- what is malformed is the encoding,
        which no field records and nothing downstream could ask about.
        """
        stream = bytesio_from_binarydata(data)

        # version is a signed int (int32_t) in bitcoin_core
        # However there are at least two transactions:
        # 35e79ee733fad376e76d16d1f10088273c2f4c2eaba1374a837378a88e530005
        # c659729a7fea5071361c2c1a68551ca2bf77679b27086cc415adeeb03852e369
        # where the version number is negative if it is considered as a signed
        # integer. As such in btclib the version is an UNSIGNED integer.
        # This has been discussed in: https://github.com/bitcoin/bitcoin/pull/16525
        version = int.from_bytes(
            read_exactly(stream, 4, "transaction version"),
            byteorder="little",
            signed=False,
        )

        # a probe and not a field, so it is read with whatever is there and
        # put back by as much: seeking -2 after a one-byte read would leave
        # the stream a byte before where it started, and the var_int below
        # would count the inputs from the wrong byte
        marker = stream.read(2)
        segwit = marker == _SEGWIT_MARKER
        if not segwit:
            # Change stream position: seek to byte offset relative to position
            stream.seek(-len(marker), SEEK_CUR)  # current position

        # each count bounded by the block that would have to hold the
        # transaction rather than by var_int's own MAX_SIZE, which answers
        # whether a CompactSize is sane and not whether anything could
        # hold this many (issue #569). What this adds to the short read
        # that TxIn.parse and TxOut.parse already raise on is the message:
        # a count above the bound is refused for what it says, before a
        # byte of the first input is read, rather than for the bytes it
        # turned out not to be followed by
        n = var_int.parse(stream, MAX_TX_IN_COUNT)
        vin = [TxIn.parse(stream, check_validity=check_validity) for _ in range(n)]

        n = var_int.parse(stream, MAX_TX_OUT_COUNT)
        vout = [TxOut.parse(stream, check_validity=check_validity) for _ in range(n)]

        if segwit:
            for tx_in in vin:
                tx_in.script_witness = Witness.parse(
                    stream, check_validity=check_validity
                )
            # Core's "Superfluous witness record": the marker said a witness
            # would follow and none did, and `serialize` drops a marker over
            # empty witnesses, so these octets do not serialize back. Asked
            # after the loop and not before, the witnesses being what the
            # question is about; the docstring has why `check_validity` does
            # not reach it
            if not any(tx_in.is_segwit for tx_in in vin):
                raise BTClibValueError("superfluous witness record")

        lock_time = int.from_bytes(
            read_exactly(stream, 4, "lock time"), byteorder="little", signed=False
        )
        assert_no_trailing(data, stream, "transaction")

        return cls(version, lock_time, vin, vout, check_validity=check_validity)


def join(
    txs: Sequence[Tx],
    enforce_same_version: bool,
    enforce_same_lock_time: bool,
    shuffle_inp: bool,
    shuffle_out: bool,
) -> Tx:
    """Join transactions into one, concatenating inputs and outputs.

    Outputs are concatenated and never merged, and no parameter asks for
    it: coalescing two outputs that pay the same script changes the
    output set, so it invalidates every signature already made over the
    old one -- and with the shuffle below the result would depend on the
    order the merge ran in. Summing two payments into one output is the
    caller's to do before signing.
    """
    assert_type(shuffle_inp, bool, "shuffle_inp")
    assert_type(shuffle_out, bool, "shuffle_out")

    version = max(tx.version for tx in txs)
    if enforce_same_version and any(tx.version != version for tx in txs):
        raise BTClibValueError("Version numbers are not the same")

    lock_time = max(tx.lock_time for tx in txs)
    if enforce_same_lock_time and any(tx.lock_time != lock_time for tx in txs):
        raise BTClibValueError("Lock times are not the same")

    vin = [vin for tx in txs for vin in tx.vin]
    if len(vin) != len({tx_in.serialize() for tx_in in vin}):
        raise BTClibValueError("common inputs")

    vout = [vout for tx in txs for vout in tx.vout]

    # avoid leaking matches between inputs and outputs
    if shuffle_inp:
        secrets.SystemRandom().shuffle(vin)
    if shuffle_out:
        secrets.SystemRandom().shuffle(vout)

    tx = Tx(version, lock_time, vin, vout)
    tx.assert_valid()
    return tx
