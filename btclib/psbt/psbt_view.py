# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A psbt read from a stream one map at a time, for a signer with no room.

`Psbt` is the whole object: `Psbt.parse` reads every map before anything
can be inspected or signed, so a psbt whose inputs carry a previous
transaction each costs all of them at once. A `PsbtView` reads the same
psbt out of a seekable stream and keeps no map at all -- it walks the
stream once to learn where each one begins, and reads one when it is
asked for it. `diybitcoinhardware/embit` calls the same idea
`psbtview.PSBTView` and states its audience, which is this one: hardware
wallets and airgapped signers, where the psbt can be larger than the
memory available to hold it (issue #647).

This is a reader, beside `Psbt` and not instead of it. Most callers want
the object model -- combining, finalizing, extracting and `sign` all
rewrite a psbt, and none of that is here. What is here is what a Signer
needs before it signs: the global fields, one input or output map at a
time, and the two messages a signature commits to. The signer's answer is
its own to assemble, one `PsbtIn` per input it signed and
`PsbtIn.serialize` how each is written, the stream this reads from being
read-only.

What it holds, exactly. At construction: the global map, which is the
transaction version and the counts, the xpubs, and in a version 0 psbt
the unsigned transaction; and one integer per input and output map, being
where in the stream it starts. Asked for a sig_hash it builds two more
things and keeps them, because BIP143 and BIP341 commit every input to
them: the unsigned transaction, and the output each input spends -- read
one input at a time, so that the *previous transaction* a non-witness
utxo carries is dropped as soon as the one output being spent is out of
it. With them it keeps `sig_hash.PrecomputedTxData`, the five 32-byte
hashes BIP341 commits to, so that signing N inputs hashes the whole
transaction once instead of N times (issue #164 for the whole-object
half of the same arithmetic).

What it therefore never holds is two input maps at once, which is where a
psbt's size is: a witness utxo is an amount and a script, a non-witness
utxo is a whole transaction, and the derivation paths, leaf scripts and
signatures of every input are each as large as the wallet that wrote
them.

**The stream must not change while the view is alive.** A view answers
from the bytes that are there when it reads them, and it reads on
request: nothing re-reads a map to check that it says what it said, and
nothing invalidates what has already been read. So a stream that changes
under a view is a view that gives two answers to one question -- and, if
what changed is an amount or a script, a sig_hash committing to a
transaction the signer was never shown, which is a time-of-check to
time-of-use attack and not merely a stale read. embit's own docstring
gives the same warning about an SD card, whose controller answers each
read separately. A caller reading a psbt from removable or untrusted
storage copies it into memory it controls first; a caller whose stream
has legitimately changed builds a new view, there being no way to refresh
one.

The stream is any seekable binary one -- a file object as much as a
`BytesIO` -- which is wider than `alias.BinaryData`, and deliberately: a
`parse` consumes what it is given, so a `BytesIO` is all it can want,
while a view over a `BytesIO` holds the whole psbt in memory and answers
the question this module exists for with "buy more memory". Octets are
taken too, and read as one whole psbt: what follows the last map in them
is refused, where what follows in a caller's stream is the caller's.

Not a `parse` classmethod, for the same reason it is not a dataclass: what
this returns is not the psbt those bytes encode but a handle on the stream
holding it, and the two are not interchangeable -- the second is only
valid while the first is unchanged. The properties `Psbt.parse` owes its
caller are still checked where they are about the bytes: the walk at
construction refuses a truncated psbt, one map at a time, and
`PsbtIn.parse` reads each map from exactly the octets the walk bounded.
"""

from __future__ import annotations

from copy import deepcopy
from io import BytesIO
from typing import BinaryIO, cast

from btclib import var_int
from btclib.alias import Octets
from btclib.bip32 import HdKeyPaths, assert_valid_hd_key_paths, decode_hd_key_paths
from btclib.exceptions import BTClibValueError
from btclib.psbt.psbt import (
    PSBT_MAGIC_BYTES,
    _assert_map_count,
    _assert_unsigned,
    _assert_valid_input_fields,
    _assert_valid_output_fields,
    _assert_valid_utxo,
    _ecdsa_sig_hash,
    _global_version,
    _lock_time,
    _parse_global_map,
    _read_tx_in,
    _read_tx_out,
    _required_lock_times,
    _settle_globals,
    _spent_outputs,
    _taproot_sig_hash,
    _tx_in,
    _tx_out,
)
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_utils import (
    SP_DLEQ_PROOF_SIZE,
    SP_ECDH_SHARE_SIZE,
    assert_valid_psbt_version,
    assert_valid_sp_scan_key_map,
    assert_valid_unknown,
    decode_dict_bytes_bytes,
    deserialize_map,
)
from btclib.script.sig_hash import PrecomputedTxData
from btclib.tx import Tx, TxOut
from btclib.tx.limits import MAX_TX_IN_COUNT, MAX_TX_OUT_COUNT
from btclib.utils import assert_no_trailing, bytes_from_octets, read_exactly

__all__ = [
    "PsbtView",
]

# every question about what a psbt's bytes mean is imported above and none
# of it is restated here: which type byte is a field of which version,
# what the global map holds, which fields each version requires of a map,
# what the transaction being built is, what a sig_hash commits to. A view
# reads the same psbts `Psbt` does, so a rule it answered on its own would
# be a second psbt format -- one that could accept what `Psbt.parse`
# refuses, and sign what `Psbt` would not

# what a compact size is at its longest: the 0xff prefix and eight octets
_MAX_VAR_INT_SIZE = 9


def _read_var_int(stream: BinaryIO) -> int:
    """Return the compact size at the stream's cursor, consuming just it.

    `var_int.parse` reads from a `BytesIO` or from octets, and this stream
    is neither, so it is handed the nine octets a compact size cannot
    exceed and the cursor is then put where the encoding it read ends.
    `var_int.serialize` is what says where that is: only the shortest
    encoding of a number is a var_int at all, so the length of the number
    written back is the length of what was read -- which keeps the
    prefix-to-width table in the one module that has it.
    """
    start = stream.tell()
    value = var_int.parse(stream.read(_MAX_VAR_INT_SIZE))
    stream.seek(start + len(var_int.serialize(value)))
    return value


def _skip_map(stream: BinaryIO) -> int:
    """Return where the map at the stream's cursor ends, reading no value.

    The 0x00 separator included, so the answer is where the next map
    begins. Only the lengths are read and the cursor is moved over the
    keys and the values, which is what makes a walk over every map of a
    psbt cost no memory; a length reaching past the end of the stream
    leaves nothing for the next one to read, so a truncated psbt is
    refused here rather than believed.

    A stream with nothing left at all is the commonest such truncation --
    a psbt declaring more maps than it carries -- and it is refused with
    `deserialize_map`'s own words, that being the same malformation read
    one map earlier.
    """
    if not stream.read(1):
        raise BTClibValueError("malformed psbt: at least a map is missing")
    stream.seek(-1, 1)

    while True:
        # a zero-length key is the separator, which is the same byte
        # `deserialize_map` stops at and the same reading of it
        key_size = _read_var_int(stream)
        if key_size == 0:
            return stream.tell()
        stream.seek(key_size, 1)
        stream.seek(_read_var_int(stream), 1)


def _assert_index(i: int, count: int, what: str) -> None:
    """Refuse an index no map of this psbt has.

    A negative one included, where a list would take it as counting from
    the end: this is a position in a stream, and the map before the first
    is the global one, which is not an input.
    """
    if not 0 <= i < count:
        raise BTClibValueError(f"invalid {what} index: {i}, the psbt has {count}")


class PsbtView:
    """A read-only view of one psbt in a seekable stream.

    The global fields are attributes, being the whole of what is read
    eagerly; `input` and `output` read one map from the stream each time
    they are called, `tx` and `prevouts` what a transaction is built out
    of, and `ecdsa_sig_hash` and `taproot_sig_hash` the two messages a
    Signer signs. The module docstring says what is kept between calls,
    and what a stream that changes underneath costs.
    """

    stream: BinaryIO
    offset: int
    version: int
    tx_version: int
    fallback_lock_time: int | None
    tx_modifiable: int | None
    input_count: int
    output_count: int
    hd_key_paths: HdKeyPaths
    unknown: dict[bytes, bytes]
    signed_message: bytes | None
    sp_ecdh_shares: dict[bytes, bytes]
    sp_dleq_proofs: dict[bytes, bytes]

    def __init__(self, data: BinaryIO | Octets) -> None:
        # `bytes` where `BytesIO` would take the buffer itself: it copies
        # either way — what it does not do is flatten a non-contiguous
        # memoryview, which `Octets` admits and which it refuses with
        # `BufferError: underlying buffer is not C-contiguous`
        stream: BinaryIO = (
            BytesIO(bytes(bytes_from_octets(data)))
            if isinstance(data, (bytes, str, bytearray, memoryview))
            else data
        )
        if not stream.seekable():
            err_msg = "a psbt view needs a seekable stream: it reads a map "
            err_msg += "when it is asked for it, not in the order they arrive"
            raise BTClibValueError(err_msg)
        self.stream = stream
        # where the psbt starts, which is where the caller's cursor is: a
        # psbt read out of a stream carrying more than the psbt is what a
        # stream is for, so nothing here assumes the stream begins with one
        self.offset = stream.tell()

        if stream.read(len(PSBT_MAGIC_BYTES)) != PSBT_MAGIC_BYTES:
            raise BTClibValueError("malformed psbt: missing magic bytes")

        global_map = deserialize_map(self._read_map())
        # the version before the rest of the map and before every map after
        # it, as in `Psbt.parse`: what a type byte means is version
        # dependent, and a map has no order to put the version first in
        version = _global_version(global_map)
        assert_valid_psbt_version(version)
        (
            tx,
            globals_,
            hd_key_paths,
            unknown,
            signed_message,
            sp_ecdh_shares,
            sp_dleq_proofs,
        ) = _parse_global_map(global_map, version)
        _settle_globals(tx, globals_, version)

        self.version = version
        self.tx_version = cast(int, globals_["tx_version"])
        self.fallback_lock_time = globals_["fallback_lock_time"]
        self.tx_modifiable = globals_["tx_modifiable"]
        self.input_count = cast(int, globals_["input_count"])
        self.output_count = cast(int, globals_["output_count"])
        self.hd_key_paths = decode_hd_key_paths(hd_key_paths)
        self.unknown = dict(sorted(decode_dict_bytes_bytes(unknown).items()))
        self.signed_message = signed_message
        # BIP375's two globals are kept and checked as every other global
        # here is: a view of a psbt that pays a silent payment address is
        # a view of the shares that derive its output scripts, and a
        # caller reading the maps one at a time has the same need of them
        # as `Psbt` does
        self.sp_ecdh_shares = decode_dict_bytes_bytes(sp_ecdh_shares)
        self.sp_dleq_proofs = decode_dict_bytes_bytes(sp_dleq_proofs)
        assert_valid_hd_key_paths(self.hd_key_paths)
        assert_valid_sp_scan_key_map(
            self.sp_ecdh_shares, SP_ECDH_SHARE_SIZE, "silent payment global ecdh share"
        )
        assert_valid_sp_scan_key_map(
            self.sp_dleq_proofs, SP_DLEQ_PROOF_SIZE, "silent payment global dleq proof"
        )
        assert_valid_unknown(self.unknown)

        # the same bound `Psbt.parse` applies, and for the same reason one
        # step further along: what is allocated per declared map here is
        # the offset of a map that may not be there
        _assert_map_count(self.input_count, MAX_TX_IN_COUNT, "input")
        _assert_map_count(self.output_count, MAX_TX_OUT_COUNT, "output")

        if tx is not None:
            _assert_unsigned(tx)
        # version 0's unsigned transaction is in the psbt's own bytes, and
        # is the only place its outpoints, sequences, amounts and scripts
        # are: it is what a map read below is completed from. In version 2
        # those live in the maps and there is no such transaction, which is
        # why the two names below start as the same object and only one of
        # them is ever built -- `_built_tx` puts a version 2 one together
        self._global_tx = tx
        self._tx = tx
        self._prevouts: list[TxOut] | None = None
        self._precomputed_data: PrecomputedTxData | None = None

        # one walk, reading no map: after it the stream is on the octet
        # after the psbt, which is where `parse` leaves it too
        offsets = [stream.tell()]
        for _ in range(self.input_count + self.output_count):
            offsets.append(_skip_map(stream))
        self._offsets = offsets

        if isinstance(data, (bytes, str, bytearray, memoryview)):
            # octets are one whole psbt and a stream is the caller's:
            # btclib/utils.py states the rule both halves read. The cast is
            # this branch's own premise -- octets are what the stream above
            # was built from, so it is the BytesIO it was wrapped in
            assert_no_trailing(data, cast(BytesIO, self.stream), "psbt")

    def _read_map(self) -> bytes:
        """Return the octets of the map at the cursor, its separator included.

        The stream is left after the map, so this is how a psbt is walked;
        the octets are handed to whoever parses them, which is what keeps
        one parser per map rather than a second one reading a stream.
        """
        start = self.stream.tell()
        end = _skip_map(self.stream)
        self.stream.seek(start)
        return read_exactly(self.stream, end - start, "psbt map")

    def _map_bytes(self, n: int) -> bytes:
        """Return the octets of map n, the inputs first as a psbt writes."""
        start, end = self._offsets[n], self._offsets[n + 1]
        self.stream.seek(start)
        return read_exactly(self.stream, end - start, f"psbt map {n}")

    def input(self, i: int, *, check_validity: bool = True) -> PsbtIn:
        """Return input i, read from the stream now and held by nothing.

        Complete whatever the version: a version 0 psbt keeps the outpoint
        and the sequence of every input in its unsigned transaction, so
        this input's are written into the map that does not carry them,
        exactly as `Psbt.parse` does for all of them at once.

        check_validity asks of the map what `Psbt.assert_valid` asks of
        every input -- the fields this version requires of it, and the
        previous transaction being the one the outpoint names -- which are
        the questions about one input alone. What it cannot ask is the
        rest: this is one map, and a psbt is valid or not as a whole.
        """
        _assert_index(i, self.input_count, "input")
        psbt_in = PsbtIn.parse(
            self._map_bytes(i),
            psbt_version=self.version,
            check_validity=check_validity,
        )
        if self._global_tx is not None:
            _read_tx_in(psbt_in, self._global_tx.vin[i])
        if check_validity:
            _assert_valid_input_fields(psbt_in, self.version, i)
            _assert_valid_utxo(psbt_in)
        return psbt_in

    def output(self, i: int, *, check_validity: bool = True) -> PsbtOut:
        """Return output i, read from the stream now and held by nothing.

        The output maps follow the input maps in a psbt, so this seeks
        past every input; `input` says what `check_validity` covers and
        what it cannot.
        """
        _assert_index(i, self.output_count, "output")
        psbt_out = PsbtOut.parse(
            self._map_bytes(self.input_count + i),
            psbt_version=self.version,
            check_validity=check_validity,
        )
        if self._global_tx is not None:
            _read_tx_out(psbt_out, self._global_tx.vout[i])
        if check_validity:
            _assert_valid_output_fields(psbt_out, self.version, i)
        return psbt_out

    @property
    def lock_time(self) -> int:
        """Return the lock time of the transaction being built.

        BIP370's, which `_lock_time` is the algorithm of: the inputs are
        streamed past it, one at a time, being read for the two fields it
        asks about and dropped. A version 0 psbt states it once, in its
        unsigned transaction, and none of its inputs may require one --
        `_assert_valid_input_fields` is where such an input is refused,
        when the map it is in is read.
        """
        if self._tx is not None:
            # version 0 states it in the transaction it carries, and a
            # version 2 transaction already built computed it while it was
            # being built: either way the walk below would reach the number
            # that is already in hand
            return self._tx.lock_time
        return _lock_time(
            (_required_lock_times(self.input(i)) for i in range(self.input_count)),
            self.fallback_lock_time,
        )

    def _built_tx(self) -> Tx:
        """Return the transaction the maps describe, reading them once.

        The version 2 half of `tx`: every input map says an outpoint, a
        sequence and its required lock times, and every output map an
        amount and a script, so one walk holds a `TxIn` and a `TxOut` per
        map -- the transaction itself -- and no map.
        """
        vin = []
        required = []
        for i in range(self.input_count):
            psbt_in = self.input(i)
            vin.append(_tx_in(psbt_in, zeroed_sequence=False))
            required.append(_required_lock_times(psbt_in))
        vout = [
            _tx_out(self.output(i), for_identifier=False)
            for i in range(self.output_count)
        ]
        lock_time = _lock_time(required, self.fallback_lock_time)
        return Tx(self.tx_version, lock_time, vin, vout, check_validity=False)

    def _transaction(self) -> Tx:
        """Return the view's own unsigned transaction, built once and kept."""
        if self._tx is None:
            self._tx = self._built_tx()
        return self._tx

    def _spent(self) -> list[TxOut]:
        """Return the view's own list of spent outputs, read once and kept."""
        if self._prevouts is None:
            self._prevouts = _spent_outputs(
                self.input(i) for i in range(self.input_count)
            )
        return self._prevouts

    def _precomputed(self) -> PrecomputedTxData:
        """Return the transaction-wide hashes BIP341 commits every input to.

        Computed once for the whole transaction and kept, which is what
        makes signing an input cost one input's worth of work: the
        alternative is Θ(N²) hashing over a psbt whose N inputs are
        exactly what does not fit in memory.
        """
        if self._precomputed_data is None:
            self._precomputed_data = PrecomputedTxData(
                self._transaction(), self._spent()
            )
        return self._precomputed_data

    @property
    def tx(self) -> Tx:
        """Return the unsigned transaction this psbt is of.

        A copy, as `Psbt.tx` is one: what is written into it is written
        into nothing -- not into the stream, which this cannot write, and
        not into what the next sig_hash commits to.
        """
        return deepcopy(self._transaction())

    @property
    def prevouts(self) -> list[TxOut]:
        """Return the output each input spends, `psbt.prevouts` over a stream.

        A copy, for the reason `tx` is one. An input carrying no utxo
        raises: a taproot signature commits to the amount and script of
        every input, so one missing utxo leaves the whole transaction
        unsignable rather than one input of it.
        """
        return deepcopy(self._spent())

    def ecdsa_sig_hash(self, vin_i: int, *, hash_type: int | None = None) -> bytes:
        """Return the hash an ECDSA spend of one input signs.

        `psbt.ecdsa_sig_hash` over a stream, and the same rules: the type
        the input asks for by default, SIGHASH_ALL when it asks for none,
        and SIGHASH_DEFAULT refused. The input is read now and the
        transaction is the one built once, so nothing is held past the
        answer but what the module docstring lists.
        """
        return _ecdsa_sig_hash(self.input(vin_i), self._transaction(), vin_i, hash_type)

    def taproot_sig_hash(
        self, vin_i: int, *, leaf_hash: Octets = b"", hash_type: int | None = None
    ) -> bytes:
        """Return the hash a taproot spend of one input signs.

        `psbt.taproot_sig_hash` over a stream, and the same rules: BIP341
        for a key path spend, BIP342 for the script path a tapleaf hash
        names, the type the input asks for by default and SIGHASH_DEFAULT
        when it asks for none, and an empty annex. What the stream buys is
        the precomputation: the whole-transaction hashes are the same for
        every input, so they are built once and this is where they are
        handed over.
        """
        return _taproot_sig_hash(
            self.input(vin_i),
            self._transaction(),
            vin_i,
            self._spent(),
            bytes_from_octets(leaf_hash),
            hash_type,
            precomputed=self._precomputed(),
        )
