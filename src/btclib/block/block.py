# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Block dataclass and its rules; the class docstring has the contract."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import ceil
from typing import Any

from btclib import var_bytes, var_int
from btclib.alias import BinaryData, Command, Octets
from btclib.block.block_context import BlockContext
from btclib.block.block_header import BlockHeader
from btclib.block.limits import (
    MAX_BLOCK_SIGOPS_COST,
    MAX_BLOCK_WEIGHT,
    MIN_SERIALIZABLE_TRANSACTION_WEIGHT,
    WITNESS_SCALE_FACTOR,
)
from btclib.block.proof_of_work import MAINNET_POW_LIMIT_BITS
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import (
    hash256,
    merkle_root_and_mutated,
    merkle_root_and_mutated_from_hashes,
)
from btclib.script.script import op_int
from btclib.script.script import serialize as serialize_script
from btclib.tx import Tx, TxOut
from btclib.utils import (
    assert_no_trailing,
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    decode_num,
    fields_from_json_object,
    is_integer,
    list_from_json_array,
)

__all__ = [
    "Block",
    "bip34_commitment",
    "coinbase_witness_commitment",
    "merkle_root_and_mutated_from_transactions",
    "witness_commitment_output",
]

_HF = hash256

# BIP141: OP_RETURN, a 36-byte push, and the aa21a9ed header of it; the
# 32 bytes that follow are the commitment.
_COMMITMENT_PREFIX = bytes.fromhex("6a24aa21a9ed")
_COMMITMENT_LENGTH = len(_COMMITMENT_PREFIX) + 32


def merkle_root_and_mutated_from_transactions(
    transactions: Sequence[Tx],
) -> tuple[bytes, bool]:
    """Return a header's merkle root over a list of transactions.

    The leaves are the transactions serialized *without* witness data,
    i.e. their txids, and the root is reversed into the byte order a
    header carries. See merkle_root_and_mutated_from_hashes for the
    second returned value, the CVE-2012-2459 flag.

    One implementation, because the block builder and the block
    validator must agree by construction: assert_valid_merkle_root
    compares this against the header at hand, and mining.py's candidate
    header is built from it.
    """
    data = [
        tx.serialize(include_witness=False, check_validity=False) for tx in transactions
    ]
    root, mutated = merkle_root_and_mutated(data, _HF)
    return root[::-1], mutated


def bip34_commitment(height: int) -> bytes:
    """Return the height as a coinbase script_sig must commit to it (BIP34).

    Bitcoin Core's `CScript() << nHeight`, which is where the bytes
    `Block.assert_valid_coinbase_height` compares against come from: the
    shortest encoding of the number, so `OP_0` for zero and `OP_1` to
    `OP_16` for one to sixteen -- one byte, no push at all -- and a
    minimal data push of the script number from seventeen up.

    Those first seventeen are not what `script.serialize([height])`
    writes. It pushes the number as data -- `0100`, `0101` to `0110` --
    and warns that an op code says the same, which is a defensible
    encoding of a number and the wrong answer here: a regtest chain has
    BIP34 in force from height 1, so those seventeen are where the rule
    binds first and every node on such a chain compares against the op
    code.
    """
    # before the comparison below, which is what a non-number reaches:
    # `-1 <= "5"` is a bare TypeError about the operands rather than
    # about the height, and `True` is the height one
    if not is_integer(height):
        raise BTClibTypeError(f"invalid height type: {type(height).__name__}")

    # Core's push_int64 has three branches -- OP_0 for zero, OP_1..OP_16
    # for 1 to 16, OP_1NEGATE for -1 -- and op_int names all three
    command: Command = op_int(height) if -1 <= height <= 16 else height
    return serialize_script([command])


def coinbase_witness_commitment(transactions: Sequence[Tx], nonce: Octets) -> bytes:
    """Return the coinbase's BIP141 commitment over every witness.

    Bitcoin Core's `GenerateCoinbaseCommitment` (`src/validation.cpp`, at
    bitcoin/bitcoin@9be056a8a7): hash256 of the witness merkle root,
    concatenated with `nonce` -- the other half of the preimage, which a
    real block carries in the coinbase's own witness stack rather than
    here.

    The witness tree is built the way
    `merkle_root_and_mutated_from_transactions` builds the txid one,
    over wtxids instead of txids, with one difference:
    `transactions[0]`'s own leaf is BIP141's all-zero placeholder rather
    than its wtxid, which is unknowable here -- it would have to commit
    to the very output this function's own result ends up inside. The
    mutation flag `merkle_root_and_mutated_from_hashes` also returns is
    not read: the witness tree has the shape of the txid one, and two
    equal wtxids mean two equal transactions, hence two equal txids
    that `assert_valid_merkle_root` already rejects.

    One implementation, shared between `assert_valid_witness_commitment`
    and `witness_commitment_output` below, for the same reason
    `merkle_root_and_mutated_from_transactions` is shared between a
    header being validated and one being mined: the validator and the
    builder must not disagree about what a set of transactions hashes to.
    """
    nonce_ = bytes_from_octets(nonce)
    hashes = [b"\x00" * 32] + [
        _HF(tx.serialize(include_witness=True, check_validity=False))
        for tx in transactions[1:]
    ]
    witness_root = merkle_root_and_mutated_from_hashes(hashes, _HF)[0]
    return _HF(witness_root + nonce_)


def witness_commitment_output(transactions: Sequence[Tx], nonce: Octets) -> TxOut:
    """Return the zero-valued coinbase output committing to every witness.

    Nothing spends this output -- it exists for `Block.witness_commitment`
    to read back, the way a real miner's coinbase carries one. BIP141's
    own `aa21a9ed` header goes in front of `coinbase_witness_commitment`'s
    32 bytes, inside an OP_RETURN push, which is `_COMMITMENT_PREFIX`'s
    own shape: this is the one place that constant is written to rather
    than compared against.
    """
    commitment = coinbase_witness_commitment(transactions, nonce)
    return TxOut(0, _COMMITMENT_PREFIX + commitment)


@dataclass
class Block:
    """A block: its header and the transactions the header commits to.

    assert_valid is Core's CheckBlock -- what the bytes answer for
    themselves, proof-of-work included; the rules that need a height
    or a clock are assert_valid_contextual, taking a BlockContext.
    """

    header: BlockHeader
    transactions: list[Tx]

    def _serialized_size(self, include_witness: bool) -> int:
        """Return what serialize writes, without writing it.

        `Tx._serialized_size` says why the sizes are summed rather than
        measured on the bytes; a block is where it matters, being what
        `assert_valid` bounds three times over -- once for the length
        and twice for the weight -- each of which built a copy of the
        whole block to take its length.
        """
        return (
            self.header._serialized_size()
            + var_int._size(len(self.transactions))
            + sum(t._serialized_size(include_witness) for t in self.transactions)
        )

    @property
    def size(self) -> int:
        """Return the serialized size, witnesses included."""
        return self._serialized_size(include_witness=True)

    @property
    def stripped_size(self) -> int:
        """Return the size of the block as a legacy node sees it.

        Core's `GetSerializeSize(TX_NO_WITNESS(block))`, and the quantity
        `assert_valid_length` bounds: the whole block with every witness
        left out, which is the serialization the witness discount is
        expressed against and what `getblock` reports under this name.
        """
        return self._serialized_size(include_witness=False)

    @property
    def weight(self) -> int:
        """Return the block weight, as Core's GetBlockWeight computes it.

        Three times the stripped size plus the size, i.e. four times what
        a legacy node relays plus the witness bytes, over the *block*: the
        eighty bytes of the header and the var_int of the transaction
        count are part of it, so this is not the sum of the transactions'
        weights -- 332 more than that sum for block 481,824, 324 for a
        block holding one transaction. The sum is the number no rule
        reads; `MAX_BLOCK_WEIGHT` bounds this one.
        """
        return self.stripped_size * (WITNESS_SCALE_FACTOR - 1) + self.size

    @property
    def vsize(self) -> int:
        """Return the virtual size, the weight over four rounded up."""
        return ceil(self.weight / 4)

    @property
    def sig_op_count(self) -> int:
        """Return the legacy sigop count, summed over the transactions.

        What `CheckBlock` sums to enforce `MAX_BLOCK_SIGOPS_COST`; see
        `script.sig_ops.sig_op_count` for what "legacy" leaves out and
        why nothing here can add it.
        """
        return sum(t.sig_op_count for t in self.transactions)

    @property
    def height(self) -> int | None:
        """Return the height committed into a BIP34 coinbase script_sig.

        Version 2 blocks commit block height into the coinbase
        script_sig.

        https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
        Block 227,835 (2013-03-24 15
        :49: 13 GMT) was the last version 1 block.

        This is the reader and not the check: it decodes whatever the
        coinbase pushed, where consensus compares bytes.
        `assert_valid_coinbase_height` is the check.
        """
        self._assert_coinbase()

        if self.header.version == 1:
            return None

        # Height is "serialized CScript": first byte is number of bytes,
        # followed by the _signed_ little-endian representation of the height
        # (genesis block is height zero).
        coinbase_script = self.transactions[0].vin[0].script_sig
        height_ = var_bytes.parse(coinbase_script)
        return decode_num(height_)

    def __init__(
        self,
        header: BlockHeader,
        transactions: Sequence[Tx] | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        self.header = header

        # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
        self.transactions = list(transactions) if transactions else []

        if check_validity:
            self.assert_valid()

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
        """Return the block as a dict of json-friendly values.

        The header and each transaction as their own to_dict render
        them; from_dict reads the same shape back.
        """
        if check_validity:
            self.assert_valid()

        return {
            "header": self.header.to_dict(check_validity=False),
            "transactions": [
                tx.to_dict(check_validity=False) for tx in self.transactions
            ],
        }

    @classmethod
    def from_dict(
        cls: type[Block], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> Block:
        """Build a Block from the dict shape to_dict writes."""
        dict_ = fields_from_json_object(dict_, "block")
        return cls(
            BlockHeader.from_dict(dict_["header"], check_validity=False),
            [
                Tx.from_dict(tx, check_validity=False)
                for tx in list_from_json_array(
                    dict_["transactions"], "block transactions"
                )
            ],
            check_validity=check_validity,
        )

    @property
    def is_segwit(self) -> bool:
        """Answer whether any transaction carries a witness."""
        return any(tx.is_segwit for tx in self.transactions)

    def _assert_coinbase(self) -> None:
        """Assert that there is a first transaction and that it is a coinbase.

        Every block carries a coinbase, so an empty list is not a block
        that happens to be empty: it is not a block. Refused here, or
        transactions[0] answers it with an IndexError -- and a var_int of
        zero where the transaction count goes is all it takes to serialize
        one. Core asks the same two questions in one line, `bad-cb-missing`
        naming the pair.

        Called by everything that reads the coinbase, so that the reader
        and the rules report it in the same words.
        """
        if not self.transactions:
            raise BTClibValueError("block with no transactions")

        if not self.transactions[0].is_coinbase:
            raise BTClibValueError("first transaction is not a coinbase")

    def assert_valid_length(self) -> None:
        """Assert the size limits of Core's CheckBlock (bad-blk-length).

        Two comparisons against MAX_BLOCK_WEIGHT, and neither of them is
        the weight: the transaction count times WITNESS_SCALE_FACTOR --
        no transaction serializes to less than a byte, and a byte outside
        the witness weighs four, so a block holds at most a quarter of the
        cap in transactions -- and the stripped size times
        WITNESS_SCALE_FACTOR. The second is what real blocks sit against:
        3,954,076 of 4,000,000 for block 481,824, 98.9% of the cap. The
        weight itself is bounded by assert_valid_weight, where Core bounds
        it.

        The count is compared first, as in Core's single condition, and
        that is what keeps this cheap: a list too long to be a block is
        refused without serializing it.
        """
        count = len(self.transactions)
        if count * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
            err_msg = f"invalid transaction count: {count}"
            err_msg += f" * {WITNESS_SCALE_FACTOR} > {MAX_BLOCK_WEIGHT}"
            raise BTClibValueError(err_msg)

        stripped_size = self.stripped_size
        if stripped_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
            err_msg = f"invalid stripped size: {stripped_size}"
            err_msg += f" * {WITNESS_SCALE_FACTOR} > {MAX_BLOCK_WEIGHT}"
            raise BTClibValueError(err_msg)

    def assert_valid_sig_op_count(self) -> None:
        """Assert the sigop bound of Core's CheckBlock (bad-blk-sigops).

        The legacy count of every script in the block, times
        WITNESS_SCALE_FACTOR, against MAX_BLOCK_SIGOPS_COST -- i.e. 20,000
        legacy signature checks. It is the only sigop rule reachable from
        the bytes: what Core adds in ConnectBlock is counted over the
        outputs being spent, which are in other blocks.

        The largest answer this library has a block for is block 481,824's
        3,409, so a block that breaks this rule has to be built for the
        purpose. That is what makes the arithmetic the thing worth
        testing, and `script.sig_ops` is where it happens.
        """
        cost = self.sig_op_count * WITNESS_SCALE_FACTOR
        if cost > MAX_BLOCK_SIGOPS_COST:
            err_msg = f"invalid sigop cost: {cost} > {MAX_BLOCK_SIGOPS_COST}"
            raise BTClibValueError(err_msg)

    def assert_valid_weight(self) -> None:
        """Assert the weight bound of BIP141 (bad-blk-weight).

        Core asks this in ContextualCheckBlock and not in CheckBlock,
        though the weight is read off the bytes like everything else, and
        the reason is the order rather than the context: the coinbase
        witness is not covered by the block hash, so a block whose weight
        is over the cap only because that witness was stuffed must not be
        marked permanently invalid before the commitment to it has been
        checked. Hence the position here, right after
        assert_valid_witness_commitment, and hence the same rule twice at
        different strengths -- assert_valid_length bounds what a legacy
        node relays, this bounds the block segwit nodes see.
        """
        weight = self.weight
        if weight > MAX_BLOCK_WEIGHT:
            err_msg = f"invalid weight: {weight} > {MAX_BLOCK_WEIGHT}"
            raise BTClibValueError(err_msg)

    def assert_valid_merkle_root(self) -> None:
        """Refuse a header whose merkle root is not the transactions'.

        The CVE-2012-2459 mutation flag is refused too, as Core's
        bad-txns-duplicate; the comment below carries the reasoning.
        """
        merkle_root_, mutated = merkle_root_and_mutated_from_transactions(
            self.transactions
        )
        if merkle_root_ != self.header.merkle_root:
            err_msg = f"invalid merkle root: {self.header.merkle_root.hex()}"
            err_msg += f" instead of: {merkle_root_.hex()}"
            raise BTClibValueError(err_msg)
        if mutated:
            # CVE-2012-2459: two equal siblings mean a shorter transaction
            # list has this very same root, so the header does not commit
            # to the list at hand and the block hash can be kept while its
            # content changes. Core checks the same flag, right after
            # comparing the root, and rejects the block as
            # bad-txns-duplicate; the order is kept so that a block failing
            # both reports the same reason it does.
            raise BTClibValueError("duplicate transaction")

    @property
    def witness_commitment(self) -> bytes | None:
        """Return the BIP141 witness commitment, if the coinbase has one.

        It is the 32 bytes following the 6a24aa21a9ed prefix in the
        *last* coinbase output carrying it, as Core's
        GetWitnessCommitmentIndex does: were the first one to win, an
        output appended to the coinbase could not be told from one the
        miner meant, and the rule has to be the same one everybody else
        applies anyway.
        """
        commitments = [
            script[len(_COMMITMENT_PREFIX) : _COMMITMENT_LENGTH]
            for script in (
                out.script_pub_key.script for out in self.transactions[0].vout
            )
            if len(script) >= _COMMITMENT_LENGTH
            and script.startswith(_COMMITMENT_PREFIX)
        ]
        return commitments[-1] if commitments else None

    def assert_valid_witness_commitment(self) -> None:
        """Assert that the coinbase commits to the witness data (BIP141).

        The merkle root of the header is computed over txids, which by
        segwit's design leave every witness out: without this check the
        witnesses of a block can be replaced wholesale, header and root
        untouched, and the signatures they carry are worth nothing.
        """
        if not self.is_segwit:
            # Nothing to commit to, and nothing to check it against: this
            # is a block as a legacy node sees it, witnesses stripped by
            # the serialization, which btclib parses and this library
            # must keep accepting. Not a hole an attacker can climb into
            # by stripping the witnesses of a segwit block: strip some
            # and the check below runs on the rest, whose wtxids no
            # longer match; strip them all and there is no witness left
            # to be taken on trust.
            return

        commitment = self.witness_commitment
        if commitment is None:
            # Core's unexpected-witness: witness data in a block that
            # does not commit to it is unverifiable, hence not allowed.
            raise BTClibValueError("unexpected witness")

        # The other half of the commitment preimage, a 32-byte nonce the
        # miner chooses, lives in the coinbase witness. Core checks the
        # size (bad-witness-nonce-size) because a shorter one would make
        # the preimage ambiguous.
        witness_stack = self.transactions[0].vin[0].script_witness.stack
        if len(witness_stack) != 1 or len(witness_stack[0]) != 32:
            sizes = [len(element) for element in witness_stack]
            err_msg = f"invalid witness nonce: {sizes} stack element size(s)"
            err_msg += " instead of: [32]"
            raise BTClibValueError(err_msg)

        # coinbase_witness_commitment is the implementation, shared with
        # witness_commitment_output so that a block's builder and its
        # validator cannot disagree over what its transactions hash to
        witness_commitment_ = coinbase_witness_commitment(
            self.transactions, witness_stack[0]
        )
        if witness_commitment_ != commitment:
            err_msg = f"invalid witness commitment: {commitment.hex()}"
            err_msg += f" instead of: {witness_commitment_.hex()}"
            raise BTClibValueError(err_msg)

    def assert_valid_coinbase_height(self, height: int) -> None:
        """Assert that the coinbase commits to a height (BIP34, bad-cb-height).

        A byte comparison, as Core's is: the coinbase script_sig must
        *start with* `CScript() << nHeight`, so a height pushed any other
        way than the shortest is refused although it decodes to the right
        number. `Block.height` is the decoder, and comparing what it
        returns would accept a commitment no other node does --
        `bip34_commitment` is what the comparison is against.

        Which height, and whether BIP34 is in force at all, are the
        caller's to say: the second is `BlockContext.is_bip34_active`, and
        `assert_valid_contextual` is what applies it. Nothing is skipped
        here, so a caller that knows the rule binds can ask for it
        directly -- which is the only way to ask it of a block whose
        height is all that is known about its place in a chain.
        """
        self._assert_coinbase()

        expected = bip34_commitment(height)
        script_sig = self.transactions[0].vin[0].script_sig
        if not script_sig.startswith(expected):
            err_msg = f"invalid coinbase height: {script_sig[: len(expected)].hex()}"
            err_msg += f" instead of: {expected.hex()}"
            raise BTClibValueError(err_msg)

    def assert_valid_contextual(self, context: BlockContext) -> None:
        """Assert the rules a block cannot be checked against on its own.

        Bitcoin Core's ContextualCheckBlockHeader and
        ContextualCheckBlock, as far as a height and a clock reach:
        time-too-new, and bad-cb-height wherever BIP34 is in force. In
        that order, which is Core's -- the header is checked before the
        block it heads.

        Separate from assert_valid, which is CheckBlock: what the bytes
        answer for themselves, and therefore what Block.parse can ask.
        Both are asked of a block being accepted, and by whoever has the
        context; neither implies the other.

        The rest of those two functions needs the chain and not merely a
        context: time-too-old is the median time past of eleven ancestors,
        bad-diffbits is the target of a whole retarget period,
        bad-version the activation heights of BIP34, BIP66 and BIP65,
        bad-txns-nonfinal every transaction's lock time against the same
        median time past. Each is a field of BlockContext away, once the
        chain state it reads is there to put in one.
        """
        # the context is an object a caller builds, and `now` reaches
        # datetime arithmetic below: unasked, a str for it raised
        # AttributeError, which is no ValueError and flies past the handler
        # the contract asks for
        context.assert_valid()

        self.header.assert_valid_time(context.now)

        if context.is_bip34_active:
            self.assert_valid_coinbase_height(context.height)

    def assert_valid_structure(self) -> None:
        """Refuse what Core's CheckBlock refuses, proof-of-work excepted.

        The size bounds, exactly one coinbase and it first, every
        transaction on its own, the sigop bound, the merkle root, the
        witness commitment, the weight -- everything `assert_valid` asks
        except `BlockHeader.assert_valid` and `assert_valid_pow`, which
        it calls immediately before this and which a pre-mining candidate
        cannot pass. `block.build.build_block` is the other caller: a
        header `mining.candidate_block_header` has already validated
        structurally, over a block that has no proof-of-work yet and
        cannot be asked for one, and everything below still has to hold
        of it -- the two coinbases, the over-weight block and the
        over-the-sigop-bound block this refuses are exactly what a
        builder must not hand back silently.
        """
        # Core's bad-blk-length is three questions in one condition -- an
        # empty transaction list, too many transactions, too many bytes --
        # and the first of them is answered by _assert_coinbase below: a
        # block with no transactions has no coinbase, so refusing it in
        # the size rule as well would be one refusal in two voices
        self.assert_valid_length()

        self._assert_coinbase()
        self.transactions[0].assert_valid()

        for transaction in self.transactions[1:]:
            # Bitcoin Core's bad-cb-multiple, asked immediately after the
            # same first-transaction question: a coinbase is a claim on
            # the subsidy, so a second one is a second claim, and it is
            # the *shape* of the block that is wrong rather than anything
            # about that transaction on its own -- which is all
            # assert_valid below can see.
            # Unreachable from a serialized block, and added anyway: the
            # proof-of-work checked above already refuses one from the
            # wire, and a coinbase cannot be added to a real block
            # without moving the merkle root the header commits to, so no
            # well-formed vector can carry two. What has no work yet is a
            # block being assembled -- the toy mining of issue #188, and
            # any candidate-block path after it -- and that is exactly
            # where nothing else says no
            if transaction.is_coinbase:
                raise BTClibValueError("more than one coinbase")
            transaction.assert_valid()

        # last of CheckBlock's own questions, where Core asks it too:
        # after every transaction has been checked on its own, the block
        # is asked what they add up to
        self.assert_valid_sig_op_count()

        self.assert_valid_merkle_root()
        self.assert_valid_witness_commitment()
        # after the commitment, and the docstring says why
        self.assert_valid_weight()

    def assert_valid(self, pow_limit_bits: Octets = MAINNET_POW_LIMIT_BITS) -> None:
        """Refuse what Core's CheckBlock refuses, in Core's order.

        The header and its proof-of-work, the size bounds, exactly one
        coinbase and it first, every transaction on its own, the sigop
        bound, the merkle root, the witness commitment, the weight.
        Height and clock rules are assert_valid_contextual's.

        `pow_limit_bits` is forwarded to assert_valid_pow, whose docstring
        says why the network's easiest target is the caller's to state and
        why mainnet's is the default. It is a parameter here and not of
        __init__, parse or serialize: those three call this to answer
        whether the bytes are a block, and a block of another network is
        built with check_validity=False and then asked, which is the same
        two steps a caller already takes to build a header being mined.
        """
        self.header.assert_valid()
        # the header alone does not assert this: a header being mined is
        # structurally valid and has no proof-of-work yet, so requiring one
        # left no way to build a candidate. A Block is not a candidate --
        # it carries the transactions the work commits to -- and Bitcoin
        # Core draws the line in the same place, CheckBlock calling
        # CheckProofOfWork with fCheckPOW defaulted to true.
        # It is also what makes the vendored block_*.bin files verify
        # themselves: Block.parse recomputes the hash from the bytes
        self.header.assert_valid_pow(pow_limit_bits)

        # assert_valid_structure is every other rule CheckBlock asks, in
        # its own order -- one implementation, so assert_valid and a
        # builder that cannot yet ask for proof-of-work cannot disagree
        # about what else a block owes
        self.assert_valid_structure()

    def serialize(
        self, include_witness: bool = True, *, check_validity: bool = True
    ) -> bytes:
        """Return the wire serialization: header, count, transactions.

        `include_witness` False gives the block as a legacy node
        relays it, every witness stripped -- a bool and nothing else,
        for the reason `Tx.serialize` states.
        """
        assert_type(include_witness, bool, "include_witness")

        if check_validity:
            self.assert_valid()

        out = self.header.serialize(check_validity=check_validity)
        out += var_int.serialize(len(self.transactions))
        return out + b"".join(
            [
                t.serialize(include_witness, check_validity=check_validity)
                for t in self.transactions
            ]
        )

    @classmethod
    def parse(
        cls: type[Block], data: BinaryData, *, check_validity: bool = True
    ) -> Block:
        """Return a Block by parsing binary data."""
        stream = bytesio_from_binarydata(data)
        header = BlockHeader.parse(stream, check_validity=check_validity)
        # bounded by what this block could hold rather than by var_int's
        # own MAX_SIZE, which would let nine octets ask for 33 million
        # transactions before a byte of the first one is read (issue #569).
        # MIN_SERIALIZABLE_TRANSACTION_WEIGHT and not the
        # MIN_TRANSACTION_WEIGHT beside it: what is being allocated for is
        # a transaction that deserializes, which is Core's own distinction
        # between the two names
        n = var_int.parse(
            stream, MAX_BLOCK_WEIGHT // MIN_SERIALIZABLE_TRANSACTION_WEIGHT
        )
        transactions = [
            Tx.parse(stream, check_validity=check_validity) for _ in range(n)
        ]
        assert_no_trailing(data, stream, "block")

        return cls(header, transactions, check_validity=check_validity)
