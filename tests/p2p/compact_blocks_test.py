# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib.p2p.compact_blocks`, the one module here with an algorithm.

Every other payload type of this package is a codec, and a round trip is
most of what there is to say about one. BIP152 is not: a short id is a
keyed hash of a wtxid under a key derived from the header and the nonce,
and an index is written as the difference from the one before it, so an
encoder and a decoder of this library can agree with each other and with
no peer at all. What is driven here is therefore in two halves.

**The derivation is checked against something that is not this library.**
The vectors are block 481,824 -- the first segwit block, already in the
tree under tests/block/_data and authenticated by its own proof of work,
which is what issue #1101 and issue #1103 leaned on -- and the short ids
and the key below were computed with Bitcoin Core's own
test/functional/test_framework/crypto/siphash.py, a second implementation
of SipHash-2-4 and not `btclib.hashes.siphash` under another name. So a
short id keyed on a txid, or on a hash the wrong way round, or under a
digest of the header without the nonce, fails here rather than
round-tripping.

**The wire form has weaker authority, and saying so is better than
dressing it up.** BIP152 publishes field tables and no test vectors, and
Core's `blockencodings_tests.cpp` builds its messages with Core's own
serializer rather than reading captured octets, so there is no
third-party byte string for a `cmpctblock` the way there is a block. What
stands behind the layout here is BIP152's tables, Core's
src/blockencodings.h, and its test framework's `P2PHeaderAndShortIDs`;
what stands behind the *differential encoding* is stronger than that,
because the vectors below spell out the octets of an index vector whose
absolute indexes are known, and a decoder that skips the difference reads
them as different indexes rather than failing.

**The reconstruction is driven over the same real block**, both when the
pool holds everything and when it comes up short, and the round trip
through `getblocktxn` and `blocktxn` ends in a block that serializes back
to the file it came from -- which is the property no self-consistent
round trip can fake.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from btclib.block import Block, BlockHeader
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p import (
    CMPCTBLOCKS_VERSION,
    BlockTxn,
    CmpctBlock,
    GetBlockTxn,
    PartialBlock,
    PrefilledTransaction,
    SendCmpct,
    compact_blocks,
    reconstruct,
)
from btclib.p2p.limits import MAX_BLOCK_TX_INDEX
from btclib.tx import OutPoint, Tx, TxIn, TxOut

_DATA = Path(__file__).parent.parent / "block" / "_data"

# block 481,824, the first block segwit was active in: a mainnet block
# whose header is authenticated by its own proof of work, and whose
# transactions carry witnesses, so that a wtxid is not a txid for most of
# them and a short id computed over the wrong one is a short id that
# differs
_BLOCK_481824 = (_DATA / "block_481824_complete.bin").read_bytes()
# the block after genesis, whose one transaction is a coinbase: what a
# case needs a valid header and a real transaction for and nothing else
_BLOCK_1 = Block.parse((_DATA / "block_1.bin").read_bytes())

# an arbitrary nonce, which is what a sender draws per block: BIP152's
# "Nodes SHOULD NOT use the same nonce across multiple different blocks"
_NONCE = 0x0123_4567_89AB_CDEF

# what Bitcoin Core's test/functional/test_framework/crypto/siphash.py
# answers for the block and the nonce above: the key is the first two
# little-endian 64-bit words of the single-SHA256 of the eighty octets of
# the header with the nonce appended, and each short id is that
# implementation's `siphash(k0, k1, wtxid)` with the two most significant
# octets dropped -- `calculate_shortid`, of that framework's messages.py.
#
# The transactions are picked for carrying a witness, which few of that
# block's do: a wtxid is a txid for a transaction that has none, and over
# one of those a short id keyed on the wrong hash is the right number
_KEY = (0xD38D_0220_3181_CC3D, 0xD86B_C578_36E4_DE25)
_SEGWIT_INDEXES = (12, 14, 22)
_SHORT_IDS = (0x541F_7307_BCCC, 0x2DBD_FF2F_FEDA, 0xFAC6_7E28_68DF)

_TX = Tx(1, 0, [TxIn(OutPoint(b"\x11" * 32, 0))], [TxOut(1000, b"\x51")])
_OTHER_TX = Tx(1, 0, [TxIn(OutPoint(b"\x22" * 32, 0))], [TxOut(2000, b"\x51")])


def _block_481824() -> Block:
    """Return the vendored block, parsed."""
    return Block.parse(_BLOCK_481824)


def _compact(block: Block, prefill: int = 1) -> CmpctBlock:
    """Return the compact form of a block, the first transactions prefilled.

    What Core's `CBlockHeaderAndShortTxIDs` constructor builds, with the
    number of prefilled transactions left open: it prefills the coinbase
    alone, and BIP152 allows "a select few which we expect a peer may be
    missing" beside it.
    """
    compact_block = CmpctBlock(block.header, _NONCE, [], [], check_validity=False)
    return CmpctBlock(
        block.header,
        _NONCE,
        [compact_block.short_id(tx.hash) for tx in block.transactions[prefill:]],
        [
            PrefilledTransaction(index, tx)
            for index, tx in enumerate(block.transactions[:prefill])
        ],
    )


def test_the_short_id_key_is_the_header_with_the_nonce_appended() -> None:
    """BIP152's step one, against a digest taken here rather than there.

    "single-SHA256 hashing the block header with the nonce appended (in
    little-endian)", and "the first two little-endian 64-bit integers
    from the above hash" -- Core's `FillShortTxIDSelector`, whose
    `shorttxidhash.GetUint64(0)` and `GetUint64(1)` are the two words.
    The recorded pair is what a second computation answers, and the lines
    below are what would still pass if the nonce were left out.
    """
    compact_block = _compact(_block_481824())
    assert compact_block.short_id_key == _KEY

    header = _block_481824().header.serialize()
    digest = hashlib.sha256(header + _NONCE.to_bytes(8, "little")).digest()
    assert compact_block.short_id_key == (
        int.from_bytes(digest[:8], "little"),
        int.from_bytes(digest[8:16], "little"),
    )

    # the nonce is in the preimage, so two senders of one block under two
    # nonces key their short ids differently: what BIP152 asks the nonce
    # for, and what a key derived from the header alone would not give
    header_only = CmpctBlock(_block_481824().header, 0, check_validity=False)
    assert header_only.short_id_key != _KEY


def test_a_short_id_is_the_wtxid_and_not_the_transaction_id() -> None:
    """The one mistake this format is written to invite.

    A short id over the txid is BIP152 version 1's and matches nothing a
    current peer sends; over the wtxid it is version 2's. The block is
    segwit, so the two hashes differ for the transactions below and the
    two answers differ with them -- against a version 1 block they would
    be equal, and this test would say nothing.
    """
    block = _block_481824()
    compact_block = _compact(block)

    wanted = tuple(block.transactions[index] for index in _SEGWIT_INDEXES)
    assert tuple(compact_block.short_id(tx.hash) for tx in wanted) == _SHORT_IDS

    # each of those is a segwit transaction, so the txid-keyed answer is
    # a different number: what a version 1 peer would have sent
    for tx, short_id in zip(wanted, _SHORT_IDS, strict=True):
        assert tx.hash != tx.id
        assert compact_block.short_id(tx.id) != short_id

    # and every short id is six octets, BIP152's step three
    for short_id in compact_block.short_ids:
        assert 0 <= short_id <= 0xFFFF_FFFF_FFFF

    # the vector is the block without the prefilled coinbase, in order
    assert len(compact_block.short_ids) == len(block.transactions) - 1
    assert compact_block.tx_count == len(block.transactions)


def test_the_short_id_is_taken_over_the_hash_the_wire_carries() -> None:
    """Display order in, internal order hashed, which is Core's way round.

    `GetShortID` hashes `wtxid.ToUint256()`, the thirty-two octets the
    hash serializes as; this package holds every hash the other way, so
    the reversal is `short_id`'s. Handing it the reversed hash is what a
    caller would get if the method did not reverse, and it answers
    something else.
    """
    block = _block_481824()
    compact_block = _compact(block)
    wtxid = block.transactions[_SEGWIT_INDEXES[0]].hash

    assert compact_block.short_id(wtxid) == _SHORT_IDS[0]
    assert compact_block.short_id(wtxid[::-1]) != _SHORT_IDS[0]
    # and hex is octets here as it is everywhere in this library
    assert compact_block.short_id(wtxid.hex()) == _SHORT_IDS[0]

    with pytest.raises(ValueError, match="invalid size"):
        compact_block.short_id(wtxid[:31])


def test_a_memoryview_wtxid_gives_the_same_short_id_as_bytes() -> None:
    """Reversing the buffer bytes_from_octets hands back must not strand it.

    A memoryview is returned unchanged, and `[::-1]` over one is a
    strided, non-contiguous view: `siphash`'s own call to
    `bytes_from_octets` used to refuse it, so a wtxid spelled as a
    memoryview raised where every other `Octets` spelling answers
    (issue #1429).
    """
    block = _block_481824()
    compact_block = _compact(block)
    wtxid = block.transactions[_SEGWIT_INDEXES[0]].hash

    assert compact_block.short_id(memoryview(wtxid)) == compact_block.short_id(wtxid)


def test_a_mainnet_block_survives_the_compact_round_trip() -> None:
    """Encode a real block, reconstruct it from a full pool, compare bytes.

    The pool is every transaction but the prefilled coinbase, which is
    what a node with the block already in its mempool holds. What comes
    back has to be the file, octet for octet: a short id derivation that
    agreed only with itself would still reconstruct here, which is why
    the vectors above are checked separately -- but a position taken from
    the wrong short id, or a prefilled index put back a place along,
    shows up in this comparison and nowhere else.
    """
    block = _block_481824()
    compact_block = _compact(block)

    assert CmpctBlock.parse(compact_block.serialize()) == compact_block
    # and it is worth what a compact block is for
    assert len(compact_block.serialize()) < len(_BLOCK_481824) // 50

    partial = reconstruct(compact_block, block.transactions[1:])
    assert partial.missing_indexes == []
    assert partial.fill().serialize(include_witness=True) == _BLOCK_481824


def test_what_the_pool_is_short_of_is_what_getblocktxn_asks_for() -> None:
    """The round trip BIP152 exists for, driven end to end.

    A pool missing three transactions leaves three indexes; the request
    is those indexes and nothing else; the answer is "exactly and only
    each transaction which is present in the appropriate block at the
    index specified in the getblocktxn indexes list, in the order
    requested"; and the block that comes out is the file again.
    """
    block = _block_481824()
    compact_block = _compact(block)
    absent = (7, 500, len(block.transactions) - 1)
    pool = [tx for index, tx in enumerate(block.transactions) if index not in absent]

    partial = reconstruct(compact_block, pool)
    assert partial.missing_indexes == list(absent)

    request = GetBlockTxn(block.header.hash, partial.missing_indexes)
    assert GetBlockTxn.parse(request.serialize()) == request

    answer = BlockTxn(
        request.block_hash, [block.transactions[index] for index in request.indexes]
    )
    assert BlockTxn.parse(answer.serialize()) == answer

    filled = partial.fill(answer.transactions)
    assert filled.serialize(include_witness=True) == _BLOCK_481824


def test_a_prefilled_transaction_can_be_more_than_the_coinbase() -> None:
    """BIP152's "a select few which we expect a peer may be missing".

    Which is where the differential encoding stops being the identity:
    with one prefilled transaction every index written is zero, and that
    is why an implementation that never takes the difference passes its
    own tests.
    """
    block = _block_481824()
    prefilled = (0, 3, 4, 900)
    keyed = CmpctBlock(block.header, _NONCE, check_validity=False)
    compact_block = CmpctBlock(
        block.header,
        _NONCE,
        [
            keyed.short_id(tx.hash)
            for index, tx in enumerate(block.transactions)
            if index not in prefilled
        ],
        [PrefilledTransaction(index, block.transactions[index]) for index in prefilled],
    )
    assert CmpctBlock.parse(compact_block.serialize()) == compact_block

    pool = [
        tx for index, tx in enumerate(block.transactions) if index not in (0, 3, 4, 900)
    ]
    partial = reconstruct(compact_block, pool)
    assert partial.missing_indexes == []
    assert partial.fill().serialize(include_witness=True) == _BLOCK_481824


def test_an_index_is_written_as_the_difference_from_the_one_before() -> None:
    """BIP152's differential encoding, spelled out in octets.

    "the number encoded is the difference between the current index and
    the previous index, minus one. For example, a first index of 0
    implies a real index of 0, a second index of 0 thereafter refers to a
    real index of 1". So absolute [0, 2, 5] is written 00 01 02, and an
    implementation that writes the indexes raw writes 00 02 05 -- which
    parses, as a different request.
    """
    request = GetBlockTxn(bytes(32), [0, 2, 5])
    assert request.serialize()[32:] == bytes.fromhex("03000102")
    assert GetBlockTxn.parse(request.serialize()).indexes == (0, 2, 5)

    # the example BIP152 gives in as many words
    consecutive = GetBlockTxn(bytes(32), [0, 1])
    assert consecutive.serialize()[32:] == bytes.fromhex("020000")

    # and the same encoding in front of a prefilled transaction, where
    # the difference is taken against the previous prefilled index
    assert PrefilledTransaction(0, _TX).serialize()[:1] == b"\x00"
    assert PrefilledTransaction(7, _TX).serialize()[:1] == b"\x07"
    assert PrefilledTransaction(7, _TX).serialize(6)[:1] == b"\x00"
    assert PrefilledTransaction(7, _TX).serialize(2)[:1] == b"\x04"

    assert PrefilledTransaction.parse(b"\x00" + _TX.serialize(True)).index == 0
    assert PrefilledTransaction.parse(b"\x00" + _TX.serialize(True), 0).index == 1
    assert PrefilledTransaction.parse(b"\x04" + _TX.serialize(True), 2).index == 7


def test_the_differences_of_a_cmpctblock_run_across_the_vector() -> None:
    """A prefilled vector's indexes are one running sum, not each its own."""
    compact_block = CmpctBlock(
        _BLOCK_1.header,
        0,
        [1, 2],
        [PrefilledTransaction(0, _TX), PrefilledTransaction(3, _OTHER_TX)],
    )
    octets = compact_block.serialize()
    # the header, the nonce, the count and the two short ids, then the
    # prefilled count and the first difference
    assert octets[80 + 8 : 80 + 8 + 1 + 12 + 1 + 1] == bytes.fromhex(
        "020100000000000200000000000200"
    )
    # the second difference is 3 - 0 - 1
    assert octets[80 + 8 + 1 + 12 + 1 + 1 + len(_TX.serialize(True))] == 2

    assert CmpctBlock.parse(octets) == compact_block
    assert [p.index for p in CmpctBlock.parse(octets).prefilled_txns] == [0, 3]


def test_the_indexes_a_differential_encoding_cannot_write_are_refused() -> None:
    """Unsigned differences, so an index must be past the one before it.

    Core's `DifferenceFormatter::Ser` throws "differential value
    overflow" on the same vector; here it is refused where a caller
    builds one, so that `serialize` is not the first to say so.
    """
    with pytest.raises(BTClibValueError, match="indexes out of order"):
        GetBlockTxn(bytes(32), [2, 2])
    with pytest.raises(BTClibValueError, match="indexes out of order"):
        GetBlockTxn(bytes(32), [3, 1])
    with pytest.raises(BTClibValueError, match="prefilled out of order"):
        CmpctBlock(
            _BLOCK_1.header,
            0,
            [],
            [PrefilledTransaction(1, _TX), PrefilledTransaction(1, _OTHER_TX)],
        )

    # and a single one written against a previous index it does not follow
    with pytest.raises(BTClibValueError, match="not past previous_index"):
        PrefilledTransaction(1, _TX).serialize(1)


def test_a_prefilled_index_must_name_a_position_of_the_block() -> None:
    """Core's `InitData` check, asked of the last index alone.

    Two short ids and a prefilled transaction are a block of three, so
    index three is a position no transaction occupies -- and a
    `cmpctblock` naming one could not be reconstructed whatever the pool
    held.
    """
    with pytest.raises(BTClibValueError, match="prefilled index past the block"):
        CmpctBlock(_BLOCK_1.header, 0, [1, 2], [PrefilledTransaction(3, _TX)])

    # the same vector one position down is a block of three
    compact_block = CmpctBlock(
        _BLOCK_1.header, 0, [1, 2], [PrefilledTransaction(2, _TX)]
    )
    assert compact_block.tx_count == 3
    assert reconstruct(compact_block).missing_indexes == [0, 1]


def test_a_sendcmpct_is_an_octet_and_a_version() -> None:
    """Core's `msg_sendcmpct`, and BIP152's "MUST have a value of 1 or 0"."""
    assert SendCmpct().version == CMPCTBLOCKS_VERSION
    assert SendCmpct(announce=True, version=2).serialize() == bytes.fromhex(
        "010200000000000000"
    )
    assert SendCmpct(announce=False, version=1).serialize() == bytes.fromhex(
        "000100000000000000"
    )

    for announce in (True, False):
        for version in (0, 1, 2, 0xFFFF_FFFF_FFFF_FFFF):
            payload = SendCmpct(announce=announce, version=version)
            assert SendCmpct.parse(payload.serialize()) == payload

    # BIP152 says the octet is a boolean, so a peer's 0x02 is refused
    # rather than read as the True that would have it push every block
    with pytest.raises(BTClibValueError, match="invalid announce octet"):
        SendCmpct.parse(bytes.fromhex("020200000000000000"))


def test_a_version_this_library_does_not_speak_still_reads_and_writes() -> None:
    """Which is what the field is for: negotiation names what is on offer.

    `btclib.p2p.compact_blocks` implements version 2's encoding alone, and
    a `sendcmpct` is how a peer says it would rather have another -- so
    the message has to survive a version this library will not answer in.
    """
    for version in (1, 3, 70016):
        payload = SendCmpct(announce=True, version=version)
        assert SendCmpct.parse(payload.serialize()).version == version


def test_reconstruction_refuses_a_block_of_no_transactions() -> None:
    """Core's `InitData` refusal: there is no block without a coinbase."""
    empty = CmpctBlock(_BLOCK_1.header, 0)
    assert empty.tx_count == 0
    assert CmpctBlock.parse(empty.serialize()) == empty

    with pytest.raises(BTClibValueError, match="a compact block of no transactions"):
        reconstruct(empty)


def test_a_cmpctblock_whose_short_ids_collide_is_read_and_not_rebuilt() -> None:
    """The two halves of BIP152's answer to a collision, which differ.

    Nodes "MUST NOT be penalized for such collisions", so the message
    parses and serializes back; and two positions wanting one transaction
    is a block that cannot be put together, so the reconstruction refuses
    it and the block is asked for the ordinary way. Core answers
    `READ_STATUS_FAILED` at exactly this point, with "Short ID collision"
    beside it.
    """
    colliding = CmpctBlock(
        _BLOCK_1.header, 0, [7, 7], [PrefilledTransaction(0, _BLOCK_1.transactions[0])]
    )
    assert CmpctBlock.parse(colliding.serialize()) == colliding

    with pytest.raises(BTClibValueError, match="short ids are not unique"):
        reconstruct(colliding, [_TX])


def test_two_pool_transactions_of_one_short_id_leave_the_position_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other collision, and the one a first-match reconstructor gets wrong.

    Where two *different* transactions of the pool answer one short id,
    which of them the block holds is not decidable and the index is asked
    for instead -- Core drops both and says why, "eating a round-trip due
    to FillBlock failure would be annoying". Taking the first is the bug
    this case exists to refuse, and it is a bug no round trip can see: the
    encoder never produces a collision, so only a pool that does reaches
    the branch.

    Forty-eight bits are what makes a real one unreachable from a test --
    the birthday bound is sixteen million transactions and this suite
    holds a few -- so the derivation is replaced for the length of this
    test and the bookkeeping over it is what is driven. The derivation
    itself is what the vectors above are for.

    What is replaced is `compact_blocks._short_id` and not
    `CmpctBlock.short_id`: `reconstruct` derives the key once for the
    whole pool and asks the module function of each transaction, which is
    the shape that keeps a mempool from costing one SHA-256 of the header
    per transaction in it.
    """
    monkeypatch.setattr(compact_blocks, "_short_id", lambda key, wtxid: 7)

    compact_block = CmpctBlock(
        _BLOCK_1.header, 0, [7], [PrefilledTransaction(0, _BLOCK_1.transactions[0])]
    )

    # one candidate fills the position
    assert reconstruct(compact_block, [_TX]).missing_indexes == []
    # the same transaction twice is not a collision, the wtxid being one
    assert reconstruct(compact_block, [_TX, _TX]).missing_indexes == []
    # two different ones are, and the position goes back to missing
    assert reconstruct(compact_block, [_TX, _OTHER_TX]).missing_indexes == [1]
    # and it stays missing however many more arrive, including one that
    # would have matched on its own
    assert reconstruct(compact_block, [_TX, _OTHER_TX, _TX]).missing_indexes == [1]


def test_a_pool_transaction_no_short_id_names_is_passed_over() -> None:
    """A mempool is not a block: most of it is not being asked for."""
    block = _block_481824()
    compact_block = _compact(block)

    partial = reconstruct(compact_block, [*block.transactions[1:], _TX, _OTHER_TX])
    assert partial.missing_indexes == []
    assert partial.fill().serialize(include_witness=True) == _BLOCK_481824


def test_fill_wants_exactly_the_transactions_that_were_missing() -> None:
    """Core's `FillBlock`, which refuses on both sides of its loop."""
    block = _block_481824()
    partial = reconstruct(_compact(block), block.transactions[1:-2])
    assert partial.missing_indexes == [
        len(block.transactions) - 2,
        len(block.transactions) - 1,
    ]

    with pytest.raises(BTClibValueError, match="invalid transactions count"):
        partial.fill()
    with pytest.raises(BTClibValueError, match="invalid transactions count"):
        partial.fill(block.transactions[-1:])
    with pytest.raises(BTClibValueError, match="invalid transactions count"):
        partial.fill(block.transactions[-3:])

    assert partial.fill(block.transactions[-2:]).serialize(True) == _BLOCK_481824


def test_a_wrong_transaction_is_caught_by_the_merkle_root() -> None:
    """What `fill` does not check, and where it shows instead.

    A short id that survived the pool and named the wrong transaction is
    a block whose header does not commit to what is in it, and
    `Block.assert_valid` recomputes the root that says so. Core reaches
    for the same answer at the end of `FillBlock`, calling `IsBlockMutated`
    and calling what it catches "Possible Short ID collision".
    """
    block = _block_481824()
    partial = reconstruct(_compact(block), block.transactions[1:-1])
    assert partial.missing_indexes == [len(block.transactions) - 1]

    wrong = partial.fill([block.transactions[1]], check_validity=False)
    assert wrong.serialize(include_witness=True, check_validity=False) != _BLOCK_481824
    with pytest.raises(BTClibValueError, match="merkle root"):
        wrong.assert_valid()


def test_a_partial_block_says_what_is_still_wanted_in_order() -> None:
    """`missing_indexes` is a request, so its order is the answer's order."""
    partial = PartialBlock(_BLOCK_1.header, [_TX, None, _OTHER_TX, None])
    assert partial.missing_indexes == [1, 3]
    filled = partial.fill([_OTHER_TX, _TX], check_validity=False)
    assert filled.transactions == [_TX, _OTHER_TX, _OTHER_TX, _TX]


def test_a_count_no_block_can_have_that_many_transactions_of_is_refused() -> None:
    """Core's "indexes overflowed 16 bits", which is `MAX_BLOCK_TX_INDEX`."""
    too_many = MAX_BLOCK_TX_INDEX + 1

    with pytest.raises(BTClibValueError, match="invalid transaction count"):
        CmpctBlock(_BLOCK_1.header, 0, [0] * too_many)
    with pytest.raises(BTClibValueError, match="invalid transaction count"):
        CmpctBlock(
            _BLOCK_1.header,
            0,
            [0] * MAX_BLOCK_TX_INDEX,
            [PrefilledTransaction(0, _TX)],
        )
    with pytest.raises(BTClibValueError, match="invalid indexes count"):
        GetBlockTxn(bytes(32), range(too_many))
    with pytest.raises(BTClibValueError, match="invalid transactions count"):
        BlockTxn(bytes(32), [_TX] * too_many)

    # and the same bound on an index rather than on a count, which is the
    # one number Core spells at both checks
    with pytest.raises(BTClibValueError, match="invalid index"):
        PrefilledTransaction(too_many, _TX)


def test_a_count_is_bounded_before_the_loop_that_allocates_on_it() -> None:
    """Read off the octets, where btclib's var_int would allow 33,554,432."""
    header_and_nonce = _BLOCK_1.header.serialize() + bytes(8)
    # a CompactSize of 65,536 in front of a vector of six-octet short ids
    with pytest.raises(BTClibValueError, match="var_int too big"):
        CmpctBlock.parse(header_and_nonce + b"\xfe\x00\x00\x01\x00")
    with pytest.raises(BTClibValueError, match="var_int too big"):
        CmpctBlock.parse(header_and_nonce + b"\x00" + b"\xfe\x00\x00\x01\x00")
    with pytest.raises(BTClibValueError, match="var_int too big"):
        GetBlockTxn.parse(bytes(32) + b"\xfe\x00\x00\x01\x00")
    with pytest.raises(BTClibValueError, match="var_int too big"):
        BlockTxn.parse(bytes(32) + b"\xfe\x00\x00\x01\x00")

    # and a difference the running index cannot take, which is the same
    # bound one field along
    with pytest.raises(BTClibValueError, match="var_int too big"):
        GetBlockTxn.parse(bytes(32) + b"\x01" + b"\xfe\x00\x00\x01\x00")
    with pytest.raises(BTClibValueError, match="invalid index"):
        GetBlockTxn.parse(
            bytes(32) + b"\x02" + b"\xfd\xff\xff" + b"\x00", check_validity=False
        )
    with pytest.raises(BTClibValueError, match="invalid index"):
        PrefilledTransaction.parse(
            b"\xfd\xff\xff" + _TX.serialize(True), 1, check_validity=False
        )


def test_the_previous_index_a_difference_is_taken_against() -> None:
    """One below zero stands in front of a first entry, and is the least."""
    assert (
        PrefilledTransaction(0, _TX).serialize(-1)
        == PrefilledTransaction(0, _TX).serialize()
    )

    for wrong in (-2, MAX_BLOCK_TX_INDEX + 1):
        with pytest.raises(BTClibValueError, match="invalid previous_index"):
            PrefilledTransaction(0, _TX).serialize(wrong)
        with pytest.raises(BTClibValueError, match="invalid previous_index"):
            PrefilledTransaction.parse(b"\x00" + _TX.serialize(True), wrong)

    with pytest.raises(BTClibTypeError, match="invalid previous_index type"):
        PrefilledTransaction(0, _TX).serialize(True)
    with pytest.raises(BTClibTypeError, match="invalid previous_index type"):
        PrefilledTransaction.parse(b"\x00" + _TX.serialize(True), "0")  # type: ignore[arg-type]


def test_a_field_no_octets_could_hold_is_refused() -> None:
    """The type and range checks, one per field."""
    with pytest.raises(BTClibTypeError, match="invalid header type"):
        CmpctBlock("not a header")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid nonce type"):
        CmpctBlock(_BLOCK_1.header, True)
    with pytest.raises(BTClibValueError, match="invalid nonce"):
        CmpctBlock(_BLOCK_1.header, 1 << 64)
    with pytest.raises(BTClibTypeError, match="invalid short id type"):
        CmpctBlock(_BLOCK_1.header, 0, [True])
    with pytest.raises(BTClibValueError, match="invalid short id"):
        CmpctBlock(_BLOCK_1.header, 0, [1 << 48])
    with pytest.raises(BTClibTypeError, match="invalid prefilled transaction type"):
        CmpctBlock(_BLOCK_1.header, 0, [], [_TX])  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError, match="invalid short_ids type"):
        CmpctBlock(_BLOCK_1.header, 0, "ab")  # type: ignore[arg-type]

    with pytest.raises(BTClibTypeError, match="invalid index type"):
        PrefilledTransaction(True, _TX)
    with pytest.raises(BTClibValueError, match="invalid index"):
        PrefilledTransaction(-1, _TX)
    with pytest.raises(BTClibTypeError, match="invalid tx type"):
        PrefilledTransaction(0, "not a transaction")  # type: ignore[arg-type]

    with pytest.raises(BTClibValueError, match="invalid block_hash length"):
        GetBlockTxn(bytes(31))
    with pytest.raises(BTClibTypeError, match="invalid index type"):
        GetBlockTxn(bytes(32), [True])
    with pytest.raises(BTClibValueError, match="invalid block_hash length"):
        BlockTxn(bytes(31))
    with pytest.raises(BTClibTypeError, match="invalid transaction type"):
        BlockTxn(bytes(32), ["not a transaction"])  # type: ignore[list-item]

    with pytest.raises(BTClibTypeError, match="invalid announce type"):
        SendCmpct(1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid version type"):
        SendCmpct(announce=True, version=True)
    with pytest.raises(BTClibValueError, match="invalid version"):
        SendCmpct(announce=True, version=1 << 64)

    with pytest.raises(BTClibTypeError, match="invalid header type"):
        PartialBlock("not a header")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid transaction type"):
        PartialBlock(_BLOCK_1.header, ["not a transaction"])  # type: ignore[list-item]


def test_reconstruct_says_what_it_was_handed_rather_than_reading_a_field() -> None:
    """A free function taking a built object checks it, `psbt`'s does too.

    CONTRIBUTING.md's "Every public function validates its inputs": what
    a caller of this library catches is `BTClibTypeError` and
    `BTClibValueError`, so "not a compact block at all" must not arrive
    as an `AttributeError` about `tx_count`.
    `tests/built_object_contract_test.py` is the gate over the family and
    drives the two arguments whole; what is driven here is the entry of
    the pool, which that table replaces as a unit.
    """
    compact_block = CmpctBlock(
        _BLOCK_1.header, 0, [1], [PrefilledTransaction(0, _BLOCK_1.transactions[0])]
    )

    with pytest.raises(BTClibTypeError, match="invalid compact_block type"):
        reconstruct("not a compact block")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid pool type"):
        reconstruct(compact_block, "ab")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid pool transaction type"):
        reconstruct(compact_block, ["not a transaction"])  # type: ignore[list-item]

    # the header is read for the short id key, so it is asked too
    with pytest.raises(BTClibTypeError, match="invalid header type"):
        reconstruct(CmpctBlock("not a header", 0, [1], check_validity=False))  # type: ignore[arg-type]

    # a pool entry is asked its type and not its validity: what
    # `reconstruct` reads of one is its wtxid, and a mempool re-validated
    # once per compact block is every transaction of it checked again --
    # which is also why the `PartialBlock` is built with the flag
    # cleared, an invalid transaction reaching a position going on being
    # the caller's own until `fill` puts it in a `Block`
    unchecked = Tx(1, 0, [], [], check_validity=False)
    assert reconstruct(compact_block, [unchecked]).missing_indexes == [1]

    invalid_prefill = CmpctBlock(
        _BLOCK_1.header,
        0,
        [],
        [PrefilledTransaction(0, unchecked, check_validity=False)],
        check_validity=False,
    )
    assert reconstruct(invalid_prefill).transactions == (unchecked,)

    # and `fill` asks the same of what it is handed, whatever the flag
    partial = reconstruct(compact_block)
    with pytest.raises(BTClibTypeError, match="invalid transaction type"):
        partial.fill(["not a transaction"], check_validity=False)  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError, match="invalid transactions type"):
        partial.fill("a", check_validity=False)  # type: ignore[arg-type]


def test_a_payload_carries_the_command_bitcoin_core_spells() -> None:
    """The four names, which btclib_node misspells two of (its issue #12)."""
    assert SendCmpct.command == "sendcmpct"
    assert CmpctBlock.command == "cmpctblock"
    assert GetBlockTxn.command == "getblocktxn"
    assert BlockTxn.command == "blocktxn"


def test_trailing_octets_are_not_a_second_record() -> None:
    """One payload is one object, so what follows it is malleability."""
    block = _block_481824()
    for payload in (
        SendCmpct(announce=True),
        _compact(block),
        GetBlockTxn(block.header.hash, [0, 2]),
        BlockTxn(block.header.hash, [block.transactions[1]]),
    ):
        octets = payload.serialize()
        assert type(payload).parse(octets) == payload
        with pytest.raises(BTClibValueError, match="bytes after the"):
            type(payload).parse(octets + b"\x00")

    prefilled = PrefilledTransaction(0, _TX)
    with pytest.raises(BTClibValueError, match="bytes after the"):
        PrefilledTransaction.parse(prefilled.serialize() + b"\x00")


def test_check_validity_reaches_the_fields_and_can_be_turned_off() -> None:
    """What every wire class of this library promises about the flag."""
    block = _block_481824()
    compact_block = _compact(block)
    assert compact_block.serialize(check_validity=False) == compact_block.serialize()

    # a compact block of a header that is not one is built and not asked
    unchecked = CmpctBlock("not a header", 0, check_validity=False)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid header type"):
        unchecked.assert_valid()

    unchecked_prefilled = PrefilledTransaction(-1, _TX, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid index"):
        unchecked_prefilled.assert_valid()

    unchecked_request = GetBlockTxn(bytes(31), check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid block_hash length"):
        unchecked_request.assert_valid()

    unchecked_answer = BlockTxn(bytes(31), check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid block_hash length"):
        unchecked_answer.assert_valid()

    unchecked_send = SendCmpct(1, check_validity=False)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid announce type"):
        unchecked_send.assert_valid()

    unchecked_partial = PartialBlock(_BLOCK_1.header, [_TX], check_validity=False)
    unchecked_partial.assert_valid()


def test_a_getblocktxn_of_no_indexes_is_a_message_and_not_an_error() -> None:
    """Core disconnects the peer that sends one; that is a rule about a peer.

    "No legitimate reason to send indexes empty", says `ProcessMessage`
    just before setting `fDisconnect` -- and a codec that refused the
    octets would refuse a message this library has to be able to write in
    order to test the one that reads it.
    """
    empty = GetBlockTxn(bytes(32))
    assert GetBlockTxn.parse(empty.serialize()) == empty
    assert empty.serialize() == bytes(32) + b"\x00"

    no_transactions = BlockTxn(bytes(32))
    assert BlockTxn.parse(no_transactions.serialize()) == no_transactions


def test_the_header_a_cmpctblock_carries_is_the_blocks_own() -> None:
    """Eighty octets, and the hash a `getblocktxn` names the block by."""
    block = _block_481824()
    compact_block = _compact(block)

    assert compact_block.serialize()[:80] == _BLOCK_481824[:80]
    assert compact_block.header.hash == block.header.hash
    assert BlockHeader.parse(compact_block.serialize()[:80]) == block.header
