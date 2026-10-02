# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Electrum server protocol: newline-delimited JSON-RPC, no socket.

Not to be confused with `btclib_wallet.mnemonic.electrum`, Electrum's seed
scheme: this module is the wire protocol an Electrum *server* speaks,
unrelated beyond sharing the project's name.

Beside `btclib.p2p`, on the same pattern and for the same reason
`btclib.p2p`'s own docstring states: `btclib_wallet.fetch.electrum` is
the one place that goes and asks a server anything, and this module is
what turns a question into a request line and a line into an answer,
opening nothing. So a module that only ever *serves* this protocol -- an
electrs-shaped index over its own chainstate, should one ever exist --
imports this and not `urllib`, `ssl` or `socket`. `btclib_wallet`
depends on `btclib` and not the reverse, so nothing here imports the
fetchers.

**Framing.** `encode_request` writes one JSON-RPC request, an id and a
newline the server splits messages on; `decode_response` reads one reply
line back, matched to the id of the request it answers, and refuses a
line that is not a well-formed answer to it -- not JSON, not an object,
answering the wrong id, or carrying neither a `result` nor an `error`.
Protocol-basics.rst encourages JSON-RPC 2.0 without requiring it, so no
`jsonrpc` member is sent and both an object `error` and a bare one are
read back, which is the one place this module still meets the elder
convention.

**Five methods, the ones a fetcher over this protocol needs.**
`blockchain.transaction.get` for a raw transaction,
`blockchain.headers.subscribe` for the chain tip's height and header,
`blockchain.block.header` for the header at a height,
`blockchain.transaction.get_merkle` for the branch and position that
proves a transaction confirmed, and `blockchain.estimatefee` for a fee
rate quoted for a confirmation target. Each is a pair of functions, one
to build the request and one to read the matching response -- shapes,
not a client: nothing here keeps a connection, retries, or knows which
request line answers which of several outstanding ones, since a codec
with no socket cannot have more than one line outstanding.

**The merkle proof.** `assert_merkle_proof` and `verify_merkle_proof`
check what `transaction_get_merkle_response` returns against a
`BlockHeader` the caller already holds, and are what
`btclib_wallet.fetch.Fetcher`'s own class docstring means by "returns
evidence beside the data": the branch and position are not evidence until
they are checked against a root, and that check is
`btclib.block.merkle_proof.assert_as_valid`, unmodified -- this module
supplies the shapes either side of it and reimplements neither the
arithmetic nor CVE-2017-12842's hardening.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, NoReturn, cast

from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.block.merkle_proof import assert_as_valid
from btclib.block.merkle_proof import verify as verify_merkle_branch
from btclib.exceptions import BTClibTypeError, BTClibValueError, RpcError
from btclib.utils import _message_text, bytes_from_octets, is_integer

__all__ = [
    "HeaderTip",
    "MerkleProof",
    "assert_merkle_proof",
    "block_header_request",
    "block_header_response",
    "decode_response",
    "encode_request",
    "estimate_fee_request",
    "estimate_fee_response",
    "headers_subscribe_request",
    "headers_subscribe_response",
    "transaction_get_merkle_request",
    "transaction_get_merkle_response",
    "transaction_get_request",
    "transaction_get_response",
    "verify_merkle_proof",
]


def encode_request(request_id: int, method: str, params: Any = ()) -> bytes:
    """Return one JSON-RPC request line, newline-terminated.

    The newline is part of the wire shape and not a transport's to add:
    `LineTransport` (`btclib_wallet.fetch.transport`) takes and returns exactly
    one such line, so a caller building one by hand -- outside the
    per-method helpers below -- still gets the framing right.
    """
    request = {"id": request_id, "method": method, "params": list(params)}
    return json.dumps(request).encode("utf-8") + b"\n"


def _raise_rpc_error(error: object) -> NoReturn:
    """Raise a JSON-RPC `error` member as `RpcError`.

    Shared by the two sites `decode_response` reads one from: the
    ordinary case, an id matching the request, and the JSON-RPC 2.0 one,
    a reply whose `id` is `null` because the server could not parse the
    request enough to answer it at all.
    """
    if isinstance(error, dict):
        message = str(error.get("message", error))
        code = error.get("code", 0)
        raise RpcError(message, code if is_integer(code) else 0, error.get("data"))
    raise RpcError(str(error), 0)


def _refuse_constant(name: str) -> NoReturn:
    """Refuse `NaN`, `Infinity` and `-Infinity`, which RFC 8259 lacks."""
    raise BTClibValueError(f"not JSON: {name}")


# The deepest answer Electrum's own client reads, `server.peers.subscribe`,
# nests 4 levels, the reply object counted. `json.loads` kills the
# interpreter, where it should raise, from about 3000 levels in a thread
# with a 512 KiB stack (CPython 3.12 and 3.13).
_MAX_NESTING = 16

# A string, whatever it holds. `_too_deep` appends two quotes, so that a
# string left open still closes, this never fails and the scan stays linear.
_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
_NOT_BRACKET = re.compile(r"[^\[\]{}]+")


def _too_deep(text: str) -> bool:
    """Return True if `text` nests brackets deeper than `_MAX_NESTING`.

    A bracket inside a string does not count. The scan stops at the first
    excess.
    """
    depth = 0
    for bracket in _NOT_BRACKET.sub("", _STRING.sub("", text + '""')):
        if bracket in "[{":
            depth += 1
            if depth > _MAX_NESTING:
                return True
        else:
            depth -= 1
    return False


def decode_response(line: bytes, request_id: int) -> Any:
    """Return the `result` of one response line, matched to `request_id`.

    `line` is bytes, UTF-8 as Electrum sends it, decoded once so that the
    nesting check and the parser read the same text. A `str`, another
    encoding or another type is refused.

    Refuses a line that is not one: not JSON (`NaN` and `Infinity`
    included), nested more than 16 levels deep -- checked before
    `json.loads` runs, which can kill the interpreter on a deeper one --
    not an object, an id that is not this request's own integer id, or
    neither a `result` nor an `error` member. An `error` member is raised
    as `RpcError` rather than returned -- a JSON-RPC error object,
    `{"code", "message"}` and an optional `data`, every field this
    module's own caller in
    `btclib_wallet.fetch.electrum` asks for the way it asks a bitcoind
    JSON-RPC error's fields. A server that still answers the elder,
    non-object form of an error -- a bare string result under protocol
    1.0 -- is read the same way, with code 0: the protocol carries no
    code for that shape, and 0 is no code Core or Electrum ever assigns
    one of their own.

    A request the server could not parse enough to answer at all is
    answered under JSON-RPC 2.0 with `"id": null`, so a `null` id
    carrying an `error` member is read as that error before the id is
    checked against `request_id` -- a `null` id with no `error` member
    falls through to the ordinary mismatch below instead, `null` being
    an id no request of this module's own ever carries. An id equal to
    `request_id` under Python's `==` but not itself an integer --
    `true`, `1.0` -- does not match either: JSON's booleans and floats
    compare equal to the integers they neighbour, and this module
    already refuses a bool as a number of any other kind (`is_integer`).
    """
    if not isinstance(line, (bytes, bytearray)):
        raise BTClibValueError(f"not a JSON-RPC line: {line!r}")
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as e:
        raise BTClibValueError(f"not a JSON-RPC line: {line!r}") from e
    if _too_deep(text):
        raise BTClibValueError(f"not a JSON-RPC line: nested beyond {_MAX_NESTING}")
    try:
        reply: Any = json.loads(text, parse_constant=_refuse_constant)
    except (TypeError, ValueError, RecursionError) as e:
        raise BTClibValueError(f"not a JSON-RPC line: {line!r}") from e
    if not isinstance(reply, dict):
        raise BTClibTypeError(f"not a JSON-RPC response object: {reply!r}")
    reply_id = reply.get("id")
    error = reply.get("error")
    if reply_id is None and error is not None:
        _raise_rpc_error(error)
    if not (is_integer(reply_id) and reply_id == request_id):
        err_msg = f"response id {reply_id!r}"
        err_msg += f" does not answer request {_message_text(request_id)}"
        raise BTClibValueError(err_msg)
    if error is not None:
        _raise_rpc_error(error)
    if "result" not in reply:
        raise BTClibValueError(f"neither a result nor an error: {reply!r}")
    return reply["result"]


def transaction_get_request(request_id: int, tx_id: str) -> bytes:
    """Return the `blockchain.transaction.get` request for `tx_id`."""
    return encode_request(request_id, "blockchain.transaction.get", [tx_id])


def transaction_get_response(line: bytes, request_id: int) -> bytes:
    """Return the raw transaction `blockchain.transaction.get` answered.

    The result is the serialization as a hex string, `verbose` left at
    its default `false`; decoded to bytes here so a caller -- and
    `btclib_wallet.fetch.fetcher.tx_from_raw`, which every other backend hands
    the same octets to -- reads the transaction and not a string it has
    to already know is hex.
    """
    result = decode_response(line, request_id)
    if not isinstance(result, str):
        raise BTClibTypeError(f"transaction.get: not a hex string: {result!r}")
    return bytes_from_octets(result)


@dataclass(frozen=True)
class HeaderTip:
    """The chain tip `blockchain.headers.subscribe` answered.

    `header` is the raw eighty-byte serialization, decoded here so a
    caller checks it with `BlockHeader.parse` rather than hex-decoding it
    a second time.
    """

    height: int
    header: bytes


def headers_subscribe_request(request_id: int) -> bytes:
    """Return the `blockchain.headers.subscribe` request.

    A subscription in the protocol's own vocabulary, but this codec
    speaks one request and one response: the notifications a live
    subscription goes on to deliver are a connection's to read off the
    wire, which nothing here holds, and are no part of what
    `decode_response` matches by id.
    """
    return encode_request(request_id, "blockchain.headers.subscribe")


def headers_subscribe_response(line: bytes, request_id: int) -> HeaderTip:
    """Return the chain tip `blockchain.headers.subscribe` answered."""
    result = decode_response(line, request_id)
    if not isinstance(result, dict):
        raise BTClibTypeError(f"headers.subscribe: not an object: {result!r}")
    height = result.get("height")
    header = result.get("hex")
    if not is_integer(height):
        raise BTClibTypeError(f"headers.subscribe: invalid height: {height!r}")
    if not isinstance(header, str):
        raise BTClibTypeError(f"headers.subscribe: invalid hex: {header!r}")
    return HeaderTip(cast(int, height), bytes_from_octets(header))


def block_header_request(request_id: int, height: int) -> bytes:
    """Return the `blockchain.block.header` request for `height`.

    `cp_height` left unsent, at its protocol default of zero: with it,
    the answer is the raw header hex alone, rather than a second, unasked
    merkle proof -- the `{"branch", "header", "root"}` checkpoint shape --
    this codec has no method for and
    `btclib_wallet.fetch.Fetcher.get_block_header`'s own checks, run on
    the header this returns, have no use for.
    """
    return encode_request(request_id, "blockchain.block.header", [height])


def block_header_response(line: bytes, request_id: int) -> bytes:
    """Return the raw header `blockchain.block.header` answered."""
    result = decode_response(line, request_id)
    if not isinstance(result, str):
        raise BTClibTypeError(f"block.header: not a hex string: {result!r}")
    return bytes_from_octets(result)


@dataclass(frozen=True)
class MerkleProof:
    """The branch `blockchain.transaction.get_merkle` answered.

    `branch` and the transaction id it is checked against are both in
    display order -- the order `assert_merkle_proof` below, `Tx.id` and a
    block explorer all already use. `block_height` is the server's own
    claim of which block, unchecked here: it is what a caller passes to
    `btclib_wallet.fetch.Fetcher.get_block_header` to fetch the header
    this proof is checked against, so a wrong claim there is a wrong
    header fetched, and the branch check below is what refuses it.
    """

    block_height: int
    branch: tuple[bytes, ...]
    pos: int


def transaction_get_merkle_request(request_id: int, tx_id: str, height: int) -> bytes:
    """Return the `blockchain.transaction.get_merkle` request."""
    return encode_request(
        request_id, "blockchain.transaction.get_merkle", [tx_id, height]
    )


def transaction_get_merkle_response(line: bytes, request_id: int) -> MerkleProof:
    """Return the merkle proof `blockchain.transaction.get_merkle` answered."""
    result = decode_response(line, request_id)
    if not isinstance(result, dict):
        raise BTClibTypeError(f"transaction.get_merkle: not an object: {result!r}")
    block_height = result.get("block_height")
    branch = result.get("merkle")
    pos = result.get("pos")
    if not is_integer(block_height):
        err_msg = f"transaction.get_merkle: invalid block_height: {block_height!r}"
        raise BTClibTypeError(err_msg)
    if not isinstance(branch, list):
        raise BTClibTypeError(f"transaction.get_merkle: invalid merkle: {branch!r}")
    if not is_integer(pos):
        raise BTClibTypeError(f"transaction.get_merkle: invalid pos: {pos!r}")
    return MerkleProof(
        cast(int, block_height),
        tuple(bytes_from_octets(sibling, 32) for sibling in branch),
        cast(int, pos),
    )


def assert_merkle_proof(tx_id: Octets, proof: MerkleProof, header: BlockHeader) -> None:
    """Raise unless `proof` proves `tx_id` is in the tree `header` commits to.

    `btclib.block.merkle_proof.assert_as_valid`, unmodified: this is the
    shape the answer arrives in, checked against the header a caller
    fetched on its own, not a second implementation of the arithmetic.
    """
    assert_as_valid(tx_id, proof.branch, proof.pos, header.merkle_root)


def verify_merkle_proof(tx_id: Octets, proof: MerkleProof, header: BlockHeader) -> bool:
    """Return True if `proof` proves `tx_id` is in the tree `header` commits to.

    See `assert_merkle_proof`, which this wraps the same way
    `btclib.block.merkle_proof.verify` wraps `assert_as_valid`.
    """
    return verify_merkle_branch(tx_id, proof.branch, proof.pos, header.merkle_root)


def estimate_fee_request(request_id: int, target: int) -> bytes:
    """Return the `blockchain.estimatefee` request for `target` blocks."""
    return encode_request(request_id, "blockchain.estimatefee", [target])


def estimate_fee_response(line: bytes, request_id: int) -> float:
    """Return the BTC/kB rate `blockchain.estimatefee` answered, or -1.

    `-1` is the protocol's own way of saying no estimate is available,
    and is returned rather than raised here: this module reads what the
    wire carries, and deciding that "no answer" is a refusal is
    `btclib_wallet.fetch.electrum.ElectrumFetcher.estimate_fee`'s to make, the
    same split `decode_response` already draws for a JSON-RPC `error`
    member. Any other answer, below 0 or not finite, is refused.
    """
    result = decode_response(line, request_id)
    if isinstance(result, bool) or not isinstance(result, (int, float)):
        raise BTClibTypeError(f"estimatefee: not a number: {result!r}")
    if (isinstance(result, float) and not math.isfinite(result)) or not (
        result >= 0 or result == -1
    ):
        raise BTClibValueError(f"estimatefee: not a rate or -1: {result!r}")
    return result
