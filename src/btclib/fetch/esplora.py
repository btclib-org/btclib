# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The block-explorer fallback, for a caller with no node.

Esplora's HTTP api, because it is an api and not a product: Blockstream
publishes the server as open source, mempool.space serves the same
endpoints this module calls, and anyone can run their own -- so a client
written against it is not written against one company's endpoint.
`BLOCKSTREAM_INFO` below is the reference deployment and is offered as a
*value to pass*, never as a default: the one decision btclib will not
take on a user's behalf is which stranger gets to see every address they
look up. mempool.space is not offered as a second constant for the same
reason, and naming it here is the evidence for the sentence above rather
than a recommendation.

What the fallback promises is the same four answers behind the same
interface. What it does not promise is that they are all true. `get_tx`
is the one answer that checks itself completely, in `tx_from_raw` -- the
serialization comes back and the id is recomputed from it, so a
substituted transaction is caught. `get_block_header` checks less:
`block_header_from_raw` only asks whether the eighty bytes are
well-formed and cost a real hash to mine, which is cheap for a host to
fabricate compared with the transaction it would have to forge to pass
the id check. The height and the tip hash have nothing here to check
them against at all, and are taken on trust.

Which chain the explorer serves is a separate question from those four,
and `verify_network` is what asks it: on by default, the same name and
the same opt-out `BitcoinCoreFetcher.verify_network` is, comparing
`/block-height/0` against the genesis `NETWORKS` carries for the network
this fetcher was built for. The failure it catches is the same silent
one -- a fetcher labelled `mainnet` over a host serving another chain
renders a mainnet address for every output it fetches -- and what a
genesis hash cannot do is separate two signets; `assert_network`'s own
docstring says why.

Nor does anything here say a transaction is *confirmed*: the answer to
that is a merkle branch checked against a header, which is what the
Electrum backend of issue #204 adds and this one cannot. That is the
trade the fallback exists to offer, and `SECURITY.md` states it.

The endpoints reached here answer in plain text rather than json:
`/tx/<txid>/hex`, `/blocks/tip/height`, `/blocks/tip/hash`,
`/block-height/<height>` and `/block/<hash>/header`, read; `POST /tx`,
written. The json renderings beside them carry the same values with more
to disagree about -- and `/hex` is what makes the id check above possible
at all. That these are what a second deployment has to serve is why they
are the thing to check before naming one: a host answering json where
this expects text is not compatible in the way that matters.
"""

from __future__ import annotations

from typing_extensions import override

from btclib.alias import Octets
from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibValueError, FetchError, HttpError
from btclib.fetch.fetcher import (
    Fetcher,
    block_header_from_raw,
    block_header_height,
    client_errors,
    fetch_errors,
    tx_from_raw,
    tx_id_hex,
)
from btclib.fetch.transport import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    HttpTransport,
    http_request,
    urlopen_transport,
)
from btclib.network import NETWORKS
from btclib.tx import Tx
from btclib.utils import bytes_from_octets

__all__ = [
    "BLOCKSTREAM_INFO",
    "EsploraFetcher",
]

# The reference deployment of the Esplora software, per network it
# serves. A constant to pass rather than a default to inherit: naming it
# spares a user a typo, and passing it is still their decision, written
# at the call site where a reviewer can see it
BLOCKSTREAM_INFO = {
    "mainnet": "https://blockstream.info/api",
    "testnet": "https://blockstream.info/testnet/api",
    "signet": "https://blockstream.info/signet/api",
}


# What each answer may weigh, because each of the four is bounded by
# what it is: a height is a decimal number, a tip hash is sixty-four hex
# digits, a header is eighty bytes of hex, and a raw transaction is hex of
# a transaction that fits in a block -- DEFAULT_MAX_BODY_SIZE, which is
# that bound. The three small ones leave room for the whitespace a
# deployment behind a proxy adds and for nothing else: a host answering a
# height with a megabyte is answering something that is not a height, and
# there is no reason to hold it in order to find that out.
#
# The body of a *failure* is not bounded by these -- see
# `MAX_ERROR_BODY_SIZE` -- so a 404 whose error page is longer than a
# height still arrives as the diagnosis it is
_MAX_HEIGHT_BODY = 64
_MAX_HASH_BODY = 128
_MAX_HEADER_BODY = 256
_MAX_TX_BODY = DEFAULT_MAX_BODY_SIZE


class EsploraFetcher(Fetcher):
    """The four questions, answered by an Esplora instance over HTTP.

    `base_url` is required and has no default, for the reason
    `BLOCKSTREAM_INFO` is a constant and not one.

    Also a `Broadcaster`: `broadcast` is `POST /tx`, the one endpoint of
    this class that writes. Holding a fetcher is not broadcasting; a
    caller has to call the method, and `broadcast`'s own docstring is
    where its non-idempotence is stated, at the point a caller meets it.

    `verify_network` is who asks whether the explorer is on the chain
    this fetcher labels with. On by default and before the first fetch
    rather than in this constructor: the answer costs a round trip that
    is worth paying where it is checked and wasted where a fetcher is
    built and never used, and an explorer that is merely unreachable
    should not be a failure to *construct* anything. The answer is then
    kept -- an explorer does not change chain under a client that goes on
    pointing at it -- and a caller that would rather not ask says
    `verify_network=False`. Same name, same keyword-only argument, same
    default, same opt-out as `BitcoinCoreFetcher.verify_network`.
    """

    def __init__(
        self,
        base_url: str,
        *,
        network: str = "mainnet",
        verify_network: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
        transport: HttpTransport = urlopen_transport,
    ) -> None:
        super().__init__(network)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport
        self.verify_network = verify_network
        self._agreed = False
        self._disagreement = ""

    def _verify_once(self) -> None:
        """Compare the explorer's chain with this fetcher's label, once.

        `BitcoinCoreFetcher._verify_once`, unchanged: called by the four
        fetches and by `broadcast`, and not by `text` or `_request`,
        which is what `assert_network` itself goes through -- a check in
        there would ask the explorer about the explorer, from inside the
        question.

        A disagreement is remembered and raised again for every later
        call, because it is a settled fact about a configuration rather
        than a request that failed -- and a fetcher that asked once,
        refused once and then served an address would be the silent
        failure this exists to stop. A `FetchError` is not an answer and
        is remembered as nothing: the explorer was unreachable or spoke
        nonsense, which the next call may well find otherwise.
        """
        if not self.verify_network or self._agreed:
            return
        if self._disagreement:
            raise BTClibValueError(self._disagreement)
        try:
            self.assert_network()
        except BTClibValueError as e:
            self._disagreement = str(e)
            raise
        self._agreed = True

    def _request(
        self, path: str, *, data: bytes | None, max_body_size: int
    ) -> tuple[int, str]:
        """Return the status and stripped text body of one exchange on `path`.

        `data` is what decides the verb, the way `http_request` itself
        decides it: `None` is the GET every read here is, and bytes are a
        POST body -- `broadcast`'s only caller today.

        Stripped because a deployment behind a proxy may add a newline
        and none of the answers this seam carries can contain whitespace.
        Decoded with `replace` rather than strictly: the body of a
        failure is an error page from whatever is in the way, and it is
        more use rendered imperfectly than swallowed by a
        UnicodeDecodeError.

        `client_errors` because `http_request` is `bitcoin_core_rpc`'s and
        raises that package's exceptions: a refused connection reaching a
        caller as something no `except FetchError` of btclib's catches is
        what it is there to prevent.
        """
        url = f"{self.base_url}{path}"
        headers = None if data is None else {"Content-Type": "text/plain"}
        with client_errors():
            status, payload = http_request(
                url,
                data=data,
                headers=headers,
                timeout=self.timeout,
                max_body_size=max_body_size,
                transport=self.transport,
            )
        return status, payload.decode("utf-8", errors="replace").strip()

    def _http_error(self, path: str, status: int, text: str) -> HttpError:
        """Return the `HttpError` a non-200 status on `path` reports."""
        url = f"{self.base_url}{path}"
        return HttpError(f"HTTP {status} from {url}: {text}", status)

    def text(self, path: str, max_body_size: int = DEFAULT_MAX_BODY_SIZE) -> str:
        """Return the body of a GET on `path`, as stripped text.

        `max_body_size` is what this particular answer may weigh; the
        default is the widest of the three, so a caller asking for
        something narrow says so.

        A status that is not 200 is an `HttpError`, which carries it:
        every answer here is a GET of an immutable value, so a 429 or a
        503 from a public deployment is the one failure worth another
        attempt, and telling it from a 404 without reading a message is
        what the field is for. btclib retries nothing itself -- an
        explorer's rate limit is the caller's budget to spend.
        """
        status, text = self._request(path, data=None, max_body_size=max_body_size)
        if status != 200:
            raise self._http_error(path, status, text)
        return text

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction, parsed and checked against its txid."""
        self._verify_once()
        hex_ = tx_id_hex(tx_id)
        raw = self.text(f"/tx/{hex_}/hex", _MAX_TX_BODY)
        return tx_from_raw(raw, hex_, self.network)

    @override
    def get_block_count(self) -> int:
        """Return the height of the server's best chain tip."""
        self._verify_once()
        with fetch_errors("blocks/tip/height"):
            return int(self.text("/blocks/tip/height", _MAX_HEIGHT_BODY))

    @override
    def get_best_block_id(self) -> bytes:
        """Return the hash of the server's best chain tip, display order."""
        self._verify_once()
        with fetch_errors("blocks/tip/hash"):
            return bytes_from_octets(self.text("/blocks/tip/hash", _MAX_HASH_BODY), 32)

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Return the header of the block at this height, checked on arrival.

        Two requests: `/block-height/<height>` maps the height to the
        hash `/block/<hash>/header` takes, both plain text like the tip
        endpoints above.
        """
        self._verify_once()
        height = block_header_height(height)
        with fetch_errors("block-height"):
            reply = self.text(f"/block-height/{height}", _MAX_HASH_BODY)
            block_hash = bytes_from_octets(reply, 32).hex()
        raw = self.text(f"/block/{block_hash}/header", _MAX_HEADER_BODY)
        return block_header_from_raw(raw, height)

    def assert_network(self) -> None:
        """Raise unless the explorer serves the chain this fetcher labels with.

        One request, `/block-height/0` -- the same endpoint
        `get_block_header` reads for every other height, asked here for
        the block every chain starts from -- compared against
        `NETWORKS[self.network].genesis_block`.

        Public for the same reason `BitcoinCoreFetcher.assert_network` is
        -- a caller that wants the question answered at a moment of its
        own.

        Worth the call, because the failure it catches is silent, the
        same one `BitcoinCoreFetcher.assert_network`'s docstring names: a
        fetcher labelled `mainnet` over an explorer serving another chain
        renders a mainnet address for every output it fetches, for coins
        that are not there.

        Signet is the case a genesis hash cannot settle: Core builds
        every signet's genesis from the same parameters
        (`kernel/chainparams.cpp`), the challenge going into the message
        start and not into the block, so this check separates mainnet,
        testnet, testnet4, signet and regtest, and separates no two
        signets -- the same limit the node backends have when no
        `signet_challenge` is given. This class takes no
        `signet_challenge` of its own: nothing Esplora's api publishes is
        a signet's challenge to compare it against.

        A malformed reply is a `FetchError`. A disagreement is a
        `BTClibValueError` naming both hashes: the explorer is the
        authority on which chain it serves, so the fetcher's label is the
        thing to fix.
        """
        with fetch_errors("block-height"):
            reply = self.text("/block-height/0", _MAX_HASH_BODY)
            reported = bytes_from_octets(reply, 32)
        expected = NETWORKS[self.network].genesis_block
        if reported != expected:
            err_msg = f"{self.base_url} serves a chain whose genesis is"
            err_msg += f" {reported.hex()}, not the {expected.hex()}"
            err_msg += f" {self.network} was built for"
            raise BTClibValueError(err_msg)

    def broadcast(self, tx: Tx) -> bytes:
        """Announce `tx` to the server, and return the txid it confirmed.

        `_verify_once` is called first, as every other method here calls
        it -- but a broadcast to a server on the wrong chain is the worst
        version of the silent failure `verify_network` exists to catch: a
        fetch answering with the wrong data is corrected on the next
        read, where a signed transaction fanned out to the wrong
        network's peers cannot be called back.

        `POST /tx` with the wire serialization's hex, witness included, as
        the body -- what a peer relays and eventually mines, not the
        stripped form `Tx.id` hashes. The server answers the same way its
        GET endpoints do, plain text and not json, which is why this
        shares `_request` with `text` rather than opening a second seam:
        the bounded read, the `transport` argument and the `client_errors`
        translation are the same regardless of which verb sent the body.

        The id is computed from `tx` before the request, the way
        `tx_from_raw` recomputes one from a fetched serialization: a
        success naming a different txid is a `FetchError`, the server
        having confirmed some other transaction. One request and no
        retry, for the reason `BitcoinCoreFetcher.broadcast`'s docstring
        gives: after a timeout this method cannot tell a transaction that
        never reached the server from one that did and whose
        acknowledgement was merely lost on the way back, and that is the
        caller's decision to make, not this one's.

        A non-200 status is an `HttpError` carrying the body, the way
        `text` reports one for a GET: an Esplora deployment answers a
        rejected transaction with a 400 and the reason in plain text.
        """
        self._verify_once()
        txid = tx.id
        hex_ = tx.serialize(include_witness=True).hex()
        status, answer = self._request(
            "/tx", data=hex_.encode("ascii"), max_body_size=_MAX_HASH_BODY
        )
        if status != 200:
            raise self._http_error("/tx", status, answer)
        with fetch_errors("POST /tx"):
            answered = bytes_from_octets(answer, 32)
        if answered != txid:
            err_msg = f"broadcast {txid.hex()}: the server confirmed {answered.hex()}"
            raise FetchError(err_msg)
        return answered
