# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The block-explorer fallback, for a caller with no node.

Esplora's HTTP api, because it is an api and not a product: Blockstream
publishes the server as open source, mempool.space serves the same three
endpoints this module calls, and anyone can run their own -- so a client
written against it is not written against one company's endpoint.
`BLOCKSTREAM_INFO` below is the reference deployment and is offered as a
*value to pass*, never as a default: the one decision btclib will not
take on a user's behalf is which stranger gets to see every address they
look up. mempool.space is not offered as a second constant for the same
reason, and naming it here is the evidence for the sentence above rather
than a recommendation.

What the fallback promises is the same three answers behind the same
interface. What it does not promise is that they are true. A node
validated the chain it reports; an explorer is a host on the internet
that says it did. `get_tx` is the one answer that checks itself, in
`tx_from_raw` -- the serialization comes back and the id is recomputed
from it, so a substituted transaction is caught -- and the height and the
tip hash are taken on trust, there being nothing here to check them
against. Nor does anything here say a transaction is *confirmed*: the
answer to that is a merkle branch against a header, which is what the
Electrum backend of issue #204 would add and this one cannot. That is the
trade the fallback exists to offer, and `SECURITY.md` states it.

Three endpoints, each answering in plain text rather than json:
`/tx/<txid>/hex`, `/blocks/tip/height` and `/blocks/tip/hash`. The json
renderings beside them carry the same values with more to disagree about
-- and `/hex` is what makes the id check above possible at all. That
those three are what a second deployment has to serve is why they are
the thing to check before naming one: a host answering json where this
expects text is not compatible in the way that matters.
"""

from __future__ import annotations

from btclib.alias import Octets
from btclib.exceptions import HttpError
from btclib.fetch.fetcher import (
    Fetcher,
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


# What each answer may weigh, because each of the three is bounded by
# what it is: a height is a decimal number, a tip hash is sixty-four hex
# digits, and a raw transaction is hex of a transaction that fits in a
# block -- DEFAULT_MAX_BODY_SIZE, which is that bound. The two small ones
# leave room for the whitespace a deployment behind a proxy adds and for
# nothing else: a host answering a height with a megabyte is answering
# something that is not a height, and there is no reason to hold it in
# order to find that out.
#
# The body of a *failure* is not bounded by these -- see
# `MAX_ERROR_BODY_SIZE` -- so a 404 whose error page is longer than a
# height still arrives as the diagnosis it is
_MAX_HEIGHT_BODY = 64
_MAX_HASH_BODY = 128
_MAX_TX_BODY = DEFAULT_MAX_BODY_SIZE


class EsploraFetcher(Fetcher):
    """The three questions, answered by an Esplora instance over HTTP.

    `base_url` is required and has no default, for the reason
    `BLOCKSTREAM_INFO` is a constant and not one.
    """

    def __init__(
        self,
        base_url: str,
        *,
        network: str = "mainnet",
        timeout: float = DEFAULT_TIMEOUT,
        transport: HttpTransport = urlopen_transport,
    ) -> None:
        super().__init__(network)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport

    def text(self, path: str, max_body_size: int = DEFAULT_MAX_BODY_SIZE) -> str:
        """Return the body of a GET on `path`, as stripped text.

        Stripped because a deployment behind a proxy may add a newline
        and none of the three answers can contain whitespace. Decoded
        with `replace` rather than strictly: the body of a failure is an
        error page from whatever is in the way, and it is more use
        rendered imperfectly than swallowed by a UnicodeDecodeError.

        `max_body_size` is what this particular answer may weigh; the
        default is the widest of the three, so a caller asking for
        something narrow says so.

        A status that is not 200 is an `HttpError`, which carries it:
        every answer here is a GET of an immutable value, so a 429 or a
        503 from a public deployment is the one failure worth another
        attempt, and telling it from a 404 without reading a message is
        what the field is for. btclib retries nothing itself -- an
        explorer's rate limit is the caller's budget to spend.

        `client_errors` because `http_request` is `bitcoin_core_rpc`'s and
        raises that package's exceptions: a refused connection reaching a
        caller as something no `except FetchError` of btclib's catches is
        what it is there to prevent.
        """
        url = f"{self.base_url}{path}"
        with client_errors():
            status, payload = http_request(
                url,
                timeout=self.timeout,
                max_body_size=max_body_size,
                transport=self.transport,
            )
        text = payload.decode("utf-8", errors="replace").strip()
        if status != 200:
            raise HttpError(f"HTTP {status} from {url}: {text}", status)
        return text

    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction, parsed and checked against its txid."""
        hex_ = tx_id_hex(tx_id)
        raw = self.text(f"/tx/{hex_}/hex", _MAX_TX_BODY)
        return tx_from_raw(raw, hex_, self.network)

    def get_block_count(self) -> int:
        """Return the height of the server's best chain tip."""
        with fetch_errors("blocks/tip/height"):
            return int(self.text("/blocks/tip/height", _MAX_HEIGHT_BODY))

    def get_best_block_id(self) -> bytes:
        """Return the hash of the server's best chain tip, display order."""
        with fetch_errors("blocks/tip/hash"):
            return bytes_from_octets(self.text("/blocks/tip/hash", _MAX_HASH_BODY), 32)
