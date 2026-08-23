# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the btclib.fetch tests share: a transport that opens no socket.

Not one test in this directory reaches the network, and none can: every
fetcher here is built with `transport=` pointing at `Recorded` below,
which answers from bytes committed under `_data` and remembers the
`urllib.request.Request` it was handed. A test that forgot the argument
would fall back to `urlopen_transport` and try to reach 127.0.0.1, so the
absence of a listening node is not what keeps the suite hermetic -- the
argument is, and it is on every construction.

The responses are what bitcoind and Esplora send, byte for byte, newline
included; `tests/_data/README.md` says where each came from and which of
them is chain data.
"""

from __future__ import annotations

from pathlib import Path
from urllib.request import Request

from typing_extensions import override

from btclib.alias import Octets
from btclib.fetch.fetcher import Fetcher
from btclib.tx import Tx

_DATA = Path(__file__).parent / "_data"

# transaction 1 of block 170, the recorded answer throughout: the first
# bitcoin payment between two people, 275 bytes of it
TX_ID = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
# the tip the recorded answers report, block 481824 -- the first block
# with a segwit transaction in it, and the one vendored whole under
# tests/block/_data
TIP_HEIGHT = 481824
TIP_ID = "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893"


def recorded_body(name: str) -> bytes:
    """Return a recorded response body, as it arrived."""
    return (_DATA / name).read_bytes()


class Recorded:
    """An HttpTransport answering from a script, remembering the requests.

    Each answer is either a `(status, body)` pair to return or an
    exception to raise, consumed in order; the last one repeats, so a
    test that makes two calls with one answer gets it twice. Everything
    it was asked is kept, which is how the tests check the url, the
    method, the headers and the timeout without a server to observe them
    from.
    """

    def __init__(self, *answers: tuple[int, bytes] | Exception) -> None:
        self.answers = list(answers)
        self.requests: list[Request] = []
        self.timeouts: list[float] = []

    def __call__(self, request: Request, timeout: float) -> tuple[int, bytes]:
        """Record the request and answer with the next scripted response."""
        self.requests.append(request)
        self.timeouts.append(timeout)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    @property
    def request(self) -> Request:
        """The only request made, when a test made exactly one."""
        assert len(self.requests) == 1
        return self.requests[0]

    @property
    def body(self) -> bytes:
        """The body of the only request made."""
        data = self.request.data
        assert isinstance(data, bytes)
        return data


class StubFetcher(Fetcher):
    """A Fetcher over a fixed transaction, for testing the base class.

    The concrete half of `Fetcher` -- the network check, `get_tx_out`
    deriving an output from the transaction that made it -- is code no
    backend re-implements, so testing it through one of them would test
    it once for bitcoind and never for the interface.
    """

    def __init__(self, tx: Tx, network: str = "mainnet") -> None:
        super().__init__(network)
        self.tx = tx
        self.asked: list[str] = []

    @override
    def get_tx(self, tx_id: Octets) -> Tx:
        """Record the tx_id asked for and answer the fixed transaction."""
        self.asked.append(bytes(tx_id).hex() if not isinstance(tx_id, str) else tx_id)
        return self.tx

    @override
    def get_block_count(self) -> int:
        """Answer the tip height the recorded responses report."""
        return TIP_HEIGHT

    @override
    def get_best_block_id(self) -> bytes:
        """Answer the tip block id the recorded responses report."""
        return bytes.fromhex(TIP_ID)
