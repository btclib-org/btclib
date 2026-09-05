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
from btclib.block.block_header import BlockHeader
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
# the first eighty bytes of tests/block/_data/block_481824.bin, i.e. the
# header of that same block -- its hash, recomputed by BlockHeader.parse,
# is TIP_ID above, which is what makes this vector checkable without a node
TIP_HEADER_RAW = (
    "02000020801b81629334be8e7af5ebfb9df09c18e1f833b5f0efcb0000000000000000"
    "0040d1ca077fefe7fb797711baa0c063eca9b8ed9469ae0128982b44ad0c253864913"
    "29e59e93c011822ff5422"
)
# transaction 22 of block 481824, read out of
# tests/block/_data/block_481824_complete.bin: a P2SH-P2WPKH spend, and
# the transaction the broadcasts announce. A witness is what separates
# the two serializations of one transaction, and the id is computed from
# the one without it -- so a broadcast that stripped the witness sends
# bytes carrying none of the signatures and still names this same id,
# which is why a witnessless vector cannot tell the two apart
SEGWIT_TX_RAW = (
    "0200000000010140d43a99926d43eb0e619bf0b3d83b4a31f60c176beecfb9d3"
    "5bf45e54d0f7420100000017160014a4b4ca48de0b3fffc15404a1acdc8dbaae"
    "226955ffffffff0100e1f5050000000017a9144a1154d50b03292b3024370901"
    "711946cb7cccc387024830450221008604ef8f6d8afa892dee0f31259b6ce02d"
    "d70c545cfcfed8148179971876c54a022076d771d6e91bed212783c9b06e0de6"
    "00fab2d518fad6f15a2b191d7fbd262a3e0121039d25ab79f41f75ceaf882411"
    "fd41fa670a4c672c23ffaf0e361a969cde0692e800000000"
)
# another transaction of that block, and the wrong id that sorts *after*
# the one above where block 170's coinbase sorts before it: a check that
# a backend confirmed what it was handed is an inequality, and a fixture
# offering one wrong value cannot say whether it is an ordering instead
LATER_TX_ID = "dfcec48bb8491856c353306ab5febeb7e99e4d783eedf3de98f3ee0812b92bad"


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

    The concrete half of `Fetcher` -- the network name it normalizes,
    `get_tx_out` deriving an output from the transaction that made it --
    is code no backend re-implements, so testing it through one of them
    would test it once for bitcoind and never for the interface.
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

    @override
    def get_block_header(self, height: int) -> BlockHeader:
        """Answer the tip header, whatever height is asked for."""
        self.asked.append(str(height))
        return BlockHeader.parse(TIP_HEADER_RAW)
