# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`btclib.p2p` against a real Core, over a socket this test opens itself.

`tests/p2p/` reads a `version` Bitcoin Core sent once, on the day the
capture was taken; `regtest_test.py` reaches a real node, but only over
`bitcoin_core_rpc`, so no octet this library serializes for the wire is
ever framed, sent, and answered by Core. Neither can say that Core still
sends what a fixture captured, or still accepts what this library still
emits -- issue #1412 is what both of those being true, once, does not
establish for the next commit.

**No downstream connection loop, and no fixed list of what Core sends.**
This dials the node directly, on a plain `socket`, sends a `Version` this
library built and serialized, and reads back whatever Core answers with
until `verack` -- the point of `Message` refusing no command being that
an *unknown* one, whichever BIP adds the next, is exactly what a fixed
list of expected commands would miss; naming today's here would be a
hostage to the commit that carries it. "Parses" is `Message.parse` not
raising: the envelope reads a command it has no `Payload` type for into
a `command` string and opaque `payload` bytes, which is the contract
`btclib.p2p.message`'s docstring states and is still the assertion this
makes of it -- an unparsable message is one
`Message.parse` refuses outright, typed payload or none.

What this does not do is complete the handshake: nothing here sends a
`verack` back, and the connection is closed once Core's own has been
read. `btclib-org/btclib-node#374` is where the two-way exchange, the
connection promoting, and a synced tip are already exercised, against
that repository's own connection loop -- reproducing it here would only
say that loop still works, not this library's wire format.
"""

from __future__ import annotations

import secrets
import socket
import time
from collections.abc import Iterator
from io import BytesIO

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient

from btclib.exceptions import IncompleteMessageError
from btclib.p2p import (
    Message,
    NetworkAddress,
    ServiceFlags,
    Verack,
    Version,
    magic_from_network,
)

pytestmark = pytest.mark.integration

# Core's node/protocol_version.h: WTXID_RELAY_VERSION. Sending at least
# this is what makes Core answer `wtxidrelay` and `sendaddrv2` ahead of
# `verack` -- the two the issue this test answers names as the ones a
# frozen capture went blind to the day Core started sending them.
_OUR_VERSION = 70016
_USER_AGENT = b"/btclib-p2p-integration-test:0/"
# the whole exchange is a handful of octets on a loopback socket, so this
# bounds the failure case -- a node that never answers -- rather than the
# work
_HANDSHAKE_TIMEOUT = 30.0


@pytest.fixture
def handshake(node: BitcoinCoreRpcClient, p2p_port: int) -> Iterator[list[Message]]:
    """Dial the node, send a `version`, and return what it answers with.

    `node` is requested for the side effect of it existing -- the process
    `p2p_port` is bound to -- and never called on: this is the one test
    in the suite that never goes through `BitcoinCoreRpcClient`, on
    purpose, an rpc client being no evidence about the wire format an
    rpc-only test cannot reach.

    Every message up to and including `verack` is read here, and
    `Message.parse` is what reads each of them: a message this library
    cannot parse fails inside this fixture rather than inside a test's
    own assertions, which is `Message`'s own contract doing the work.
    """
    magic = magic_from_network("regtest")
    version = Version(
        version=_OUR_VERSION,
        services=ServiceFlags.NODE_NONE,
        timestamp=int(time.time()),
        addr_recv=NetworkAddress(ip="127.0.0.1", port=p2p_port),
        addr_from=NetworkAddress(ip="127.0.0.1", port=0),
        nonce=secrets.randbits(64),
        user_agent=_USER_AGENT,
        start_height=0,
        relay=True,
    )

    with socket.create_connection(
        ("127.0.0.1", p2p_port), timeout=_HANDSHAKE_TIMEOUT
    ) as sock:
        sock.sendall(version.to_message(magic).serialize())
        yield _read_until_verack(sock)


def _read_until_verack(sock: socket.socket) -> list[Message]:
    """Return every message read off `sock` up to and including `verack`.

    A `BytesIO` and not plain bytes, which is what lets one buffer hold
    several messages at once: `Message.parse` refuses trailing octets in
    a bytes object -- one whole object in, one whole object out -- and
    leaves a stream positioned after what it read instead, exactly the
    two halves `btclib.p2p.message`'s own docstring describes for a
    socket reader. `IncompleteMessageError` -- "not enough yet" -- is the
    one parse failure this catches; a message this library refuses
    outright raises past it and fails the test. A `recv` that times out
    is caught for the message rather than the behaviour: the socket
    carries `_HANDSHAKE_TIMEOUT` from `create_connection`, so a stuck
    node already fails within it, and catching it only says so in the
    words the deadline below uses instead of a bare traceback.
    """
    stream = BytesIO()
    messages: list[Message] = []
    deadline = time.monotonic() + _HANDSHAKE_TIMEOUT
    while not messages or messages[-1].command != "verack":
        if time.monotonic() > deadline:
            pytest.fail(f"no verack within {_HANDSHAKE_TIMEOUT}s: {messages}")
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            pytest.fail(f"no verack within {_HANDSHAKE_TIMEOUT}s: {messages}")
        if not chunk:
            pytest.fail(f"connection closed before verack: {messages}")
        # what `stream` had not yet consumed, plus what just arrived: a
        # fresh `BytesIO` rather than seeking back on the old one, which
        # `Message.parse` already left positioned on the octet after the
        # last complete message it read
        stream = BytesIO(stream.read() + chunk)
        while True:
            try:
                message = Message.parse(stream)
            except IncompleteMessageError:
                break
            messages.append(message)
    return messages


def test_core_answers_a_btclib_version_with_one_of_its_own_and_a_verack(
    handshake: list[Message],
) -> None:
    """The shape issue #1412 asks for, over one connection.

    Every message here already parsed -- `handshake` built `messages`
    with nothing but `Message.parse`, and would have failed the test
    inside the fixture on the first one that did not.
    """
    messages = handshake
    assert messages

    # Core framed every one of them on the network this test asked for,
    # which is `magic_from_network`'s own claim about what it returns
    assert {message.magic for message in messages} == {magic_from_network("regtest")}

    # Core's own `version`, read back into this library's type: what
    # `nVersion`, the service bits and the user agent are, according to
    # this library rather than only according to whoever sent them
    core_version = next(m for m in messages if m.command == "version")
    parsed = Version.parse(core_version.payload)
    assert parsed.version >= _OUR_VERSION
    assert ServiceFlags.NODE_NETWORK in parsed.services
    assert ServiceFlags.NODE_WITNESS in parsed.services
    assert b"Satoshi" in parsed.user_agent

    # and Core answered `verack` -- accepting the `version` this library
    # built and serialized, which is the only way to learn that of
    # something other than this library's own parser
    assert messages[-1].command == "verack"
    assert Verack.parse(messages[-1].payload) == Verack()
