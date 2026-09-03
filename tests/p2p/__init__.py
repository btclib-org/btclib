# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Non-regression tests for btclib.p2p, and the walk two of them share."""

from typing import Any

from btclib import p2p


def payload_types() -> set[type[Any]]:
    """Return every concrete payload type of the library.

    The package is imported rather than the module: `Payload` fills
    `__subclasses__` as each payload module is read, and
    `btclib/p2p/__init__.py` is what reads them all.

    Two things are skipped, and each for its own reason: a name starting
    with an underscore is a shared body rather than a message type --
    `keepalive._NoncePayload`, `inventory._InventoryPayload` and
    `inventory._LocatorPayload` are those -- and a class defined outside
    `btclib` is another test's, `__subclasses__` being a live registry
    that whatever ran before this leaves its own subclasses in.

    Here rather than in the module that first needed it, which is what
    `tests/__init__.py` says shared test code does: two modules ask this
    walk different questions -- whether every payload type is driven by a
    value, and whether every command is one Bitcoin Core declares -- and
    neither owns it.
    """
    found: set[type[Any]] = set()
    pending = list(p2p.Payload.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if not cls.__name__.startswith("_") and cls.__module__.startswith("btclib"):
            found.add(cls)
    return found
