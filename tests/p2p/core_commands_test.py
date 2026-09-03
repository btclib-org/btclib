# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every message type Core declares is carried here, or named as not carried.

`src/btclib/p2p/` publishes one `Payload` subclass per command and holds
no table of them, which is `btclib/p2p/payload.py`'s decision (issue
#1098). So this package's command set is what its classes answer, Bitcoin
Core's is what `src/protocol.h` declares, and the two are separately
valid: only reading them together says they have drifted. A message type
Core adds is one nothing here is red about, and a command misspelled here
round-trips as well as the real thing -- which is how btclib_node came to
send `sendcmpt` to the whole network.

Core's set is transcribed below rather than read from a checkout of it.
A test that goes and fetches its own input has a verdict that depends on
somebody else's uptime, which is the trade `tests/_data/README.md`
declines for every vector it pins: "a network call in the test suite
would trade a documented drift for a flaky one". What the transcription
catches is this package's set changing; Core changing its own is what the
pin is for, and the two together are the whole of the census.

That division is `tests/hwi_test.py`'s, and for the same reason. What is
pinned there is an interface rather than a file, upstream publishing no
file to compare bytes with, and `.github/workflows/vendored-vectors.yml`
re-checks the pin weekly and opens an issue where upstream's tip has
moved past it. `src/protocol.h` is that shape too: the message types are
declarations in C++ source, so a copy of the file would be a copy of a
header this project cannot compile, and the pin buys the re-check
instead.

Two alternatives were open, and each is refused for its own reason. A
test reading a Core checkout behind an environment switch -- which is
[ISS 198](https://github.com/btclib-org/btclib/issues/198)'s eventual
ambition -- measures nothing on the run that gates a merge, which is the
run this issue is about. Vendoring `src/protocol.h` under
`tests/p2p/_data/` puts a file in the tree whose bytes move for reasons
that are not the message types, so the refresh it asks for would be a
chore answering a question nobody asked.

What this cannot do is notice a message type Core added since the pin.
Nothing offline can: the weekly re-check is what says the pin has moved,
the refresh of the tuple below is what makes the new name visible, and
`test_every_command_core_declares_is_carried_or_named` is what then holds
somebody to a decision about it rather than to silence.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests.p2p import payload_types

_PACKAGE = Path(__file__).parents[2] / "src" / "btclib" / "p2p"

# a payload class's own command constant, which `btclib/p2p/payload.py`
# puts on the class so that the name serialized and the name matched on
# are one string
_COMMAND = re.compile(r'^    command = "([a-z0-9]+)"$', re.MULTILINE)

# Bitcoin Core's `NetMsgType`, transcribed from `src/protocol.h` in the
# order it declares them; `tests/_data/README.md` pins the revision, and
# a refresh of it is a diff over this tuple.
_CORE_COMMANDS = (
    "version",
    "verack",
    "addr",
    "addrv2",
    "sendaddrv2",
    "inv",
    "getdata",
    "merkleblock",
    "getblocks",
    "getheaders",
    "tx",
    "headers",
    "block",
    "getaddr",
    "mempool",
    "ping",
    "pong",
    "notfound",
    "filterload",
    "filteradd",
    "filterclear",
    "sendheaders",
    "feefilter",
    "sendcmpct",
    "cmpctblock",
    "getblocktxn",
    "blocktxn",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "wtxidrelay",
    "sendtxrcncl",
    "feature",
)

# what Core declares and this package does not carry, under the issue
# holding the decision. BIP37's bloom set and the `merkleblock` a loaded
# filter is answered with are one question -- whether a deprecated
# privacy leak belongs in a library whose defence is that parsing is not
# endorsing -- and it is argued in the issue rather than here.
_NOT_CARRIED = {
    "merkleblock": 1120,
    "filterload": 1120,
    "filteradd": 1120,
    "filterclear": 1120,
}

# what this package carries and Core's `NetMsgType` does not declare.
# `src/btclib/p2p/reject.py` is where the reason is: Core removed both
# directions of BIP61's `reject` in bitcoin/bitcoin#15437, and an
# implementation that has not followed it off the wire sends one anyway,
# so there is a message to parse under a name Core no longer names.
_NOT_CORE_S = ("reject",)

_DECLARED = frozenset(
    command
    for path in sorted(_PACKAGE.glob("*.py"))
    for command in _COMMAND.findall(path.read_text(encoding="utf-8"))
)
_PUBLISHED = frozenset(cls.command for cls in payload_types())


def test_both_sides_of_the_census_were_read() -> None:
    """A comparison over a side that came up empty is true of nothing.

    This package's set is read twice, and the two readings fail
    differently: the walk over `Payload.__subclasses__` answers short
    where a payload module is not reached by `btclib/p2p/__init__.py`, so
    a caller importing the package could not name the type either, and
    the regex over the source answers short where the constant is spelled
    some other way. Neither can be believed on its own, and an empty one
    is what makes every comparison below pass.
    """
    assert _PUBLISHED == _DECLARED, (
        f"the payload types the package publishes are {sorted(_PUBLISHED)},"
        f" where its source declares {sorted(_DECLARED)}"
    )
    assert _PUBLISHED, "no payload type was found at all"
    assert len(set(_CORE_COMMANDS)) == len(_CORE_COMMANDS), (
        f"a message type is transcribed twice: {sorted(_CORE_COMMANDS)}"
    )


def test_every_name_left_out_is_a_name_the_other_side_has() -> None:
    """An exemption outliving its own subject is how this rots.

    A message type Core drops, or one this package starts carrying, would
    otherwise leave a line below excusing a difference that is not there
    any more -- and an exemption nothing holds to a subject excuses
    whatever it is next pointed at.
    """
    assert set(_NOT_CARRIED) <= set(_CORE_COMMANDS), (
        f"named as not carried, and not Core's: "
        f"{sorted(set(_NOT_CARRIED) - set(_CORE_COMMANDS))}"
    )
    assert not set(_NOT_CORE_S) & set(_CORE_COMMANDS), (
        f"named as Core's own absence, and declared by Core: "
        f"{sorted(set(_NOT_CORE_S) & set(_CORE_COMMANDS))}"
    )
    assert not set(_NOT_CARRIED) & _PUBLISHED, (
        f"named as not carried, and carried: {sorted(set(_NOT_CARRIED) & _PUBLISHED)}"
    )


def test_every_command_core_declares_is_carried_or_named() -> None:
    """The census: a message type Core has is answered for, either way.

    This is what the issue bodies used to hold. A name arriving in the
    transcription above and in neither this package nor `_NOT_CARRIED` is
    red here, so the decision to leave it out is written down rather than
    taken by nobody.
    """
    unaccounted = sorted(set(_CORE_COMMANDS) - _PUBLISHED - set(_NOT_CARRIED))
    assert not unaccounted, (
        f"Core declares {unaccounted}, which this package neither carries"
        " nor names in _NOT_CARRIED with the issue that decided it"
    )


def test_every_command_this_package_carries_is_core_s_or_named() -> None:
    """The other direction, which is the one a misspelling falls into.

    A command Core does not declare is either a name it dropped -- BIP61's
    `reject` is that, and says so -- or a typo in a string constant no
    round trip can see, this package's classes being the only thing that
    reads it.
    """
    unaccounted = sorted(_PUBLISHED - set(_CORE_COMMANDS) - set(_NOT_CORE_S))
    assert not unaccounted, (
        f"this package carries {unaccounted}, which Core's NetMsgType does"
        " not declare and _NOT_CORE_S does not name"
    )
