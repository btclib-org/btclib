# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.block_filters`'s payload parsers.

`getcfilters`, `getcfheaders`, `cfilter`, `cfheaders`, `getcfcheckpt` and
`cfcheckpt` (BIP157) are reached behind `Message.parse`'s envelope and
ahead of any signature check. `fuzz/fuzz_handshake.py`'s own docstring is
where the absence of a dispatch table is argued; the same reasoning puts
each of the module's `parse` classmethods here, reached directly on
`message.payload` once a caller has read `message.command`.

The module has six concrete `Payload` subclasses, so this harness runs
all six `parse` methods against the same bytes rather than picking one.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.block_filters import (
    CFCheckpt,
    CFHeaders,
    CFilter,
    GetCFCheckpt,
    GetCFHeaders,
    GetCFilters,
)


def fuzz_target(data: bytes) -> None:
    """Parse `data` under each of the module's six commands in turn.

    `BTClibException` is swallowed as each `parse`'s own refusal of
    malformed input; any other exception propagates, which is how
    atheris tells a defect in `parse` from the domain of input it
    already rejects.
    """
    for cls in (
        GetCFilters,
        GetCFHeaders,
        CFilter,
        CFHeaders,
        GetCFCheckpt,
        CFCheckpt,
    ):
        with contextlib.suppress(BTClibException):
            cls.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
