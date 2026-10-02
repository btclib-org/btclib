# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing the response decoders of `btclib.electrum`.

An Electrum server answers with one line of JSON, and a hostile server
chooses every byte of it. `decode_response` reads the line and each
`*_response` function reads the `result` it returns, so this harness
hands the same bytes to all of them: what the line says is what decides
which of them gets past the first.

The line is bytes, and `REQUEST_ID` is the id every seed under
`fuzz/corpus/fuzz_electrum/` answers.

`BTClibException` is `decode_response`'s own refusal of a line that is
no valid answer, and `RpcError` is a server's own error object, which is
one too. Any other exception is a defect in the decoder and propagates
to atheris as the finding it is.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib import electrum
from btclib.exceptions import BTClibException

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris above is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = (
    "btclib.electrum:decode_response",
    "btclib.electrum:transaction_get_response",
    "btclib.electrum:headers_subscribe_response",
    "btclib.electrum:block_header_response",
    "btclib.electrum:transaction_get_merkle_response",
    "btclib.electrum:estimate_fee_response",
)

REQUEST_ID = 1


def fuzz_target(data: bytes) -> None:
    """Decode `data` as the answer to each request in turn."""
    with contextlib.suppress(BTClibException):
        electrum.decode_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.transaction_get_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.headers_subscribe_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.block_header_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.transaction_get_merkle_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.estimate_fee_response(data, REQUEST_ID)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
