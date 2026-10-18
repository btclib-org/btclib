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
`fuzz/corpus/fuzz_electrum/` answers. `HEADERS_ASKED` is the number of
headers the request behind `block_headers.bin` asked for, and `BATCH_IDS`
the ids a balance batch asked for.

`BTClibException` is `decode_response`'s own refusal of a line that is
no valid answer, and `RpcError` is a server's own error object, which is
one too. Any other exception is a defect in the decoder and propagates
to atheris as the finding it is.

No round trip is asserted: the answer is a JSON line, which has many
spellings of one value (whitespace, key order, escapes, number forms), and
what the decoders return is not a serialization of it.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib import electrum
from btclib.exceptions import BTClibException

REQUEST_ID = 1
HEADERS_ASKED = 2
BATCH_IDS = (1,)

# what each entry point takes after the line. tests/fuzz_corpus_test.py
# reads this with ast and checks it against fuzz_target's calls.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = {
    "btclib.electrum:decode_response": (REQUEST_ID,),
    "btclib.electrum:transaction_get_response": (REQUEST_ID,),
    "btclib.electrum:headers_subscribe_response": (REQUEST_ID,),
    "btclib.electrum:block_header_response": (REQUEST_ID,),
    "btclib.electrum:block_headers_response": (REQUEST_ID, HEADERS_ASKED),
    "btclib.electrum:transaction_get_merkle_response": (REQUEST_ID,),
    "btclib.electrum:estimate_fee_response": (REQUEST_ID,),
    "btclib.electrum:scripthash_get_balance_response": (REQUEST_ID,),
    "btclib.electrum:scripthash_get_balance_batch_response": (BATCH_IDS,),
}


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
        electrum.block_headers_response(data, REQUEST_ID, HEADERS_ASKED)
    with contextlib.suppress(BTClibException):
        electrum.transaction_get_merkle_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.estimate_fee_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.scripthash_get_balance_response(data, REQUEST_ID)
    with contextlib.suppress(BTClibException):
        electrum.scripthash_get_balance_batch_response(data, BATCH_IDS)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
