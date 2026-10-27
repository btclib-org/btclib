# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing what `btclib.p2p.bip324` reads off a connection.

`Cipher.decrypt_length` and `Cipher.decrypt` take the peer's bytes before
any check, and `message_from_contents` parses the contents they decrypt.
Each input goes to all three.

`message_from_contents` gets the input as a packet's contents. Where it
accepts them with a non-empty command, `contents_from_message` must write
them back unchanged. The exception is a long type spelling a command
that has a short id, which comes back as that short id.

The cipher reads the input as a stream of packets: an encrypted length,
then the header, the contents and the tag that length asks for. Each
input gets a fresh `Cipher`, built from a BIP324 packet vector so that
the seeds made with its keys decrypt. The stream ends at the first
refusal, as a connection does.

Every refusal is a `BTClibException`. Anything else propagates to
atheris as a finding.
"""

from __future__ import annotations

import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p import bip324

# tests/fuzz_corpus_test.py reads these with ast.literal_eval.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = ("btclib.p2p.bip324:message_from_contents",)
# the bip324 extra, which the suite may run without
REQUIRES = ("cryptography",)
# packets, which only the cipher reads
STATEFUL_SEEDS = ("packet_ping.bin", "packets_vector.bin")

# the in_idx 1 row of BIP324's packet_encoding_test_vectors.csv
_PRV_KEY = 0x61062EA5071D800BBFD59E2E8B53D47D194B095AE5A4DF04936B49772EF0D4D7
_ELL_OURS = bytes.fromhex(
    "ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa1"
    "86f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b"
)
_ELL_THEIRS = bytes.fromhex(
    "a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafa"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d5"
)
_INITIATOR = True
# the message start the vectors' salt was made with
_MAGIC = bytes.fromhex("f9beb4d9")


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a packet's contents, then decrypt it as packets."""
    try:
        command, payload = bip324.message_from_contents(data)
    except BTClibException:
        pass
    else:
        if command:
            expected = data
            if data[0] == 0 and command in bip324.MESSAGE_IDS:
                expected = bytes([bip324.MESSAGE_IDS.index(command)]) + payload
            assert bip324.contents_from_message(command, payload) == expected

    # self_decrypt: decrypt what the vector's own cipher encrypts
    cipher = bip324.Cipher(
        _PRV_KEY, _ELL_OURS, _ELL_THEIRS, _INITIATOR, _MAGIC, self_decrypt=True
    )
    rest = data
    while True:
        try:
            length = cipher.decrypt_length(rest[: bip324.LENGTH_LEN])
            end = bip324.LENGTH_LEN + bip324.HEADER_LEN + length + bip324.TAG_LEN
            cipher.decrypt(rest[bip324.LENGTH_LEN : end])
        except BTClibException:
            return
        rest = rest[end:]


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
