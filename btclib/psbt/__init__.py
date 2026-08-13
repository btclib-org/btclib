# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Partially signed bitcoin transactions and the BIP174/BIP370 roles.

What this package exports is the format and the roles: the three maps a
psbt is made of, the Combiner, the Finalizer, the Extractor, the outputs
an unsigned psbt spends, the two messages a Signer signs and `sign`
which plays the role over a `KeyManager`'s answers, and the size
estimation a fee rate is applied to. `musig2` is named as a module, being
the BIP373 role rather than one function, the way btclib.ecc names dsa; so
is `silent_payments`, BIP375's two roles over the fields BIP375 adds --
what a Signer writes into a psbt paying a silent payment address, and what
a Transaction Extractor has to recompute before it hands the bytes over.

`PsbtView` is the same psbt read a map at a time out of a stream, for a
signer with less memory than the psbt takes (issue #647). It is beside
`Psbt` and not another way to spell it: it reads, where every role above
rewrites, and what it hands back is the psbt's maps one by one rather
than the psbt. Its module docstring states what it holds between calls
and what a stream that changes underneath it costs.

`assert_signatures_only` is the check that belongs before `combine` when
the psbt being merged came from somebody else. BIP174 gives the Combiner
no such role -- it takes the union of what it is given and may resolve a
conflict by picking either side -- so a caller merging an external
signer's answer has to hold it to the request first. `new_signers` is
what the same caller reads off that answer before merging it: which
wallets it adds the signatures of, which the union no longer says.

`assert_signed` is the other question about a signature, and about the
psbt rather than about an answer to a request: every signature it carries
verifies, and every input carries one. Neither of the two roles that read
a signature answers it -- a request nobody signed passes
`assert_signatures_only` unchanged, and `finalize` reads a signature it
cannot verify as one that is not there.

`ecdsa_sig_hash` and `taproot_sig_hash` are here for the same reason
`prevouts` is: `sign` needs the message before it needs anything else,
and a caller playing the Signer by hand -- writing a signature into a
psbt without going through `sign` -- needs it too, `KeyManager` not
being the only way to hold a key.

btclib.psbt.psbt_utils is not exported, and this is where that decision is
recorded: serialize_bytes, deserialize_map, deserialize_tx,
the encode/decode_dict_bytes_bytes pair,
serialize_dict_bytes_bytes, serialize_hd_key_paths and
assert_valid_unknown are how one field of one map is written and read.
They are called by psbt_in, psbt_out and psbt itself and by nothing
outside this package, and there were more of them in __all__ than there
were names for the format -- so a caller reading btclib.psbt was offered
the plumbing of a file format ahead of the psbt. Each is importable from
the module that defines it, which is where the test suite takes the other
half of that module from already.
"""

from btclib.psbt import musig2, silent_payments
from btclib.psbt.psbt import (
    InputSolver,
    KeyManager,
    Psbt,
    assert_signatures_only,
    assert_signed,
    combine,
    ecdsa_sig_hash,
    extract_tx,
    finalize,
    join,
    new_signers,
    prevouts,
    sign,
    taproot_sig_hash,
)
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_size import SolutionSizer, estimated_input_sizes
from btclib.psbt.psbt_view import PsbtView

__all__ = [
    "InputSolver",
    "KeyManager",
    "Psbt",
    "PsbtIn",
    "PsbtOut",
    "PsbtView",
    "SolutionSizer",
    "assert_signatures_only",
    "assert_signed",
    "combine",
    "ecdsa_sig_hash",
    "estimated_input_sizes",
    "extract_tx",
    "finalize",
    "join",
    "musig2",
    "new_signers",
    "prevouts",
    "sign",
    "silent_payments",
    "taproot_sig_hash",
]
