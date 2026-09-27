# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The consensus limits on a script, with Bitcoin Core's names.

The caps at the top of Core's `script/script.h`, in one place because
the same number is read from more than one module: the element size bounds
a witness stack element in the engine and a tapscript push in
`taproot.parse`, and the code that reads it in one place cannot see the
copy in the other.

A module of its own rather than the top of `script.py`, because of what
`script.py` is: the encoding -- the tables, `parse`, `serialize` -- while
every limit here is a rule about *executing* one. Reading them from the
decoder is what let a 1443-byte push be refused as unparsable when it is
merely unspendable (issue #123), and a module the decoder need not import
is what says so.

`MAX_SCRIPT_ELEMENT_SIZE` and `MAX_SCRIPT_SIZE` are defined in
`btclib.consensus` and re-exported here, which is a layering fact and not
a second home for them: `btclib.b58` and `btclib.b32` bound the scripts
they hash into an address by them, and neither can import this package.
`btclib.consensus` says why; a caller reading a script's rules still names
this module.

`LOCKTIME_THRESHOLD` is deliberately not here, though script.h declares it
in the same block: it is not a limit but the value that tells a lock time
read as a block height from one read as a timestamp, and it means the same
in a transaction as in a script. It is `btclib.tx.limits`'s, and
`OP_CHECKLOCKTIMEVERIFY` imports it from there.
"""

from btclib.consensus import MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE

__all__ = [
    "MAX_OPS_PER_SCRIPT",
    "MAX_PUBKEYS_PER_MULTISIG",
    "MAX_SCRIPT_ELEMENT_SIZE",
    "MAX_SCRIPT_SIZE",
    "MAX_STACK_SIZE",
]

# Maximum number of non-push operations per script
MAX_OPS_PER_SCRIPT = 201

# Maximum number of public keys per multisig
MAX_PUBKEYS_PER_MULTISIG = 20

# Maximum number of values on script interpreter stack
MAX_STACK_SIZE = 1000
