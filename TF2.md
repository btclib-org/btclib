# The tf2 ledger

One entry per Python file of Bitcoin Core's
`test/functional/test_framework/`, naming what covers it in btclib, what
the covering module asserts, and the revision of that file the entry was
read at.

What it is for is
[ISS 198](https://github.com/btclib-org/btclib/issues/198)'s "strictly
equivalent", the phrase on which offering anything back to Core rests.
That is a claim about a moving target: Core's framework changes, so an
equivalence measured against a revision nobody wrote down is an
equivalence nobody can re-check. An entry here turns "btclib covers
`blocktools`" into a sentence with a truth value -- which `blocktools`,
asserted by what, and what has moved upstream since.

It makes the gap visible in the other direction too. Re-deriving what is
left of Core's framework means reading the directory again, which is
work that starts going stale the moment it is finished; this is that
reading written down once, and moved by whatever moves it.

The file is btclib's while tf2 has no repository of its own, and it is
tf2's the day one exists. It sits at the root rather than inside
`tests/_data/README.md` for that reason and for one more: that README is
about `tests/**/_data/`, and a record of files this tree deliberately
does *not* hold is a different subject, which appending it there would
make both records harder to read.

## Reading an entry

An entry is a `###` heading naming the file's path in Core, a fenced
block pinning it, and a verdict with what stands behind it.

`repo`, `path` and `commit` are the pin, and `behind` is how many
upstream revisions of that path have landed since. That is the grammar
`tests/_data/README.md` uses, so an entry here can be read without
learning a second shape -- by a person, and by
`.github/scripts/check_vendored_vectors.py`, which parses exactly those
fields. That script is not yet asked to read this file: it takes one
README path and names one drift issue in a module constant, and
btclib-secp256k1 carries a copy of it under the same name that a change
to either would be owed. Wiring is therefore its own change, not this
file's.

An entry's `commit` is the tip of its own path, so `behind` reads zero
and a re-check can clear it. A repository-wide revision is a perfectly
good "this is the tree I read" pin, and `contents/<path>?ref=<sha>`
resolves one; what it cannot be is the tip of any single path, so
`behind` never reads zero for it and a per-path staleness check never
clears it. A ledger whose whole purpose is re-checkability takes the pin
that goes stale loudly.

## The verdicts

- **covered** -- btclib publishes the same thing, and a test asserts it.
- **covered in part** -- some of the file's surface is btclib's and some
  is not; the entry names both halves.
- **vendored** -- btclib holds Core's own file, with the attribution.
- **tf2's by decision** -- an issue decided it out of btclib, and the
  entry names that issue.
- **tf2's (harness)** -- it drives a node: a process, an RPC client, a
  socket, an event loop. Nothing in btclib answers it, and nothing is
  meant to.
- **empty upstream** -- the file has no content at the pinned commit.
  The entry is there so that content arriving in it moves the pin.

## Re-checking a pin

The path stands in a fence of its own, sitting inside the API argument
rather than at the end of the command; the fence below reads it as
`${entry_path:?}`, the shell's must-be-set form, so a paste of that
fence alone fails naming the variable rather than asking about whatever
the shell already held.

The variable is `entry_path` and not `path`, which is the name the
argument wants: in `zsh` -- the shell this is read in -- `path` is tied
to `PATH` as an array, so assigning a file path to it replaces the
reader's `PATH` with that one entry and the next command in their
terminal is not found. The `:?` guard does not catch it either, `path`
being always set there where `bash` refuses it. Measured both ways:
`zsh -c 'path=a/b.py; git --version'` answers `command not found: git`,
and `entry_path` leaves `PATH` alone.

```shell
entry_path=<the path the entry gives>
```

```shell
gh api --method GET repos/bitcoin/bitcoin/commits \
    -f "path=${entry_path:?}" -f per_page=1 \
    --jq '.[0].sha + "  " + .[0].commit.committer.date[:10]'
```

The answer is the entry's own `commit` where nothing has moved.
Any other commit means the file changed after it was read, and the
entry's verdict is then a claim about a file that is no longer there.

What no fence here catches is a file Core *gains*. The census in
`tests/tf2_ledger_test.py` runs offline and holds this file to a
transcription of Core's directory rather than to Core, so a new
`test_framework/*.py` upstream is invisible to it and to a pin re-check,
which only reads the entries a ledger already carries. Listing the
directory at a fresh commit is the read that answers it.

No entry carries a `blob`, and that is where this file parts from
`tests/_data/README.md`: nothing in this tree is a copy of any file
below but the RIPEMD-160 implementation, whose own entry names where
that comparison lives instead of making one here.

## bitcoin/bitcoin

### `test/functional/test_framework/__init__.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/__init__.py
commit  c28ee91db07ce82e134d500ddeb5600363c98048  2017-03-20
behind  0 revisions; that commit is the tip of the path
```

Verdict: **empty upstream**. The package marker, with no content at the
pinned commit. The entry is here so that content arriving in it moves
the pin rather than passing unnoticed.

### `test/functional/test_framework/address.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/address.py
commit  4dbaa7cc65b9546d07f1f9bfc8fb912b6fb20a5e  2026-06-16
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**. `b58.address_from_h160` and `b58.h160_from_address`
for the base58 addresses, `b32.address_from_witness` and
`b32.witness_from_address` for the segwit ones, each over the codec
below it -- `base58` and `bech32`, a split Core's file does not make.
`script.script_pub_key`'s `address`, `addresses` and `type_and_payload`
are the `address_to_scriptpubkey` direction.
`create_deterministic_address_bcrt1_p2tr_op_true` composes
`script.taproot.output_pubkey` over `tree_helper` with `b32.p2tr`, so it
is a convenience of tf2's assembled from parts that are here.
`tests/key_io_test.py` runs Core's own `key_io_valid.json` and
`key_io_invalid.json`, both vendored and pinned in
`tests/_data/README.md`.

### `test/functional/test_framework/authproxy.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/authproxy.py
commit  f42226d526ebb3eb9217e738108e4f8148a1b069  2026-06-04
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's (harness)**. Reaching a node over JSON-RPC is the
`bitcoin-core-rpc` package, which this organization publishes and
`btclib.fetch.bitcoin_core` builds on. Core's file is not a vendoring
candidate either: its header puts it under the GNU Lesser General Public
License, which is not this project's.

### `test/functional/test_framework/blockfilter.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/blockfilter.py
commit  fa5f29774872d18febc0df38831a6e45f3de69cc  2025-12-16
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**. `block/block_filter.py` holds both halves.
`BasicBlockFilter` maps an element into the filter's range as
`bip158_basic_element_hash` does, keyed on the block hash, and its
`from_block` selects what `bip158_relevant_scriptpubkeys` selects --
the previous output script of every non-coinbase input, and every output
script BIP158 does not exclude -- with the utxo set handed in through
`prevout_scripts_from_utxos` rather than read off a node. Each draws the
output rule from a different place, and btclib's is the one the BIP
states: Core's Python asks whether the output type is `nulldata`, where
btclib tests the first byte for `OP_RETURN` as Core's own C++ does, and
says beside `_OP_RETURN` why a non-standard OP_RETURN output separates
them.
`p2p/block_filters.py` carries BIP157's messages over it, and
`tests/block/blockfilters_test.py` runs Core's `blockfilters.json`,
vendored and pinned.

### `test/functional/test_framework/blocktools.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/blocktools.py
commit  1966621b76885257b4b4e44aab4712e9f84313e6  2026-05-13
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered in part**. `block/build.py` is `create_coinbase`,
`create_block` and `add_witness_commitment`:
[ISS 1118](https://github.com/btclib-org/btclib/issues/1118) put
`build_coinbase`, which pays `consensus.subsidy` at a height and commits
to that height as BIP34 requires, beside `build_block`, which assembles
the block over a list of transactions and its witness commitment.
`block/proof_of_work`'s `target_from_bits` and `bits_from_target` are
what `nbits_str` and `target_str` print, and `script.sig_ops`'s
`sig_op_count` is what `get_legacy_sigopcount_tx` counts.
`tests/block/build_test.py` asserts the first group against real
mainnet blocks. `create_tx_with_script`, `create_witness_tx` and
`send_to_witness` spend against a node's wallet, and are tf2's.

### `test/functional/test_framework/compressor.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/compressor.py
commit  b34fdb5ade0b48384636f8c7c9673554bf82cedf  2025-03-04
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's by decision**.
[ISS 1123](https://github.com/btclib-org/btclib/issues/1123): the
chainstate encoding is the format Core reserves for itself, where
`fetch/` depends on the interface Core publishes for everyone else.
`util.util_xor`, the obfuscation of Core's own block files, went to tf2
with it.

### `test/functional/test_framework/coverage.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/coverage.py
commit  fa71c15f8610816a6ee0426cd396315da3d27c30  2025-11-26
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's (harness)**. It records which RPCs a run reached.
Nothing in btclib answers it.

### `test/functional/test_framework/crypto/bip324_cipher.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/crypto/bip324_cipher.py
commit  fa5f29774872d18febc0df38831a6e45f3de69cc  2025-12-16
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's by decision**.
[ISS 1066](https://github.com/btclib-org/btclib/issues/1066) drew the
line: what btclib builds out of the standard library is in, and a
hand-rolled cipher is not.

### `test/functional/test_framework/crypto/chacha20.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/crypto/chacha20.py
commit  fa5f29774872d18febc0df38831a6e45f3de69cc  2025-12-16
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's by decision**. ISS 1066, the same line.
`muhash.py` carries a private `_chacha20_block` because `MuHash3072`'s
element hash is a keyed ChaCha20 keystream and nothing else here needs
one; its `__all__` publishes `MuHash3072` alone, which is
[ISS 1122](https://github.com/btclib-org/btclib/issues/1122) reading
that line rather than excepting itself from it.

### `test/functional/test_framework/crypto/ellswift.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/crypto/ellswift.py
commit  3fd68a95e68b4c6f3bb6c59d41dd196001110f3a  2026-04-07
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**. `ecc/ellswift.py`: `create_var` for
`ellswift_create`, `encode_var` for `xelligatorswift`, `decode_var` for
`xswiftec`, and `xdh` for `ellswift_ecdh_xonly`, over `_xswiftec_var`
and `_xswiftec_inv_var`. `tests/ecc/ellswift_test.py` runs BIP324's
`ellswift_decode_test_vectors.csv` and `xswiftec_inv_test_vectors.csv`,
vendored from bitcoin/bips and pinned.

### `test/functional/test_framework/crypto/hkdf.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/crypto/hkdf.py
commit  fa5f29774872d18febc0df38831a6e45f3de69cc  2025-12-16
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**. `kdf.hkdf` is Core's `hkdf_sha256`, and
`kdf.hkdf_extract` and `kdf.hkdf_expand` stand beside it where Core's
file offers the one-shot alone
([ISS 1080](https://github.com/btclib-org/btclib/issues/1080)).
`tests/kdf_test.py` runs RFC 5869's own vectors.

### `test/functional/test_framework/crypto/muhash.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/crypto/muhash.py
commit  fec2ca6c9a8a8e44b6e4d51c4ef7fa6eaca6e446  2023-09-29
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**. `muhash.MuHash3072` is Core's class operation for
operation -- `insert`, `remove` and the digest are all the pinned file
has -- and `coinstats.py` is what feeds a utxo set through one. btclib's
`serialize` and `deserialize` answer Core's C++ class instead, which the
module says where it implements them.
`tests/muhash_test.py` runs `muhash_vectors.json` and
`chacha20_vectors.json`, both transcribed from Core's `crypto_tests.cpp`
and pinned in `tests/_data/README.md`.

### `test/functional/test_framework/crypto/poly1305.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/crypto/poly1305.py
commit  fa5f29774872d18febc0df38831a6e45f3de69cc  2025-12-16
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's by decision**. ISS 1066, the same line: an
authenticator written out by hand is what that issue put on tf2's side.

### `test/functional/test_framework/crypto/ripemd160.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/crypto/ripemd160.py
commit  08a4a56cbcfa54366c2c0bb52bb147fc2740edc5  2023-09-10
behind  0 revisions; that commit is the tip of the path
```

Verdict: **vendored**. `src/btclib/_ripemd160.py` is Core's file, MIT
and therefore this project's licence too, for an interpreter whose
`hashlib` offers no RIPEMD-160; its docstring carries the attribution,
the revision it was taken at, and every delta from upstream.
`tests/ripemd160_test.py` holds the vectors that were in Core's own
`unittest.TestCase`.

### `test/functional/test_framework/crypto/secp256k1.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/crypto/secp256k1.py
commit  3fd68a95e68b4c6f3bb6c59d41dd196001110f3a  2026-04-07
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**, and wider than Core's file: `curves/curve.py`,
`curves/curve_group.py`, `curves/curve_group_2.py`,
`curves/curve_group_f.py` and `curves/sec_point.py` carry every curve
this library has rather than secp256k1 alone. What the arithmetic is
asserted against is not a vector file but the `btclib_secp256k1`
bindings, which `curves.curve.mult` and its variants delegate to for
secp256k1 and which the suite validates the Python arm against. Core's
file warns that it is slow and side-channel vulnerable; `SECURITY.md`
publishes the same about the Python arm here.

### `test/functional/test_framework/crypto/siphash.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/crypto/siphash.py
commit  af50ba8500a81e1a79cdf953d27bbf53ee6c979f  2026-07-18
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**. `hashes.siphash` takes the key words in the order
Core's own `siphash(k0, k1, data)` reads them out of a key
([ISS 373](https://github.com/btclib-org/btclib/issues/373)). Core's
second entry point, `siphash256`, is a little-endian `to_bytes` of a
`uint256` ahead of that same call, and `hashes.siphash`'s docstring is
where declining to restate that conversion is argued: a hash is already
bytes in that order here. `tests/siphash_test.py` runs Core's
`siphash.json`, vendored and pinned, and
`tests/p2p/compact_blocks_test.py` reads Core's own Python as a second
implementation.

### `test/functional/test_framework/descriptors.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/descriptors.py
commit  fab300b378941a233119805c0d62198596a57790  2025-12-26
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered in part**. `descriptors.checksum`,
`descriptors.add_checksum` and `descriptors.strip_checksum` are
`descsum_polymod`, `descsum_expand`, `descsum_create` and
`descsum_check`, asserted in `tests/descriptors/descriptors_test.py`
against `descriptor_checksums.json`. `drop_origins` has no equivalent:
`descriptors.normalized` is Core's `ToNormalizedString`, which re-roots
each key at its last hardened step, where dropping key origins is a
different operation that nothing here publishes.

### `test/functional/test_framework/extendedkey.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/extendedkey.py
commit  d2a03d50acbf4bffc11048ef2cabb1b42ea78989  2026-06-19
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**. `bip32/` is BIP32 whole, where Core's file says of
itself that it provides "only basic functionality", and `slip132`,
`bip44`, `bip85` and `bip32/key_origin.py` stand beside it. `tests/bip32/`
runs BIP32's own vectors and its invalid extended keys, both pinned.

### `test/functional/test_framework/ipc_util.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/ipc_util.py
commit  3962138cc036578926d901e6ff4ff807243bbb4e  2026-05-26
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's (harness)**. Cap'n Proto IPC into a `bitcoin-node`
process. `src/btclib` names it nowhere.

### `test/functional/test_framework/key.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/key.py
commit  3fd68a95e68b4c6f3bb6c59d41dd196001110f3a  2026-04-07
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**. `ecc/dsa.py` and `ecc/ssa.py` sign and verify,
`ecc/rfc6979_nonce.py` and `ecc/bip340_nonce.py` derive the nonces,
`key.py`, `to_prv_key.py` and `to_pub_key.py` are the key objects Core's
`ECKey` and `ECPubKey` are, `hashes.tagged_hash` is `TaggedHash`, and
`script/taproot.py` holds the x-only tweak. What the signatures are
asserted against is BIP340's own vectors and the `btclib_secp256k1`
bindings, which are the authority on the answer.

### `test/functional/test_framework/mempool_util.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/mempool_util.py
commit  fa5f29774872d18febc0df38831a6e45f3de69cc  2025-12-16
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's (harness)**. It fills and reads a running node's
mempool.

### `test/functional/test_framework/messages.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/messages.py
commit  e3b026bf56e66baa6e070a00c136da95f3a16ef8  2026-07-07
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered in part**. `p2p/` publishes one `Payload` subclass
per command over `tx/`, `block/`, `var_int`, `var_bytes`, `hashes`,
`block/partial_merkle_tree.py` and `p2p/merkleblock.py`
([ISS 1083](https://github.com/btclib-org/btclib/issues/1083) and its
children); the `C`-prefixed structures Core's file also carries are
`tx/` and `block/` here. `tests/p2p/core_commands_test.py` asserts that
census in both directions against Core's `src/protocol.h`, pinned in
`tests/_data/README.md`. `filterload`, `filteradd` and `filterclear` are
left out for good by
[ISS 1120](https://github.com/btclib-org/btclib/issues/1120): a client
constructs those to ask a node for the service that leaks its wallet to
that node, and BIP157 is what replaced them.

### `test/functional/test_framework/netutil.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/netutil.py
commit  59ebf558f3458bbc9038c7bf2958f2f224485ee1  2026-09-02
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's (harness)**. Interfaces, sockets and kernel inode
tables. `src/btclib` imports `socket` nowhere.

### `test/functional/test_framework/p2p.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/p2p.py
commit  e4d80e7001e9996a2836225f45a905dd16ffc777  2026-08-18
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered in part**. The envelope is `p2p/message.py`:
`Message.parse` reads one message off a stream and answers "not enough
bytes yet" as `IncompleteMessageError`, distinctly from a wrong
checksum, rewinding the stream to where it started.
`P2PConnection`, `P2PInterface`, `NetworkThread`, `P2PDataStore` and the
listener are the socket, the event loop and the peer state machine, and
are tf2's.

### `test/functional/test_framework/psbt.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/psbt.py
commit  a2a2b1745f0818364dd8149161e88cea1475d9b6  2026-05-27
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**. `psbt/` -- `Psbt`, `PsbtIn`, `PsbtOut`,
`psbt_view`, `psbt_size`, `musig2` and `silent_payments` -- where Core's
file is a reader and a writer of the maps. `tests/psbt/` runs BIP174,
BIP370, BIP371, BIP373 and BIP375 vectors, each pinned.

### `test/functional/test_framework/script.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/script.py
commit  3fd68a95e68b4c6f3bb6c59d41dd196001110f3a  2026-04-07
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**. `script/script.py` is the codec,
`script/engine/` the execution, `script/op_codes_tapscript.py` and
`script/taproot.py` the taproot half, and `script/sig_hash.py` the
signature hashes Core's file also carries. `tests/script/` and
`tests/script_engine/` run Core's `script_tests.json`, `tx_valid.json`,
`tx_invalid.json` and `sighash.json`, all vendored and pinned.

### `test/functional/test_framework/script_util.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/script_util.py
commit  3fd68a95e68b4c6f3bb6c59d41dd196001110f3a  2026-04-07
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered in part**. `script/script_pub_key.py` publishes the
`ScriptPubKey` constructors Core's `*_script` functions are, with the
`assert_*` and `is_*` pair beside them, `type_and_payload` and
`address`; `tests/script/script_pub_key_test.py` asserts them.
`bulk_vout` and `build_malleated_tx_package` build a transaction of a
chosen size or a package of a chosen shape for a node to accept or
refuse, and are tf2's.

### `test/functional/test_framework/segwit_addr.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/segwit_addr.py
commit  fe5e495c31de47b0ec732b943db11fe345d874af  2021-03-16
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered**. `bech32.py` is the codec with no bitcoin in it and
`b32.py` the bitcoin semantics on top, which is the split this file does
not make; `tests/bech32_test.py` and `tests/b32_test.py` assert each
half.

### `test/functional/test_framework/socks5.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/socks5.py
commit  4e8c4bc794c045beb678854e6e326fc04322c7c3  2026-08-04
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's (harness)**. A SOCKS5 server for the Tor tests.
`src/btclib` names SOCKS nowhere.

### `test/functional/test_framework/test_framework.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/test_framework.py
commit  fa7be0a8df9d99d4dd880afb4f48a9b197dca5b0  2026-08-27
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's (harness)**. The base class every functional test
derives from.

### `test/functional/test_framework/test_node.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/test_node.py
commit  de2adc308a421ea57414c4e28f9a75350df54f25  2026-08-11
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's (harness)**. It starts, stops and drives a `bitcoind`,
and wraps `bitcoin-cli`.

### `test/functional/test_framework/test_shell.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/test_shell.py
commit  fa5f29774872d18febc0df38831a6e45f3de69cc  2025-12-16
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's (harness)**. The framework driven from a python shell.

### `test/functional/test_framework/util.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/util.py
commit  6f4109b4489182bf5fa517630043df1829f00808  2026-08-25
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered in part**. `get_fee` is `fee.fee_from_vsize` over a
`FeeRate`, and what `satoshi_round` quantizes to is what `amount.py`'s
`valid_btc_amount`, `sats_from_btc` and `btc_from_sats` work in;
`util_xor` went to tf2 with the compressor by ISS 1123. The rest is the
harness: the assertions, the ports, the datadirs, the cookie files, the
configuration files and the waits.

### `test/functional/test_framework/v2_p2p.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/v2_p2p.py
commit  6a129983c9bf8efa1081f9a8b462c3635d1cfb39  2026-06-04
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's by decision**. ISS 1066 put BIP324's transport on tf2's
side. Its non-cipher halves are btclib's and are here:
`ecc/ellswift.py` is the key exchange and `kdf.hkdf` the key schedule.

### `test/functional/test_framework/wallet.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/wallet.py
commit  91586f701e1ebb12d8147feda7e78169a05da36f  2026-06-30
behind  0 revisions; that commit is the tip of the path
```

Verdict: **tf2's (harness)**. `MiniWallet` spends against a node's
chain. Its building blocks are btclib's -- `tx_builder.build_psbt`,
`coin_selection`, `psbt_signer` and `script/script_pub_key.py` -- so it
is tf2 written on btclib rather than a gap in btclib.

### `test/functional/test_framework/wallet_util.py`

```text
repo    bitcoin/bitcoin
path    test/functional/test_framework/wallet_util.py
commit  42330922dd8d5f96dbc0cc6a8e4092500029f89d  2026-05-27
behind  0 revisions; that commit is the tip of the path
```

Verdict: **covered in part**. `tx.input_weight` is
`calculate_input_weight`, with Core's own cases transcribed in
`tests/tx/tx_in_test.py`
([ISS 1067](https://github.com/btclib-org/btclib/issues/1067)), and
`b58.wif_from_prv_key` is `bytes_to_wif`. `get_generate_key`,
`test_address` and `WalletUnlock` need a node.

## The files that are not Python

The directory also carries `bip340_test_vectors.csv`,
`crypto/ellswift_decode_test_vectors.csv` and
`crypto/xswiftec_inv_test_vectors.csv`. Those are Core's copies of
bitcoin/bips files, and btclib vendors the bips originals instead, each
pinned against bitcoin/bips in `tests/_data/README.md`. No entry above
pins Core's copy, on purpose: pinning a copy of an upstream makes a
record drift for a reason that is not its subject's.
