# Architecture

btclib is a library that runs inside its caller's process. This page is its
high-level design: the major components, how they depend on one another,
and the properties those dependencies keep. What a user can expect of it
in terms of security is [SECURITY](./SECURITY.md), and why those
expectations hold is the [assurance case](./ASSURANCE_CASE.md).

## The curve arithmetic is btclib_ecc's

Elliptic-curve arithmetic and the cryptography built on it are
[btclib_ecc](https://github.com/btclib-org/btclib-ecc), a required
dependency: `curves`, `number_theory`, `kdf`, `ecc` and the SwiftEC map
of `ecc.ellswift`. btclib imports each name it uses from
`btclib_ecc` and publishes none of them: `btclib_ecc.curves.mult` is spelt
that way and no other, and `tests/all_test.py`'s
`test_no_module_exports_another_distributions_name` holds every `__all__`
of btclib to it. What those names raise is btclib_ecc's exception
classes, which derive from the built-in classes and not from
`BTClibException`, and a caller names them from `btclib_ecc.exceptions`.

btclib_ecc delegates secp256k1 to
[btclib-secp256k1](https://github.com/btclib-org/btclib-secp256k1), the
cffi bindings to Bitcoin Core's
[libsecp256k1](https://github.com/bitcoin-core/secp256k1), conditionally,
and btclib delegates its own few operations on the same condition.

- **One switch.** `btclib_ecc.curves.is_libsecp256k1_serving` answers
  whether the process delegates, and
  `btclib_ecc.curves.set_libsecp256k1_serving` sets it;
  `BTCLIB_ECC_NO_LIBSECP256K1` in the environment sets it off at
  import. btclib's own delegating calls, `ecc.ellswift.xdh`, the
  script engine's signature checks and `script.taproot`'s tweaks, ask it
  first and add their own conditions to it. SECURITY.md's *Limitations,
  not vulnerabilities* states those conditions operation by operation.
- **The Python arithmetic.** Whatever the switch and the call site
  decline runs btclib_ecc's Python arithmetic. That path is not dead
  code: it serves every other curve, every other hash function and a
  caller-imposed nonce, it answers for the point at infinity, which
  libsecp256k1 has no public key for, and it is the whole library in an
  install without the `secp256k1` extra. It is not constant-time, which
  SECURITY.md publishes as a known limitation.
- **The bindings are the authority on the answer.** The suite validates
  btclib's own Python arms against them. `tests/no_bindings_test.py`
  imports btclib in an interpreter with the bindings out of reach and
  compares what it computes with what the bindings compute, and
  `tests/py_arm_authority_test.py` records, for each of btclib's Python
  arms, which vectors published by somebody else reach it.
  `.github/workflows/py-arm-authority.yml` re-measures that record.

## Layers

Roughly bottom-up. The directions that hold without exception are the
substrate, `ecc` without `ecc.bms`, the pairs in the next section and the edge to
`btclib_wallet` below, each held by a test; elsewhere a module reaches up
where its subject asks for it, as `ecc.bms` does for the address a
message signature names.

- **the substrate**: `alias`, `exceptions`, `utils`
- **the curve and what is built on it**: btclib_ecc's `curves`,
  `number_theory`, `kdf` and `ecc`, in a distribution of their own, with
  btclib's `ecc.ellswift` beside them
- **bitcoin's hashes, integers and constants**: `hashes`, `var_int`,
  `var_bytes`, `obfuscation`, `consensus`, `amount`, `compressor`
- **networks, keys and addresses**: `network`, `base58`, `bech32`, `key`,
  `b58`, `b32`
- **the chain**: `script`, `tx`, `block`, `fee`, `policy`, `coinstats`,
  `muhash`
- **the wire**: `p2p`, `electrum`

`alias` holds the types the public API accepts, much of it taking anything
convertible rather than one type, and `exceptions` the errors it raises.
`consensus` holds the consensus constants and the per-network table, and
importing it imports nothing else of btclib, which `tests/imports_test.py`
asserts.

### What of the curve's layer is btclib's

Two modules under `ecc` are btclib's own, and `btclib.ecc` holds no other:

- `ecc.bms` names its signer by an address, so it imports `b32`, `b58`,
  `key` and `network`, and `ecc` imports it on demand rather than eagerly.
- `ecc.ellswift` is `xdh`, `XDH_TAG` and `ELL_SIZE`, BIP324's agreement on
  btclib_ecc's SwiftEC map, which is btclib's.

### Each pair is one idea split in two

| the codec or the arithmetic | the bitcoin semantics on top |
| --- | --- |
| `btclib.base58`: the encoding | `btclib.b58`: WIF, p2pkh, p2sh |
| `btclib.bech32`: the encoding | `btclib.b32`: p2wpkh, p2wsh, p2tr |

The right column imports the left one, and the left never imports the
right. So `btclib.b58` for an address, and `btclib.base58` for the
encoding on its own. Each of these modules states its direction in its
docstring, and `tests/imports_test.py` holds `btclib.base58` and
`btclib.bech32` to closures that do not reach the other column.

The same split lies between btclib_ecc's `curves` and its `ecc`, which
btclib imports in place of a pair of its own.

### Where a key's spelling is read

A caller states which half of a pair it holds, rather than leaving a size
or a format to decide it. `key.PubKeyData` is the SEC octets and the
network an address builder takes, and `key.PrvKeyData` the scalar, the
network and the compression flag `ecc.bms` signs with.

Each spelling of a key is read by the module that defines it:

- the scalar and the curve point in their octet spellings are facts about
  the curve, read by `btclib_ecc.curves.scalar_from_prv_key` and
  `btclib_ecc.curves.point_from_pub_key`
- the network and the compression, which a record carries and a key does
  not, are `key`'s
- a WIF is Base58Check with a prefix and a flag, so
  `b58.prv_key_data_from_wif` reads it and `b58.wif_from_prv_key` writes
  it
- an extended key is BIP32's format, parsed by `btclib_wallet.bip32`; a
  caller holding one parses it there and passes on the scalar or the
  point

### The chain and the wire

`script`, `tx` and `block` build and validate what goes on the chain, and
`script.engine` verifies a transaction against the consensus rules.
`p2p` is the wire format peers speak: the message envelope, its framing,
the message start of each network, and the payloads. `electrum` is the
Electrum server protocol. Both turn octets into objects and objects into
octets, and neither opens a socket: a caller reading from a connection
hands them what it read.

## What sits outside the package

- **The wallet side** (key derivation, mnemonics, PSBTs, output
  descriptors, signers and chain backends) is the `btclib-wallet`
  distribution, imported as `btclib_wallet`. It imports btclib, and
  nothing in btclib imports it: `tests/imports_test.py` holds that edge to
  one direction.
- **[bitcoin-core-rpc](https://github.com/btclib-org/bitcoin-core-rpc)** is
  a required dependency. `btclib.p2p.magic` takes the message start of
  each network from its `chains` module, which depends on nothing beyond
  the standard library. `btclib.p2p.magic` is the one module that imports
  that package, and no module loads `urllib.request` on its way to
  anything else, so a caller who parses messages pays nothing for a
  client it never uses. `tests/imports_test.py`'s
  `test_the_codec_does_not_pay_for_the_rpc_package` and
  `test_electrum_codec_stays_stdlib_light` hold both codecs to that.
- **Package data.** The networks are JSON under `src/btclib/_data/`, read
  once at import by `src/btclib/network.py`; the catalogued curves are
  btclib_ecc's package data.

## The public surface

Every module and every package declares `__all__`, and a public function
validates its inputs before a private twin does the work.
CONTRIBUTING.md's *The public surface* states both rules and names the
tests that hold them.
