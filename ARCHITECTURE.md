# Architecture

btclib is a library that runs inside its caller's process. This page is its
high-level design: the major components, how they depend on one another,
and the properties those dependencies keep. What a user can expect of it
in terms of security is [SECURITY](./SECURITY.md), and why those
expectations hold is the [assurance case](./ASSURANCE_CASE.md).

## The curve arithmetic is btclib_ecc's

Elliptic-curve arithmetic and the cryptography built on it are
[btclib_ecc](https://github.com/btclib-org/ellipticcurves), a required
dependency: `curves`, `number_theory`, `kdf`, `ecc` except `ecc.bms`, and
the SwiftEC map of `ecc.ellswift`. btclib binds each of those names again
under its btclib path, so `btclib.curves.mult` is
`btclib_ecc.curves.mult`, the same object; `tests/all_test.py`'s
`REEXPORTED` holds every such module to that. What those names raise is
btclib_ecc's exception classes, which derive from the built-in classes
and not from `BTClibException`.

btclib_ecc delegates secp256k1 to
[btclib-secp256k1](https://github.com/btclib-org/btclib-secp256k1), the
cffi bindings to Bitcoin Core's
[libsecp256k1](https://github.com/bitcoin-core/secp256k1), conditionally,
and btclib delegates its own few operations on the same condition.

- **One switch.** `curves.is_libsecp256k1_serving` answers whether the
  process delegates, and `curves.set_libsecp256k1_serving` sets it;
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
curve's layer, the pairs in the next section and the edge to
`btclib_wallet` below, each held by a test; elsewhere a module reaches up
where its subject asks for it, as `ecc.bms` does for the address a
message signature names.

- **the substrate**: `alias`, `exceptions`, `utils`
- **the curve**: `number_theory`, `curves`, bound again from
  btclib_ecc
- **what is built on a curve**: `ecc`, and `kdf` beside it, bound again
  from btclib_ecc but for `ecc.bms` and `ecc.ellswift.xdh`
- **bitcoin's hashes, integers and constants**: `hashes`, `var_int`,
  `var_bytes`, `consensus`, `amount`
- **networks, keys and addresses**: `network`, `base58`, `bech32`, `key`,
  `b58`, `b32`
- **the chain**: `script`, `tx`, `block`, `fee`, `coinstats`, `muhash`
- **the wire**: `p2p`, `electrum`

`alias` holds the types the public API accepts, much of it taking anything
convertible rather than one type, and `exceptions` the errors it raises.
`consensus` holds the consensus constants and the per-network table, and
importing it imports nothing else of btclib, which `tests/imports_test.py`
asserts.

### What of the curve's layer is btclib's

Two modules under `ecc` are btclib's own rather than btclib_ecc's:

- `ecc.bms` names its signer by an address, so it imports `b32`, `b58`,
  `key` and `network`, and `ecc` imports it on demand rather than eagerly.
- `ecc.ellswift` binds btclib_ecc's SwiftEC map again beside `xdh`,
  `XDH_TAG` and `ELL_SIZE`, BIP324's agreement on the map, which are
  btclib's.

### Each pair is one idea split in two

| the codec or the arithmetic | the bitcoin semantics on top |
| --- | --- |
| `btclib.curves`: `Curve`, `mult` | `btclib.ecc`: `dsa`, `ssa`, `bms` |
| `btclib.base58`: the encoding | `btclib.b58`: WIF, p2pkh, p2sh |
| `btclib.bech32`: the encoding | `btclib.b32`: p2wpkh, p2wsh, p2tr |

The right column imports the left one, and the left never imports the
right. So `from btclib.ecc import dsa` for a signature,
`from btclib.curves import mult` for a point multiplication, `btclib.b58`
for an address, and `btclib.base58` for the encoding on its own. Each of
these modules states its direction in its docstring, and
`tests/imports_test.py` holds `btclib.curves`, `btclib.base58` and
`btclib.bech32` to closures that do not reach the other column.

### Where a key's spelling is read

A caller states which half of a pair it holds, rather than leaving a size
or a format to decide it. `key.PubKeyData` is the SEC octets and the
network an address builder takes, and `key.PrvKeyData` the scalar, the
network and the compression flag `ecc.bms` signs with.

Each spelling of a key is read by the module that defines it:

- the scalar and the curve point in their octet spellings are facts about
  the curve, read by `curves.scalar_from_prv_key` and
  `curves.point_from_pub_key`
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
