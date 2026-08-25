# A command line interface for btclib

Draft proposal. Nothing described here is implemented, and no name below
is settled: the last section lists the decisions this needs before any
code is written. Every measurement quoted carries the command that
produced it, so it can be checked against a tree that has moved.

## What a command line is for here

btclib is a library for teaching, learning and using bitcoin, and a
command line is the shortest path from a BIP to something a reader can
run. `btclib b32 p2wpkh 02cc...` is one line on a slide; the same answer
in Python is an interpreter, an import and a print.

Three audiences, in the order they matter:

1. the reader of the documentation and of the BIPs, who wants the
   worked example to be runnable rather than quotable;
1. the person checking one value — an address, a checksum, a sighash, a
   descriptor — for whom opening a REPL is heavier than the question;
1. the shell script: conformance runs, exercises graded automatically,
   cross-checks against Bitcoin Core's `bitcoin-cli` where both tools
   answer the same question.

What it is not for is being a wallet. `src/btclib/keystore.py` already
draws that line for the library — no utxo tracking, no balances, no persistence
to disk, no encryption at rest — and the command line inherits it whole:
a tool that cannot see the chain cannot spend, and one that writes no
file cannot remember. Every command is a pure function of its arguments,
the `fetch` group excepted, and that is the property that makes the whole
surface testable in process.

## Electrum as the feature list, not as the shape

Electrum's `electrum/commands.py` declares each command with the
resources it needs — `w` a wallet file, `n` a network connection, `p` a
password, `l` a Lightning node — and that flag is the mapping to btclib,
read off the source rather than guessed:

```shell
gh api -H "Accept: application/vnd.github.raw" \
    "/repos/spesmilo/electrum/contents/electrum/commands.py"
```

Commands flagged `w`, `n` or `l` need something btclib does not have. The
ones flagged with the empty string are the offline ones, and setting
aside the `config` commands and the two that write a wallet file
(`create`, `restore`), they are very nearly the list btclib can answer
today: `deserialize`, `serialize`, `validateaddress`, `createmultisig`,
`convert_xkey`, `make_seed`, `verifymessage`,
`signtransaction_with_privkey`, `encrypt` and `dumpprivkeys`.

The shape is where the two part company. Electrum's CLI is the remote
control of a daemon: `electrum daemon` runs, and each command is a
JSON-RPC call into a process that holds the wallet and the server
connection. btclib has no daemon and no state to keep one for, so the
btclib command line is a program that starts, computes and exits.

What btclib can offer that Electrum has no reason to expose is the more
interesting half of the surface: curve arithmetic, the script engine,
PSBT field-level work, descriptors, proof-of-work and difficulty
arithmetic, and three mnemonic standards where Electrum reads two.

## The naming rule

**Every name in the command line is a name in the library.** Precisely:

- the command path is the import path — `btclib ecc dsa sign` is
  `btclib.ecc.dsa.sign`, `btclib b58 p2pkh` is `btclib.b58.p2pkh`;
- the command name is the function name with `_` written `-`;
- the option name is the parameter name with `_` written `-`, and its
  default is the function's default.

**The command tree is `__all__` minus the recorded exclusions.** Every
module and package of the library declares one, at every depth, so the
commands of a group are the names its list holds, and the only decision
left is the short list of published modules that carry no commands — empty
today, for the reason Phase 4 gives, and the test that builds the tree is
to assert that list rather than discover it. What
the published tree settles is everything else: `btclib script serialize`
and `btclib bip32 derive` sit on the group because those two packages
re-export them, while `sig_hash` and `bip39` are not re-exported and
become subgroups — `btclib script sig-hash legacy`, and
`btclib mnemonic bip39 seed-from-mnemonic`. `ecc.__all__` names its
schemes as submodules, so even the subgroups are in a list the library
already maintains for its own reasons.

**The traversal contract**, which issue #338 settled and
`tests/all_test.py` holds:

1. every non-private module and package declares its own `__all__`; an
   empty list is valid where a module has no public surface of its own,
   and declaring nothing is not;
1. `btclib.__all__` is the root of the tree: the packages and top-level
   modules of the library, `getattr` answering each on a fresh
   interpreter through a module `__getattr__` that imports it on demand.
   The metadata — `name`, `__version__` — is not part of the tree;
1. a module-valued name in a list is an edge, and it is a submodule of
   the module publishing it, so the command path is the import path by
   construction rather than by convention;
1. a module declares its surface whether or not its parent publishes an
   edge to it. `psbt.psbt_utils` and `curves.curve_group` say what they
   hold and are reachable by import; the walk never arrives, so no
   command comes of them. Being a group is the parent's decision, and
   being declared is the module's;
1. a public name a module keeps out of its list is recorded, in the
   module docstring and in that test file's `UNEXPORTED` table.

Point 4 is what makes the mirror implementable from outside this
repository: nothing unpublished can be reached, because the walk follows
`__all__` and what must not be reached is what nothing published. What it
does not settle is the converse — a module can be published and still carry
no commands — and that is the exclusion list above rather than a property of
the tree, because the tree cannot express it. One entry, asserted by the
walker's own test, is the whole of it.

Nothing is renamed for the shell, and no verb is invented. So the command
line reads `btclib mnemonic bip39 mnemonic-from-entropy`, which is long;
`btclib b58 wif-from-prv-key`, which is longer than `dumpprivkey`; and
`btclib base58 encode`, matching `base58.encode` — the first of the
renamings two sections below, since a stutter the mirror once showed
(`base58 b58encode`) is a stutter the library no longer has.

That price is worth paying, for a reason the README states about the
library: it "is often refactored for improved clarity, without care for
backward compatibility". An invented command vocabulary is a second set
of names that a refactor has to carry, plus a mapping between the two
that nothing can check; the mirror is a mapping a test can check, and a
rename that forgets the command line fails in the pull request that made
it. The brevity an invented name would buy is what a shell alias buys
anyway, in the user's own shell, where it costs the project nothing.

The rule also settles the questions a CLI usually argues about. Two
`sign` commands are fine because the library has two, and the group tells
them apart exactly as the import does. `verify` and `assert-as-valid`
both exist because the library offers both. No command needs a `--quiet`
flag, because the pair already covers what one would be for.

### What the rule excludes

- private names: a leading underscore is not a command;
- the trailing-underscore variants (`dsa.sign_`, `ssa.verify_`), which
  take a pre-hashed message and a caller-supplied nonce. They are the
  library's expert door, and the argument they add is one a shell user
  cannot supply safely;
- functions whose arguments cannot be spelled as text: a `HashF`, a
  `CipherF`, the `ordering_func` of `Psbt.sort_inputs`. A hash function
  is recoverable by name and is the open question below; a caller's
  callable is not, and those overloads stay out;
- classes, which reach the command line through their own methods, and
  are the one place the mirror is not mechanical. A package's namesake
  type puts its methods on the group — `btclib tx parse` is `Tx.parse`,
  `btclib psbt b64encode` is `Psbt.b64encode` — while another class
  re-exported beside it becomes a subgroup of its own name:
  `btclib script script-pub-key p2ms` is `ScriptPubKey.p2ms`, and
  `btclib script witness serialize` is `Witness.serialize`. `script` is
  the package that forces the distinction, re-exporting `Script`,
  `ScriptPubKey` and `Witness` at once; everywhere else the namesake
  answers it alone.

A method needs a receiver, and on a command line the receiver is the
first argument, in the text form the class itself parses:
`btclib tx to-dict HEX` builds its `Tx` with `Tx.parse`,
`btclib psbt to-dict BASE64` builds its `Psbt` with `Psbt.b64decode`, and
`btclib descriptors address DESCRIPTOR` builds its `Descriptor` with
`descriptors.parse`. One text form per class, named in the help of the
group that holds it.

### The test that keeps it true

One test walks the click command tree, and for each leaf resolves the
module from the command path and `getattr`s the function from the command
name. It asserts that the attribute exists, that it is public, and that
every option corresponds to a parameter of that function. A command whose
function was renamed fails; a function that grew a parameter the command
does not offer is reported rather than failed, since not every parameter
belongs on a command line.

## What the mirror finds in `__all__`

Reading the command tree off `__all__` only works if `__all__` says what
each module offers, and it did not: measured over the ten packages that
declared one, half of them said the wrong thing, and no module of the
library declared one at all. What follows are the library findings the
command line made visible, and the pull requests that answered each.

**Whether a submodule is named is a per-package decision**, and it was
made once per package and nowhere written down: `ecc`, `mnemonic` and
`block` named theirs, while `curves`, `script`, `script.engine`, `tx`,
`psbt`, `bip32` and `fetch` named none. So `from btclib.ecc import dsa`
was blessed by a list and `from btclib.script import sig_hash`, which
works identically, was stated nowhere. It is the decision point 4 of the
contract above keeps -- a module declares its surface, its parent decides
whether the offer is a group -- so what changed is that each decision is
now written: `psbt` names `musig2`, `script` names the three subgroups the
tables below promise, and `curves`, `tx`, `bip32`, `fetch` and
`script.engine` name none, their submodules being where a flat surface is
defined rather than groups of their own.

**Missing.** Each of these is public, tested, and absent from its
package's list:

- `curves.CURVES`: `secp256k1` is exported and the registry it comes
  from is not, while `mnemonic` exports `WORDLISTS`;
- `script.addresses`, beside the `address` that is there; and
  `is_segwit` with `assert_segwit`, the one missing pair of nine — the
  file already carries a comment recording that this audit was run once,
  for `is_p2pkh`;
- the three nonce modules of `ecc`, where the docstring names "the
  RFC6979, BIP340 and sign-to-contract nonces" and `__all__` carried one
  loose function out of one of them, `bip340_nonce_`;
- `block.merkle_root_and_mutated_from_transactions`, where
  `bip34_commitment` from the same module is exported;
- `mnemonic.entropy` and `mnemonic.mnemonic`, the two submodules of six
  the list leaves out;
- `psbt.prevouts`, the outputs a psbt spends.

**Two findings did not survive being checked**, which is the other half of
what an audit is for. `bip32.slip132` could not be exported at all: it
imports `b58` and `b32`, which import `to_pub_key`, which imports
`btclib.bip32`, so naming it meant importing it and that closed a cycle —
73 tests failed with `cannot import name 'BIP32Key' from partially
initialized module`. That one was a defect after all, and issue #340 had
the cause rather than the symptom: `ecc.bms` imports `b58` and `b32` the
same way and `btclib.ecc` exports it without trouble, so what was wrong
was narrower — `bip32` was the only package a lower layer imports *and*
that held a module belonging to a higher one. The module is
`btclib.slip132` now, published at the root, which is why the tables below
spell it without a package in front. And `fetch.cookie_auth` is not
missing: `BitcoinCoreRpcClient` takes a `cookie_path` and reads the file at
every call, the node rewriting the cookie when it restarts, so a caller
passes a path and never a credential. In both cases what was missing was
the statement of why, not the name.

**Too much.** Each of these is used nowhere outside its own package:

```shell
grep -rn "\bserialize_bytes\b" --include="*.py" src/btclib \
    | grep -v "^src/btclib/psbt/"
```

- nine `psbt_utils` names in `psbt.__all__` — `serialize_bytes`,
  `deserialize_int`, `deserialize_map`, `deserialize_tx`,
  `encode_dict_bytes_bytes`, `decode_dict_bytes_bytes`,
  `serialize_dict_bytes_bytes`, `serialize_hd_key_paths` and
  `assert_valid_unknown` — which is more than half that list, and which
  the mirror would turn into commands nobody wants:
  `btclib psbt deserialize-int`;
- twelve flattened helpers in `mnemonic.__all__`, the nine
  `bin_str_entropy_from_*` among them, none of them used outside
  `src/btclib/mnemonic/`. The flattening is also why those names are so
  long: it dropped the module that said "entropy", so every name has to
  say it again;
- `ecc.bip340_nonce_`, a trailing-underscore expert variant sitting at
  the top of a package's public list.

**A rule that decides it**, and the command line needs one anyway: a
package's `__all__` is the types and functions a caller calls, plus every
submodule with a public surface of its own. Under it `psbt` loses nine
names and gains `musig2`, `mnemonic` gains `entropy` and `mnemonic`,
`script` gains the two missing pairs, `curves` gains `CURVES`, `ecc` gains
its three nonce modules and loses its one expert door.

Each of those is a pull request of its own, one per module: #319 `curves`,
\#320 `ecc`, #328 `script`, #329 `psbt`, #330 `block`, #332 `bip32`, #333
`mnemonic`, #334 `fetch`. The renamings below are proposals in those
bodies, and the three modules whose only finding is a rename are issues:
\#335 `base58`, #336 `descriptors`, #337 `tx` with the psbt trio. #338 asks
the question none of them can answer.

The larger gap was that no module declared an `__all__` at all — the
twenty-two at the top level, `b58`, `b32`, `descriptors`, `keystore`,
`network`, `amount`, `fee` and the rest, and the fifty-nine below the
packages. There "public" was a naming convention rather than a
declaration, and a command line reading the library's own word for it
would have been the first thing to depend on the difference. Issue #338
asked which of the two the library meant, and the answer is a declaration
everywhere: the contract above, with `btclib.__all__` the root a walker
starts from.

## Renamings worth making

Each of these is a library improvement first, and each is smaller than
the audit above.

1. **`base58.b58encode` and `b58decode` become `encode` and `decode`.**
   `bech32` already spells them so, and `b32.py` imports them bare:
   `from btclib.bech32 import decode, encode`. The module name carries
   the prefix, and a file that needs both codecs at once says so at the
   import — `from btclib.base58 import decode as b58decode`. What keeps
   its prefix, and rightly, is `BIP32KeyData.b58encode` and
   `Psbt.b64encode`: on a class the prefix names which encoding, rather
   than repeating the module.
1. **`pubkey` becomes `pub_key` in the taproot names.**
   `output_pubkey`, `output_prvkey`, `check_output_pubkey`, the
   `internal_pubkey` parameter and `ssa.point_from_bip340pub_key` are the
   only btclib-owned names spelled that way; `pub_key` is what the rest
   of the library writes, and every other `pubkey` in the tree is a
   libsecp256k1 entry point — `ec_pubkey_parse`, `pubkey_tweak_add` —
   which must not move.
1. **`descriptors.descriptor_checksum` becomes `checksum`, and
   `descriptor_from_address` becomes `from_address`.** `add_checksum`
   and `strip_checksum`, in that same file, already drop the prefix.
1. **`psbt.combine_psbts`, `join_psbts` and `finalize_psbt` become
   `combine`, `join` and `finalize`; `tx.join_txs` becomes `join`.** The
   same stutter and the same remedy at the import site. `extract_tx`
   keeps its noun, which names what comes out rather than what goes in.
1. **One name for the master extended key.** `bip32.rootxprv_from_seed`
   against `mnemonic.*.mxprv_from_mnemonic`, at 53 occurrences of
   `rootxprv` and 51 of `mxprv` over library and tests: two names for one
   object, not a stray. `mxprv` is the one that matches the `m/...`
   notation the derivation paths already use.
1. **`mnemonic.dispatch` stops being a name.** The module says how it
   works rather than what it answers; its two functions belong in
   `mnemonic.__all__` beside the rest, and the module drops out of it.

Not to be renamed, with the reason: `point_from_octets` beside
`bytes_from_point` reads asymmetric and is exact — `Octets` is the union
the function accepts, `bytes` is what it hands back.

One open question, larger than the six: `to_prv_key` and `to_pub_key`
read as verbs and stutter under the mirror, `btclib to-pub-key
pub-keyinfo-from-key` being the worst command in the tree. `to_pub_key`
already imports `to_prv_key`, so a single `btclib.keys` holding
`prv_keyinfo_from_prv_key`, `pub_keyinfo_from_key`, `point_from_key` and
`fingerprint` would be acyclic; it is 26 import sites inside the library,
and it is not part of this proposal.

## Argument and option types

`src/btclib/alias.py` is already the list of what the public API accepts, so
it is also the list of parameter types the command line needs. One click
`ParamType` per alias, and no ad-hoc conversion anywhere else:

| alias | its text form |
| --- | --- |
| `Octets` | hex, `-` for stdin, `@path` for a file |
| `String` | text as given, or hex if it is not valid text |
| `Integer` | decimal, or `0x`-prefixed hex |
| `Point` | a SEC point, compressed or not, as hex |
| `NetworkName` | a `Choice` over `NETWORKS` |
| `MnemonicLang` | a `Choice` over the wordlists |
| `BIP44ScriptType` | a `Choice`: p2pkh, p2wpkh-p2sh, p2wpkh, p2tr |
| `DerPath` | `m/84h/0h/0h/0/0`, as `der_path` already parses |
| `Curve` | a name from `CURVES`, `secp256k1` by default |
| `HashF` | no name in the library: see the open questions |

The `Literal` aliases are the reason this is cheap: `NetworkName`,
`MnemonicLang`, `BIP44ScriptType` and `ScriptType` each become a
`click.Choice` whose members are the `Literal`'s own, so the help text of
every command that takes one lists the accepted values without anybody
writing them down a second time.

## Output, streams and exit codes

- a single value goes to stdout alone: no label, no quotes, no trailing
  prose, so `$(btclib b58 p2pkh "$key")` is the address and nothing else;
- `bytes` are printed as hex, never as a Python repr;
- a tuple is printed one field per line, in the order the function
  returns them;
- a dataclass is printed as its `to_dict()`, as JSON: `Tx`, `Psbt`,
  `BlockHeader` and the rest already have that method, and it is the
  serialization the library itself chose;
- `--json` makes every command print JSON, so a script has one shape to
  parse rather than three;
- anything that is not the answer goes to stderr: a `BTClibUserWarning`,
  a progress line, a prompt. stdout stays substitutable.

Exit codes:

| code | meaning |
| --- | --- |
| 0 | the answer is on stdout |
| 1 | a btclib exception: the message on stderr, no traceback |
| 2 | a usage error, which is click's own code |
| 3 | `FetchError` or `RpcError`: the node, not the argument |

A traceback is available behind `--traceback`, and only there: a stack
trace is the library's diagnostic, and on a command line a malformed hex
string should read as one line saying so.

`verify` prints `true` or `false` and exits 0 either way — it answers a
question. `assert-as-valid` prints nothing and exits 1 on failure — it
makes a demand. The shell can use whichever it wants, and neither
behaviour had to be invented: the library already offers both functions
under those two names.

## Secrets

`argv` is readable by every process on the machine and is written to the
shell's history file. So no parameter that carries key material is
argv-only:

- `-` reads the value from stdin, which is the form a pipe and a heredoc
  both produce;
- `@path` reads it from a file, so a WIF on disk with the permissions its
  owner chose never becomes a process argument;
- click's `auto_envvar_prefix` gives every option an environment variable
  for free, which is the form a CI secret takes.

Each of the three is named in the help text of the parameter itself, not
only in the manual page nobody opens. And a command never prints a
private key it was not explicitly asked for: `keystore address-info`
reports the derivation path, `keystore prv-key` is the separate request,
exactly as `AddressInfo` and `KeyStore.prv_key` already split it.

## The framework

Four candidates, and the dependency closure of each measured rather than
recalled:

```shell
echo click > req.in
uv pip compile --universal --python-version 3.10 req.in
```

| framework | packages | note |
| --- | --- | --- |
| `argparse` | 0 | the standard library |
| `click` | 2 | `colorama` only on win32 |
| `typer` | 8 | click, rich, shellingham |
| `cyclopts` | 10 | rich, attrs, docstring-parser |

**The recommendation is click, behind an optional extra.** What was
measured, on click 8.4.2 and Python 3.10:

- it ships `py.typed`, and a three-level nested-group sample with typed
  callbacks passes `mypy --strict` with no ignore;
- `click.echo` is not `print`, so ruff's T20 stays enforced over the
  whole tree and `src/btclib/mnemonic/entropy.py` keeps being the only file
  that writes to a stream of its own;
- help output wraps at 80 columns whatever the terminal is — run with
  `COLUMNS=200`, no line exceeded 76 — which is the width MD013 and
  ruff's `max-doc-length` already hold this repository to;
- `click.testing.CliRunner` runs a command in process, so coverage sees
  the command line without a subprocess. At `fail_under = 100.0` that is
  not a convenience.

Against click, honestly: it is a dependency, and btclib has exactly one
today; and a command with six options is six lines of decorator stacked
above a function, which reads worse than the signature it is describing.

typer and cyclopts read the type hints, which for a fully annotated
library is the natural fit and would be the choice if it were free. It is
not: four and five times click's closure, most of it `rich`, for output
formatting this proposal does not want — a value on stdout is a value on
stdout, and a table drawn in box characters is not substitutable.

argparse costs nothing and is what a one-dependency library should try
first. What it costs instead is written in Electrum's own file, which is
the largest argparse command tree at hand: `commands.py` adds
`ArgumentParser.set_default_subparser` and replaces
`argparse._SubParsersAction.__call__` outright, the second as a
documented workaround for CPython's issue 23058, where a subparser
discards the arguments it did not recognize. Beyond the patches, every
command becomes an `add_parser` block, an `add_argument` block and an
entry in a dispatch table — which is the registry click's decorators
already are.

## Packaging and layering

**A separate repository, not `src/btclib/cli/`.** Issue #357 is the
decision, reversing what this section used to argue: the command line
is its own project, depending on published btclib releases the way any
other consumer does, rather than a subpackage of this one. What
follows is the design that still holds regardless of which repository
carries it, and what the split costs.

- the command tree still mirrors the library's own, one module per
  group; `__main__.py`, `[project.scripts]` and the `click` dependency
  are the new repository's `pyproject.toml`, not this one's;
- the layering argument still holds, one repository further out: the
  CLI imports btclib and nothing in btclib imports the CLI, so the
  command line is the top layer whichever repository it lives in;
- the mirror test (`## The test that keeps it true`) moves with it and
  loses its in-tree reach: it can walk only the `__all__` this package
  publishes, not the private tree a same-repository test could still
  see. Outside this repository there is no escape hatch past an
  incomplete `__all__`, which is why the audit (#319, #320, #328 to
  #334, #338, #340) went first and why the traversal contract above is
  stated as a contract: the new repository's walk depends on it, and
  `tests/all_test.py` is where it is enforced on this side;
- a version boundary now exists where the old, in-tree design had
  none. This repository's own README is the reason: a library "often
  refactored for improved clarity, without care for backward
  compatibility" is exactly why the new repository needs an explicit
  compatibility contract — a supported btclib version range, declared
  and tested, the way `btclib_secp256k1` is pinned from this side
  (issue #325) — where the in-tree design had a rename break the
  command in the same commit and needed no such contract at all.

## The command surface

Each block below lists a group and the commands on it; the function
behind each is the naming rule read backwards, so it is not repeated. The
phases are an order of work, not a promise of releases.

### Phase 1: codecs and chain formats

No key material, no network, no state. It is the half of the surface that
can be written and reviewed without deciding anything about secrets.

```text
base58        encode  decode
bech32        encode  decode
b58           wif-from-prv-key  address-from-h160  h160-from-address
              p2pkh  p2sh  p2wpkh-p2sh  p2wsh-p2sh
b32           address-from-witness  witness-from-address
              p2wpkh  p2wsh  p2tr  has-segwit-prefix
script        serialize  parse  script-to-dict  script-from-dict
              address  type-and-payload  op-int  sig-op-count
              is-p2pk  is-p2pkh  is-p2sh  is-p2ms  is-p2wpkh
              is-p2wsh  is-p2tr  is-nulldata, and the assert- of each
tx            parse  serialize  to-dict  from-dict  id  vsize
              weight  sig-op-count  join
block         parse  to-dict  bip34-commitment
block proof-of-work
              target-from-bits  bits-from-target  block-work
              chain-work  hash-rate  next-bits
descriptors   checksum  add-checksum  strip-checksum
              from-address  address  addresses
              script-pub-key
amount        btc-from-sats  sats-from-btc  valid-btc-amount
fee           fee-from-vsize  dust-threshold
```

No `list` command for the registries, and none is missing: `--network`
and `--curve` are `Choice` types, and click prints a `Choice`'s members
in the help of the option that takes it. `NETWORKS` and `CURVES` are
dictionaries rather than functions, so a command over either would have
been the first invented name in the tree, and the help text is where a
reader was going to look anyway.

Worked examples, in the shape a documentation page would quote:

```shell
btclib b58 p2pkh 02cc71...
btclib script type-and-payload 76a914...88ac
btclib tx to-dict @signed.hex
btclib descriptors add-checksum "wpkh(xpub6.../0/*)"
btclib fee dust-threshold --script-type p2wpkh
```

### Phase 2: keys, extended keys, mnemonics

The first phase that touches secrets, so the stdin and `@path` forms of
the octets parameter type have to be in place before it.

```text
to-prv-key    prv-keyinfo-from-prv-key  int-from-prv-key
to-pub-key    pub-keyinfo-from-key  pub-keyinfo-from-prv-key
              point-from-key  point-from-pub-key  fingerprint
curves        mult  double-mult  multi-mult  point-from-octets
              bytes-from-point  bytes-from-prv-key-int
bip32         rootxprv-from-seed  xpub-from-xprv  derive
              derive-from-account  crack-prv-key
              str-from-der-path  indexes-from-der-path
              int-from-index-str  str-from-index-int
slip132       address-from-xkey  address-from-xpub  p2pkh-xkey
              p2wpkh-xkey  p2wpkh-p2sh-xkey
bip44         address-from-der-path
bip85         entropy-from-der-path  mnemonic-from-root-key
              wif-from-root-key  xprv-from-root-key
              bytes-entropy-from-root-key  rolls-from-root-key
              base64-password-from-root-key
              base85-password-from-root-key
              drng-from-der-path  rsa-drng-from-root-key
mnemonic bip39
              mnemonic-from-entropy  entropy-from-mnemonic
              seed-from-mnemonic  mxprv-from-mnemonic
              lang-from-mnemonic
mnemonic electrum
              mnemonic-from-entropy  entropy-from-mnemonic
              mxprv-from-mnemonic  version-from-mnemonic
mnemonic slip39
              mnemonics-from-master-secret  master-secret-from-mnemonics
              mxprv-from-mnemonics  share-from-mnemonic
mnemonic dispatch
              seed-type-from-mnemonic  all-seed-types-from-mnemonic
mnemonic      collect-rolls  bin-str-entropy-from-rolls
              bin-str-entropy-from-random  bin-str-entropy-from-str
              normalize-mnemonic  indexes-from-mnemonic
              mnemonic-from-indexes
```

`collect-rolls` is the one interactive command in the whole surface: the
module already prompts with `input()` and already has the T201 exemption
that says so. It is the exception the rest of the design is measured
against, not a precedent.

`bip85` is where the class rule above meets a type with no text form of
its own. `BIP85DRNG` is a reader over a SHAKE256 stream, so its receiver
is the 64 entropy bytes as hex and its one method is `read`; and
`drng-from-der-path` and `rsa-drng-from-root-key` return that reader
rather than a value, which no rule in "Output, streams and exit codes"
prints. The decision below is how much of the stream a command squeezes.

### Phase 3: signatures, PSBT, the script engine

```text
ecc dsa       sign  verify  assert-as-valid  recover-pub-keys
              crack-prv-key
ecc ssa       sign  verify  assert-as-valid  batch-verify
ecc bms       sign  verify  assert-as-valid
ecc           diffie-hellman  ansi-x9-63-kdf  second-generator
ecc pedersen  commit  verify  assert-as-valid
ecc borromean sign  verify  assert-as-valid
ecc ecies     encrypt  decrypt  derive-keys
ecc musig2    key-agg  key-sort  apply-tweak  nonce-gen  nonce-agg
              session-values  sign  deterministic-sign
              partial-sig-verify  partial-sig-agg
script        output-pubkey  output-prvkey  input-script-sig
              check-output-pubkey
script sig-hash
              legacy  segwit-v0  taproot  from-tx  redeem-script
script taproot
              serialize  parse  leaf-hash  assert-valid-control-block
script engine verify-input  verify-transaction  verify-amounts
psbt          parse  b64encode  b64decode  to-dict  from-tx
              combine  join  finalize  extract-tx
              to-v0  to-v2  estimated-vsize  prevouts
descriptors   satisfy  update-psbt
keystore      addresses  address-info  next-address  address
              prv-key  sign
block merkle-proof
              verify  assert-as-valid
block mining  candidate-block-header  mine
```

`script engine verify-transaction` is the command with the most teaching
value in the list: a transaction, its prevouts and a flag set in, a
verdict out, with the engine that produced it being the one the test
suite runs against Bitcoin Core's own vectors.

### Phase 4: the network, and what sits on top

```text
fetch         get-tx  get-tx-out  get-block-count  get-best-block-id
bip21         parse  serialize
```

**The rpc client is not in the tree at all, and that settles a question
this proposal used to answer at length.** While
`btclib.bitcoin_core_rpc` was a module of this package it was in
`btclib.__all__` — the root publishes every top-level module, and the suite
asserts that — so a walker reached it, and what it found there was not a
command surface: exception classes, size and timeout constants, the
`HttpTransport` protocol, `http_request` and `urlopen_transport`, the client
class, and `cookie_auth`. That last one reads a node's credential and
returns it, so a command spelling of it would print a live rpc password to a
terminal and into whatever shell history or CI log is watching. It therefore
needed a recorded exclusion, by name, because no predicate separated it from
`alias` and `exceptions` mechanically.

It is now the
[bitcoin-core-rpc](https://github.com/btclib-org/btclib-bitcoin-core-rpc)
package, which btclib depends on and does not publish, so the walker never
reaches it and there is nothing to exclude. **The exclusion table is empty
today**, and the traversal contract above is the whole of the rule: the
command tree is the published tree. The node commands are the `fetch` group,
which is that client with the btclib types on top.

The table stays in the design even so, because the question it answers
recurs: a published module carrying no commands is a thing this tree can
grow again, and the answer of record is one line naming it beside the
reason, never a predicate over what a module exports.

The two `Fetcher` implementations are two option sets, not two command
trees: `--rpc-url` with a cookie file for `bitcoind`, `--esplora-url`
defaulting to `BLOCKSTREAM_INFO`. No configuration file. That is the same
decision `keystore` took for persistence and for the same reason — a
config file is a format and a search path that outlive the release that
chose them — and click's environment variables cover the case a file
would have been for.

## What Electrum has and this will not

| electrum | btclib |
| --- | --- |
| `deserialize` | `tx to-dict`, `psbt to-dict` |
| `serialize` | `tx from-dict` |
| `validateaddress` | `b58 h160-from-address`, `b32 witness-from-address` |
| `getpubkeys` | `to-pub-key pub-keyinfo-from-key` |
| `convert_xkey` | `slip132`, `bip32 xpub-from-xprv` |
| `getmasterprivate` | `mnemonic bip39 mxprv-from-mnemonic` |
| `make_seed` | `mnemonic bip39 mnemonic-from-entropy` |
| `getseed` | `mnemonic bip39 seed-from-mnemonic` |
| `signmessage` | `ecc bms sign`, `keystore sign` |
| `verifymessage` | `ecc bms verify` |
| `createmultisig` | `script script-pub-key p2ms`, `descriptors address` |
| `encrypt` / `decrypt` | `ecc ecies encrypt` / `decrypt` |
| `gettransaction` | `fetch tx` |
| `getmerkle` | `block merkle-proof verify` |
| `listaddresses` | `keystore addresses` |
| `getunusedaddress` | `keystore next-address` |
| `getprivatekeys` | `keystore prv-key` |
| `ismine` | `keystore` membership |
| `signtransaction` | no Signer role in the library: see below |
| `getbalance`, `listunspent` | out of scope: no utxo view |
| `history`, `onchain_history` | out of scope: no wallet state |
| `payto`, `paytomany`, `sweep` | out of scope: no coin selection |
| `bumpfee` | out of scope: needs the two above |
| `broadcast` | not today: `Fetcher` reads, it does not send |
| `freeze`, `setlabel`, requests | out of scope: no persistence |
| `daemon`, `gui`, `stop` | out of scope: no daemon |
| lightning commands | out of scope |

Two rows are worth reading as findings rather than as omissions.

`signtransaction` has no btclib equivalent because BIP174's **Signer** is
the role the library does not implement: `Descriptor.update_psbt` is the
Updater, `finalize` the Finalizer and `extract_tx` the Extractor,
and between the second and the third there is a step a caller has to do
by hand with `sig_hash` and `ecc.dsa`. A command line makes that gap
visible in a way the library does not — `btclib psbt --help` would list
every role but one — which is an argument for implementing the Signer,
not for hiding the hole behind a command that composes it.

`broadcast` is the other: one method on `Fetcher`, and what turns the
PSBT commands into something a reader can finish. It is left out here
because a write path deserves its own decision — every other `fetch` call
is idempotent and this one is not.

## Testing and the gates

With the CLI in its own repository (see "Packaging and layering"
above), the gates below are that repository's to set up, mirroring
this one's conventions rather than sharing its configuration:

- `CliRunner`, in process, so no subprocess and no coverage gap;
- the mirror test above, which is what makes the naming rule a rule,
  walking whatever btclib's own `__all__` publishes rather than its
  private tree (a reach the split already costs, above);
- one test walks the whole command tree asking for `--help`, which also
  catches a command with no docstring — a docstring D102/D103 already
  require of the btclib function behind it, and with click the
  docstring *is* the help text;
- round trips are not restated here. `parse(serialize(x)) == x` is
  already asserted in btclib's own suite, and repeating it through argv
  tests argv. What this layer owes tests for is its own surface: the
  octets parameter type and its `-` and `@` forms, the exit codes, the
  stdout/stderr split, the JSON shape, and the secret never printed;
- a coverage floor of its own, and markdownlint/sphinx settings of its
  own for whatever documents the CLI, rather than this repository's.

## Documentation

The CLI's own documentation -- its README, its own sphinx or mkdocs
pages if it has any -- lives in the new repository, not here.
btclib's side of this is what a dependent project's is: at most a
mention where README.md already lists `btclib_secp256k1`, once the
new repository exists to link to. Nothing in this repository's own
CHANGELOG.md or RELEASE_NOTES.md is owed an entry for a project the CLI's
repository, not this one, releases and versions.

## The decisions this needs

1. **click behind an optional extra, or argparse in the library
   proper?** The recommendation is click; the counter-argument is that
   btclib's single dependency is a promise, and an extra is still a
   second name in `pyproject.toml`.
1. **The mirror rule, at full verbosity?** The alternative is a small
   alias table (`btclib address` for `b58 p2pkh` and friends), which
   costs a second set of names and a second thing to keep true.
1. ~~**Is the `__all__` audit a prerequisite or a consequence?**~~
   Decided: a prerequisite, and done. The eight package pull requests
   (#319, #320, #328 to #334), the three renamings (#335 to #337), the
   move of #340 and the declaration everywhere of #338 all landed before
   any command line exists, so the first version of the tree reads a
   surface somebody decided rather than one an import section left
   behind — and the traversal contract above is what it reads.
1. **Do the six renamings go in, and in one commit or six?** Each is
   source-breaking on its own, and RELEASE_NOTES.md's breaking-changes list is
   where a user reads them; one release absorbing all six is one entry
   to read instead of six spread over months.
1. **Does `HashF` get a name?** The command line needs
   `--hf sha256`, and the library has no table from a string to a hash
   function. Either the CLI keeps a private one — the only CLI-only
   vocabulary in the design — or `btclib.hashes` grows one, which the
   library itself could then use in its own error messages.
1. **What does a command that returns a stream print?** BIP85's DRNG is
   the first published type that is neither a value nor a dataclass:
   `btclib bip85 drng-from-der-path` has nothing to print until a length
   is named. Either those two commands take a `--num-bytes`, which is an
   option no parameter of the function corresponds to, or the group
   exposes `BIP85DRNG.read` alone and the path is spelled twice.
1. **Is `--json` off by default, or on?** Off reads better for a human
   and pipes better for `$(...)`; on gives a script one shape everywhere.
1. **Does `fetch` get a write path?** `broadcast` is one method, and it
   is the difference between a PSBT walkthrough that ends in a hex string
   and one that ends on the chain.
1. **Does the PSBT Signer come first?** The phase 3 list has every
   BIP174 role but that one, so either the command line ships with the
   gap in plain sight, or the Signer is written before it — which is
   library work this proposal has no business deciding on its own.
1. **Where does this document live?** ~~It is in `docs/proposals/` so
   that it stays out of btclib.org — `_config.yml` excludes `docs/` —
   and out of the sphinx build, which reads `docs/source/` only. An
   issue is the other candidate, and is where the discussion would
   happen anyway.~~ Decided: issue #357 is where the discussion
   continues, this document being the design reference underneath it
   rather than the place a decision gets made.
