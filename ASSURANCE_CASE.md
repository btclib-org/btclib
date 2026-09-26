# Assurance case

[SECURITY](./SECURITY.md) states what a user can and cannot expect of
btclib in terms of security. This page argues why those expectations
hold: the threat model, the trust boundaries, how secure design
principles are applied, and how common implementation weaknesses are
countered. Each argument below names the file, the test or the workflow
that supports it; where SECURITY.md already states a fact, this page
points at it instead of repeating it. The components named here are the ones
[ARCHITECTURE](./ARCHITECTURE.md) describes.

## What is claimed

- **The answers are right.** A signature, a verification, a key, an
  address, a script's verdict and a transaction's validity agree with the
  reference each is defined by: libsecp256k1, Bitcoin Core, and the
  vectors the BIPs and the RFCs publish.
- **Malformed input is refused the way the library says it is.** A
  public function handed an argument it cannot use raises
  `BTClibTypeError` or `BTClibValueError`.
- **Parsing octets from outside costs what the protocol allows.** A
  length or a count read from the input is checked against a bound before
  anything is built from it.
- **Where a secret meets the curve, the protection is the one
  SECURITY.md states**, and no more: SECURITY.md says which operations
  cross into libsecp256k1, whose constant-time properties hold on the C
  side of that call, and which multiplication there is not constant time
  in its scalar; the Python arithmetic is published as not
  constant-time.
- **A published distribution is what this tree built.** SECURITY.md's
  *Supported versions* and the
  [package-content policy](./docs/source/package-content-policy.md) state
  how that is verified and what the files may hold.

## Threat model

btclib is a library in its caller's process. It loads no network client
and no way to start a process, and the only files it opens are its own
package data and its own distribution's metadata, so every input it has,
but for one environment variable, is one a caller handed it. The command
below lists the top-level name of every module `src/` imports, at any
depth of the code and in any spelling of the statement. Beside btclib's
own, what it lists is the dependencies `pyproject.toml` declares,
`btclib_secp256k1` being the `secp256k1` extra, and standard-library
modules none of which is a network client or a process launcher; `os` is
there for `os.environ` alone, and `importlib` to import btclib's own
submodules and read its version.

One of those dependencies, `bitcoin_core_rpc`, is an RPC client package,
and btclib does not load the client in it. `src/btclib/p2p/magic.py` is
the one module importing it, and it takes three names of the package's
`chains` vocabulary; the package's `__init__` imports `chains` and
`errors` eagerly and its `client` and `transport` only when one of their
names is asked for, which btclib never does, so nothing it loads opens a
socket. ARCHITECTURE.md's *What sits outside the package* describes that
edge, and `tests/imports_test.py`'s
`test_the_codec_does_not_pay_for_the_rpc_package` asserts that asking
`btclib.p2p` for a message start loads the package without
`urllib.request`.

```shell
python3 - <<'EOF'
import ast, pathlib
names = set()
for p in pathlib.Path("src").rglob("*.py"):
    for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
        if isinstance(n, ast.Import):
            names.update(a.name.split(".")[0] for a in n.names)
        elif isinstance(n, ast.ImportFrom) and n.level == 0:
            names.add(n.module.split(".")[0])
print(sorted(names))
EOF
```

**What is defended.**

- Private keys, nonces and shared secrets, against recovery from what
  btclib returns or raises, and from the timing of the calls that cross
  into libsecp256k1, the multiplication SECURITY.md lists as variable
  time in its scalar excepted.
- The correctness of every verdict, against an adversary who chooses the
  input: a forged signature accepted, an invalid transaction or block
  accepted, a valid one refused, or a consensus rule applied differently
  from Bitcoin Core.
- The caller's process, against octets built to make a parser raise an
  exception the library does not document, or allocate without bound.

**The adversaries.**

- A remote party supplying octets: a peer's p2p messages, an Electrum
  server's replies, a transaction, a block, a script or a signature
  received from anyone.
- A counterparty in a protocol: a co-signer in MuSig2 or FROST, the other
  side of a key agreement, the author of a public key or a signature to
  verify.
- An observer of timing on the same machine, for the calls that cross
  into libsecp256k1.
- A party tampering with a distribution between this tree and the user.

**What is not defended**, each stated in SECURITY.md's *Limitations, not
vulnerabilities*:

- side channels on the Python arithmetic, which is not constant-time and
  serves every call the dispatch declines, every call in an install
  without the bindings, and every call with the dispatch turned off
- memory disclosure: a secret in a Python object is not zeroized
- a secret handed to a delegated `_var` multiplication, which is
  variable time in its scalar
- the block cipher `ecc.ecies` takes from its caller, whose resistance to
  side channels is the caller's
- the operating system's random number generator, which btclib uses
  through `secrets` rather than seeding one of its own

Nor is the interpreter or the operating system btclib runs on: a library
shares its caller's process and has no defence against it.

## Trust boundaries

**The caller and the public API.** Arguments cross from the caller into
btclib at every public function, and each is validated there.
CONTRIBUTING.md's *The public surface* states the rule and names the
tests that drive it, `tests/input_validation_test.py` among them;
`tests/serialization_boundary_test.py` drives the same rule where an
object meets octets, text or json. The
caller is trusted with the choices the API offers it: a caller-imposed
nonce, a hash function, a curve, or `check_validity=False`. Some of those
choices select the Python arithmetic, and SECURITY.md states which.

**btclib and btclib_ecc.** The curve arithmetic and the schemes built
on it are btclib_ecc's, a btclib-org package btclib binds again under
its own paths. What they raise derives from the built-in exception
classes and not from `BTClibException`, as [ARCHITECTURE](./ARCHITECTURE.md)'s
*The curve arithmetic is btclib_ecc's* describes.

**btclib and the bindings.** Past this boundary is C code btclib does
not own. `curves.is_libsecp256k1_serving` decides each call, btclib's
own and btclib_ecc's alike, so whether anything crosses is decided by
one switch rather than at each call site. The bindings are trusted for
the answer, and the suite compares btclib's own Python arms against
them. A flaw on the far side is reported upstream, as SECURITY.md's
*What belongs here, and what belongs upstream* says.

**Octets from the network.** A p2p message, a block, a transaction, a
script and a witness come from parties btclib has no reason to trust.
`src/btclib/utils.py` states the parse contract: a field is as long as
its encoding says, and a complete octet string is one whole object.
`tests/parse_contract_test.py` walks the package for every public class
carrying a `parse`, and holds each to that contract or names the reason
it is excluded.
The bounds are Bitcoin Core's, under Core's names:
`src/btclib/p2p/limits.py` for a message and the counts in its payloads,
`src/btclib/tx/limits.py`, `src/btclib/block/limits.py` and
`src/btclib/script/limits.py` for what goes on the chain, and
`var_int.MAX_SIZE` in `src/btclib/var_int.py` for any length or count
with no bound of its own. The script engine in
`src/btclib/script/engine/` runs a script it received against the
consensus rules and the limits Core applies to it. An Electrum reply is
json, and `electrum.decode_response` refuses a line that is not a
well-formed answer to the request it is matched to.

**Files.** btclib opens no file a caller names. What it reads is its own
package data, the network tables under `src/btclib/_data/`, once, at
import, in `src/btclib/network.py`. A caller
reading a file hands btclib its contents, and `from_dict` is the
boundary a json document crosses: `tests/serialization_boundary_test.py`
holds it to the same refusals as any other input.

**The environment.** `BTCLIB_ECC_NO_LIBSECP256K1` is read once, by
btclib_ecc at import, and can only turn the delegation off.

## Secure design principles

Saltzer and Schroeder's principles, and the layering ARCHITECTURE
describes beside them.

- **Economy of mechanism.** One switch for the dispatch, as above, where
  a copy per call site could drift. Every error btclib defines derives
  from `BTClibException` (`src/btclib/exceptions.py`), and
  `BTClibValueError` and btclib_ecc's `BTClibEccValueError` both
  derive from `ValueError`, so `except ValueError` catches a value refused
  by either package.
- **Fail-safe defaults.** A function whose duration follows its operand
  ends in `_var`, and the plain name beside it is the one a secret may be
  handed, so a caller who does not choose gets the safer call:
  CONTRIBUTING.md's *A `_var` suffix means the operand decides the work*
  states it with the measurement behind each name. `check_validity`
  defaults to `True`, so a caller who passes nothing gets the check;
  `tests/check_validity_test.py` asserts that default for the wire-format
  classes it walks. A hash function that is
  not sha256 itself, by identity, sends a call down the Python path,
  never to an answer computed for a different function.
- **Complete mediation.** Every public function validates its inputs,
  and where it defers the work to a private twin, the twin trusts its
  inputs because its callers checked them (CONTRIBUTING.md's *The public
  surface*).
- **Open design.** The code, the vectors the suite answers to, and the
  limitations are all published: `tests/_data/README.md` says where every
  vendored vector came from and, for one copied from upstream, which
  upstream commit it matches, and SECURITY.md states what is not
  defended.
- **Least privilege.** The library holds no socket and runs no program,
  as the census under *Threat model* shows, `bitcoin_core_rpc`'s client
  and transport included, which btclib never loads. `btclib.p2p` and
  `btclib.electrum` turn octets into objects and back, and
  `tests/imports_test.py` holds both to import closures without
  `urllib.request`. The one environment variable btclib reads can only
  take the bindings away.
- **Psychological acceptability.** The choice that matters is made at
  the call site and read there: `mod_inv` beside `mod_inv_var`, `mult`
  beside `double_mult_var`. A verification answers `False` for a
  signature that does not verify and raises for an input it cannot read,
  so a caller can tell a forgery from a mistake (CONTRIBUTING.md's *The
  public surface*).
- **Layering.** The curve arithmetic does not import the schemes built
  on it, the codecs do not import the bitcoin semantics on top of them,
  and nothing in btclib imports `btclib_wallet`: `tests/imports_test.py`
  holds each of those edges.

**Constant time where it is claimed.** It is claimed only of
libsecp256k1: CONTRIBUTING.md's `_var` section sets out the tiers of
duration and puts nothing written in Python in the first. Which
operations cross into libsecp256k1, and which multiplication there is
not constant time in its scalar, is SECURITY.md's *Limitations, not
vulnerabilities*.

## Common implementation weaknesses

Weaknesses from MITRE's CWE list that a library of this kind is exposed
to, and what counters each.

- **Improper input validation (CWE-20).** The tests under *Trust
  boundaries*, and `tests/integer_policy_test.py`, which refuses a
  `bool` where an integer field is expected.
- **Uncaught exceptions on hostile input (CWE-248, CWE-755).**
  `tests/fuzz_test.py` asserts that every parser fails the way the
  library says it fails, whatever it is handed. The targets under `fuzz/`
  run under ClusterFuzzLite in `.github/workflows/fuzz.yml`, ranked by
  whether they are reached from the network before any signature is
  checked, and `tests/fuzz_corpus_test.py` checks that every seed of
  their corpus still parses.
- **Uncontrolled resource consumption (CWE-400, CWE-770).** The bounds
  under *Trust boundaries*, read before anything is built.
- **Observable timing (CWE-208).** The `_var` convention and the
  delegation above; what is left is published in SECURITY.md.
- **Weak randomness (CWE-330, CWE-338).** Randomness comes from `secrets`
  (SECURITY.md), and ruff's flake8-bandit rules, selected with the rest
  of `ALL` in `pyproject.toml`, flag a call into the `random` module
  under `src/`. A `dsa` or `ssa` nonce the caller does not impose is
  derived by RFC 6979 or by BIP340, each checked by btclib_ecc's suite
  against the vectors its specification publishes.
- **Improper verification of a signature (CWE-347).** A scheme whose
  specification publishes vectors is checked against them, by
  btclib_ecc's suite for the schemes that package carries, and the
  script engine against Bitcoin Core's own script, transaction and
  sighash vectors, all pinned in `tests/_data/README.md` and compared
  with upstream on a schedule by `.github/workflows/vendored-vectors.yml`.
  `.github/workflows/integration-bitcoind.yml`, a required check on
  `main`, runs a regtest Bitcoin Core node against what btclib computes
  and emits: the UTXO-set statistics of `btclib.coinstats`, and a
  `version` message `btclib.p2p` serialized.
- **Exposure of sensitive information (CWE-209).** A refusal of octets
  that may be key material does not echo them: `tests/key_test.py` pins
  the messages the key parsers refuse with, and btclib_ecc's own
  `tests/ecc/dsa_test.py` asserts that a private key handed where a
  public key belongs is not repeated in the error.
- **Deserialization of untrusted data (CWE-502).** btclib reads only its
  own binary formats, its text encodings and json, through the parsers
  and `from_dict` above. The census under *Threat model* lists neither
  `pickle` nor `marshal` nor `shelve`, and of `bitcoin_core_rpc` btclib
  loads only `chains` and `errors`, which import neither. CodeQL analyses
  the code and the workflows in `.github/workflows/codeql.yml`.
- **Type confusion (CWE-843).** mypy runs with `strict = true`
  (`pyproject.toml`) over the library and the suite, as a hook of the
  lint gate in `.pre-commit-config.yaml`.
- **Code that is wrong and still passes.** Line and branch coverage of
  the library and of the suite is held at 100% by `fail_under` in
  `pyproject.toml`, and mutation testing, profiled under
  `.github/mutation/` and run by `.github/workflows/mutation.yml`, asks
  whether the suite notices a line that is wrong.
- **Supply chain.** SECURITY.md's *Supported versions* describes the
  attestations and the bill of materials. `uv.lock` pins every
  dependency, and CONTRIBUTING.md's *The environment and the gates*
  states that every job installs with `--locked`. Every third-party
  action is pinned to a commit sha, the organization's own reusable
  workflows being called at `@main` as `.github/zizmor.yml` permits and
  gives the reason for; `actionlint`, `zizmor` and `detect-secrets` run
  as hooks in `.pre-commit-config.yaml`.

**Upstream.** A vendored vector that disagrees with the rule it tests is
kept byte for byte, so that its pin still compares, and the disagreement
is reported to the project that publishes it: `tests/_data/README.md`
records the report beside the file, as it does for
[python-bitcoinlib#323](https://github.com/petertodd/python-bitcoinlib/issues/323).
