# Repository instructions

Every session works in its own worktree from its first edit; never work in the
primary checkout.

Follow [CONTRIBUTING.md](./CONTRIBUTING.md) for issues, pull requests,
local gates, and worktree setup and cleanup. Use
[REVIEWING.md](./REVIEWING.md) for reviews and
[ARCHITECTURE.md](./ARCHITECTURE.md) for design. Read
[REPOSITORY.md](./REPOSITORY.md) before changing workflows or repository
settings, and [SECURITY.md](./SECURITY.md) for vulnerability reporting.

Choose the least capable model that can reliably complete the task: use a fast
model for straightforward execution, a reasoning-focused model for multi-step
work, and the most capable available model for difficult or ambiguous problems.
Increase capability if progress stalls.

Read `ARCHITECTURE.md` before changing `src/btclib/ecc/`; it defines the
module boundaries and the Python and bindings paths.

Never state how many of anything a file holds. Tests enforce this in
`CHANGELOG.md`, `RELEASE_NOTES.md`, and `tests/_data/README.md`;
`SECURITY.md` is maintained by hand. A count of what upstream published
is the exception.

rust-bitcoin fuzz builds replace hashes and secp256k1 with stubs. Its
qa-assets may therefore contain fake hashes and signatures; see
`tests/integration/qa_assets_test.py` and `fuzz/rustflags.sh` before
treating a replay as a real hash or signature check.

`Block.parse`, `Block.serialize`, and `Block(...)` use mainnet's
proof-of-work limit by default. See `Block.assert_valid` for checking
another network.
