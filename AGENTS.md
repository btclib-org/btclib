# Repository instructions

Keep the primary checkout clean and on `main`; use a separate worktree
for each task, following the setup and cleanup commands in
`CONTRIBUTING.md`.

Follow [CONTRIBUTING.md](./CONTRIBUTING.md) for issues, pull requests,
local gates, and worktree setup and cleanup. Use
[REVIEWING.md](./REVIEWING.md) for reviews and
[ARCHITECTURE.md](./ARCHITECTURE.md) for design, and read it before
changing `src/btclib/bms.py` or `src/btclib/ellswift.py`: it defines the
module boundaries and the Python and bindings paths. Read
[REPOSITORY.md](./REPOSITORY.md) before changing workflows or repository
settings, and [SECURITY.md](./SECURITY.md) for vulnerability reporting.

Choose the least capable model that can reliably complete the task: use a fast
model for straightforward execution, a reasoning-focused model for multi-step
work, and the most capable available model for difficult or ambiguous problems.
Increase capability if progress stalls.

Never state how many of anything a file holds. Tests enforce this in
`CHANGELOG.md`, `RELEASE_NOTES.md`, and `tests/_data/README.md`;
`SECURITY.md` is maintained by hand. A count of what upstream published
is the exception.

rust-bitcoin fuzz builds, all but the `hashes_*` targets, replace hashes
and secp256k1 with stubs. Its
qa-assets may therefore contain fake hashes and signatures; see
`tests/integration/qa_assets_test.py` and rust-bitcoin's
`fuzz/rustflags.sh` before treating a replay as a real hash or signature
check.

`Block.parse`, `Block.serialize`, and `Block(...)` use mainnet's
proof-of-work limit by default. See `Block.assert_valid` for checking
another network.

## Code Review Rules

Review against [REVIEWING.md](./REVIEWING.md). Its *The verdict* says
which review opens with a verdict line and what every other review
posts.

The heading is the one Codex's GitHub review asks for
([Customize what Codex reviews](https://learn.chatgpt.com/docs/third-party/github#customize-what-codex-reviews)).
