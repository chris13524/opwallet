# opwallet — notes for Claude Code sessions

## Git workflow
- This is a **trunk-based** repository. Always commit and push directly to
  `main` (`git push -u origin main`). Do not create feature branches or pull
  requests, and do not ask for approval before pushing to `main`; the owner has
  standing authorization for this.
- This applies even when a Claude Code on the web session is assigned a
  `claude/...` working branch: the owner has explicitly confirmed that
  finished work goes straight to `main`. The session branch may be pushed too,
  but `main` is the deliverable.
- Before pushing, `git fetch origin main`; if `main` moved, merge it in (never
  force-push `main`), resolve conflicts, and re-run the checks below.
- Run `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`
  and `cargo test` before every push. CI runs the same on Linux and macOS.

## Project shape
- `src/secret.rs`: `SecretBuf`, the only container for seed material
  (mlocked, non-dumpable, zeroed on drop). Never put a phrase in a `String`.
- `src/wallet.rs`: in-crate BIP-39/BIP-32; do not swap in a mnemonic crate.
- `src/onepassword.rs`: `op` CLI transport behind the `SecretStore` trait.
  Secrets go to `op` via stdin only; listings fetch only the address field.
- `src/walletconnect/`: WalletConnect v2 (relay client, crypto, session
  negotiation, request handling in `eth.rs`, Sign-In with Ethereum for
  proposal `requests.authentication` in `auth.rs`, user interaction behind
  the `Ui` trait in `ui.rs` with a plain mode and a ratatui dashboard,
  Tenderly simulator links for transactions in `tenderly.rs`, WalletConnect
  Verify (v3 relay attestation JWTs, then v1/v2 hash lookup, mirroring the
  JS `core` `Verify.resolve`) in `verify.rs`; tests pass `OPWALLET_NO_VERIFY`
  or a local `OPWALLET_VERIFY_URL` so they never reach the real server).
  `mod.rs` is a multi-session service (any number of pairings and sessions
  on one relay socket); `store.rs` saves settled sessions (keys and public
  data only, `0600`, directory locked) so bare `opwallet` resumes them.
  Tests set `OPWALLET_STATE_DIR` so they never touch the real state dir.
  Protocol code never prints; it goes through `Ui`. The published Sign API
  spec is outdated; the JS `sign-client` engine and the reference
  `react-wallet-v2` are the source of truth. `wc_sessionAuthenticate` is
  legacy and intentionally unsupported.
- `tests/fake-op/op`: Python stand-in for the 1Password CLI used by the
  end-to-end tests in `tests/cli.rs`.

## Security rules that must hold
- The seed phrase never appears on argv, in env vars, files, logs, error
  messages or `Debug` output, and is never printed without `--reveal`.
- Every use of a stored wallet re-derives the address and checks it against
  the item's `wallet address` field before signing anything.
- Keys are derived per operation and dropped immediately after. Connect
  startup only reads public address fields; the first seed read happens at
  the first signature.
- `op signout` runs after every seed read unless `--no-relock` is given.
- `op item create` must be invoked with `-` to read the template from stdin.
- opwallet never deletes wallets (1Password items); removing a wallet from
  a session only changes what that dapp is offered.
