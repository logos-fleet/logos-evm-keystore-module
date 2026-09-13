# logos-evm-keystore-module

A Logos `core` module (Rust, rust-first cdylib) that is the **keystore** for the
Logos multi-chain EVM wallet: scrypt-encrypted vaults, BIP39/BIP32 HD derivation,
and secp256k1 signing. It does **no networking**, and private keys never cross the
module boundary — only addresses, signed payloads, and (re-encrypted) keystore
JSON do.

Built on well-established crates: [`alloy`](https://github.com/alloy-rs/alloy)
(signing, tx encoding), [`eth-keystore`](https://crates.io/crates/eth-keystore)
(Web3 Secure Storage scrypt vaults), and `coins-bip39`/`coins-bip32` (HD wallets).

## Contract (`KeystoreModule`)

`create_mnemonic`, `import_mnemonic`, `new_account`, `import_private_key`,
`import_keystore_json`, `export_keystore_json`, `list_accounts`, `has_address`,
`delete_account`, `unlock`/`timed_unlock`/`lock`/`is_unlocked`,
`sign_transaction` (legacy EIP-155 + EIP-1559), `sign_message` (EIP-191). Event:
`accounts_changed`. All structured values cross the IPC boundary as JSON strings.

## Persistence

Vaults live in a `logos_rust_sdk::storage` store, not in `std::fs`.

Natively the two are the same thing — the per-instance directory the host stamped into
the module context. Inside a Wasm host (this module's `web` variant, running in a
webview) they are not: an emscripten image *has* a filesystem, so a plain `std::fs` write
would succeed, read back correctly for the life of the page, and be gone on the next
load, with no error anywhere. What the store adds is the one operation the plain
filesystem does not have:

> **`commit()` is the durability barrier.** A write is durable once it returns.

Every mutating method here ends at one — creating an account, importing one, and deleting
one, because a delete is a write and a vault deleted without a barrier is *back* after the
next page load. `every_mutation_commits` is the guard: nothing natively distinguishes a
write that committed from one that did not, so the property is asserted as a count.

`eth_keystore`'s public surface is path-based (`encrypt_key` takes a directory and
performs its own write), so those two calls go through `Storage::local_dir()` — the
escape hatch the storage contract documents for exactly this. A keystore over a store
with no directory behind it refuses rather than quietly doing something else.

`logos-rust-sdk` is therefore a plain (non-optional) dependency; `--no-default-features`
still drops the module glue and the lp_* link symbols.

## Build & test

```bash
# crypto core (no Logos runtime needed)
cd rust-lib && cargo test --no-default-features

# full module (Qt plugin) + .lgx package
nix build .#install   # -> result/modules/keystore_module/
nix build .#lgx
```

The crypto core is feature-gated away from the Logos glue so it stays
`cargo test`-able on its own; the builder compiles the glue via the default
`logos_module` feature. See the wallet plan for the full architecture.
