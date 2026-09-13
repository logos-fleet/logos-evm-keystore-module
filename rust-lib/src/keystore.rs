//! Keystore core — pure, offline Ethereum key management and signing.
//!
//! No network, no Logos dependencies; this module is unit-testable on its own
//! (`cargo test`). Private keys live only inside a `Keystore`: on disk as
//! scrypt-encrypted JSON vaults (eth-keystore / Web3 Secure Storage), and in
//! memory only while an account is unlocked. Nothing here ever returns a raw
//! private key across its API — only addresses, signed payloads, and
//! (re-encrypted) vault JSON.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use logos_rust_sdk::storage::{FileStorage, Storage};

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::signers::local::{
    coins_bip39::{English, Mnemonic},
    MnemonicBuilder, PrivateKeySigner,
};
use alloy::signers::SignerSync;
use serde::Deserialize;
use thiserror::Error;

/// BIP-44 Ethereum account path, account 0, external chain: m/44'/60'/0'/0/<index>.
fn eth_derivation_path(index: u32) -> String {
    format!("m/44'/60'/0'/0/{index}")
}

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("account not found: {0}")]
    NotFound(String),
    #[error("account is locked: {0}")]
    Locked(String),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("vault error: {0}")]
    Vault(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("io error: {0}")]
    Io(String),
}

type Result<T> = std::result::Result<T, KeystoreError>;

/// An unlocked, in-memory signer with an optional auto-relock deadline.
struct Unlocked {
    signer: PrivateKeySigner,
    expires_at: Option<Instant>,
}

/// Manages a store of scrypt vault documents plus the set of currently-unlocked
/// signers. One vault per account, keyed `<lowercase-hex-address>.json`.
///
/// THE STORE IS THE SDK'S, NOT `std::fs`. Natively the two are the same thing —
/// a directory the host stamped into the module context. Inside a Wasm host
/// (the module's `web` variant, running in a webview) they are not: an
/// emscripten image HAS a filesystem, so a plain `std::fs` write here would
/// succeed, read back correctly for the life of the page, and be gone on the
/// next load, with no error anywhere. `logos_rust_sdk::storage` is that
/// difference, and `commit()` — the durability barrier — is the operation the
/// plain filesystem does not have. Every mutating method below ends at one.
pub struct Keystore {
    // Held as a Result rather than opened lazily so that `new` can stay
    // infallible (the glue constructs one in on_context_ready, where there is
    // nothing to report an error to) while a bad persistence path is still
    // reported at the first operation that needs the store, which is exactly
    // where `ensure_dir` used to report it.
    store: std::result::Result<Box<dyn Storage>, String>,
    unlocked: HashMap<Address, Unlocked>,
}

/// Fields of an unsigned transaction, as JSON from the caller. All numeric
/// fields are hex (`0x…`) or decimal strings to avoid precision loss across the
/// JSON boundary. `fee_mode` selects EIP-1559 (default) vs legacy.
#[derive(Debug, Deserialize)]
struct UnsignedTx {
    to: Option<String>,
    #[serde(default)]
    value: String,
    nonce: String,
    #[serde(default)]
    gas_limit: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    fee_mode: String, // "eip1559" (default) | "legacy"
    #[serde(default)]
    max_fee_per_gas: String,
    #[serde(default)]
    max_priority_fee_per_gas: String,
    #[serde(default)]
    gas_price: String,
}

fn parse_u128(s: &str, what: &str) -> Result<u128> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16)
    } else {
        s.parse::<u128>()
    };
    v.map_err(|e| KeystoreError::InvalidParams(format!("{what}: {e}")))
}

fn parse_u64(s: &str, what: &str) -> Result<u64> {
    Ok(parse_u128(s, what)? as u64)
}

fn parse_u256(s: &str, what: &str) -> Result<U256> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(U256::ZERO);
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        U256::from_str_radix(hex, 16).map_err(|e| KeystoreError::InvalidParams(format!("{what}: {e}")))
    } else {
        s.parse::<U256>().map_err(|e| KeystoreError::InvalidParams(format!("{what}: {e}")))
    }
}

fn parse_address(s: &str) -> Result<Address> {
    // Accept with or without `0x`, any case (no EIP-55 checksum requirement) —
    // decode the 20 raw bytes directly rather than going through the
    // checksum-validating FromStr.
    let t = s.trim();
    let hexpart = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    let bytes = hex::decode(hexpart).map_err(|e| KeystoreError::InvalidAddress(format!("{s}: {e}")))?;
    if bytes.len() != 20 {
        return Err(KeystoreError::InvalidAddress(format!("{s}: expected 20 bytes, got {}", bytes.len())));
    }
    Ok(Address::from_slice(&bytes))
}

/// The store key a vault is filed under: lowercase hex, no `0x`, `.json`.
/// Flat, which is what the storage contract requires and what this module
/// always used anyway, and stable enough that `list_accounts` reads an address
/// back out of it.
fn vault_key(addr: &Address) -> String {
    format!("{addr:x}.json")
}

impl Keystore {
    /// A keystore over `dir` — the per-instance persistence path the host
    /// stamped onto this module, plus whatever subdirectory the glue chose.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let store = FileStorage::open(dir.into())
            .map(|s| Box::new(s) as Box<dyn Storage>)
            .map_err(|e| e.to_string());
        Self { store, unlocked: HashMap::new() }
    }

    /// A keystore over an arbitrary store. THE TEST SEAM: the barrier has no
    /// observable effect on a native filesystem, so the only way to assert that
    /// every mutation reaches it is to count the calls.
    pub fn with_store(store: Box<dyn Storage>) -> Self {
        Self { store: Ok(store), unlocked: HashMap::new() }
    }

    fn store(&self) -> Result<&dyn Storage> {
        match &self.store {
            Ok(s) => Ok(s.as_ref()),
            Err(e) => Err(KeystoreError::Io(e.clone())),
        }
    }

    /// The vault's path on a real filesystem, for the parts of `eth_keystore`
    /// whose whole public surface is path-based (`encrypt_key` takes a
    /// directory and performs its own write; `decrypt_key` takes a file). This
    /// is the escape hatch `Storage::local_dir` documents, and it is why a
    /// keystore over a store with no directory behind it refuses rather than
    /// silently doing something else.
    fn vault_path(&self, addr: &Address) -> Result<PathBuf> {
        Ok(self.vault_dir()?.join(vault_key(addr)))
    }

    fn vault_dir(&self) -> Result<&Path> {
        self.store()?.local_dir().ok_or_else(|| {
            KeystoreError::Io(
                "this keystore's store has no directory behind it, and scrypt vault \
                 encryption is path-based"
                    .to_string(),
            )
        })
    }

    /// Generate a fresh BIP-39 mnemonic of `words` (12/15/18/21/24). Does NOT
    /// persist anything — the caller decides whether to import it.
    pub fn create_mnemonic(words: u32) -> Result<String> {
        let count = match words {
            12 | 15 | 18 | 21 | 24 => words as usize,
            _ => return Err(KeystoreError::InvalidParams(format!("word count must be 12/15/18/21/24, got {words}"))),
        };
        let mut rng = rand::thread_rng();
        let mnemonic = Mnemonic::<English>::new_with_count(&mut rng, count)
            .map_err(|e| KeystoreError::InvalidParams(e.to_string()))?;
        Ok(mnemonic.to_phrase())
    }

    fn persist_signer(&self, signer: &PrivateKeySigner, password: &str) -> Result<Address> {
        let dir = self.vault_dir()?.to_path_buf();
        let addr = signer.address();
        let key: B256 = signer.to_bytes();
        let mut rng = rand::thread_rng();
        let name = vault_key(&addr);
        eth_keystore::encrypt_key(&dir, &mut rng, key.as_slice(), password, Some(&name))
            .map_err(|e| KeystoreError::Vault(e.to_string()))?;
        // THE BARRIER. Natively an fsync; in a Wasm host what pushes the vault
        // into the browser's IndexedDB. Without it the account exists for the
        // life of the page and not one instant longer.
        self.store()?.commit().map_err(|e| KeystoreError::Io(e.to_string()))?;
        Ok(addr)
    }

    /// Create a brand-new random account, persisting its scrypt vault.
    pub fn new_account(&self, password: &str) -> Result<Address> {
        let signer = PrivateKeySigner::random();
        self.persist_signer(&signer, password)
    }

    /// Import a raw private key (hex, with or without 0x), persisting a vault.
    pub fn import_private_key(&self, priv_hex: &str, password: &str) -> Result<Address> {
        let signer = signer_from_hex(priv_hex)?;
        self.persist_signer(&signer, password)
    }

    /// Derive account `index` from a mnemonic (+ optional BIP-39 passphrase) and
    /// persist its vault under `password`.
    pub fn import_mnemonic(&self, phrase: &str, bip39_passphrase: &str, index: u32, password: &str) -> Result<Address> {
        let signer = signer_from_mnemonic(phrase, bip39_passphrase, index)?;
        self.persist_signer(&signer, password)
    }

    /// Import an existing scrypt keystore JSON, re-encrypting under `new_password`.
    pub fn import_keystore_json(&self, key_json: &str, password: &str, new_password: &str) -> Result<Address> {
        let tmp = tempfile_with(key_json)?;
        let key = eth_keystore::decrypt_key(&tmp, password).map_err(|e| KeystoreError::Vault(e.to_string()))?;
        let signer = PrivateKeySigner::from_slice(&key).map_err(|e| KeystoreError::InvalidKey(e.to_string()))?;
        self.persist_signer(&signer, new_password)
    }

    /// Export an account as a fresh scrypt keystore JSON (string), without
    /// touching the on-disk vault. Requires the vault password.
    pub fn export_keystore_json(&self, address: &str, password: &str) -> Result<String> {
        let addr = parse_address(address)?;
        let path = self.vault_path(&addr)?;
        // Validate the password decrypts, then re-emit canonical JSON contents.
        eth_keystore::decrypt_key(&path, password).map_err(|e| KeystoreError::Vault(e.to_string()))?;
        let bytes = self.store()?
            .read(&vault_key(&addr))
            .map_err(|e| KeystoreError::Io(e.to_string()))?;
        String::from_utf8(bytes).map_err(|e| KeystoreError::Io(e.to_string()))
    }

    pub fn list_accounts(&self) -> Vec<Address> {
        let mut out = Vec::new();
        // A store that cannot be opened or listed holds no accounts, which is
        // what an unreadable directory used to answer here.
        let keys = self.store().ok().and_then(|s| s.list().ok()).unwrap_or_default();
        for name in keys {
            if let Some(stem) = name.strip_suffix(".json") {
                if let Ok(addr) = format!("0x{stem}").parse::<Address>() {
                    out.push(addr);
                }
            }
        }
        out.sort();
        out
    }

    pub fn has_address(&self, address: &str) -> bool {
        match parse_address(address) {
            Ok(addr) => self.store().map(|s| s.exists(&vault_key(&addr))).unwrap_or(false),
            Err(_) => false,
        }
    }

    pub fn delete_account(&mut self, address: &str, password: &str) -> Result<bool> {
        let addr = parse_address(address)?;
        let path = self.vault_path(&addr)?;
        if !self.store()?.exists(&vault_key(&addr)) {
            return Ok(false);
        }
        // Require the correct password before destroying the vault.
        eth_keystore::decrypt_key(&path, password).map_err(|e| KeystoreError::Vault(e.to_string()))?;
        let store = self.store()?;
        if !store.remove(&vault_key(&addr)).map_err(|e| KeystoreError::Io(e.to_string()))? {
            return Ok(false);
        }
        // A DELETE IS A WRITE. Without the barrier a vault deleted inside a
        // webview is back after the next page load — the same class of bug as a
        // lost write, and worse in consequence.
        store.commit().map_err(|e| KeystoreError::Io(e.to_string()))?;
        self.unlocked.remove(&addr);
        Ok(true)
    }

    pub fn unlock(&mut self, address: &str, password: &str, ttl: Option<Duration>) -> Result<()> {
        let addr = parse_address(address)?;
        let path = self.vault_path(&addr)?;
        if !self.store()?.exists(&vault_key(&addr)) {
            return Err(KeystoreError::NotFound(address.to_string()));
        }
        let key = eth_keystore::decrypt_key(&path, password).map_err(|e| KeystoreError::Vault(e.to_string()))?;
        let signer = PrivateKeySigner::from_slice(&key).map_err(|e| KeystoreError::InvalidKey(e.to_string()))?;
        let expires_at = ttl.map(|d| Instant::now() + d);
        self.unlocked.insert(addr, Unlocked { signer, expires_at });
        Ok(())
    }

    pub fn lock(&mut self, address: &str) -> bool {
        match parse_address(address) {
            Ok(addr) => self.unlocked.remove(&addr).is_some(),
            Err(_) => false,
        }
    }

    pub fn is_unlocked(&mut self, address: &str) -> bool {
        match parse_address(address) {
            Ok(addr) => self.live_signer(&addr).is_some(),
            Err(_) => false,
        }
    }

    /// Fetch an unlocked signer, evicting it first if its TTL has elapsed.
    fn live_signer(&mut self, addr: &Address) -> Option<&PrivateKeySigner> {
        if let Some(u) = self.unlocked.get(addr) {
            if let Some(exp) = u.expires_at {
                if Instant::now() >= exp {
                    self.unlocked.remove(addr);
                    return None;
                }
            }
        }
        self.unlocked.get(addr).map(|u| &u.signer)
    }

    /// EIP-191 personal_sign over `message`. Returns 65-byte signature hex.
    pub fn sign_message(&mut self, address: &str, message: &str) -> Result<String> {
        let addr = parse_address(address)?;
        let signer = self.live_signer(&addr).ok_or_else(|| KeystoreError::Locked(address.to_string()))?;
        let sig = signer
            .sign_message_sync(message.as_bytes())
            .map_err(|e| KeystoreError::Signing(e.to_string()))?;
        Ok(format!("0x{}", hex::encode(sig.as_bytes())))
    }

    /// Sign an unsigned tx and return the raw, broadcast-ready signed tx hex
    /// (EIP-2718 envelope). Supports legacy (EIP-155) and EIP-1559.
    pub fn sign_transaction(&mut self, address: &str, unsigned_tx_json: &str, chain_id: u64) -> Result<String> {
        let addr = parse_address(address)?;
        let signer = self
            .live_signer(&addr)
            .ok_or_else(|| KeystoreError::Locked(address.to_string()))?
            .clone();

        let tx: UnsignedTx = serde_json::from_str(unsigned_tx_json)
            .map_err(|e| KeystoreError::InvalidParams(format!("tx json: {e}")))?;

        let to = match tx.to.as_deref() {
            Some(s) if !s.trim().is_empty() => TxKind::Call(parse_address(s)?),
            _ => TxKind::Create,
        };
        let value = parse_u256(&tx.value, "value")?;
        let nonce = parse_u64(&tx.nonce, "nonce")?;
        let gas_limit = parse_u64(&tx.gas_limit, "gas_limit")?;
        let input = parse_bytes(&tx.data)?;

        let raw = if tx.fee_mode.eq_ignore_ascii_case("legacy") {
            let t = TxLegacy {
                chain_id: Some(chain_id),
                nonce,
                gas_price: parse_u128(&tx.gas_price, "gas_price")?,
                gas_limit,
                to,
                value,
                input,
            };
            let sig = signer
                .sign_hash_sync(&t.signature_hash())
                .map_err(|e| KeystoreError::Signing(e.to_string()))?;
            let signed = t.into_signed(sig);
            TxEnvelope::Legacy(signed).encoded_2718()
        } else {
            let t = TxEip1559 {
                chain_id,
                nonce,
                gas_limit,
                max_fee_per_gas: parse_u128(&tx.max_fee_per_gas, "max_fee_per_gas")?,
                max_priority_fee_per_gas: parse_u128(&tx.max_priority_fee_per_gas, "max_priority_fee_per_gas")?,
                to,
                value,
                input,
                access_list: Default::default(),
            };
            let sig = signer
                .sign_hash_sync(&t.signature_hash())
                .map_err(|e| KeystoreError::Signing(e.to_string()))?;
            let signed = t.into_signed(sig);
            TxEnvelope::Eip1559(signed).encoded_2718()
        };

        Ok(format!("0x{}", hex::encode(raw)))
    }

    /// Sign a raw 32-byte `digest` with `address`'s key (ECDSA over the hash —
    /// no EIP-191/EIP-712 prefix). Returns the 65-byte signature hex.
    ///
    /// ⚠️ SECURITY: this signs an *opaque* hash. Unlike [`Self::sign_transaction`],
    /// whose fields a UI can display, the caller fully controls the preimage — and
    /// a 32-byte digest could be a transaction's `signature_hash`, so anyone able
    /// to reach an *unlocked* account here could obtain a draining-tx signature.
    /// Expose it only to trusted in-app modules signing protocol digests (an
    /// ERC-4337 UserOperation hash or an EIP-7702 authorization hash), never to
    /// untrusted input. The account must be unlocked (same gate as the others).
    pub fn sign_digest(&mut self, address: &str, digest_hex: &str) -> Result<String> {
        let addr = parse_address(address)?;
        let digest = parse_b256(digest_hex)?;
        let signer = self
            .live_signer(&addr)
            .ok_or_else(|| KeystoreError::Locked(address.to_string()))?;
        let sig = signer
            .sign_hash_sync(&digest)
            .map_err(|e| KeystoreError::Signing(e.to_string()))?;
        Ok(format!("0x{}", hex::encode(sig.as_bytes())))
    }
}

/// Parse a 32-byte hash hex (`0x`-prefixed or bare) into a `B256`.
fn parse_b256(s: &str) -> Result<B256> {
    let s = s.trim();
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let bytes = hex::decode(h).map_err(|e| KeystoreError::InvalidParams(format!("digest hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(KeystoreError::InvalidParams(format!(
            "digest must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

fn parse_bytes(s: &str) -> Result<Bytes> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Bytes::new());
    }
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let v = hex::decode(h).map_err(|e| KeystoreError::InvalidParams(format!("data: {e}")))?;
    Ok(Bytes::from(v))
}

fn signer_from_hex(priv_hex: &str) -> Result<PrivateKeySigner> {
    let h = priv_hex.trim();
    let h = h.strip_prefix("0x").or_else(|| h.strip_prefix("0X")).unwrap_or(h);
    let bytes = hex::decode(h).map_err(|e| KeystoreError::InvalidKey(e.to_string()))?;
    PrivateKeySigner::from_slice(&bytes).map_err(|e| KeystoreError::InvalidKey(e.to_string()))
}

fn signer_from_mnemonic(phrase: &str, passphrase: &str, index: u32) -> Result<PrivateKeySigner> {
    let mut builder = MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .derivation_path(eth_derivation_path(index))
        .map_err(|e| KeystoreError::InvalidParams(e.to_string()))?;
    if !passphrase.is_empty() {
        builder = builder.password(passphrase);
    }
    builder.build().map_err(|e| KeystoreError::InvalidParams(e.to_string()))
}

/// Write `contents` to a uniquely-named temp file and return its path. Used to
/// hand keystore JSON to eth-keystore (which is path-based).
fn tempfile_with(contents: &str) -> Result<PathBuf> {
    use std::io::Write;
    let mut path = std::env::temp_dir();
    // A best-effort unique name; collisions are astronomically unlikely and the
    // file is short-lived.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("logos-ks-import-{nanos}.json"));
    let mut f = std::fs::File::create(&path).map_err(|e| KeystoreError::Io(e.to_string()))?;
    f.write_all(contents.as_bytes()).map_err(|e| KeystoreError::Io(e.to_string()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use logos_rust_sdk::storage::Result as StorageResult;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use alloy::consensus::transaction::SignerRecoverable;
    use alloy::eips::eip2718::Decodable2718;
    use alloy::primitives::address;

    // Foundry's canonical test mnemonic → account 0.
    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";
    const ACCT0: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    const ACCT0_PK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    #[test]
    fn hd_derivation_matches_known_vector() {
        let signer = signer_from_mnemonic(TEST_MNEMONIC, "", 0).unwrap();
        assert_eq!(signer.address(), ACCT0);
        let signer1 = signer_from_mnemonic(TEST_MNEMONIC, "", 1).unwrap();
        assert_eq!(signer1.address(), address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"));
    }

    #[test]
    fn private_key_import_matches_address() {
        let signer = signer_from_hex(ACCT0_PK).unwrap();
        assert_eq!(signer.address(), ACCT0);
    }

    #[test]
    fn create_mnemonic_lengths() {
        assert_eq!(Keystore::create_mnemonic(12).unwrap().split_whitespace().count(), 12);
        assert_eq!(Keystore::create_mnemonic(24).unwrap().split_whitespace().count(), 24);
        assert!(Keystore::create_mnemonic(13).is_err());
    }

    /// A COUNTING STORE, so the barrier can be asserted at all.
    ///
    /// Nothing on a native filesystem distinguishes a write that committed from
    /// one that did not — the barrier is an fsync and its absence costs
    /// durability across a power cut. In a `web` variant it costs the vault:
    /// written, read back correctly for the life of the page, gone on the next
    /// load. So the property is asserted as a count.
    struct CountingStore {
        inner: FileStorage,
        commits: Arc<AtomicUsize>,
    }

    impl CountingStore {
        fn new(dir: &Path, commits: Arc<AtomicUsize>) -> Self {
            Self { inner: FileStorage::open(dir).unwrap(), commits }
        }
    }

    impl Storage for CountingStore {
        fn read(&self, key: &str) -> StorageResult<Vec<u8>> { self.inner.read(key) }
        fn write(&self, key: &str, bytes: &[u8]) -> StorageResult<()> { self.inner.write(key, bytes) }
        fn remove(&self, key: &str) -> StorageResult<bool> { self.inner.remove(key) }
        fn exists(&self, key: &str) -> bool { self.inner.exists(key) }
        fn list(&self) -> StorageResult<Vec<String>> { self.inner.list() }
        fn local_dir(&self) -> Option<&Path> { self.inner.local_dir() }
        fn commit(&self) -> StorageResult<()> {
            self.commits.fetch_add(1, Ordering::Relaxed);
            self.inner.commit()
        }
    }

    #[test]
    fn every_mutation_commits() {
        let dir = tempfile::tempdir().unwrap();
        let commits = Arc::new(AtomicUsize::new(0));
        let mut ks = Keystore::with_store(Box::new(CountingStore::new(dir.path(), commits.clone())));

        let before = commits.load(Ordering::Relaxed);
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        assert!(commits.load(Ordering::Relaxed) > before, "a persisted vault was not committed");

        // A delete is a write. Without the barrier a vault deleted in a webview
        // is BACK after the next page load.
        let before = commits.load(Ordering::Relaxed);
        assert!(ks.delete_account(&addr.to_string(), "pw").unwrap());
        assert!(commits.load(Ordering::Relaxed) > before, "a deleted vault was not committed");

        // ...and a delete that found nothing wrote nothing, so it commits nothing.
        let before = commits.load(Ordering::Relaxed);
        assert!(!ks.delete_account(&addr.to_string(), "pw").unwrap());
        assert_eq!(commits.load(Ordering::Relaxed), before, "an absent vault committed anyway");
    }

    /// The store is one flat namespace of vault documents, and everything it did
    /// not write is not an account. A staging file left by a crash mid-write is
    /// the case that actually occurs.
    #[test]
    fn a_stray_file_in_the_store_is_not_an_account() {
        let dir = tempfile::tempdir().unwrap();
        let ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        std::fs::write(dir.path().join(".logos-stage-1-x.json"), "half").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "hello").unwrap();
        assert_eq!(ks.list_accounts(), vec![addr]);
    }

    #[test]
    fn vault_roundtrip_and_listing() {
        let dir = tempfile::tempdir().unwrap();
        let mut ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        assert_eq!(addr, ACCT0);
        assert!(ks.has_address(&addr.to_string()));
        assert_eq!(ks.list_accounts(), vec![ACCT0]);

        // wrong password fails, correct password unlocks
        assert!(ks.unlock(&addr.to_string(), "wrong", None).is_err());
        ks.unlock(&addr.to_string(), "pw", None).unwrap();
        assert!(ks.is_unlocked(&addr.to_string()));
        ks.lock(&addr.to_string());
        assert!(!ks.is_unlocked(&addr.to_string()));
    }

    #[test]
    fn sign_message_recovers_signer() {
        let dir = tempfile::tempdir().unwrap();
        let mut ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        ks.unlock(&addr.to_string(), "pw", None).unwrap();
        let sig_hex = ks.sign_message(&addr.to_string(), "hello logos").unwrap();
        let sig: alloy::primitives::Signature =
            sig_hex.strip_prefix("0x").unwrap().parse::<alloy::primitives::Signature>().unwrap();
        let recovered = sig.recover_address_from_msg("hello logos").unwrap();
        assert_eq!(recovered, ACCT0);
    }

    #[test]
    fn locked_account_cannot_sign() {
        let dir = tempfile::tempdir().unwrap();
        let mut ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        assert!(matches!(ks.sign_message(&addr.to_string(), "x"), Err(KeystoreError::Locked(_))));
    }

    #[test]
    fn sign_digest_recovers_signer_from_prehash() {
        use alloy::primitives::b256;
        let dir = tempfile::tempdir().unwrap();
        let mut ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        ks.unlock(&addr.to_string(), "pw", None).unwrap();
        // A raw 32-byte digest (e.g. an ERC-4337 UserOperation hash) — signed with
        // no prefix, so it recovers via the prehash (not the EIP-191 msg) path.
        let digest = b256!("00000000000000000000000000000000000000000000000000000000deadbeef");
        let sig_hex = ks.sign_digest(&addr.to_string(), &digest.to_string()).unwrap();
        let sig: alloy::primitives::Signature =
            sig_hex.strip_prefix("0x").unwrap().parse().unwrap();
        assert_eq!(sig.recover_address_from_prehash(&digest).unwrap(), ACCT0);
        // Bare (no 0x) hex also accepted; wrong length rejected.
        assert!(ks.sign_digest(&addr.to_string(), &hex::encode(digest)).is_ok());
        assert!(ks.sign_digest(&addr.to_string(), "0x1234").is_err());
    }

    #[test]
    fn sign_digest_requires_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let mut ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        let digest = "0x00000000000000000000000000000000000000000000000000000000deadbeef";
        assert!(matches!(ks.sign_digest(&addr.to_string(), digest), Err(KeystoreError::Locked(_))));
    }

    #[test]
    fn sign_eip1559_recovers_signer() {
        let dir = tempfile::tempdir().unwrap();
        let mut ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        ks.unlock(&addr.to_string(), "pw", None).unwrap();
        let unsigned = serde_json::json!({
            "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "value": "0xde0b6b3a7640000",
            "nonce": "0x0",
            "gas_limit": "0x5208",
            "max_fee_per_gas": "0x77359400",
            "max_priority_fee_per_gas": "0x3b9aca00",
            "fee_mode": "eip1559"
        })
        .to_string();
        let raw = ks.sign_transaction(&addr.to_string(), &unsigned, 1).unwrap();
        assert!(raw.starts_with("0x02")); // typed EIP-1559 envelope
        // decode + recover
        let bytes = hex::decode(raw.strip_prefix("0x").unwrap()).unwrap();
        let env = TxEnvelope::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(env.recover_signer().unwrap(), ACCT0);
    }

    #[test]
    fn sign_legacy_recovers_signer() {
        let dir = tempfile::tempdir().unwrap();
        let mut ks = Keystore::new(dir.path());
        let addr = ks.import_private_key(ACCT0_PK, "pw").unwrap();
        ks.unlock(&addr.to_string(), "pw", None).unwrap();
        let unsigned = serde_json::json!({
            "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "value": "0x1",
            "nonce": "0x0",
            "gas_limit": "0x5208",
            "gas_price": "0x3b9aca00",
            "fee_mode": "legacy"
        })
        .to_string();
        let raw = ks.sign_transaction(&addr.to_string(), &unsigned, 1).unwrap();
        let bytes = hex::decode(raw.strip_prefix("0x").unwrap()).unwrap();
        let env = TxEnvelope::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(env.recover_signer().unwrap(), ACCT0);
    }
}
