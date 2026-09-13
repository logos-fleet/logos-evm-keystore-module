//! Writes that cannot leave a live key, or a half-written file, behind.
//!
//! Two shapes, because the two writers differ in who owns the write. We own the bytes of a
//! document, so it is staged as a file and renamed. `eth_keystore::encrypt_key` owns the
//! write of a vault — its whole public surface is path-based, one `File::create` straight
//! to the destination — so the directory it writes into is the only handle there is on it,
//! and the way to make that write atomic is to give it a temporary directory to write into
//! and rename the result out.

use std::io;
use std::path::{Path, PathBuf};

/// Prefix of the randomly-named file a document write stages under. Random so two
/// processes replacing the same document cannot collide on one staging path, prefixed so a
/// copy a SIGKILL leaves behind is still recognisably ours rather than unexplained.
pub const DOC_STAGE_PREFIX: &str = ".ks-stage-";

/// Set a path's mode. No-op off unix, where the enclosing directory ACL is the control.
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

/// Clear a directory's group and other bits, keeping the owner's. Tightens 0755 to 0700
/// the way a plain `set_mode(0o700)` did, but never LOOSENS: a directory an operator locked
/// down to 0500 stays at 0500, and the write that needed it refuses instead of quietly
/// reopening it.
pub fn tighten_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o700;
        set_mode(path, mode)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// THE DURABILITY BARRIER, and the one call site every publishing write here ends at.
///
/// It used to be an inline `#[cfg(unix)]` directory fsync, and natively that is still
/// exactly what it does. It is `logos_rust_sdk::storage::commit` now because the same
/// sources build a `web` variant, and there the barrier is not a formality: an emscripten
/// image has a filesystem, so every write in this module SUCCEEDS in a webview, reads back
/// correctly for the life of the page, and is gone on the next load unless something pushes
/// it into the browser's IndexedDB. That push is what the SDK's barrier is on emscripten.
///
/// One function, and every writer routed through it, so a new write path cannot be correct
/// natively and lossy on a phone — see the test at the bottom of this file.
///
/// Best-effort, unchanged: a failed barrier cannot make a rename non-atomic, only
/// non-durable across a power cut (or, on the web, across a page load), which this module
/// does not promise.
fn barrier(dir: &Path) {
    #[cfg(test)]
    BARRIERS.with(|n| n.set(n.get() + 1));
    let _ = logos_rust_sdk::storage::commit(dir);
}

// How many times `barrier` has been reached ON THIS THREAD. Tests only: the barrier has
// no observable effect on a native filesystem, and the property worth guarding is that
// every writer goes through it.
//
// Per-thread rather than global because the test harness runs the suite in parallel and a
// shared counter would make every other writing test this one's flake.
#[cfg(test)]
thread_local! {
    static BARRIERS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn barrier_count() -> usize {
    BARRIERS.with(|n| n.get())
}

/// Remove a published path and commit the removal.
///
/// A delete is a write. On a native filesystem the unlink is already durable enough for
/// what this module promises, so the barrier reads as ceremony; in a Wasm host a vault
/// deleted without one is BACK after the next page load, which is the same class of bug as
/// a lost write and worse in consequence. `Ok(false)` when there was nothing there — and
/// then nothing was written, so nothing is committed.
pub fn remove_published(path: &Path) -> io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                barrier(parent);
            }
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// A staging directory for a write we do not perform ourselves.
///
/// Named after what it holds rather than randomly, so a copy a SIGKILL leaves behind is
/// nameable — and therefore classifiable and deletable, which is the property that made the
/// group half's leftover recoverable. Removed on every exit this process can take: `?`,
/// early return, panic, unwind. The scan covers the one it cannot.
pub struct Stage(PathBuf);

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Stage {
    /// Fresh, empty and 0700, replacing any leftover of the same name.
    pub fn create(path: PathBuf) -> io::Result<Self> {
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)?;
        // DirBuilder::mode is masked by the umask, so the mode is set here, not requested.
        set_mode(&path, 0o700)?;
        Ok(Self(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Put `bytes` in the stage at `name`, 0600 from creation and synced. For a library
    /// whose only input is a PATH: the stage is the sole handle on where that path lands.
    pub fn write(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        use std::io::Write;
        let path = self.0.join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true); // O_EXCL: never adopt an existing path
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(path)
    }

    /// Move `name` out to `dest`. Restricted and synced while still inside the 0700 stage,
    /// so the file is never briefly world-readable at its real path, and the bytes are down
    /// before the rename that publishes them.
    pub fn promote(&self, name: &str, dest: &Path) -> io::Result<()> {
        let staged = self.0.join(name);
        set_mode(&staged, 0o600)?;
        std::fs::OpenOptions::new().write(true).open(&staged)?.sync_all()?;
        std::fs::rename(&staged, dest)?;
        if let Some(parent) = dest.parent() {
            barrier(parent);
        }
        Ok(())
    }
}

/// Replace `dest` with `bytes`: staged in `root` at 0600 from creation, synced, renamed.
/// A crash can leave the staged copy — which the scan reports — but never a truncated
/// destination, and never a destination that was briefly readable by anyone else.
pub fn write_doc(root: &Path, dest: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut f = tempfile::Builder::new().prefix(DOC_STAGE_PREFIX).tempfile_in(root)?;
    f.write_all(bytes)?;
    // The rename is only atomic with respect to a crash if the bytes are down first.
    f.as_file().sync_all()?;
    f.persist(dest).map_err(|e| e.error)?;
    barrier(root);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stage_is_removed_on_every_exit_this_process_can_take() {
        // The three ways `change_password` leaked a live account key: an early return past
        // the cleanup, a panic, and a normal exit that simply never reached it.
        let dir = tempfile::tempdir().unwrap();

        let early = || -> io::Result<()> {
            let stage = Stage::create(dir.path().join(".stage-early"))?;
            std::fs::write(stage.path().join("k.json"), "ciphertext")?;
            Err(io::Error::other("ENOSPC"))
        };
        assert!(early().is_err());
        assert!(!dir.path().join(".stage-early").exists(), "an early return left a key staged");

        let hit = std::panic::catch_unwind(|| {
            let stage = Stage::create(dir.path().join(".stage-panic")).unwrap();
            std::fs::write(stage.path().join("k.json"), "ciphertext").unwrap();
            panic!("ENOSPC");
        });
        assert!(hit.is_err());
        assert!(!dir.path().join(".stage-panic").exists(), "a panic left a key staged");

        {
            let stage = Stage::create(dir.path().join(".stage-ok")).unwrap();
            std::fs::write(stage.path().join("k.json"), "ciphertext").unwrap();
            stage.promote("k.json", &dir.path().join("k.json")).unwrap();
        }
        assert!(!dir.path().join(".stage-ok").exists());
        assert_eq!(std::fs::read_to_string(dir.path().join("k.json")).unwrap(), "ciphertext");
    }

    #[test]
    fn a_blocked_promotion_leaves_nothing_staged() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("blocked.json");
        std::fs::create_dir_all(&dest).unwrap();

        let stage = Stage::create(dir.path().join(".stage-blocked")).unwrap();
        std::fs::write(stage.path().join("k.json"), "ciphertext").unwrap();
        assert!(stage.promote("k.json", &dest).is_err());
        let path = stage.path().to_path_buf();
        drop(stage);
        assert!(!path.exists(), "a decryptable key outlived a failed rename");
    }

    #[test]
    fn a_staged_file_is_restricted_before_it_is_published() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let stage = Stage::create(dir.path().join(".stage-mode")).unwrap();
            assert_eq!(std::fs::metadata(stage.path()).unwrap().permissions().mode() & 0o777, 0o700);
            std::fs::write(stage.path().join("k.json"), "ciphertext").unwrap();
            set_mode(&stage.path().join("k.json"), 0o644).unwrap();
            let dest = dir.path().join("k.json");
            stage.promote("k.json", &dest).unwrap();
            assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_document_is_never_written_in_place_and_never_briefly_world_readable() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("doc.json");
        write_doc(dir.path(), &dest, b"{\"a\":1}").unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "{\"a\":1}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // A failed write leaves the destination byte-identical and nothing staged. The
        // staging name is random, so this blocks the write the only way that covers EVERY
        // name: the directory itself.
        set_mode(dir.path(), 0o500).unwrap();
        let failed = write_doc(dir.path(), &dest, b"{\"a\":2}");
        set_mode(dir.path(), 0o700).unwrap();
        assert!(failed.is_err(), "a failed staging must not report success");
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "{\"a\":1}");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "doc.json")
            .collect();
        assert!(left.is_empty(), "left staged: {left:?}");
    }

    /// EVERY PUBLISHING OPERATION REACHES THE BARRIER.
    ///
    /// Natively the barrier is the directory fsync this module always did, and a missing
    /// one costs durability across a power cut. In the `web` variant it is what pushes the
    /// image's filesystem into the browser's IndexedDB, and a missing one costs the vault:
    /// written, read back correctly for the life of the page, gone on the next load, with
    /// no error anywhere. Nothing observable distinguishes the two natively, so the guard
    /// is the count -- a new writer that publishes without going through `barrier` fails
    /// here rather than on a phone.
    #[test]
    fn every_published_write_and_removal_reaches_the_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let doc = dir.path().join("doc.json");

        let before = barrier_count();
        write_doc(dir.path(), &doc, b"{}").unwrap();
        assert_eq!(barrier_count(), before + 1, "write_doc did not commit");

        let stage = Stage::create(dir.path().join(".stage-barrier")).unwrap();
        stage.write("k.json", b"ciphertext").unwrap();
        let before = barrier_count();
        stage.promote("k.json", &dir.path().join("k.json")).unwrap();
        assert_eq!(barrier_count(), before + 1, "promote did not commit");

        let before = barrier_count();
        assert!(remove_published(&doc).unwrap());
        assert_eq!(barrier_count(), before + 1, "a removal did not commit");

        // Removing what is not there is not a write, so it is not a barrier either.
        let before = barrier_count();
        assert!(!remove_published(&doc).unwrap());
        assert_eq!(barrier_count(), before, "an absent path committed anyway");
    }

    #[test]
    fn two_writers_do_not_collide_on_one_staging_path() {
        // The fixed `groups.json.tmp` was a single path two processes both created. A
        // random name removes the collision outright rather than serialising around it.
        let dir = tempfile::tempdir().unwrap();
        let mut names = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let f = tempfile::Builder::new().prefix(DOC_STAGE_PREFIX).tempfile_in(dir.path()).unwrap();
            names.insert(f.path().file_name().unwrap().to_string_lossy().into_owned());
            std::mem::forget(f);
        }
        assert_eq!(names.len(), 8, "staging names collided: {names:?}");
        assert!(names.iter().all(|n| n.starts_with(DOC_STAGE_PREFIX)));
    }
}
