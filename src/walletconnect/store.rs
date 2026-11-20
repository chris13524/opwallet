//! Sessions saved between runs.
//!
//! A settled session is only useful across restarts if its symmetric key is
//! kept, so the state file holds session and pairing keys (never anything
//! derived from a seed phrase). Whoever can read the file can read the
//! dapp's requests and answer them in the wallet's name, but cannot sign
//! anything: every signature still needs the seed phrase from 1Password.
//! The file is created `0600` inside a `0700` directory, is written atomically,
//! and the directory is locked so two running copies never serve the same
//! sessions.

use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::{Zeroize, Zeroizing};

use super::session::Metadata;

const STATE_FILE: &str = "sessions.json";
const LOCK_FILE: &str = "lock";
const VERSION: u32 = 1;

/// A wallet taking part in a saved session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAccount {
    pub name: String,
    pub address: String,
}

/// Everything needed to resume a settled session. Holds keys, so no `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub topic: String,
    /// Session symmetric key, hex.
    pub key: String,
    pub pairing_topic: String,
    /// Pairing symmetric key, hex.
    pub pairing_key: String,
    pub peer: Metadata,
    pub chains: Vec<String>,
    pub methods: Vec<String>,
    pub events: Vec<String>,
    pub accounts: Vec<StoredAccount>,
    #[serde(default)]
    pub active: usize,
    /// Unix time the session expires.
    pub expiry: u64,
    #[serde(default)]
    pub last_chain: Option<String>,
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub sign_ins: usize,
    #[serde(default)]
    pub requests_approved: usize,
    #[serde(default)]
    pub requests_rejected: usize,
}

impl Drop for StoredSession {
    fn drop(&mut self) {
        self.key.zeroize();
        self.pairing_key.zeroize();
    }
}

/// Contents of the state file.
#[derive(Default, Serialize, Deserialize)]
pub struct SavedState {
    #[serde(default)]
    pub version: u32,
    /// Ed25519 seed of the relay client identity, hex. Keeping it means the
    /// relay sees the same client before and after a restart.
    #[serde(default)]
    pub relay_key: Option<String>,
    #[serde(default)]
    pub sessions: Vec<StoredSession>,
}

impl Drop for SavedState {
    fn drop(&mut self) {
        if let Some(k) = &mut self.relay_key {
            k.zeroize();
        }
    }
}

/// Where state lives when `--state-dir` / `OPWALLET_STATE_DIR` is not given.
pub fn default_dir() -> Result<PathBuf> {
    default_dir_for("opwallet")
}

/// The default state directory of the program called `app`.
pub fn default_dir_for(app: &str) -> Result<PathBuf> {
    let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let base = if cfg!(target_os = "macos") {
        var("HOME").map(|h| h.join("Library/Application Support"))
    } else if cfg!(windows) {
        var("LOCALAPPDATA")
    } else {
        var("XDG_STATE_HOME").or_else(|| var("HOME").map(|h| h.join(".local/state")))
    };
    base.map(|b| b.join(app))
        .ok_or_else(|| anyhow::anyhow!("cannot find a home directory; pass --state-dir"))
}

/// Read `file` in `dir` as JSON; `None` when it does not exist yet.
pub fn read_json<T: DeserializeOwned>(dir: &Path, file: &str) -> Result<Option<T>> {
    let path = dir.join(file);
    let text = match fs::read_to_string(&path) {
        Ok(t) => Zeroizing::new(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
    };
    serde_json::from_str(&text).map(Some).with_context(|| {
        format!("{} is corrupt; delete it to forget all saved sessions", path.display())
    })
}

/// Read the saved sessions without taking the lock (for listings).
pub fn read(dir: &Path) -> Result<SavedState> {
    let path = dir.join(STATE_FILE);
    let state: SavedState = read_json(dir, STATE_FILE)?.unwrap_or_default();
    if state.version > VERSION {
        bail!("{} was written by a newer opwallet (version {})", path.display(), state.version);
    }
    Ok(state)
}

/// The state directory, locked for as long as this value lives.
pub struct SessionStore {
    dir: PathBuf,
    _lock: File,
}

impl SessionStore {
    /// Create the directory if needed and take its lock.
    pub fn open(dir: &Path) -> Result<Self> {
        let (lock, lock_path) = open_lock(dir)?;
        lock_exclusive(&lock).with_context(|| {
            format!(
                "another opwallet is already serving the saved sessions (it holds {}); \
                 use that one, or quit it first",
                lock_path.display()
            )
        })?;
        Ok(Self { dir: dir.to_path_buf(), _lock: lock })
    }

    /// Like [`SessionStore::open`], but wait for whoever holds the lock to
    /// let go (calling `waiting` first) instead of failing.
    pub fn open_waiting(dir: &Path, waiting: impl FnOnce()) -> Result<Self> {
        let (lock, lock_path) = open_lock(dir)?;
        if lock_exclusive(&lock).is_err() {
            waiting();
            lock_blocking(&lock)
                .with_context(|| format!("could not lock {}", lock_path.display()))?;
        }
        Ok(Self { dir: dir.to_path_buf(), _lock: lock })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn load(&self) -> Result<SavedState> {
        read(&self.dir)
    }

    /// Replace the state file atomically (write a private temp file, rename).
    pub fn save(&self, state: &SavedState) -> Result<()> {
        self.save_json(
            STATE_FILE,
            &SavedStateRef {
                version: VERSION,
                relay_key: state.relay_key.as_deref(),
                sessions: &state.sessions,
            },
        )
    }

    /// Replace `file` in the directory with `value` as JSON, atomically.
    pub fn save_json<T: Serialize>(&self, file: &str, value: &T) -> Result<()> {
        let path = self.dir.join(file);
        let tmp = self.dir.join(format!("{file}.tmp"));
        let mut body = Zeroizing::new(serde_json::to_string_pretty(value)?);
        body.push('\n');
        let _ = fs::remove_file(&tmp);
        let mut file = private_file(&tmp)?;
        file.write_all(body.as_bytes())
            .and_then(|_| file.sync_all())
            .with_context(|| format!("could not write {}", tmp.display()))?;
        drop(file);
        fs::rename(&tmp, &path).with_context(|| format!("could not replace {}", path.display()))
    }
}

#[derive(Serialize)]
struct SavedStateRef<'a> {
    version: u32,
    relay_key: Option<&'a str>,
    sessions: &'a [StoredSession],
}

fn open_lock(dir: &Path) -> Result<(File, PathBuf)> {
    create_private_dir(dir)?;
    let lock_path = dir.join(LOCK_FILE);
    let lock = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("could not open {}", lock_path.display()))?;
    Ok((lock, lock_path))
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
    }
    let mode = fs::metadata(dir)?.permissions().mode();
    if mode & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("could not make {} private", dir.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("could not create {}", dir.display()))
}

#[cfg(unix)]
fn private_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    File::options()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))
}

#[cfg(not(unix))]
fn private_file(path: &Path) -> Result<File> {
    File::options()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: flock on a descriptor we own; the lock is released when it closes.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn lock_exclusive(file: &File) -> Result<()> {
    file.try_lock().map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(unix)]
fn lock_blocking(file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    loop {
        // SAFETY: as in `lock_exclusive`, blocking this time.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e.into());
        }
    }
}

#[cfg(not(unix))]
fn lock_blocking(file: &File) -> Result<()> {
    file.lock().map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("opwallet-store-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn session(topic: &str) -> StoredSession {
        StoredSession {
            topic: topic.into(),
            key: "11".repeat(32),
            pairing_topic: "p".into(),
            pairing_key: "22".repeat(32),
            peer: Metadata { name: "Dapp".into(), ..Default::default() },
            chains: vec!["eip155:1".into()],
            methods: vec!["personal_sign".into()],
            events: vec![],
            accounts: vec![StoredAccount { name: "a".into(), address: "0xabc".into() }],
            active: 0,
            expiry: 42,
            last_chain: None,
            created: 1,
            sign_ins: 0,
            requests_approved: 3,
            requests_rejected: 0,
        }
    }

    #[test]
    fn saves_loads_and_locks() {
        let dir = temp_dir("roundtrip");
        let store = SessionStore::open(&dir).unwrap();
        assert!(store.load().unwrap().sessions.is_empty(), "no file means no sessions");
        let state = SavedState {
            version: 0,
            relay_key: Some("33".repeat(32)),
            sessions: vec![session("t1"), session("t2")],
        };
        store.save(&state).unwrap();
        let back = store.load().unwrap();
        assert_eq!(back.version, VERSION);
        assert_eq!(back.relay_key.as_deref(), Some("33".repeat(32).as_str()));
        assert_eq!(back.sessions.len(), 2);
        assert_eq!(back.sessions[1].topic, "t2");
        assert_eq!(back.sessions[0].requests_approved, 3);
        assert_eq!(back.sessions[0].accounts[0].address, "0xabc");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir.join(STATE_FILE)), 0o600);
            assert_eq!(mode(&dir), 0o700);
            // A second copy cannot take the lock while the first holds it.
            let err = SessionStore::open(&dir).err().unwrap();
            assert!(format!("{err:#}").contains("already serving"), "{err:#}");
        }
        // A waiting opener gets the lock once the holder lets go.
        let waited = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (flag, d) = (waited.clone(), dir.clone());
        let waiter = std::thread::spawn(move || {
            SessionStore::open_waiting(&d, || flag.store(true, std::sync::atomic::Ordering::SeqCst))
                .map(|_| ())
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        drop(store);
        waiter.join().unwrap().unwrap();
        #[cfg(unix)]
        assert!(waited.load(std::sync::atomic::Ordering::SeqCst), "it was told it had to wait");
        assert!(SessionStore::open(&dir).is_ok(), "lock is released on drop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_and_future_files_are_refused() {
        let dir = temp_dir("corrupt");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(STATE_FILE), "{nope").unwrap();
        assert!(format!("{:#}", read(&dir).err().unwrap()).contains("corrupt"));
        fs::write(dir.join(STATE_FILE), r#"{"version": 99}"#).unwrap();
        assert!(format!("{:#}", read(&dir).err().unwrap()).contains("newer"));
        let _ = fs::remove_dir_all(&dir);
    }
}
