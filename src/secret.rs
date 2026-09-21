//! Memory-locked, zero-on-drop buffers for secret material.
//!
//! [`SecretBuf`] is the only container the seed phrase, BIP-39 seed and
//! derived private key bytes are ever placed in by this crate:
//!
//! * backed by its own anonymous `mmap` region, so it never shares a page
//!   with ordinary heap data;
//! * `mlock`ed, so the kernel will not write it to swap;
//! * marked `MADV_DONTDUMP` on Linux, so it is excluded from core dumps;
//! * zeroed with volatile writes before it is unmapped, and also whenever it
//!   is cleared or has to grow (the old region is wiped before release).
//!
//! On non-Unix targets it degrades to a `Zeroizing<Vec<u8>>`.

use std::{fmt, io};

use anyhow::{Context, Result, anyhow};

/// Environment variable that downgrades an `mlock` failure from an error to a
/// one-time warning. Only meant for sandboxes that forbid memory locking.
pub const ALLOW_UNLOCKED_ENV: &str = "OPWALLET_ALLOW_UNLOCKED_MEMORY";

#[cfg(unix)]
mod imp {
    use std::{
        io,
        ptr::NonNull,
        sync::atomic::{AtomicBool, Ordering},
    };

    static WARNED: AtomicBool = AtomicBool::new(false);

    pub struct Raw {
        ptr: NonNull<u8>,
        cap: usize,
        locked: bool,
    }

    // SAFETY: the mapping is uniquely owned; no interior aliasing.
    unsafe impl Send for Raw {}

    fn page_size() -> usize {
        // SAFETY: sysconf has no preconditions.
        let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if p <= 0 { 4096 } else { p as usize }
    }

    impl Raw {
        pub fn alloc(min_cap: usize) -> io::Result<Self> {
            let page = page_size();
            let cap = min_cap.max(1).div_ceil(page) * page;
            // SAFETY: anonymous private mapping; all arguments are valid.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    cap,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            let ptr = NonNull::new(p.cast::<u8>()).expect("mmap returned null");

            // SAFETY: p..p+cap is our own fresh mapping.
            let locked = unsafe { libc::mlock(p, cap) } == 0;
            if !locked {
                let err = io::Error::last_os_error();
                if std::env::var_os(super::ALLOW_UNLOCKED_ENV).is_none() {
                    // SAFETY: unmapping the region we just mapped.
                    unsafe { libc::munmap(p, cap) };
                    return Err(err);
                }
                if !WARNED.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "warning: mlock failed ({err}); secrets may be swapped to disk \
                         ({} is set)",
                        super::ALLOW_UNLOCKED_ENV
                    );
                }
            }
            #[cfg(target_os = "linux")]
            // SAFETY: advisory call on our own mapping; failure is harmless.
            unsafe {
                libc::madvise(p, cap, libc::MADV_DONTDUMP);
            }
            Ok(Self { ptr, cap, locked })
        }

        pub fn cap(&self) -> usize {
            self.cap
        }

        pub fn as_slice(&self) -> &[u8] {
            // SAFETY: mapping is valid, readable and `cap` bytes long.
            unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.cap) }
        }

        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            // SAFETY: mapping is valid, writable, `cap` bytes long and uniquely borrowed.
            unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.cap) }
        }
    }

    impl Drop for Raw {
        fn drop(&mut self) {
            zeroize::Zeroize::zeroize(self.as_mut_slice());
            let p = self.ptr.as_ptr().cast::<libc::c_void>();
            // SAFETY: releasing our own mapping exactly once.
            unsafe {
                if self.locked {
                    libc::munlock(p, self.cap);
                }
                libc::munmap(p, self.cap);
            }
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use std::io;
    use zeroize::Zeroizing;

    pub struct Raw(Zeroizing<Vec<u8>>);

    impl Raw {
        pub fn alloc(min_cap: usize) -> io::Result<Self> {
            Ok(Self(Zeroizing::new(vec![0u8; min_cap.max(1)])))
        }
        pub fn cap(&self) -> usize {
            self.0.len()
        }
        pub fn as_slice(&self) -> &[u8] {
            &self.0
        }
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }
}

/// Growable byte buffer living in locked, non-dumpable memory. See module docs.
pub struct SecretBuf {
    raw: imp::Raw,
    len: usize,
}

impl SecretBuf {
    /// Allocate an empty buffer able to hold at least `capacity` bytes.
    pub fn with_capacity(capacity: usize) -> Result<Self> {
        let raw = imp::Raw::alloc(capacity).map_err(|e| {
            anyhow!(
                "could not allocate locked memory for secrets: {e}. Raise the memlock limit \
                 (`ulimit -l`) or, if you accept secrets possibly being swapped to disk, set \
                 {ALLOW_UNLOCKED_ENV}=1"
            )
        })?;
        Ok(Self { raw, len: 0 })
    }

    /// A buffer of `len` zero bytes, ready to be written through [`as_mut_bytes`](Self::as_mut_bytes).
    pub fn zeroed(len: usize) -> Result<Self> {
        let mut b = Self::with_capacity(len)?;
        b.len = len;
        Ok(b)
    }

    /// Copy `data` into fresh locked memory.
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let mut b = Self::with_capacity(data.len())?;
        b.push_bytes(data)?;
        Ok(b)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.raw.cap()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw.as_slice()[..self.len]
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.raw.as_mut_slice()[..len]
    }

    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(self.as_bytes()).context("secret is not valid UTF-8")
    }

    /// Unused capacity, for reading directly into locked memory.
    pub fn spare_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.raw.as_mut_slice()[len..]
    }

    /// Mark `n` bytes of the spare region as initialised.
    pub fn advance(&mut self, n: usize) {
        assert!(self.len + n <= self.capacity(), "advance past capacity");
        self.len += n;
    }

    /// Ensure room for `additional` more bytes, moving to a larger locked
    /// region if needed (the old region is zeroed on release).
    pub fn reserve(&mut self, additional: usize) -> Result<()> {
        let needed = self.len + additional;
        if needed <= self.capacity() {
            return Ok(());
        }
        let mut bigger = Self::with_capacity(needed.max(self.capacity() * 2))?;
        bigger.push_bytes(self.as_bytes())?;
        *self = bigger;
        Ok(())
    }

    pub fn push_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.reserve(data.len())?;
        self.spare_mut()[..data.len()].copy_from_slice(data);
        self.len += data.len();
        Ok(())
    }

    pub fn push_str(&mut self, s: &str) -> Result<()> {
        self.push_bytes(s.as_bytes())
    }

    /// Wipe the contents (the memory stays allocated and locked).
    pub fn clear(&mut self) {
        zeroize::Zeroize::zeroize(self.raw.as_mut_slice());
        self.len = 0;
    }
}

impl io::Write for SecretBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.push_bytes(buf).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf(<{} bytes redacted>)", self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn push_grow_and_read_back() {
        let mut b = SecretBuf::with_capacity(4).unwrap();
        assert!(b.capacity() >= 4);
        b.push_str("hello ").unwrap();
        let big = "x".repeat(b.capacity() * 3);
        b.push_str(&big).unwrap();
        assert_eq!(b.len(), 6 + big.len());
        assert!(b.as_str().unwrap().starts_with("hello xxx"));
        b.clear();
        assert!(b.is_empty());
        assert!(b.raw.as_slice().iter().all(|&x| x == 0));
    }

    #[test]
    fn write_trait_and_debug_redaction() {
        let mut b = SecretBuf::with_capacity(1).unwrap();
        write!(b, "{}", "abc".repeat(5000)).unwrap();
        assert_eq!(b.len(), 15000);
        assert_eq!(format!("{b:?}"), "SecretBuf(<15000 bytes redacted>)");
        let z = SecretBuf::zeroed(64).unwrap();
        assert_eq!(z.as_bytes(), &[0u8; 64]);
    }
}
