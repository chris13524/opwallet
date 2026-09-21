//! Process-level hardening applied before any secret is touched.
//!
//! * Core dumps are disabled (`RLIMIT_CORE = 0`).
//! * On Linux the process is marked non-dumpable (`PR_SET_DUMPABLE = 0`),
//!   which also stops other non-root processes of the same user from
//!   attaching with `ptrace` or reading `/proc/<pid>/mem`.
//! * On macOS `PT_DENY_ATTACH` blocks debugger attachment.
//!
//! Set `OPWALLET_NO_HARDEN=1` to skip this (only useful when debugging the
//! tool itself). Failures are reported as warnings, never as errors, so the
//! wallet stays usable in restricted sandboxes.

/// Environment variable that disables hardening.
pub const NO_HARDEN_ENV: &str = "OPWALLET_NO_HARDEN";

/// Apply all hardening measures; returns human-readable warnings for any that failed.
pub fn harden_process() -> Vec<String> {
    if std::env::var_os(NO_HARDEN_ENV).is_some() {
        return vec![format!("process hardening skipped because {NO_HARDEN_ENV} is set")];
    }
    let mut warnings = Vec::new();
    #[cfg(unix)]
    unix::apply(&mut warnings);
    #[cfg(not(unix))]
    warnings.push(
        "process hardening (core dump / ptrace protection) is not implemented on this platform"
            .into(),
    );
    warnings
}

#[cfg(unix)]
mod unix {
    pub fn apply(warnings: &mut Vec<String>) {
        let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: plain syscall with a valid, fully initialised struct.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
            warnings
                .push(format!("could not disable core dumps: {}", std::io::Error::last_os_error()));
        }

        #[cfg(target_os = "linux")]
        // SAFETY: prctl with constant arguments; no pointers involved.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            warnings.push(format!(
                "could not mark process non-dumpable: {}",
                std::io::Error::last_os_error()
            ));
        }

        #[cfg(target_os = "macos")]
        {
            const PT_DENY_ATTACH: libc::c_int = 31;
            // SAFETY: PT_DENY_ATTACH takes no pointer arguments.
            if unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0 {
                warnings.push(format!(
                    "could not deny debugger attachment: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }
}
