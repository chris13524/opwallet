//! `opwallet`: a CLI Ethereum wallet whose only copy of the seed lives in
//! 1Password. See `README.md` for the security model.

pub mod cli;
pub mod harden;
pub mod onepassword;
pub mod secret;
pub mod wallet;
pub mod walletconnect;
