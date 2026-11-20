//! `opwallet`'s command line.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use super::{DisconnectArgs, MessageArgs, OutputArgs, RelayArgs, TxArgs, TypedDataArgs};
use crate::wallet::DEFAULT_DERIVATION_PATH;

/// Environment variable prefix (`OPWALLET_VAULT`, ...).
pub const ENV_PREFIX: &str = "OPWALLET";

#[derive(Parser, Debug)]
#[command(
    name = "opwallet",
    version,
    about = "Ethereum wallet with its seed phrase stored in 1Password",
    long_about = "Ethereum wallet with its seed phrase stored in 1Password.\n\n\
        Uses the 1Password CLI (`op`) which unlocks through the locally running \
        1Password desktop app. Enable Settings > Developer > \"Integrate with 1Password CLI\" \
        in the app first.\n\n\
        Run without a command to open the dashboard: saved WalletConnect sessions, \
        connecting more dapps, adding and removing wallets on a session, and \
        generating new wallets.\n\n\
        `wcapp` takes the same commands and performs them through a wallet over \
        WalletConnect instead (for example, this one running its dashboard)."
)]
pub struct Cli {
    /// Path to the 1Password CLI binary.
    #[arg(long, global = true, default_value = "op")]
    pub op_bin: String,

    /// 1Password vault to use (name or ID). Defaults to op's default vault.
    #[arg(long, global = true)]
    pub vault: Option<String>,

    /// Keep the 1Password CLI signed in after reading a seed phrase.
    /// By default the CLI is signed out after every read, so the next read
    /// needs a fresh unlock (Touch ID / system auth) in the desktop app.
    #[arg(long, global = true)]
    pub no_relock: bool,

    /// Directory for saved WalletConnect sessions
    /// (default: ~/.local/state/opwallet, ~/Library/Application Support/opwallet on macOS).
    #[arg(long, global = true)]
    pub state_dir: Option<PathBuf>,

    #[command(flatten)]
    pub serve: ServeArgs,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Args, Debug)]
pub struct RpcArgs {
    /// JSON-RPC endpoint override per chain, e.g. `1=https://eth.example`.
    /// Chains without one use the WalletConnect blockchain API.
    #[arg(long = "rpc", value_name = "CHAIN_ID=URL")]
    pub rpc: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Line-based prompts instead of the full-screen dashboard.
    #[arg(long)]
    pub plain: bool,

    #[command(flatten)]
    pub relay: RelayArgs,

    #[command(flatten)]
    pub rpc: RpcArgs,

    /// Tenderly `ACCOUNT/PROJECT` (or its dashboard URL) that transaction
    /// simulation links open in.
    /// Without it they open in your default Tenderly project.
    #[arg(long, value_name = "ACCOUNT/PROJECT")]
    pub tenderly_project: Option<String>,

    /// WalletConnect Verify server used to confirm where proposals and
    /// requests really come from.
    #[arg(long, default_value = crate::walletconnect::VERIFY_SERVER)]
    pub verify_url: String,

    /// Skip WalletConnect Verify; prompts then show the dapp's claimed URL only.
    #[arg(long)]
    pub no_verify: bool,
}

/// Chain access for commands that build transactions locally.
#[derive(Args, Debug)]
pub struct ChainArgs {
    #[command(flatten)]
    pub rpc: RpcArgs,

    /// WalletConnect project ID, for the WalletConnect blockchain API on
    /// chains without an --rpc endpoint. Not needed when every field
    /// (--nonce, --gas and fees) is given.
    #[arg(long)]
    pub project_id: Option<String>,
}

#[derive(Args, Debug)]
pub struct WalletName {
    /// Title of the 1Password item holding the wallet.
    #[arg(long, short = 'n')]
    pub name: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Check that the 1Password CLI is installed and signed in.
    Doctor,

    /// Generate a new seed phrase and store it in 1Password as a Crypto Wallet item.
    Create {
        #[command(flatten)]
        wallet: WalletName,

        /// Number of words in the seed phrase.
        #[arg(long, short = 'w', default_value_t = 12, value_parser = clap::value_parser!(u8).range(12..=24))]
        words: u8,

        /// BIP-32 derivation path for the wallet address.
        #[arg(long, default_value = DEFAULT_DERIVATION_PATH)]
        path: String,

        /// Print the seed phrase to the terminal after storing it (not recommended).
        #[arg(long)]
        reveal: bool,
    },

    /// List wallets stored in 1Password.
    List {
        #[command(flatten)]
        output: OutputArgs,
    },

    /// Print a wallet's address after verifying it against the stored seed phrase.
    Address {
        #[command(flatten)]
        wallet: WalletName,
    },

    /// Verify that the stored address matches the stored seed phrase.
    Verify {
        #[command(flatten)]
        wallet: WalletName,
    },

    /// Sign a message with EIP-191 (`personal_sign`) semantics.
    Sign {
        #[command(flatten)]
        wallet: WalletName,

        #[command(flatten)]
        message: MessageArgs,
    },

    /// Sign EIP-712 typed data (`eth_signTypedData_v4`).
    SignTypedData {
        #[command(flatten)]
        wallet: WalletName,

        #[command(flatten)]
        data: TypedDataArgs,
    },

    /// Sign a transaction and print it raw, without broadcasting it.
    SignTx {
        #[command(flatten)]
        wallet: WalletName,

        #[command(flatten)]
        tx: TxArgs,

        #[command(flatten)]
        chain: ChainArgs,
    },

    /// Sign a transaction, broadcast it, and print its hash.
    SendTx {
        #[command(flatten)]
        wallet: WalletName,

        #[command(flatten)]
        tx: TxArgs,

        #[command(flatten)]
        chain: ChainArgs,
    },

    /// Pair with a dapp over WalletConnect, then serve it and every saved session.
    Connect {
        /// Wallet(s) to connect; repeat for several. Prompts when omitted.
        #[arg(long, short = 'n', value_delimiter = ',')]
        name: Vec<String>,

        /// WalletConnect pairing URI (wc:...), copied from the dapp. Prompts when omitted.
        uri: Option<String>,

        #[command(flatten)]
        serve: ServeArgs,
    },

    /// List saved WalletConnect sessions.
    Sessions {
        #[command(flatten)]
        output: OutputArgs,
    },

    /// End saved WalletConnect sessions and tell their dapps.
    Disconnect {
        #[command(flatten)]
        disconnect: DisconnectArgs,

        #[command(flatten)]
        relay: RelayArgs,
    },
}
