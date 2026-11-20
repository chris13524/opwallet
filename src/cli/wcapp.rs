//! `wcapp`'s command line: `opwallet`'s commands, carried out by a wallet
//! over WalletConnect.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use super::{DisconnectArgs, MessageArgs, OutputArgs, RelayArgs, TxArgs, TypedDataArgs};

/// Environment variable prefix (`WCAPP_PROJECT_ID`, ...).
pub const ENV_PREFIX: &str = "WCAPP";

/// Chains asked for when pairing, unless `--chain` says otherwise.
pub const DEFAULT_CHAINS: &[u64] = &[1, 10, 137, 8453, 42161];

#[derive(Parser, Debug)]
#[command(
    name = "wcapp",
    version,
    arg_required_else_help = true,
    about = "Use a wallet over WalletConnect from the command line",
    long_about = "Use a wallet over WalletConnect from the command line.\n\n\
        wcapp is the dapp side of WalletConnect: pair it with a wallet once \
        (`wcapp connect`), then sign messages, typed data and transactions with \
        the same commands and flags as `opwallet`. The wallet shows each request \
        and decides; wcapp never holds a key.\n\n\
        Works with any WalletConnect wallet, including opwallet's dashboard."
)]
pub struct Cli {
    /// Directory for saved sessions
    /// (default: ~/.local/state/wcapp, ~/Library/Application Support/wcapp on macOS).
    #[arg(long, global = true)]
    pub state_dir: Option<PathBuf>,

    /// Seconds to wait for the wallet to answer (approve a connection or a
    /// request). The wallet refuses to act on a request after this.
    #[arg(long, global = true, default_value_t = 300, value_name = "SECONDS")]
    pub timeout: u64,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args, Debug)]
pub struct WalletSelector {
    /// Account to use: an address (or a unique prefix of one), a number from
    /// `wcapp list`, or part of a wallet's name for its active account.
    /// Default: the active account, when only one wallet is connected.
    #[arg(long, short = 'n')]
    pub name: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Check that each connected wallet is reachable and answering.
    Doctor {
        #[command(flatten)]
        relay: RelayArgs,
    },

    /// List the accounts connected wallets share.
    List {
        #[command(flatten)]
        output: OutputArgs,
    },

    /// Print an account's address.
    Address {
        #[command(flatten)]
        wallet: WalletSelector,
    },

    /// Ask the wallet to sign a message (`personal_sign`).
    Sign {
        #[command(flatten)]
        wallet: WalletSelector,

        #[command(flatten)]
        message: MessageArgs,

        #[command(flatten)]
        relay: RelayArgs,
    },

    /// Ask the wallet to sign EIP-712 typed data (`eth_signTypedData_v4`).
    SignTypedData {
        #[command(flatten)]
        wallet: WalletSelector,

        #[command(flatten)]
        data: TypedDataArgs,

        #[command(flatten)]
        relay: RelayArgs,
    },

    /// Ask the wallet to sign a transaction and print it raw, without
    /// broadcasting it (`eth_signTransaction`).
    SignTx {
        #[command(flatten)]
        wallet: WalletSelector,

        #[command(flatten)]
        tx: TxArgs,

        #[command(flatten)]
        relay: RelayArgs,
    },

    /// Ask the wallet to sign and broadcast a transaction, and print its hash
    /// (`eth_sendTransaction`).
    SendTx {
        #[command(flatten)]
        wallet: WalletSelector,

        #[command(flatten)]
        tx: TxArgs,

        #[command(flatten)]
        relay: RelayArgs,
    },

    /// Pair with a wallet: print a pairing URI (wc:...) to paste into it,
    /// then wait for the wallet to approve.
    Connect {
        /// Chain IDs to ask the wallet for; repeat or separate with commas.
        #[arg(long, value_delimiter = ',', default_values_t = DEFAULT_CHAINS.to_vec())]
        chain: Vec<u64>,

        /// Print the URI and exit without waiting. The next command that
        /// needs the wallet waits for the approval instead.
        #[arg(long)]
        no_wait: bool,

        #[command(flatten)]
        relay: RelayArgs,
    },

    /// List saved sessions (and pairings waiting for approval).
    Sessions {
        #[command(flatten)]
        output: OutputArgs,
    },

    /// End saved sessions and tell their wallets.
    Disconnect {
        #[command(flatten)]
        disconnect: DisconnectArgs,

        #[command(flatten)]
        relay: RelayArgs,
    },
}
