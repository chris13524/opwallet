//! `opwallet`: a CLI Ethereum wallet whose only copy of the seed lives in
//! 1Password.

use std::{path::PathBuf, process::ExitCode};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use opwallet::{
    harden,
    onepassword::{self, ItemRef, NewWallet, OpCli, SecretStore, StoredWallet, WalletSummary},
    wallet::{self, DEFAULT_DERIVATION_PATH, Wallet},
    walletconnect::{
        self,
        eth::{Account, Opener},
        store::{self, SessionStore},
        ui::{self, Ui},
    },
};

#[derive(Parser)]
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
        generating new wallets."
)]
struct Cli {
    /// Path to the 1Password CLI binary.
    #[arg(long, global = true, env = "OPWALLET_OP_BIN", default_value = "op")]
    op_bin: String,

    /// 1Password vault to use (name or ID). Defaults to op's default vault.
    #[arg(long, global = true, env = "OPWALLET_VAULT")]
    vault: Option<String>,

    /// Keep the 1Password CLI signed in after reading a seed phrase.
    /// By default the CLI is signed out after every read, so the next read
    /// needs a fresh unlock (Touch ID / system auth) in the desktop app.
    #[arg(long, global = true, env = "OPWALLET_NO_RELOCK")]
    no_relock: bool,

    /// Directory for saved WalletConnect sessions
    /// (default: ~/.local/state/opwallet, ~/Library/Application Support/opwallet on macOS).
    #[arg(long, global = true, env = "OPWALLET_STATE_DIR")]
    state_dir: Option<PathBuf>,

    #[command(flatten)]
    serve: ServeArgs,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Args)]
struct RelayArgs {
    /// WalletConnect Cloud project ID (free at https://cloud.reown.com).
    #[arg(long, env = "OPWALLET_PROJECT_ID")]
    project_id: Option<String>,

    /// Relay websocket URL.
    #[arg(long, env = "OPWALLET_RELAY_URL", default_value = walletconnect::DEFAULT_RELAY_URL)]
    relay_url: String,
}

#[derive(Args)]
struct ServeArgs {
    /// Line-based prompts instead of the full-screen dashboard.
    #[arg(long)]
    plain: bool,

    #[command(flatten)]
    relay: RelayArgs,

    /// JSON-RPC endpoint override per chain, e.g. `1=https://eth.example`.
    /// Chains without one use the WalletConnect blockchain API.
    #[arg(long = "rpc", value_name = "CHAIN_ID=URL")]
    rpc: Vec<String>,

    /// Tenderly `ACCOUNT/PROJECT` (or its dashboard URL) that transaction
    /// simulation links open in.
    /// Without it they open in your default Tenderly project.
    #[arg(long, env = "OPWALLET_TENDERLY_PROJECT", value_name = "ACCOUNT/PROJECT")]
    tenderly_project: Option<String>,
}

#[derive(Args)]
struct WalletName {
    /// Title of the 1Password item holding the wallet.
    #[arg(long, short = 'n', env = "OPWALLET_NAME")]
    name: String,
}

#[derive(Subcommand)]
enum Commands {
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
    List,

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

        /// Message to sign. Prefix with 0x to sign raw bytes instead of UTF-8 text.
        #[arg(long, short = 'm')]
        message: String,
    },

    /// Pair with a dapp over WalletConnect, then serve it and every saved session.
    Connect {
        /// Wallet(s) to connect; repeat for several. Prompts when omitted.
        #[arg(long, short = 'n', env = "OPWALLET_NAME", value_delimiter = ',')]
        name: Vec<String>,

        /// WalletConnect pairing URI (wc:...), copied from the dapp. Prompts when omitted.
        uri: Option<String>,

        #[command(flatten)]
        serve: ServeArgs,
    },

    /// List saved WalletConnect sessions.
    Sessions,

    /// End saved WalletConnect sessions and tell their dapps.
    Disconnect {
        /// Sessions to end: a number from `opwallet sessions`, part of the
        /// dapp's name or URL, or a topic prefix.
        session: Vec<String>,

        /// End every saved session.
        #[arg(long, conflicts_with = "session")]
        all: bool,

        #[command(flatten)]
        relay: RelayArgs,
    },
}

fn main() -> ExitCode {
    for warning in harden::harden_process() {
        eprintln!("warning: {warning}");
    }
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let store = OpCli::new(cli.op_bin).with_relock(!cli.no_relock);
    let vault = cli.vault.as_deref();
    let state_dir = match cli.state_dir {
        Some(d) => d,
        None => store::default_dir()?,
    };

    let Some(command) = cli.command else {
        return serve(&store, vault, &state_dir, cli.serve, None);
    };
    match command {
        Commands::Doctor => doctor(&store, vault),
        Commands::Create { wallet, words, path, reveal } => {
            create(&store, vault, &wallet.name, words as usize, &path, reveal)
        }
        Commands::List => list(&store, vault),
        Commands::Address { wallet } => {
            let (stored, w) = load(&store, vault, &wallet.name)?;
            println!("{}", w.address());
            eprintln!(
                "verified: address matches seed phrase in 1Password item {:?} ({})",
                stored.title,
                w.derivation_path()
            );
            Ok(())
        }
        Commands::Verify { wallet } => {
            let (stored, w) = load(&store, vault, &wallet.name)?;
            println!(
                "OK: {} matches the seed phrase in {:?} (item {}{}) at {}",
                w.address(),
                stored.title,
                stored.id,
                stored.vault.as_deref().map(|v| format!(", vault {v}")).unwrap_or_default(),
                w.derivation_path()
            );
            Ok(())
        }
        Commands::Sign { wallet, message } => {
            let (_, w) = load(&store, vault, &wallet.name)?;
            let bytes = if let Some(hex) = message.strip_prefix("0x") {
                alloy_primitives::hex::decode(hex).context("message is not valid hex")?
            } else {
                message.into_bytes()
            };
            println!("{}", w.sign_message(&bytes)?);
            Ok(())
        }
        Commands::Connect { name, uri, serve: args } => {
            serve(&store, vault, &state_dir, args, Some((uri, name)))
        }
        Commands::Sessions => sessions(&state_dir),
        Commands::Disconnect { session, all, relay } => disconnect(&state_dir, session, all, relay),
    }
}

fn project_id(given: Option<String>) -> Result<String> {
    given
        .or_else(|| std::env::var("OPWALLET_WC_PROJECT_ID").ok())
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no WalletConnect project ID: pass --project-id or set OPWALLET_PROJECT_ID \
                 (free at https://cloud.reown.com)"
            )
        })
}

fn doctor(store: &dyn SecretStore, vault: Option<&str>) -> Result<()> {
    let who = store.whoami()?;
    println!("1Password CLI: signed in as {who}");
    let wallets = store.list_wallets(vault)?;
    println!("Crypto Wallet items visible: {}", wallets.len());
    Ok(())
}

fn create(
    store: &dyn SecretStore,
    vault: Option<&str>,
    name: &str,
    words: usize,
    path: &str,
    reveal: bool,
) -> Result<()> {
    let (created, address, stored) = create_verified(store, vault, name, words, path)?;
    println!("Created wallet {:?}", created.title);
    println!(
        "  1Password item: {}{}",
        created.id,
        created.vault.map(|v| format!(" (vault {v})")).unwrap_or_default()
    );
    println!("  Derivation path: {path}");
    println!("  Address: {address}");
    if reveal {
        eprintln!("warning: printing the seed phrase; clear your terminal scrollback afterwards");
        println!("  Seed phrase: {}", stored.seed_phrase.as_str()?);
    } else {
        println!("  Seed phrase: stored in 1Password only (use --reveal to print it)");
    }
    Ok(())
}

/// Generate a phrase, store it as a new item, read it back and check it.
/// Returns the item, its address and what was read back (phrase included,
/// for `--reveal`; callers that do not print it drop it right away).
fn create_verified(
    store: &dyn SecretStore,
    vault: Option<&str>,
    name: &str,
    words: usize,
    path: &str,
) -> Result<(ItemRef, String, StoredWallet)> {
    if name.trim().is_empty() {
        bail!("wallet name must not be empty");
    }
    if store.wallet_exists(name, vault)? {
        bail!("a Crypto Wallet item named {name:?} already exists; pick a new name");
    }

    let phrase = wallet::generate_mnemonic(words)?;
    let address = Wallet::from_mnemonic(phrase.as_str()?, path)?.address().to_string();

    let created = store.create_wallet(&NewWallet {
        title: name,
        vault,
        seed_phrase: phrase.as_str()?,
        address: &address,
        derivation_path: path,
    })?;
    // Our copy is no longer needed: 1Password is the source of truth now.
    drop(phrase);

    // Read it back and verify: proves the phrase survived the round trip and
    // that the address field matches what we will derive next time.
    let stored = store.get_wallet(name, vault)?;
    let reloaded = Wallet::from_mnemonic(stored.seed_phrase.as_str()?, path)?;
    reloaded.verify_stored_address(&address)?;
    if stored.address.as_deref().map(str::trim) != Some(address.as_str()) {
        bail!("wallet address read back from 1Password does not match what was stored");
    }
    Ok((created, address, stored))
}

fn list(store: &dyn SecretStore, vault: Option<&str>) -> Result<()> {
    let mut wallets = store.list_wallets(vault)?;
    onepassword::sort_wallets(&mut wallets);
    if wallets.is_empty() {
        println!("No Crypto Wallet items found. Create one with `opwallet create --name <name>`.");
        return Ok(());
    }
    let width = wallets.iter().map(|w| w.title.len()).max().unwrap_or(0).max(4);
    println!("{:width$}  {:42}  {:26}  VAULT", "NAME", "ADDRESS", "ITEM ID", width = width);
    for w in wallets {
        println!(
            "{:width$}  {:42}  {:26}  {}",
            w.title,
            w.address.as_deref().unwrap_or("-"),
            w.id,
            w.vault.as_deref().unwrap_or("-"),
            width = width
        );
    }
    Ok(())
}

/// The wallets in 1Password, as the WalletConnect service sees them.
struct OpWallets<'a> {
    store: &'a OpCli,
    vault: Option<&'a str>,
}

impl Opener for OpWallets<'_> {
    fn open(&self, name: &str) -> Result<Wallet> {
        load(self.store, self.vault, name).map(|(_, w)| w)
    }
}

impl walletconnect::Wallets for OpWallets<'_> {
    fn list(&self) -> Result<Vec<WalletSummary>> {
        let mut wallets = self.store.list_wallets(self.vault)?;
        onepassword::sort_wallets(&mut wallets);
        Ok(wallets)
    }

    fn lookup(&self, name: &str) -> Result<Account> {
        let address = self
            .store
            .get_address(name, self.vault)?
            .ok_or_else(|| anyhow::anyhow!("wallet {name:?} has no wallet address field"))?
            .parse()
            .with_context(|| format!("wallet {name:?} has an invalid address"))?;
        Ok(Account { name: name.to_string(), address })
    }

    fn create(&self, name: &str) -> Result<Account> {
        let (created, address, stored) =
            create_verified(self.store, self.vault, name, 12, DEFAULT_DERIVATION_PATH)?;
        drop(stored);
        Ok(Account { name: created.title, address: address.parse()? })
    }
}

/// Run the WalletConnect service: bare `opwallet` (resume saved sessions)
/// or `opwallet connect` (`pair` = URI and wallet names, prompted if missing).
fn serve(
    store: &OpCli,
    vault: Option<&str>,
    state_dir: &std::path::Path,
    args: ServeArgs,
    pair: Option<(Option<String>, Vec<String>)>,
) -> Result<()> {
    let rpc_overrides = walletconnect::parse_rpc_overrides(&args.rpc)?;
    let tenderly = args
        .tenderly_project
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(walletconnect::tenderly::TenderlyProject::parse)
        .transpose()?;
    let plain = args.plain || !ui::interactive_terminal();
    if pair.is_none() && plain && store::read(state_dir)?.sessions.is_empty() {
        println!(
            "No saved sessions. Pair with a dapp with `opwallet connect`, or run opwallet \
             in a terminal for the dashboard."
        );
        return Ok(());
    }
    let project_id = project_id(args.relay.project_id)?;
    let sessions = SessionStore::open(state_dir)?;

    let stop = ui::install_ctrlc();
    let mut ui: Box<dyn Ui> = if plain {
        Box::new(ui::PlainUi::new(stop))
    } else {
        Box::new(ui::Tui::new(&args.relay.relay_url)?)
    };
    let wallets = OpWallets { store, vault };
    let initial = match pair {
        None => None,
        Some((uri, names)) => {
            Some(walletconnect::prepare_pairing(ui.as_mut(), &wallets, uri, &names)?.ok_or_else(
                || anyhow::anyhow!("nothing to connect: no URI given or no wallets selected"),
            )?)
        }
    };
    let opts = walletconnect::ServiceOptions {
        project_id,
        relay_url: args.relay.relay_url,
        rpc_overrides,
        tenderly,
        metadata: walletconnect::default_metadata(),
        exit_when_idle: plain,
    };
    walletconnect::run(opts, sessions, initial, &wallets, ui.as_mut())
}

fn sessions(state_dir: &std::path::Path) -> Result<()> {
    let state = store::read(state_dir)?;
    if state.sessions.is_empty() {
        println!("No saved sessions.");
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let width =
        state.sessions.iter().map(|s| s.peer.name.chars().count()).max().unwrap_or(0).max(4);
    println!("{:>2}  {:width$}  {:8}  {:10}  URL / WALLETS", "#", "DAPP", "EXPIRES", "TOPIC");
    for (i, s) in state.sessions.iter().enumerate() {
        let left = s.expiry.saturating_sub(now);
        let expires = if left == 0 {
            "expired".to_string()
        } else if left >= 86_400 {
            format!("{}d", (left + 43_200) / 86_400)
        } else {
            format!("{}h", left.div_ceil(3_600))
        };
        let wallets: Vec<String> =
            s.accounts.iter().map(|a| format!("{} {}", a.name, a.address)).collect();
        println!(
            "{:>2}  {:width$}  {:8}  {:10}  {}",
            i + 1,
            s.peer.name,
            expires,
            &s.topic[..s.topic.len().min(10)],
            s.peer.url
        );
        for w in wallets {
            println!("{:>2}  {:width$}  {:8}  {:10}    {w}", "", "", "", "");
        }
    }
    Ok(())
}

fn disconnect(
    state_dir: &std::path::Path,
    selectors: Vec<String>,
    all: bool,
    relay: RelayArgs,
) -> Result<()> {
    let store = SessionStore::open(state_dir)?;
    let state = store.load()?;
    let mut indices: Vec<usize> = if all {
        (0..state.sessions.len()).collect()
    } else if selectors.is_empty() {
        bail!("name the session(s) to end (see `opwallet sessions`) or pass --all");
    } else {
        selectors
            .iter()
            .map(|s| walletconnect::select_saved(&state.sessions, s))
            .collect::<Result<_>>()?
    };
    indices.sort_unstable();
    indices.dedup();
    if indices.is_empty() {
        println!("No saved sessions.");
        return Ok(());
    }
    let project_id = project_id(relay.project_id)?;
    for name in walletconnect::disconnect_saved(&project_id, &relay.relay_url, &store, &indices)? {
        println!("Disconnected {name}");
    }
    Ok(())
}

/// Non-secret facts about a loaded wallet item.
struct WalletInfo {
    id: String,
    title: String,
    vault: Option<String>,
}

/// Fetch a wallet from 1Password, derive its key, wipe the phrase and verify
/// the stored address against the derived one.
fn load(store: &dyn SecretStore, vault: Option<&str>, name: &str) -> Result<(WalletInfo, Wallet)> {
    let mut stored = store.get_wallet(name, vault)?;
    let path = stored.derivation_path.as_deref().unwrap_or(DEFAULT_DERIVATION_PATH);
    let w = Wallet::from_mnemonic(stored.seed_phrase.as_str()?, path)
        .with_context(|| format!("1Password item {:?} ({})", stored.title, stored.id))?;
    stored.seed_phrase.clear();
    match &stored.address {
        Some(addr) => w.verify_stored_address(addr)?,
        None => bail!(
            "1Password item {:?} has no {:?} field to check against; refusing to use it",
            stored.title,
            onepassword::FIELD_WALLET_ADDRESS
        ),
    }
    Ok((WalletInfo { id: stored.id, title: stored.title, vault: stored.vault }, w))
}
