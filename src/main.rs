//! `opwallet`: a CLI Ethereum wallet whose only copy of the seed lives in
//! 1Password.

use std::process::ExitCode;

use alloy_primitives::{Address, hex};
use anyhow::{Context, Result, anyhow, bail};
use opwallet::{
    cli::{
        self, DisconnectArgs, OutputArgs, RelayArgs, TxArgs,
        opwallet::{ChainArgs, Cli, Commands, ENV_PREFIX, ServeArgs},
    },
    harden,
    onepassword::{self, ItemRef, NewWallet, OpCli, SecretStore, StoredWallet, WalletSummary},
    wallet::{self, DEFAULT_DERIVATION_PATH, Wallet},
    walletconnect::{
        self,
        eth::{self, Account, Opener, RpcClient},
        session::RpcError,
        store::{self, SessionStore},
        ui::{self, Ui},
    },
};
use serde_json::json;

fn main() -> ExitCode {
    for warning in harden::harden_process() {
        eprintln!("warning: {warning}");
    }
    let cli: Cli = cli::parse(ENV_PREFIX);
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
        Commands::List { output } => list(&store, vault, output),
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
            let bytes = message.bytes()?;
            let (_, w) = load(&store, vault, &wallet.name)?;
            println!("{}", w.sign_message(&bytes)?);
            Ok(())
        }
        Commands::SignTypedData { wallet, data } => {
            let (_, _, hash) = eth::typed_data_digest(&data.json()?).map_err(rpc_error)?;
            let (_, w) = load(&store, vault, &wallet.name)?;
            println!("{}", eth::sign_typed_digest(&w, &hash)?);
            Ok(())
        }
        Commands::SignTx { wallet, tx, chain } => {
            transaction(&store, vault, &wallet.name, &tx, chain, false)
        }
        Commands::SendTx { wallet, tx, chain } => {
            transaction(&store, vault, &wallet.name, &tx, chain, true)
        }
        Commands::Connect { name, uri, serve: args } => {
            serve(&store, vault, &state_dir, args, Some((uri, name)))
        }
        Commands::Sessions { output } => sessions(&state_dir, output),
        Commands::Disconnect { disconnect: d, relay } => disconnect(&state_dir, d, relay),
    }
}

/// Older name of the project ID variable, still honoured.
const LEGACY_PROJECT_ID_VAR: &str = "OPWALLET_WC_PROJECT_ID";

fn project_id(given: Option<String>) -> Result<String> {
    cli::require_project_id(given, &[LEGACY_PROJECT_ID_VAR], "OPWALLET_PROJECT_ID")
}

fn rpc_error(e: RpcError) -> anyhow::Error {
    anyhow!("{}", e.message)
}

/// `sign-tx` / `send-tx`: build the transaction from public data (address
/// field, chain), show it, then read the seed once to sign it.
fn transaction(
    store: &OpCli,
    vault: Option<&str>,
    name: &str,
    tx: &TxArgs,
    chain: ChainArgs,
    broadcast: bool,
) -> Result<()> {
    let address: Address = store
        .get_address(name, vault)?
        .ok_or_else(|| anyhow!("wallet {name:?} has no wallet address field"))?
        .trim()
        .parse()
        .with_context(|| format!("wallet {name:?} has an invalid address"))?;
    let overrides = walletconnect::parse_rpc_overrides(&chain.rpc.rpc)?;
    let project = cli::project_id(chain.project_id, &[LEGACY_PROJECT_ID_VAR]).unwrap_or_default();
    let rpc = RpcClient::new(&project, overrides);
    let prepared = eth::prepare_transaction(&tx.to_json(address), &rpc, tx.chain, address)
        .map_err(rpc_error)?;
    let account = Account { name: name.to_string(), address };
    eprintln!("{}", eth::describe(&prepared, tx.chain, &account));

    let (_, w) = load(store, vault, name)?;
    if w.address() != address {
        bail!("1Password item {name:?} no longer derives {address}");
    }
    let raw = hex::encode_prefixed(eth::sign_transaction(prepared, &w)?);
    drop(w);
    if !broadcast {
        println!("{raw}");
        return Ok(());
    }
    let hash = rpc.call(tx.chain, "eth_sendRawTransaction", json!([raw]))?;
    println!("{}", hash.as_str().map(str::to_string).unwrap_or_else(|| hash.to_string()));
    Ok(())
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

fn list(store: &dyn SecretStore, vault: Option<&str>, output: OutputArgs) -> Result<()> {
    let mut wallets = store.list_wallets(vault)?;
    onepassword::sort_wallets(&mut wallets);
    if output.json {
        let rows: Vec<_> = wallets
            .iter()
            .map(|w| json!({ "name": w.title, "address": w.address, "id": w.id, "vault": w.vault }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
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
    let rpc_overrides = walletconnect::parse_rpc_overrides(&args.rpc.rpc)?;
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
        verify_server: (!args.no_verify).then_some(args.verify_url),
        metadata: walletconnect::default_metadata(),
        exit_when_idle: plain,
    };
    walletconnect::run(opts, sessions, initial, &wallets, ui.as_mut())
}

fn sessions(state_dir: &std::path::Path, output: OutputArgs) -> Result<()> {
    let state = store::read(state_dir)?;
    if output.json {
        let rows: Vec<_> = state
            .sessions
            .iter()
            .enumerate()
            .map(|(i, s)| {
                json!({
                    "number": i + 1,
                    "topic": s.topic,
                    "dapp": s.peer.name,
                    "url": s.peer.url,
                    "expiry": s.expiry,
                    "chains": s.chains,
                    "wallets": s.accounts,
                    "active": s.accounts.get(s.active).map(|a| &a.address),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
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

fn disconnect(state_dir: &std::path::Path, args: DisconnectArgs, relay: RelayArgs) -> Result<()> {
    let DisconnectArgs { session: selectors, all } = args;
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
