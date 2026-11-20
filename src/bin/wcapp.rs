//! `wcapp`: opwallet's commands, carried out by a wallet over WalletConnect.
//!
//! Exit status: 0 on success, 2 when the wallet refused (the user said no,
//! or the request expired unanswered in the wallet), 1 for anything else.

use std::{
    io::{IsTerminal, Write},
    path::Path,
    process::ExitCode,
    time::Duration,
};

use alloy_primitives::hex;
use anyhow::{Result, anyhow, bail};
use opwallet::{
    cli::{
        self, DisconnectArgs, OutputArgs, RelayArgs,
        wcapp::{Cli, Commands, ENV_PREFIX, WalletSelector},
    },
    harden,
    walletconnect::{
        self,
        dapp::{self, Dapp, DappOptions, DappState, WalletError},
        eth, store,
    },
};
use serde_json::{Value, json};

fn main() -> ExitCode {
    for warning in harden::harden_process() {
        eprintln!("warning: {warning}");
    }
    let cli: Cli = cli::parse(ENV_PREFIX);
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            if e.downcast_ref::<WalletError>().is_some() {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let state_dir = match cli.state_dir {
        Some(d) => d,
        None => store::default_dir_for("wcapp")?,
    };
    let timeout = Duration::from_secs(cli.timeout.max(1));
    let mut note = |line: &str| eprintln!("{line}");
    let net = Net { dir: &state_dir, timeout };

    match cli.command {
        Commands::List { output } => list(&dapp::read_state(&state_dir)?, output),
        Commands::Address { wallet } => {
            let state = dapp::read_state(&state_dir)?;
            let (_, address) = resolve(&state, &wallet)?;
            println!("{address}");
            Ok(())
        }
        Commands::Sessions { output } => sessions(&dapp::read_state(&state_dir)?, output),
        Commands::Connect { chain, no_wait, relay } => {
            let mut dapp = net.open(relay, &mut note)?;
            let uri = dapp.pair(&chain)?;
            println!("{uri}");
            std::io::stdout().flush()?;
            show_qr(&uri);
            if no_wait {
                eprintln!(
                    "Paste the URI into the wallet. The next wcapp command that needs the \
                     wallet waits for its approval."
                );
                return Ok(());
            }
            eprintln!("Paste the URI into the wallet (or scan the code), then approve there.");
            dapp.finish_pairings(true)?;
            Ok(())
        }
        Commands::Sign { wallet, message, relay } => {
            let bytes = message.bytes()?;
            let mut dapp = net.ready(relay, &mut note)?;
            let (si, address) = resolve(&dapp.state, &wallet)?;
            let chain = dapp::pick_chain(&dapp.state.sessions[si], None, None)?;
            let params = json!([hex::encode_prefixed(&bytes), address]);
            print_result(dapp.request(si, &chain, "personal_sign", params)?)
        }
        Commands::SignTypedData { wallet, data, relay } => {
            let data = data.json()?;
            // Refuse malformed typed data here rather than in the wallet.
            eth::typed_data_digest(&data).map_err(|e| anyhow!("{}", e.message))?;
            let domain_chain = match &data["domain"]["chainId"] {
                Value::Number(n) => n.as_u64(),
                Value::String(s) => s
                    .strip_prefix("0x")
                    .map_or_else(|| s.parse().ok(), |h| u64::from_str_radix(h, 16).ok()),
                _ => None,
            };
            let mut dapp = net.ready(relay, &mut note)?;
            let (si, address) = resolve(&dapp.state, &wallet)?;
            let chain = dapp::pick_chain(&dapp.state.sessions[si], None, domain_chain)?;
            let params = json!([address, data.to_string()]);
            print_result(dapp.request(si, &chain, "eth_signTypedData_v4", params)?)
        }
        Commands::SignTx { wallet, tx, relay } => {
            let mut dapp = net.ready(relay, &mut note)?;
            let (si, address) = resolve(&dapp.state, &wallet)?;
            let chain = dapp::pick_chain(&dapp.state.sessions[si], Some(tx.chain), None)?;
            let params = json!([tx.to_json(address)]);
            print_result(dapp.request(si, &chain, "eth_signTransaction", params)?)
        }
        Commands::SendTx { wallet, tx, relay } => {
            let mut dapp = net.ready(relay, &mut note)?;
            let (si, address) = resolve(&dapp.state, &wallet)?;
            let chain = dapp::pick_chain(&dapp.state.sessions[si], Some(tx.chain), None)?;
            let params = json!([tx.to_json(address)]);
            print_result(dapp.request(si, &chain, "eth_sendTransaction", params)?)
        }
        Commands::Disconnect { disconnect, relay } => {
            // Check the selection before needing a relay, then again under the lock.
            if select(&dapp::read_state(&state_dir)?, &disconnect)?.is_empty() {
                println!("No saved sessions.");
                return Ok(());
            }
            let mut dapp = net.open(relay, &mut note)?;
            let indices = select(&dapp.state, &disconnect)?;
            for name in dapp.disconnect(&indices)? {
                println!("Disconnected {name}");
            }
            Ok(())
        }
        Commands::Doctor { relay } => doctor(net.ready(relay, &mut note)?),
    }
}

/// What a command needs to talk to the wallet.
struct Net<'p> {
    dir: &'p Path,
    timeout: Duration,
}

impl Net<'_> {
    fn open<'n>(&self, relay: RelayArgs, note: &'n mut dyn FnMut(&str)) -> Result<Dapp<'n>> {
        let project_id = cli::require_project_id(
            relay.project_id,
            &["OPWALLET_PROJECT_ID"],
            "WCAPP_PROJECT_ID",
        )?;
        let opts = DappOptions {
            project_id,
            relay_url: relay.relay_url,
            metadata: dapp::default_metadata(),
            timeout: self.timeout,
        };
        Dapp::open(self.dir, opts, note)
    }

    /// Open, finish a pairing that is the only way to a wallet, and take in
    /// what the wallets sent since the last command.
    fn ready<'n>(&self, relay: RelayArgs, note: &'n mut dyn FnMut(&str)) -> Result<Dapp<'n>> {
        let mut dapp = self.open(relay, note)?;
        if dapp.state.sessions.is_empty() && !dapp.state.pending.is_empty() {
            dapp.finish_pairings(true)?;
        }
        dapp.sync()?;
        Ok(dapp)
    }
}

fn resolve(
    state: &DappState,
    wallet: &WalletSelector,
) -> Result<(usize, alloy_primitives::Address)> {
    if state.sessions.is_empty() && !state.pending.is_empty() {
        bail!(
            "the wallet has not approved the connection yet; a command that talks to it \
             (such as `wcapp doctor`) waits for the approval"
        );
    }
    dapp::resolve_account(state, wallet.name.as_deref())
}

fn print_result(v: Value) -> Result<()> {
    match v {
        Value::String(s) => println!("{s}"),
        other => println!("{other}"),
    }
    Ok(())
}

fn show_qr(uri: &str) {
    if !std::io::stderr().is_terminal() {
        return;
    }
    if let Ok(code) = qrcode::QrCode::new(uri.as_bytes()) {
        let art = code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .quiet_zone(true)
            .build();
        eprintln!("{art}");
    }
}

fn list(state: &DappState, output: OutputArgs) -> Result<()> {
    let rows = dapp::account_rows(state);
    if output.json {
        let rows: Vec<Value> = rows
            .iter()
            .map(|r| {
                let s = &state.sessions[r.session];
                json!({
                    "number": r.number,
                    "address": r.address,
                    "wallet": s.peer.name,
                    "url": s.peer.url,
                    "active": r.active,
                    "chains": s.chains,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    if rows.is_empty() {
        if state.pending.is_empty() {
            println!("No wallet connected. Pair with one with `wcapp connect`.");
        } else {
            println!("No wallet connected yet; a pairing is waiting for the wallet's approval.");
        }
        return Ok(());
    }
    let width = state.sessions.iter().map(|s| s.name().chars().count()).max().unwrap_or(0).max(6);
    println!("{:>2}  {:42}  {:width$}  ACTIVE", "#", "ADDRESS", "WALLET");
    for r in rows {
        let name = state.sessions[r.session].name();
        println!(
            "{:>2}  {:42}  {name:width$}  {}",
            r.number,
            r.address,
            if r.active { "*" } else { "" }
        );
    }
    Ok(())
}

fn remaining(expiry: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let left = expiry.saturating_sub(now);
    if left == 0 {
        "expired".into()
    } else if left >= 86_400 {
        format!("{}d", (left + 43_200) / 86_400)
    } else if left >= 3_600 {
        format!("{}h", left.div_ceil(3_600))
    } else {
        format!("{}m", left.div_ceil(60))
    }
}

fn sessions(state: &DappState, output: OutputArgs) -> Result<()> {
    if output.json {
        let rows: Vec<Value> = state
            .sessions
            .iter()
            .enumerate()
            .map(|(i, s)| {
                json!({
                    "number": i + 1,
                    "topic": s.topic,
                    "wallet": s.peer.name,
                    "url": s.peer.url,
                    "expiry": s.expiry,
                    "chains": s.chains,
                    "accounts": s.accounts,
                    "active": s.accounts.first(),
                })
            })
            .collect();
        let pending: Vec<Value> = state
            .pending
            .iter()
            .map(|p| json!({ "topic": p.topic, "expiry": p.expiry, "approved": p.session_key.is_some() }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "sessions": rows, "pending": pending }))?
        );
        return Ok(());
    }
    if state.sessions.is_empty() && state.pending.is_empty() {
        println!("No saved sessions.");
        return Ok(());
    }
    if !state.sessions.is_empty() {
        let width =
            state.sessions.iter().map(|s| s.name().chars().count()).max().unwrap_or(0).max(6);
        println!(
            "{:>2}  {:width$}  {:8}  {:10}  URL / ACCOUNTS",
            "#", "WALLET", "EXPIRES", "TOPIC"
        );
        for (i, s) in state.sessions.iter().enumerate() {
            println!(
                "{:>2}  {:width$}  {:8}  {:10}  {}",
                i + 1,
                s.name(),
                remaining(s.expiry),
                &s.topic[..s.topic.len().min(10)],
                s.peer.url
            );
            for (j, a) in s.accounts.iter().enumerate() {
                let mark = if j == 0 { " (active)" } else { "" };
                println!("{:>2}  {:width$}  {:8}  {:10}    {a}{mark}", "", "", "", "");
            }
        }
    }
    for p in &state.pending {
        let what =
            if p.session_key.is_some() { "approved, settling" } else { "waiting for approval" };
        println!(
            "pairing {}: {what} (proposal expires in {})",
            &p.topic[..p.topic.len().min(10)],
            remaining(p.expiry)
        );
    }
    Ok(())
}

fn select(state: &DappState, args: &DisconnectArgs) -> Result<Vec<usize>> {
    let mut indices: Vec<usize> = if args.all {
        (0..state.sessions.len()).collect()
    } else if args.session.is_empty() {
        bail!("name the session(s) to end (see `wcapp sessions`) or pass --all");
    } else {
        let entries: Vec<(&str, &str, &str)> = state
            .sessions
            .iter()
            .map(|s| (s.topic.as_str(), s.peer.name.as_str(), s.peer.url.as_str()))
            .collect();
        args.session
            .iter()
            .map(|s| walletconnect::select_session(&entries, s, "wcapp sessions"))
            .collect::<Result<_>>()?
    };
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}

fn doctor(mut dapp: Dapp<'_>) -> Result<()> {
    if dapp.state.sessions.is_empty() {
        bail!("no wallet is connected; pair with one with `wcapp connect`");
    }
    let mut failed = 0;
    for si in 0..dapp.state.sessions.len() {
        let (name, url) = {
            let s = &dapp.state.sessions[si];
            (s.name(), s.peer.url.clone())
        };
        match dapp.ping(si) {
            Ok(took) => {
                let s = &dapp.state.sessions[si];
                println!(
                    "{name} ({url}): answering ({} ms); {} account(s), active {}; chains {}",
                    took.as_millis(),
                    s.accounts.len(),
                    s.accounts.first().map(String::as_str).unwrap_or("-"),
                    s.chains.join(", ")
                );
            }
            Err(e) => {
                failed += 1;
                println!("{name} ({url}): {e:#}");
            }
        }
    }
    if failed > 0 {
        bail!("{failed} wallet(s) did not answer");
    }
    Ok(())
}
