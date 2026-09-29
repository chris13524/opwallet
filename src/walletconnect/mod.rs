//! WalletConnect v2 (Sign API) support: pair with any number of dapps,
//! approve sessions for chosen wallets, serve their signing requests, and
//! keep settled sessions across restarts.
//!
//! The seed phrase is fetched from 1Password for each signing request
//! and wiped right after. What is kept for a session's lifetime (and saved
//! between runs, see [`store`]) is only its symmetric key and public data.

pub mod auth;
pub mod crypto;
pub mod eth;
pub mod relay;
pub mod session;
pub mod store;
pub mod tenderly;
pub mod ui;
pub mod uri;
pub mod verify;

use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::onepassword::{WalletSummary, natural_cmp};
use crypto::{KeyPair, SymKey};
use eth::{Account, Opener, RequestContext, RpcClient};
use relay::{Incoming, Relay, new_rpc_id};
use session::*;
use store::{SavedState, SessionStore, StoredAccount, StoredSession};
use ui::{SessionView, Ui, UiAction, WalletRow};

pub use relay::DEFAULT_RELAY_URL;
pub use verify::VERIFY_SERVER;

/// How long to wait for the dapp's session proposal after pairing.
const PROPOSAL_TIMEOUT: Duration = Duration::from_secs(300);
/// Reconnect attempts before giving up on the relay.
const MAX_RECONNECTS: u32 = 5;
/// How often to look for sessions to extend or drop.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(3600);
/// Extend a session once it has less than this much of its lifetime left.
const EXTEND_BELOW: u64 = SESSION_LIFETIME - 86_400;

pub struct ServiceOptions {
    pub project_id: String,
    pub relay_url: String,
    /// chain id → JSON-RPC URL; anything else uses the WalletConnect blockchain API.
    pub rpc_overrides: HashMap<u64, String>,
    /// Tenderly project that transaction simulation links open in.
    pub tenderly: Option<tenderly::TenderlyProject>,
    /// WalletConnect Verify server, or `None` to skip origin verification.
    pub verify_server: Option<String>,
    pub metadata: Metadata,
    /// Return once no session and no pending pairing is left (plain mode).
    /// The dashboard keeps running until the user quits.
    pub exit_when_idle: bool,
}

pub fn default_metadata() -> Metadata {
    Metadata {
        name: "opwallet".into(),
        description: "CLI wallet with its seed phrase in 1Password".into(),
        url: "https://github.com/chris13524/opwallet".into(),
        icons: vec![],
        verify_url: None,
    }
}

/// Parse `--rpc 1=https://...` style overrides.
pub fn parse_rpc_overrides(items: &[String]) -> Result<HashMap<u64, String>> {
    let mut out = HashMap::new();
    for item in items {
        let (chain, url) = item
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--rpc expects CHAIN_ID=URL, got {item:?}"))?;
        let chain = chain.trim().strip_prefix("eip155:").unwrap_or(chain.trim());
        let chain: u64 = chain.parse().with_context(|| format!("bad chain id in {item:?}"))?;
        out.insert(chain, url.trim().to_string());
    }
    Ok(out)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The wallets in 1Password, as the service needs them. Listing and lookups
/// only read public address fields; `open` reads a seed phrase.
pub trait Wallets: Opener + Sync {
    /// Every wallet with its public address, sorted by name.
    fn list(&self) -> Result<Vec<WalletSummary>>;
    /// One wallet's name and public address.
    fn lookup(&self, name: &str) -> Result<Account>;
    /// Generate a wallet, store it in 1Password, verify the round trip.
    fn create(&self, name: &str) -> Result<Account>;
}

/// A dapp to pair with: its `wc:` URI and the wallets to offer it.
pub struct PairRequest {
    pub uri: String,
    pub accounts: Vec<Account>,
}

fn clean_uri(u: &str) -> String {
    u.trim().trim_matches(['"', '\'', '<', '>']).trim().to_string()
}

/// Gather what a new pairing needs, prompting for whatever was not given.
/// `Ok(None)` when the user cancels a prompt.
pub fn prepare_pairing(
    ui: &mut dyn Ui,
    wallets: &dyn Wallets,
    uri: Option<String>,
    names: &[String],
) -> Result<Option<PairRequest>> {
    let uri = match uri.map(|u| clean_uri(&u)).filter(|u| !u.is_empty()) {
        Some(u) => u,
        None => match ui
            .input("Paste the WalletConnect URI (wc:...)")?
            .map(|u| clean_uri(&u))
            .filter(|u| !u.is_empty())
        {
            Some(u) => u,
            None => return Ok(None),
        },
    };
    // Fail fast on a bad URI before anything touches 1Password.
    let pairing = uri::parse_pairing_uri(&uri)?;
    if pairing.relay_protocol != "irn" {
        bail!("unsupported relay protocol {:?}", pairing.relay_protocol);
    }

    // Addresses come from the public field; no seed is read until a signature is needed.
    let accounts = if names.is_empty() {
        pick_wallets(ui, wallets, "Select the wallet(s) to connect", &[])?
    } else {
        let mut looked_up = ui::run_busy(ui, "Looking up wallet addresses in 1Password", || {
            names.iter().map(|n| wallets.lookup(n)).collect::<Result<Vec<_>>>()
        })?;
        looked_up.sort_by(|a, b| natural_cmp(&a.name, &b.name));
        looked_up
    };
    if accounts.is_empty() {
        return Ok(None);
    }
    for a in &accounts {
        ui.log(&format!("wallet {:?}: {}", a.name, a.address));
    }
    Ok(Some(PairRequest { uri, accounts }))
}

/// Let the user tick wallets, starting from `current`. Empty when cancelled.
fn pick_wallets(
    ui: &mut dyn Ui,
    wallets: &dyn Wallets,
    title: &str,
    current: &[Account],
) -> Result<Vec<Account>> {
    let mut list = ui::run_busy(ui, "Loading wallets from 1Password", || wallets.list())?;
    let parsed = |w: &WalletSummary| {
        w.address.as_deref().and_then(|a| a.parse::<alloy_primitives::Address>().ok())
    };
    // Wallets already connected stay on offer even if the listing lost them
    // (moved vault, renamed item), so keeping them is still a choice.
    for a in current {
        if !list.iter().any(|w| parsed(w) == Some(a.address)) {
            list.push(WalletSummary {
                id: String::new(),
                title: a.name.clone(),
                vault: Some("not found in 1Password".into()),
                address: Some(a.address.to_string()),
            });
        }
    }
    if list.is_empty() {
        bail!(
            "no Crypto Wallet items found; generate one with g in the dashboard or \
             `opwallet create --name <name>`"
        );
    }
    let labels: Vec<String> = list
        .iter()
        .map(|w| {
            format!(
                "{}  {}  {}",
                w.title,
                w.address.as_deref().unwrap_or("<no address>"),
                w.vault.as_deref().unwrap_or("")
            )
        })
        .collect();
    let preselected: Vec<usize> = list
        .iter()
        .enumerate()
        .filter(|(_, w)| current.iter().any(|a| parsed(w) == Some(a.address)))
        .map(|(i, _)| i)
        .collect();
    let picked = ui.select_many(title, &labels, &preselected)?;
    let mut accounts = Vec::new();
    for i in picked {
        let w = &list[i];
        let address = w
            .address
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("wallet {:?} has no wallet address field", w.title))?
            .parse()
            .with_context(|| format!("wallet {:?} has an invalid address", w.title))?;
        accounts.push(Account { name: w.title.clone(), address });
    }
    accounts.sort_by(|a, b| natural_cmp(&a.name, &b.name));
    Ok(accounts)
}

/// A pairing topic we listen on: either waiting for the dapp's proposal
/// (`pending`) or the pairing an established session came from.
struct Pairing {
    topic: String,
    key: SymKey,
    accounts: Vec<Account>,
    pending: bool,
    created: Instant,
}

struct Session {
    topic: String,
    key: SymKey,
    pairing_topic: String,
    pairing_key: SymKey,
    peer: Metadata,
    chains: Vec<String>,
    methods: Vec<String>,
    events: Vec<String>,
    accounts: Vec<Account>,
    /// Index of the account the dapp sees as selected.
    active: usize,
    expiry: u64,
    /// Chain of the most recent request, used for accountsChanged events.
    last_chain: Option<String>,
    created: u64,
    /// Id of our `wc_sessionSettle`, until the dapp answers it.
    settle_id: Option<u64>,
    sign_ins: usize,
    requests_approved: usize,
    requests_rejected: usize,
}

fn dapp_name(meta: &Metadata) -> String {
    if meta.name.is_empty() { "<unnamed dapp>".to_string() } else { meta.name.clone() }
}

impl Session {
    fn name(&self) -> String {
        dapp_name(&self.peer)
    }

    fn addresses(&self) -> Vec<String> {
        eth::ordered_addresses(&self.accounts, self.active)
    }

    fn to_stored(&self) -> StoredSession {
        StoredSession {
            topic: self.topic.clone(),
            key: self.key.to_hex().to_string(),
            pairing_topic: self.pairing_topic.clone(),
            pairing_key: self.pairing_key.to_hex().to_string(),
            peer: self.peer.clone(),
            chains: self.chains.clone(),
            methods: self.methods.clone(),
            events: self.events.clone(),
            accounts: self
                .accounts
                .iter()
                .map(|a| StoredAccount { name: a.name.clone(), address: a.address.to_string() })
                .collect(),
            active: self.active,
            expiry: self.expiry,
            last_chain: self.last_chain.clone(),
            created: self.created,
            sign_ins: self.sign_ins,
            requests_approved: self.requests_approved,
            requests_rejected: self.requests_rejected,
        }
    }

    fn from_stored(s: &StoredSession) -> Result<Self> {
        let key = SymKey::from_hex(&s.key)?;
        if key.topic() != s.topic {
            bail!("saved key does not match the session topic");
        }
        let accounts = s
            .accounts
            .iter()
            .map(|a| {
                Ok(Account {
                    name: a.name.clone(),
                    address: a
                        .address
                        .parse()
                        .with_context(|| format!("bad address {:?}", a.address))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if accounts.is_empty() {
            bail!("no wallets");
        }
        Ok(Self {
            topic: s.topic.clone(),
            key,
            pairing_topic: s.pairing_topic.clone(),
            pairing_key: SymKey::from_hex(&s.pairing_key)?,
            peer: s.peer.clone(),
            chains: s.chains.clone(),
            methods: s.methods.clone(),
            events: s.events.clone(),
            active: s.active.min(accounts.len() - 1),
            accounts,
            expiry: s.expiry,
            last_chain: s.last_chain.clone(),
            created: s.created,
            settle_id: None,
            sign_ins: s.sign_ins,
            requests_approved: s.requests_approved,
            requests_rejected: s.requests_rejected,
        })
    }

    fn view(&self) -> SessionView {
        SessionView {
            pending: false,
            dapp_name: self.name(),
            dapp_url: self.peer.url.clone(),
            chains: self.chains.clone(),
            methods: self.methods.clone(),
            wallets: wallet_rows(&self.accounts),
            active: self.active,
            expiry: self.expiry,
            sign_ins: self.sign_ins,
            requests_approved: self.requests_approved,
            requests_rejected: self.requests_rejected,
        }
    }
}

fn wallet_rows(accounts: &[Account]) -> Vec<WalletRow> {
    accounts
        .iter()
        .map(|a| WalletRow { name: a.name.clone(), address: a.address.to_string() })
        .collect()
}

fn send(
    relay: &mut Relay,
    topic: &str,
    key: &SymKey,
    plaintext: &str,
    ttl: u64,
    tag: u64,
) -> Result<()> {
    let envelope = crypto::encrypt(key, plaintext.as_bytes())?;
    relay.publish(topic, &envelope, ttl, tag)
}

struct Service<'a> {
    relay: Relay,
    store: SessionStore,
    pairings: Vec<Pairing>,
    sessions: Vec<Session>,
    /// Topic of the selected session or pending pairing.
    selected: Option<String>,
    metadata: Metadata,
    wallets: &'a dyn Wallets,
    rpc: RpcClient,
    tenderly: Option<tenderly::TenderlyProject>,
    verifier: verify::Verifier,
    ui: &'a mut dyn Ui,
    exit_when_idle: bool,
}

/// Run the WalletConnect service: resume the saved sessions, pair with
/// `initial` if given, then serve requests until the user quits (or, with
/// `exit_when_idle`, until nothing is left to serve).
pub fn run(
    opts: ServiceOptions,
    store: SessionStore,
    initial: Option<PairRequest>,
    wallets: &dyn Wallets,
    ui: &mut dyn Ui,
) -> Result<()> {
    let state = store.load()?;
    let mut sessions = Vec::new();
    for stored in &state.sessions {
        let name = dapp_name(&stored.peer);
        if stored.expiry <= now() {
            ui.log(&format!("saved session with {name} has expired; dropping it"));
            continue;
        }
        match Session::from_stored(stored) {
            Ok(s) => sessions.push(s),
            Err(e) => ui.warn(&format!("dropping unreadable saved session with {name}: {e:#}")),
        }
    }
    if opts.exit_when_idle && sessions.is_empty() && initial.is_none() {
        ui.status("No saved sessions. Pair with a dapp with `opwallet connect`.");
        if !state.sessions.is_empty() {
            store.save(&SavedState {
                version: 0,
                relay_key: state.relay_key.clone(),
                sessions: Vec::new(),
            })?;
        }
        return Ok(());
    }

    let client_key = match state.relay_key.as_deref().map(relay::client_key_from_hex) {
        Some(Ok(k)) => k,
        Some(Err(e)) => {
            ui.warn(&format!("saved relay identity is unusable ({e:#}); using a new one"));
            relay::new_client_key()?
        }
        None => relay::new_client_key()?,
    };
    ui.status("Connecting to the relay");
    let (relay_url, project_id) = (opts.relay_url.clone(), opts.project_id.clone());
    let relay = ui::run_busy(ui, "Connecting to the relay", move || {
        Relay::connect_as(&relay_url, &project_id, client_key)
    })?;

    let mut svc = Service {
        relay,
        store,
        pairings: Vec::new(),
        selected: sessions.first().map(|s| s.topic.clone()),
        sessions,
        metadata: opts.metadata,
        wallets,
        rpc: RpcClient::new(&opts.project_id, opts.rpc_overrides),
        tenderly: opts.tenderly,
        verifier: verify::Verifier::new(opts.verify_server),
        ui,
        exit_when_idle: opts.exit_when_idle,
    };
    svc.resume()?;
    if let Some(req) = initial {
        svc.pair(req)?;
    }
    svc.idle_status();
    svc.serve()
}

impl Service<'_> {
    /// Subscribe to every restored session and its pairing.
    fn resume(&mut self) -> Result<()> {
        for s in &self.sessions {
            if !self.pairings.iter().any(|p| p.topic == s.pairing_topic) {
                self.pairings.push(Pairing {
                    topic: s.pairing_topic.clone(),
                    key: s.pairing_key.clone(),
                    accounts: s.accounts.clone(),
                    pending: false,
                    created: Instant::now(),
                });
            }
        }
        let topics: Vec<String> = self
            .sessions
            .iter()
            .map(|s| s.topic.clone())
            .chain(self.pairings.iter().map(|p| p.topic.clone()))
            .collect();
        if !topics.is_empty() {
            let relay = &mut self.relay;
            ui::run_busy(
                self.ui,
                &format!("Resuming {} saved session(s)", self.sessions.len()),
                || topics.iter().try_for_each(|t| relay.subscribe(t)),
            )?;
        }
        for s in &self.sessions {
            let names: Vec<&str> = s.accounts.iter().map(|a| a.name.as_str()).collect();
            self.ui.log(&format!(
                "resumed session with {} ({}) for {}",
                s.name(),
                s.peer.url,
                names.join(", ")
            ));
        }
        self.maintain();
        // Also records the relay identity for the next run.
        self.persist();
        self.refresh();
        Ok(())
    }

    fn serve(&mut self) -> Result<()> {
        let mut reconnects = 0u32;
        let mut last_maintenance = Instant::now();
        loop {
            match self.ui.poll()? {
                UiAction::Quit => {
                    self.persist();
                    let n = self.sessions.len();
                    self.ui.status(&if n == 0 {
                        "Exiting".to_string()
                    } else {
                        format!("Exiting; {n} session(s) saved and resumed next time")
                    });
                    return Ok(());
                }
                UiAction::Idle => {}
                action => {
                    if let Err(e) = self.act(action) {
                        self.ui.warn(&format!("{e:#}"));
                    }
                }
            }
            let incoming = match self.relay.next_incoming() {
                Ok(x) => x,
                Err(e) => {
                    reconnects += 1;
                    if reconnects > MAX_RECONNECTS {
                        self.persist();
                        return Err(e.context("giving up on the relay"));
                    }
                    self.ui.warn(&format!(
                        "relay error: {e:#}; reconnecting ({reconnects}/{MAX_RECONNECTS})"
                    ));
                    std::thread::sleep(Duration::from_secs(1 << reconnects.min(4)));
                    let relay = &mut self.relay;
                    if let Err(e) =
                        ui::run_busy(self.ui, "Reconnecting to the relay", || relay.reconnect())
                    {
                        self.ui.warn(&format!("reconnect failed: {e:#}"));
                    }
                    continue;
                }
            };
            if let Some(incoming) = incoming {
                reconnects = 0;
                if let Err(e) = self.handle(incoming) {
                    self.ui.warn(&format!("{e:#}"));
                }
            }
            self.expire_pairings()?;
            if last_maintenance.elapsed() > MAINTENANCE_INTERVAL {
                last_maintenance = Instant::now();
                self.maintain();
            }
            if self.exit_when_idle
                && self.sessions.is_empty()
                && !self.pairings.iter().any(|p| p.pending)
            {
                return Ok(());
            }
        }
    }

    fn act(&mut self, action: UiAction) -> Result<()> {
        match action {
            UiAction::Idle | UiAction::Quit => Ok(()),
            UiAction::SwitchAccount(idx) => self.switch_account(idx),
            UiAction::SelectSession(idx) => {
                self.selected = self.entries().get(idx).cloned();
                self.refresh();
                Ok(())
            }
            UiAction::NewConnection => {
                if let Some(req) = prepare_pairing(self.ui, self.wallets, None, &[])? {
                    self.pair(req)?;
                }
                Ok(())
            }
            UiAction::Disconnect => self.disconnect_selected(),
            UiAction::EditWallets => self.edit_wallets(),
            UiAction::NewWallet => self.new_wallet(),
        }
    }

    /// Topics in list order: sessions first, then pending pairings.
    fn entries(&self) -> Vec<String> {
        self.sessions
            .iter()
            .map(|s| s.topic.clone())
            .chain(self.pairings.iter().filter(|p| p.pending).map(|p| p.topic.clone()))
            .collect()
    }

    fn selected_session(&self) -> Option<usize> {
        let topic = self.selected.as_deref()?;
        self.sessions.iter().position(|s| s.topic == topic)
    }

    fn refresh(&mut self) {
        let entries = self.entries();
        if self.selected.as_ref().is_none_or(|t| !entries.contains(t)) {
            self.selected = entries.first().cloned();
        }
        let mut views: Vec<SessionView> = self.sessions.iter().map(Session::view).collect();
        views.extend(self.pairings.iter().filter(|p| p.pending).map(|p| SessionView {
            pending: true,
            wallets: wallet_rows(&p.accounts),
            ..Default::default()
        }));
        let selected = self.selected.as_ref().and_then(|t| entries.iter().position(|e| e == t));
        self.ui.sessions(views, selected);
    }

    fn idle_status(&mut self) {
        let sessions = self.sessions.len();
        let pending = self.pairings.iter().filter(|p| p.pending).count();
        let status = match (sessions, pending) {
            (0, 0) => "No sessions; press n to connect a dapp".to_string(),
            (0, _) => "Waiting for the dapp's session proposal".to_string(),
            (n, 0) => format!("{n} session(s); waiting for requests"),
            (n, p) => format!("{n} session(s); {p} pairing(s) waiting for a proposal"),
        };
        self.ui.status(&status);
    }

    fn persist(&mut self) {
        let state = SavedState {
            version: 0,
            relay_key: Some(self.relay.client_key_hex().to_string()),
            sessions: self.sessions.iter().map(Session::to_stored).collect(),
        };
        if let Err(e) = self.store.save(&state) {
            self.ui.warn(&format!("could not save sessions: {e:#}"));
        }
    }

    /// Start listening for a dapp's proposal on a new pairing.
    fn pair(&mut self, req: PairRequest) -> Result<()> {
        let pairing = uri::parse_pairing_uri(&req.uri)?;
        let key = SymKey::from_hex(&pairing.sym_key)?;
        if key.topic() != pairing.topic {
            self.ui.warn("pairing topic does not equal sha256(symKey); continuing anyway");
        }
        if self.pairings.iter().any(|p| p.topic == pairing.topic) {
            bail!("already paired with this URI; generate a fresh one in the dapp");
        }
        self.relay.subscribe(&pairing.topic)?;
        self.pairings.push(Pairing {
            topic: pairing.topic.clone(),
            key,
            accounts: req.accounts,
            pending: true,
            created: Instant::now(),
        });
        self.selected = Some(pairing.topic);
        self.refresh();
        self.ui.status("Waiting for the dapp's session proposal");
        Ok(())
    }

    /// Drop pairings whose dapp never proposed.
    fn expire_pairings(&mut self) -> Result<()> {
        let expired: Vec<String> = self
            .pairings
            .iter()
            .filter(|p| p.pending && p.created.elapsed() > PROPOSAL_TIMEOUT)
            .map(|p| p.topic.clone())
            .collect();
        if expired.is_empty() {
            return Ok(());
        }
        for topic in &expired {
            self.pairings.retain(|p| &p.topic != topic);
            let _ = self.relay.unsubscribe(topic);
        }
        let msg = format!(
            "no session proposal arrived within {PROPOSAL_TIMEOUT:?}; generate a fresh URI in the dapp"
        );
        if self.exit_when_idle
            && self.sessions.is_empty()
            && !self.pairings.iter().any(|p| p.pending)
        {
            bail!(msg);
        }
        self.ui.warn(&msg);
        self.refresh();
        Ok(())
    }

    /// Drop expired sessions and extend the ones past a day old.
    fn maintain(&mut self) {
        let now = now();
        let expired: Vec<String> =
            self.sessions.iter().filter(|s| s.expiry <= now).map(|s| s.topic.clone()).collect();
        for topic in expired {
            if let Some(i) = self.sessions.iter().position(|s| s.topic == topic) {
                self.ui.log(&format!("session with {} expired", self.sessions[i].name()));
                self.remove_session(i, false);
            }
        }
        let mut changed = false;
        for s in &mut self.sessions {
            if s.expiry >= now + EXTEND_BELOW {
                continue;
            }
            let expiry = now + SESSION_LIFETIME;
            let body = request_json(new_rpc_id(), "wc_sessionExtend", json!({ "expiry": expiry }));
            match send(
                &mut self.relay,
                &s.topic,
                &s.key,
                &body,
                TTL_ONE_DAY,
                TAG_SESSION_EXTEND_REQ,
            ) {
                Ok(()) => {
                    s.expiry = expiry;
                    changed = true;
                }
                Err(e) => {
                    self.ui.warn(&format!("could not extend the session with {}: {e:#}", s.name()))
                }
            }
        }
        if changed {
            self.persist();
            self.refresh();
        }
    }

    /// Forget session `idx`, telling the dapp first when `notify` is set, and
    /// its pairing once nothing else uses it.
    fn remove_session(&mut self, idx: usize, notify: bool) {
        let s = self.sessions.remove(idx);
        if notify {
            let body = request_json(
                new_rpc_id(),
                "wc_sessionDelete",
                json!({ "code": ERR_USER_DISCONNECTED, "message": "User disconnected." }),
            );
            if let Err(e) =
                send(&mut self.relay, &s.topic, &s.key, &body, TTL_ONE_DAY, TAG_SESSION_DELETE_REQ)
            {
                self.ui.warn(&format!("could not notify {}: {e:#}", s.name()));
            }
        }
        let _ = self.relay.unsubscribe(&s.topic);
        let pairing_used = self.sessions.iter().any(|o| o.pairing_topic == s.pairing_topic);
        if !pairing_used
            && let Some(pi) =
                self.pairings.iter().position(|p| p.topic == s.pairing_topic && !p.pending)
        {
            let p = self.pairings.remove(pi);
            let _ = self.relay.unsubscribe(&p.topic);
        }
        self.persist();
        self.refresh();
    }

    fn disconnect_selected(&mut self) -> Result<()> {
        let Some(topic) = self.selected.clone() else {
            self.ui.warn("no session selected");
            return Ok(());
        };
        if let Some(pi) = self.pairings.iter().position(|p| p.topic == topic && p.pending) {
            self.pairings.remove(pi);
            let _ = self.relay.unsubscribe(&topic);
            self.ui.log("abandoned the pairing");
            self.refresh();
            self.idle_status();
            return Ok(());
        }
        let Some(idx) = self.selected_session() else { return Ok(()) };
        let name = self.sessions[idx].name();
        let body = format!(
            "End the session with {name} ({})?\n\nThe dapp is told the wallet disconnected; \
             connecting again needs a new pairing.",
            self.sessions[idx].peer.url
        );
        if !self.ui.confirm(&format!("Disconnect {name}"), &body)? {
            return Ok(());
        }
        self.remove_session(idx, true);
        self.ui.log(&format!("disconnected from {name}"));
        self.idle_status();
        Ok(())
    }

    /// Make wallet `idx` the selected session's active account and tell the
    /// dapp (`accountsChanged`).
    fn switch_account(&mut self, idx: usize) -> Result<()> {
        let Some(si) = self.selected_session() else { return Ok(()) };
        let s = &mut self.sessions[si];
        if idx >= s.accounts.len() || idx == s.active {
            return Ok(());
        }
        s.active = idx;
        let name = s.accounts[idx].name.clone();
        let chain = self.accounts_changed(si)?;
        self.ui.log(&format!(
            "switched {}'s active account to {name}; told the dapp (accountsChanged on {chain})",
            self.sessions[si].name()
        ));
        self.persist();
        self.refresh();
        Ok(())
    }

    /// Send `accountsChanged` for session `si`; returns the chain used.
    fn accounts_changed(&mut self, si: usize) -> Result<String> {
        let s = &self.sessions[si];
        let chain = s
            .last_chain
            .clone()
            .or_else(|| s.chains.first().cloned())
            .unwrap_or_else(|| "eip155:1".to_string());
        let params = accounts_changed_params(&chain, &s.addresses());
        let body = request_json(new_rpc_id(), "wc_sessionEvent", params);
        send(&mut self.relay, &s.topic, &s.key, &body, TTL_FIVE_MINUTES, TAG_SESSION_EVENT_REQ)?;
        Ok(chain)
    }

    /// Add or remove wallets on the selected session (`wc_sessionUpdate`).
    fn edit_wallets(&mut self) -> Result<()> {
        let Some(si) = self.selected_session() else {
            self.ui.warn("select a connected session first");
            return Ok(());
        };
        let current = self.sessions[si].accounts.clone();
        let title = format!("Wallets connected to {}", self.sessions[si].name());
        let picked = pick_wallets(self.ui, self.wallets, &title, &current)?;
        if picked.is_empty() {
            return Ok(());
        }
        self.set_accounts(si, picked)
    }

    fn set_accounts(&mut self, si: usize, accounts: Vec<Account>) -> Result<()> {
        let s = &self.sessions[si];
        let same = |a: &Account, b: &Account| a.address == b.address;
        let added: Vec<String> = accounts
            .iter()
            .filter(|a| !s.accounts.iter().any(|b| same(a, b)))
            .map(|a| a.name.clone())
            .collect();
        let removed: Vec<String> = s
            .accounts
            .iter()
            .filter(|a| !accounts.iter().any(|b| same(a, b)))
            .map(|a| a.name.clone())
            .collect();
        if added.is_empty() && removed.is_empty() {
            return Ok(());
        }
        let active_address = s.accounts.get(s.active).map(|a| a.address);
        let active = accounts.iter().position(|a| Some(a.address) == active_address).unwrap_or(0);
        let addresses = eth::ordered_addresses(&accounts, active);
        let namespaces = session::namespaces(&s.chains, &s.methods, &s.events, &addresses);
        let body =
            request_json(new_rpc_id(), "wc_sessionUpdate", json!({ "namespaces": namespaces }));
        let (topic, key) = (s.topic.clone(), s.key.clone());
        send(&mut self.relay, &topic, &key, &body, TTL_ONE_DAY, TAG_SESSION_UPDATE_REQ)?;

        let s = &mut self.sessions[si];
        s.accounts = accounts;
        s.active = active;
        if let Some(p) = self.pairings.iter_mut().find(|p| p.topic == s.pairing_topic) {
            p.accounts = s.accounts.clone();
        }
        let name = s.name();
        // Wallets without the update event still learn the selected account.
        if let Err(e) = self.accounts_changed(si) {
            self.ui.warn(&format!("could not send accountsChanged: {e:#}"));
        }
        let mut what = Vec::new();
        if !added.is_empty() {
            what.push(format!("added {}", added.join(", ")));
        }
        if !removed.is_empty() {
            what.push(format!("removed {}", removed.join(", ")));
        }
        self.ui.log(&format!("{name}: {}", what.join("; ")));
        self.persist();
        self.refresh();
        Ok(())
    }

    /// Generate a wallet in 1Password, then offer it to the selected session.
    fn new_wallet(&mut self) -> Result<()> {
        let Some(name) = self
            .ui
            .input("Name for the new wallet (its 1Password item title)")?
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
        else {
            return Ok(());
        };
        let wallets = self.wallets;
        let account = ui::run_busy(self.ui, &format!("Creating {name:?} in 1Password"), || {
            wallets.create(&name)
        })?;
        self.ui.log(&format!(
            "created wallet {:?}: {} (seed phrase stored in 1Password only)",
            account.name, account.address
        ));
        self.ui.copyable(
            &format!("address of new wallet {}", account.name),
            &account.address.to_string(),
        );
        let Some(si) = self.selected_session() else { return Ok(()) };
        let dapp = self.sessions[si].name();
        let body = format!(
            "Connect {} ({}) to the session with {dapp}?\n\nThe dapp sees it as an extra account; \
             the active account does not change.",
            account.name, account.address
        );
        if self.ui.confirm(&format!("Add {} to {dapp}", account.name), &body)? {
            let mut accounts = self.sessions[si].accounts.clone();
            accounts.push(account);
            accounts.sort_by(|a, b| natural_cmp(&a.name, &b.name));
            self.set_accounts(si, accounts)?;
        }
        Ok(())
    }

    fn handle(&mut self, inc: Incoming) -> Result<()> {
        if let Some(pi) = self.pairings.iter().position(|p| p.topic == inc.topic) {
            self.handle_pairing(pi, &inc)
        } else if let Some(si) = self.sessions.iter().position(|s| s.topic == inc.topic) {
            self.handle_session(si, &inc)
        } else {
            Ok(())
        }
    }

    fn handle_pairing(&mut self, pi: usize, inc: &Incoming) -> Result<()> {
        let (topic, key) = (self.pairings[pi].topic.clone(), self.pairings[pi].key.clone());
        let plaintext = match crypto::decrypt(&key, &inc.message) {
            Ok(p) => p,
            Err(e) => {
                self.ui.warn(&format!("ignoring pairing message (tag {}): {e}", inc.tag));
                return Ok(());
            }
        };
        let text = std::str::from_utf8(&plaintext).context("pairing message is not UTF-8")?;
        let Some(rpc) = parse_rpc(text) else { return Ok(()) };
        match rpc.method.as_deref() {
            Some("wc_sessionPropose") => {
                let evidence =
                    verify::Evidence::new(&inc.message, &plaintext, inc.attestation.clone());
                self.on_proposal(pi, &rpc, &evidence)
            }
            Some("wc_pairingPing") => send(
                &mut self.relay,
                &topic,
                &key,
                &result_json(rpc.id, json!(true)),
                TTL_THIRTY_SECONDS,
                TAG_PAIRING_PING_RES,
            ),
            Some("wc_pairingDelete") => {
                send(
                    &mut self.relay,
                    &topic,
                    &key,
                    &result_json(rpc.id, json!(true)),
                    TTL_ONE_DAY,
                    TAG_PAIRING_DELETE_RES,
                )?;
                if self.pairings[pi].pending {
                    self.pairings.remove(pi);
                    let _ = self.relay.unsubscribe(&topic);
                    self.ui.status("The dapp deleted the pairing before proposing a session");
                    self.refresh();
                }
                Ok(())
            }
            Some(other) => {
                self.ui.warn(&format!("ignoring unsupported pairing request {other}"));
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn on_proposal(&mut self, pi: usize, rpc: &Rpc, evidence: &verify::Evidence) -> Result<()> {
        let (topic, key) = (self.pairings[pi].topic.clone(), self.pairings[pi].key.clone());
        let accounts = self.pairings[pi].accounts.clone();
        let reply = |relay: &mut Relay, body: &str| {
            send(relay, &topic, &key, body, TTL_FIVE_MINUTES, TAG_SESSION_PROPOSE_RES)
        };
        let proposal: SessionProposal = match serde_json::from_value(rpc.params.clone()) {
            Ok(p) => p,
            Err(e) => {
                let err = RpcError::invalid_params(format!("bad proposal: {e}"));
                return reply(&mut self.relay, &error_json(rpc.id, &err));
            }
        };
        if let Some(exp) = proposal.expiry_timestamp
            && exp < now()
        {
            self.ui.warn("ignoring expired session proposal");
            return Ok(());
        }

        let meta = &proposal.proposer.metadata;
        let dapp_name = dapp_name(meta);
        let addresses = eth::ordered_addresses(&accounts, 0);
        let plan = match plan_approval(&proposal, &addresses) {
            Ok(plan) => plan,
            Err(err) => {
                self.ui.warn(&format!("cannot approve proposal from {dapp_name}: {err}"));
                return reply(&mut self.relay, &error_json(rpc.id, &err));
            }
        };
        let verified = verify::resolve(self.ui, &self.verifier, evidence, meta);
        let mut body = format!(
            "dapp:        {dapp_name}\nurl:         {}\n{}description: {}\nchains:      {}\nmethods:     {}\n\naccounts:\n",
            meta.url,
            verified.lines(&meta.url),
            meta.description,
            plan.chains.join(", "),
            plan.methods.join(", ")
        );
        for a in &accounts {
            body.push_str(&format!("  {} ({})\n", a.address, a.name));
        }
        let auth_count = proposal.requests.authentication.len();
        if auth_count > 0 {
            body.push_str(&format!("\n{auth_count} sign-in request(s) follow after approval.\n"));
        }
        let title = verified.title(&format!("Session proposal from {dapp_name}"));
        let mut approved = self.ui.confirm(&title, &body)?;
        // A mismatched or scam origin needs a second, explicit yes.
        if approved && let Some((title, body)) = verified.reconfirm(&dapp_name, &meta.url) {
            approved = self.ui.confirm(&title, &body)?;
        }
        if !approved {
            reply(&mut self.relay, &error_json(rpc.id, &RpcError::user_rejected()))?;
            self.ui.status("Rejected; still listening for a new proposal on this pairing");
            return Ok(());
        }

        let authentication =
            self.sign_in_requests(&proposal.requests.authentication, meta, &verified, &accounts)?;

        let keypair = KeyPair::generate()?;
        let session_key = keypair.derive_session_key(&proposal.proposer.public_key)?;
        let session_topic = session_key.topic();

        let response = result_json(
            rpc.id,
            json!({ "relay": { "protocol": "irn" }, "responderPublicKey": keypair.public_hex() }),
        );
        self.relay.subscribe(&session_topic)?;
        reply(&mut self.relay, &response)?;

        let settle_id = new_rpc_id();
        let expiry = now() + SESSION_LIFETIME;
        let settle = request_json(
            settle_id,
            "wc_sessionSettle",
            settle_params(&keypair.public_hex(), &self.metadata, &plan, expiry, &authentication),
        );
        send(
            &mut self.relay,
            &session_topic,
            &session_key,
            &settle,
            TTL_FIVE_MINUTES,
            TAG_SESSION_SETTLE_REQ,
        )?;

        if let Some(p) = self.pairings.iter_mut().find(|p| p.topic == topic) {
            p.pending = false;
        }
        self.ui.log(&format!(
            "Session with {dapp_name} ({}) on {}",
            meta.url,
            plan.chains.join(", ")
        ));
        self.sessions.push(Session {
            topic: session_topic.clone(),
            key: session_key,
            pairing_topic: topic.clone(),
            pairing_key: key.clone(),
            peer: meta.clone(),
            chains: plan.chains,
            methods: plan.methods,
            events: plan.events,
            accounts,
            active: 0,
            expiry,
            last_chain: None,
            created: now(),
            settle_id: Some(settle_id),
            sign_ins: authentication.len(),
            requests_approved: 0,
            requests_rejected: 0,
        });
        self.selected = Some(session_topic);
        self.persist();
        self.refresh();
        self.ui.status(&format!("Session approved; waiting for requests from {dapp_name}"));
        Ok(())
    }

    /// Sign-In with Ethereum requests attached to a proposal: show each one,
    /// ask, then sign the approved ones (one CACAO per account and EVM chain)
    /// with a single wallet open per account. Declined requests are simply
    /// omitted, as in the reference wallet.
    fn sign_in_requests(
        &mut self,
        requests: &[auth::AuthPayload],
        dapp: &Metadata,
        verified: &verify::Context,
        accounts: &[Account],
    ) -> Result<Vec<Value>> {
        let mut approved: Vec<(auth::AuthPayload, Vec<String>)> = Vec::new();
        for (i, request) in requests.iter().enumerate() {
            let chains = request.evm_chains();
            let mut body = format!(
                "domain:      {}\nuri:         {}\n",
                request.domain,
                request.uri().unwrap_or("<missing>")
            );
            body.push_str(&verified.lines(&dapp.url));
            if let Some(host) = dapp.url.split("://").nth(1).and_then(|r| r.split('/').next())
                && !host.is_empty()
                && host != request.domain
                && !host.ends_with(&format!(".{}", request.domain))
            {
                body.push_str(&format!(
                    "WARNING:     domain {:?} does not match the dapp's url host {host:?}\n",
                    request.domain
                ));
            }
            if chains.is_empty() {
                self.ui.warn(&format!(
                    "sign-in request {} skipped: no EVM chains requested ({})",
                    i + 1,
                    request.chains.join(", ")
                ));
                continue;
            }
            body.push_str(&format!(
                "chains:      {}\nnonce:       {}\nissued at:   {}\n",
                chains.join(", "),
                request.nonce,
                request.iat
            ));
            if let Some(exp) = &request.exp {
                body.push_str(&format!("expires:     {exp}\n"));
            }
            let first = &accounts[0];
            let preview =
                match auth::format_message(request, &auth::issuer(&chains[0], &first.address)) {
                    Ok(m) => m,
                    Err(e) => {
                        self.ui.warn(&format!(
                            "sign-in request {} skipped: cannot build message: {e}",
                            i + 1
                        ));
                        continue;
                    }
                };
            let copies = chains.len() * accounts.len();
            body.push_str(&format!(
                "\nMessage to sign{}:\n\n{preview}\n",
                if copies > 1 {
                    format!(" (signed once per account and chain, {copies} signatures)")
                } else {
                    String::new()
                }
            ));
            let title = format!(
                "Sign in to {} ({} of {}, from {})",
                request.domain,
                i + 1,
                requests.len(),
                dapp.name
            );
            if self.ui.confirm(&verified.title(&title), &body)? {
                approved.push((request.clone(), chains));
            } else {
                self.ui.log(&format!(
                    "declined sign-in to {}; the session will be approved without it",
                    request.domain
                ));
            }
        }
        if approved.is_empty() {
            return Ok(Vec::new());
        }

        let mut cacaos = Vec::new();
        for account in accounts {
            let opener: &(dyn Opener + Sync) = self.wallets;
            let name = account.name.clone();
            let wallet = ui::run_busy(
                self.ui,
                &format!("Waiting for 1Password to unlock {:?}", account.name),
                move || opener.open(&name),
            )?;
            if wallet.address() != account.address {
                bail!("1Password item {:?} no longer derives {}", account.name, account.address);
            }
            for (request, chains) in &approved {
                for chain in chains {
                    let iss = auth::issuer(chain, &account.address);
                    let message = auth::format_message(request, &iss)?;
                    let signature = wallet.sign_message(message.as_bytes())?;
                    cacaos.push(auth::build_cacao(request, &iss, &signature));
                }
            }
            drop(wallet);
        }
        self.ui.log(&format!("signed {} sign-in message(s)", cacaos.len()));
        Ok(cacaos)
    }

    fn handle_session(&mut self, si: usize, inc: &Incoming) -> Result<()> {
        let (key, topic, peer_name) = {
            let s = &self.sessions[si];
            (s.key.clone(), s.topic.clone(), s.name())
        };
        let plaintext = match crypto::decrypt(&key, &inc.message) {
            Ok(p) => p,
            Err(e) => {
                self.ui.warn(&format!("ignoring session message (tag {}): {e}", inc.tag));
                return Ok(());
            }
        };
        let text = std::str::from_utf8(&plaintext).context("session message is not UTF-8")?;
        let Some(rpc) = parse_rpc(text) else { return Ok(()) };
        let ack = |relay: &mut Relay, ttl: u64, tag: u64| {
            send(relay, &topic, &key, &result_json(rpc.id, json!(true)), ttl, tag)
        };

        let Some(method) = rpc.method.as_deref() else {
            let settle = self.sessions[si].settle_id == Some(rpc.id);
            match (&rpc.error, settle) {
                (Some(err), true) => {
                    self.ui.warn(&format!("{peer_name} rejected the session settlement: {err}"));
                    self.remove_session(si, false);
                }
                (None, true) => {
                    self.sessions[si].settle_id = None;
                    self.ui.log("the dapp acknowledged the session");
                }
                (Some(err), false) => {
                    self.ui.warn(&format!("{peer_name} answered with an error: {err}"))
                }
                (None, false) => {}
            }
            return Ok(());
        };

        match method {
            "wc_sessionRequest" => {
                let chain = rpc.params.get("chainId").and_then(Value::as_str).unwrap_or("");
                let request = &rpc.params["request"];
                let req_method = request.get("method").and_then(Value::as_str).unwrap_or("");
                let req_params = request.get("params").cloned().unwrap_or(Value::Null);
                self.ui.log(&format!("request from {peer_name}: {req_method} on {chain}"));

                let reply = match chain.strip_prefix("eip155:").and_then(|n| n.parse::<u64>().ok())
                {
                    None => Err(RpcError::invalid_params(format!("unsupported chain {chain:?}"))),
                    Some(chain_id) => {
                        let s = &mut self.sessions[si];
                        s.last_chain = Some(chain.to_string());
                        let evidence = verify::Evidence::new(
                            &inc.message,
                            &plaintext,
                            inc.attestation.clone(),
                        );
                        let mut ctx = RequestContext {
                            dapp: &peer_name,
                            accounts: &s.accounts,
                            active: s.active,
                            chain_id,
                            opener: self.wallets,
                            rpc: &self.rpc,
                            tenderly: self.tenderly.as_ref(),
                            verify: verify::Deferred::new(&self.verifier, evidence, &s.peer),
                            ui: self.ui,
                        };
                        eth::handle(req_method, &req_params, &mut ctx)
                    }
                };
                let body = match &reply {
                    Ok(result) => {
                        self.ui.log(&format!("{req_method}: approved"));
                        self.sessions[si].requests_approved += 1;
                        result_json(rpc.id, result.clone())
                    }
                    Err(err) => {
                        self.ui.log(&format!("{req_method}: rejected ({err})"));
                        self.sessions[si].requests_rejected += 1;
                        error_json(rpc.id, err)
                    }
                };
                self.persist();
                self.refresh();
                send(
                    &mut self.relay,
                    &topic,
                    &key,
                    &body,
                    TTL_FIVE_MINUTES,
                    TAG_SESSION_REQUEST_RES,
                )
            }
            "wc_sessionPing" => ack(&mut self.relay, TTL_THIRTY_SECONDS, TAG_SESSION_PING_RES),
            "wc_sessionDelete" => {
                ack(&mut self.relay, TTL_ONE_DAY, TAG_SESSION_DELETE_RES)?;
                self.remove_session(si, false);
                self.ui.status(&format!("{peer_name} disconnected the session"));
                Ok(())
            }
            "wc_sessionUpdate" => ack(&mut self.relay, TTL_ONE_DAY, TAG_SESSION_UPDATE_RES),
            "wc_sessionExtend" => {
                ack(&mut self.relay, TTL_ONE_DAY, TAG_SESSION_EXTEND_RES)?;
                let now = now();
                if let Some(expiry) = rpc.params.get("expiry").and_then(Value::as_u64)
                    && expiry > now
                    && expiry <= now + SESSION_LIFETIME
                {
                    self.sessions[si].expiry = expiry;
                    self.persist();
                    self.refresh();
                }
                Ok(())
            }
            "wc_sessionEvent" => ack(&mut self.relay, TTL_FIVE_MINUTES, TAG_SESSION_EVENT_RES),
            other => {
                let err =
                    RpcError::new(ERR_UNSUPPORTED_METHODS, format!("{other} is not supported"));
                send(
                    &mut self.relay,
                    &topic,
                    &key,
                    &error_json(rpc.id, &err),
                    TTL_FIVE_MINUTES,
                    TAG_SESSION_REQUEST_RES,
                )
            }
        }
    }
}

/// End saved sessions without starting the service: tell each dapp over the
/// relay, then forget the session. Returns the dapp names.
pub fn disconnect_saved(
    project_id: &str,
    relay_url: &str,
    store: &SessionStore,
    indices: &[usize],
) -> Result<Vec<String>> {
    let mut state = store.load()?;
    let client_key = match state.relay_key.as_deref().map(relay::client_key_from_hex) {
        Some(Ok(k)) => k,
        _ => relay::new_client_key()?,
    };
    let chosen: Vec<&StoredSession> =
        indices.iter().filter_map(|&i| state.sessions.get(i)).collect();
    let mut names = Vec::new();
    if chosen.iter().any(|s| s.expiry > now()) {
        let mut relay = Relay::connect_as(relay_url, project_id, client_key)?;
        for s in &chosen {
            if s.expiry <= now() {
                continue;
            }
            let key = SymKey::from_hex(&s.key)?;
            let body = request_json(
                new_rpc_id(),
                "wc_sessionDelete",
                json!({ "code": ERR_USER_DISCONNECTED, "message": "User disconnected." }),
            );
            send(&mut relay, &s.topic, &key, &body, TTL_ONE_DAY, TAG_SESSION_DELETE_REQ)
                .with_context(|| format!("could not notify {}", dapp_name(&s.peer)))?;
        }
    }
    for s in &chosen {
        names.push(dapp_name(&s.peer));
    }
    let mut i = 0;
    state.sessions.retain(|_| {
        let keep = !indices.contains(&i);
        i += 1;
        keep
    });
    store.save(&state)?;
    Ok(names)
}

/// Resolve a session selector from `opwallet disconnect`: a 1-based number
/// from `opwallet sessions`, a topic prefix, or part of the dapp's name or URL.
pub fn select_saved(sessions: &[StoredSession], selector: &str) -> Result<usize> {
    let sel = selector.trim();
    if let Ok(n) = sel.parse::<usize>() {
        if n == 0 || n > sessions.len() {
            bail!("no saved session number {n}; see `opwallet sessions`");
        }
        return Ok(n - 1);
    }
    let lower = sel.to_lowercase();
    let matches: Vec<usize> = sessions
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            (sel.len() >= 6 && s.topic.starts_with(sel))
                || s.peer.name.to_lowercase().contains(&lower)
                || s.peer.url.to_lowercase().contains(&lower)
        })
        .map(|(i, _)| i)
        .collect();
    match matches.as_slice() {
        [i] => Ok(*i),
        [] => bail!("no saved session matches {sel:?}; see `opwallet sessions`"),
        _ => bail!(
            "{sel:?} matches {} sessions; use its number from `opwallet sessions`",
            matches.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_override_parsing() {
        let m =
            parse_rpc_overrides(&["1=https://a".into(), "eip155:10 = https://b".into()]).unwrap();
        assert_eq!(m[&1], "https://a");
        assert_eq!(m[&10], "https://b");
        assert!(parse_rpc_overrides(&["nope".into()]).is_err());
        assert!(parse_rpc_overrides(&["x=https://a".into()]).is_err());
    }

    #[test]
    fn saved_session_selectors() {
        let mk = |topic: &str, name: &str, url: &str| StoredSession {
            topic: topic.into(),
            key: String::new(),
            pairing_topic: String::new(),
            pairing_key: String::new(),
            peer: Metadata { name: name.into(), url: url.into(), ..Default::default() },
            chains: vec![],
            methods: vec![],
            events: vec![],
            accounts: vec![],
            active: 0,
            expiry: 0,
            last_chain: None,
            created: 0,
            sign_ins: 0,
            requests_approved: 0,
            requests_rejected: 0,
        };
        let list = [
            mk("aaaaaaaa11", "Uniswap", "https://app.uniswap.org"),
            mk("bbbbbbbb22", "Safe", "https://app.safe.global"),
        ];
        assert_eq!(select_saved(&list, "2").unwrap(), 1);
        assert_eq!(select_saved(&list, "uniswap").unwrap(), 0);
        assert_eq!(select_saved(&list, "safe.global").unwrap(), 1);
        assert_eq!(select_saved(&list, "bbbbbbbb").unwrap(), 1);
        assert!(select_saved(&list, "3").is_err());
        assert!(select_saved(&list, "app").unwrap_err().to_string().contains("matches 2"));
        assert!(select_saved(&list, "nothing").is_err());
    }
}
