//! The dapp side of WalletConnect v2 (Sign API), for `wcapp`: propose a
//! session to a wallet, keep the settled session across runs, and send it
//! signing requests, each one answered (or refused) by the wallet.
//!
//! Every command is a short process: it connects to the relay, picks up
//! whatever the wallet sent meanwhile (account switches, updates, a
//! deleted session), does its one thing and exits. Saved state holds
//! session keys and public data only; there is no key to any account here.
//!
//! A pairing can outlive the process that created it (`wcapp connect
//! --no-wait`): its symmetric key and our proposal key are saved, and the
//! next command finishes it from the relay's mailbox.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use alloy_primitives::Address;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroize;

use super::{
    crypto::{self, KeyPair, SymKey, random_array},
    now,
    relay::{self, Incoming, Relay, new_rpc_id},
    send,
    session::*,
    store::{self, SessionStore},
};

const STATE_FILE: &str = "dapp-sessions.json";
const VERSION: u32 = 1;
/// How long a proposal waits on the relay for a wallet to pick it up.
const PROPOSAL_TTL: u64 = TTL_FIVE_MINUTES;
/// Extra time to wait for an answer past a request's expiry, for clocks
/// that disagree a little and for the answer's trip back.
const ANSWER_GRACE: Duration = Duration::from_secs(15);
/// Extend the session once it has less than this much of its lifetime left.
const EXTEND_BELOW: u64 = SESSION_LIFETIME - 86_400;

/// Methods asked for when proposing a session.
pub const DAPP_METHODS: &[&str] = &[
    "personal_sign",
    "eth_signTypedData_v4",
    "eth_signTransaction",
    "eth_sendTransaction",
    "eth_accounts",
    "eth_chainId",
];
/// Events asked for when proposing a session.
pub const DAPP_EVENTS: &[&str] = &["accountsChanged", "chainChanged"];

/// A proposal sent to a wallet that has not settled yet. Holds keys, so no `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingPairing {
    pub topic: String,
    /// Pairing symmetric key, hex.
    pub key: String,
    /// Our X25519 private key for the proposal, hex.
    pub secret: String,
    pub proposal_id: u64,
    pub chains: Vec<String>,
    /// Unix time the proposal expires unanswered.
    pub expiry: u64,
    /// Session key, hex, once the wallet has approved (its settle may still be on the way).
    #[serde(default)]
    pub session_key: Option<String>,
    /// The wallet's public key from its approval; the settle must come from it.
    #[serde(default)]
    pub responder: Option<String>,
}

impl Drop for PendingPairing {
    fn drop(&mut self) {
        self.key.zeroize();
        self.secret.zeroize();
        if let Some(k) = &mut self.session_key {
            k.zeroize();
        }
    }
}

/// A settled session with a wallet. Holds keys, so no `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct DappSession {
    pub topic: String,
    /// Session symmetric key, hex.
    pub key: String,
    pub pairing_topic: String,
    /// The wallet's metadata, as it describes itself.
    pub peer: Metadata,
    /// Addresses the wallet shares, the one it has selected first.
    pub accounts: Vec<String>,
    pub chains: Vec<String>,
    pub methods: Vec<String>,
    pub events: Vec<String>,
    /// Unix time the session expires.
    pub expiry: u64,
    #[serde(default)]
    pub created: u64,
}

impl Drop for DappSession {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl DappSession {
    pub fn name(&self) -> String {
        if self.peer.name.is_empty() { "<unnamed wallet>".into() } else { self.peer.name.clone() }
    }
}

/// Contents of the state file.
#[derive(Default, Serialize, Deserialize)]
pub struct DappState {
    #[serde(default)]
    pub version: u32,
    /// Ed25519 seed of the relay client identity, hex.
    #[serde(default)]
    pub relay_key: Option<String>,
    #[serde(default)]
    pub pending: Vec<PendingPairing>,
    #[serde(default)]
    pub sessions: Vec<DappSession>,
}

impl Drop for DappState {
    fn drop(&mut self) {
        if let Some(k) = &mut self.relay_key {
            k.zeroize();
        }
    }
}

/// Read the saved state without taking the lock (for listings).
pub fn read_state(dir: &Path) -> Result<DappState> {
    let state: DappState = store::read_json(dir, STATE_FILE)?.unwrap_or_default();
    if state.version > VERSION {
        bail!("{} was written by a newer wcapp (version {})", dir.display(), state.version);
    }
    Ok(state)
}

/// An account, as `wcapp list` numbers them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRow {
    /// 1-based, across every session.
    pub number: usize,
    /// Index into [`DappState::sessions`].
    pub session: usize,
    pub address: String,
    /// The wallet's selected account in that session.
    pub active: bool,
}

/// Every account of every live session, in listing order.
pub fn account_rows(state: &DappState) -> Vec<AccountRow> {
    let mut rows = Vec::new();
    for (si, s) in state.sessions.iter().enumerate() {
        for (i, a) in s.accounts.iter().enumerate() {
            rows.push(AccountRow {
                number: rows.len() + 1,
                session: si,
                address: a.clone(),
                active: i == 0,
            });
        }
    }
    rows
}

/// Pick the account `selector` names (see `wcapp --help` for `-n`).
pub fn resolve_account(state: &DappState, selector: Option<&str>) -> Result<(usize, Address)> {
    let rows = account_rows(state);
    let parse = |r: &AccountRow| -> Result<(usize, Address)> {
        let a = r.address.parse().with_context(|| format!("bad saved address {:?}", r.address))?;
        Ok((r.session, a))
    };
    if state.sessions.is_empty() {
        bail!("no wallet is connected; pair with one with `wcapp connect`");
    }
    let Some(sel) = selector.map(str::trim).filter(|s| !s.is_empty()) else {
        let active: Vec<&AccountRow> = rows.iter().filter(|r| r.active).collect();
        return match active.as_slice() {
            [one] => parse(one),
            [] => bail!("the connected wallet shares no accounts"),
            _ => bail!(
                "{} wallets are connected; pick an account with -n (see `wcapp list`)",
                active.len()
            ),
        };
    };
    if let Ok(n) = sel.parse::<usize>() {
        return match rows.get(n.wrapping_sub(1)) {
            Some(r) => parse(r),
            None => bail!("no account number {n}; see `wcapp list`"),
        };
    }
    let lower = sel.to_ascii_lowercase();
    if lower.starts_with("0x") {
        let matches: Vec<&AccountRow> =
            rows.iter().filter(|r| r.address.to_ascii_lowercase().starts_with(&lower)).collect();
        let mut distinct: Vec<String> =
            matches.iter().map(|r| r.address.to_ascii_lowercase()).collect();
        distinct.dedup();
        return match (matches.first(), distinct.len()) {
            (Some(r), 1) => parse(r),
            (None, _) => bail!("no connected account starts with {sel}; see `wcapp list`"),
            (_, n) => bail!("{sel} matches {n} accounts; give more of the address"),
        };
    }
    let sessions: Vec<usize> = state
        .sessions
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            s.peer.name.to_lowercase().contains(&lower)
                || s.peer.url.to_lowercase().contains(&lower)
        })
        .map(|(i, _)| i)
        .collect();
    match sessions.as_slice() {
        [si] => rows
            .iter()
            .find(|r| r.session == *si && r.active)
            .ok_or_else(|| anyhow!("{} shares no accounts", state.sessions[*si].name()))
            .and_then(parse),
        [] => bail!("no connected account or wallet matches {sel:?}; see `wcapp list`"),
        _ => bail!("{sel:?} matches {} wallets; use an address or number", sessions.len()),
    }
}

/// The chain to send a request on: `wanted` if given (it must be one the
/// session has), else `fallback` if the session has it, else its first chain.
pub fn pick_chain(s: &DappSession, wanted: Option<u64>, fallback: Option<u64>) -> Result<String> {
    let has = |c: u64| s.chains.iter().any(|x| x == &format!("eip155:{c}"));
    if let Some(c) = wanted {
        if has(c) {
            return Ok(format!("eip155:{c}"));
        }
        bail!(
            "the session with {} does not include chain {c}; pair again with \
             `wcapp connect --chain {c}` (it has {})",
            s.name(),
            s.chains.join(", ")
        );
    }
    if let Some(c) = fallback.filter(|c| has(*c)) {
        return Ok(format!("eip155:{c}"));
    }
    s.chains.first().cloned().ok_or_else(|| anyhow!("the session with {} has no chains", s.name()))
}

/// Addresses from CAIP-10 accounts (or plain addresses), first-seen order, no repeats.
fn addresses_of<'a>(items: impl IntoIterator<Item = &'a Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in items {
        let Some(s) = v.as_str() else { continue };
        let addr = s.rsplit(':').next().unwrap_or(s);
        if addr.parse::<Address>().is_ok() && !out.iter().any(|a| a.eq_ignore_ascii_case(addr)) {
            out.push(addr.to_string());
        }
    }
    out
}

fn chains_of(ns: &Value) -> Vec<String> {
    let mut chains: Vec<String> = ns["chains"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    if chains.is_empty() {
        for acc in ns["accounts"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            let mut parts = acc.splitn(3, ':');
            if let (Some(n), Some(r), Some(_)) = (parts.next(), parts.next(), parts.next()) {
                let c = format!("{n}:{r}");
                if !chains.contains(&c) {
                    chains.push(c);
                }
            }
        }
    }
    chains
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

/// Apply `namespaces` from a settle or update; the selected account stays
/// first when the wallet still shares it.
fn apply_namespaces(s: &mut DappSession, namespaces: &Value) -> Result<()> {
    let ns = &namespaces["eip155"];
    let mut accounts = addresses_of(ns["accounts"].as_array().into_iter().flatten());
    if accounts.is_empty() {
        bail!("the wallet shared no EVM accounts");
    }
    if let Some(active) = s.accounts.first()
        && let Some(i) = accounts.iter().position(|a| a.eq_ignore_ascii_case(active))
    {
        let a = accounts.remove(i);
        accounts.insert(0, a);
    }
    s.accounts = accounts;
    s.chains = chains_of(ns);
    s.methods = strings(&ns["methods"]);
    s.events = strings(&ns["events"]);
    Ok(())
}

/// What a request from the wallet did to a session.
#[derive(Debug, PartialEq, Eq)]
pub enum EventOutcome {
    /// Acknowledge with `true` under this tag.
    Ack { tag: u64, ttl: u64, changed: bool },
    /// The wallet ended the session: acknowledge, then forget it.
    Deleted,
    /// Not something a dapp answers to.
    Unsupported,
}

/// Apply one request the wallet sent on the session topic.
pub fn apply_event(s: &mut DappSession, method: &str, params: &Value) -> EventOutcome {
    let ack = |tag, ttl, changed| EventOutcome::Ack { tag, ttl, changed };
    match method {
        "wc_sessionEvent" => {
            let event = &params["event"];
            if event["name"] == "accountsChanged" {
                let accounts = addresses_of(event["data"].as_array().into_iter().flatten());
                if !accounts.is_empty() && accounts != s.accounts {
                    s.accounts = accounts;
                    return ack(TAG_SESSION_EVENT_RES, TTL_FIVE_MINUTES, true);
                }
            }
            ack(TAG_SESSION_EVENT_RES, TTL_FIVE_MINUTES, false)
        }
        "wc_sessionUpdate" => {
            let changed = apply_namespaces(s, &params["namespaces"]).is_ok();
            ack(TAG_SESSION_UPDATE_RES, TTL_ONE_DAY, changed)
        }
        "wc_sessionExtend" => {
            let now = now();
            let changed = match params["expiry"].as_u64() {
                Some(e) if e > now && e <= now + SESSION_LIFETIME && e != s.expiry => {
                    s.expiry = e;
                    true
                }
                _ => false,
            };
            ack(TAG_SESSION_EXTEND_RES, TTL_ONE_DAY, changed)
        }
        "wc_sessionPing" => ack(TAG_SESSION_PING_RES, TTL_THIRTY_SECONDS, false),
        "wc_sessionSettle" => ack(TAG_SESSION_SETTLE_RES, TTL_FIVE_MINUTES, false),
        "wc_sessionDelete" => EventOutcome::Deleted,
        _ => EventOutcome::Unsupported,
    }
}

/// A settled session from the wallet's `wc_sessionSettle`.
fn settle_session(
    pending: &PendingPairing,
    topic: &str,
    key: &SymKey,
    params: &Value,
) -> Result<DappSession> {
    let controller = params["controller"]["publicKey"].as_str().unwrap_or("");
    if pending.responder.as_deref().is_some_and(|r| r != controller) {
        bail!("the settlement's controller is not the wallet that approved the proposal");
    }
    let peer: Metadata =
        serde_json::from_value(params["controller"]["metadata"].clone()).unwrap_or_default();
    let now = now();
    let expiry = params["expiry"].as_u64().unwrap_or(0);
    if expiry <= now {
        bail!("the wallet settled a session that has already expired");
    }
    let mut s = DappSession {
        topic: topic.to_string(),
        key: key.to_hex().to_string(),
        pairing_topic: pending.topic.clone(),
        peer,
        accounts: Vec::new(),
        chains: Vec::new(),
        methods: Vec::new(),
        events: Vec::new(),
        expiry: expiry.min(now + SESSION_LIFETIME),
        created: now,
    };
    apply_namespaces(&mut s, &params["namespaces"])?;
    Ok(s)
}

pub struct DappOptions {
    pub project_id: String,
    pub relay_url: String,
    pub metadata: Metadata,
    /// How long to wait for the wallet; also how long a request stays valid.
    pub timeout: Duration,
}

/// What `wcapp` shows wallets about itself.
pub fn default_metadata() -> Metadata {
    Metadata {
        name: "wcapp".into(),
        description: "Command-line WalletConnect app (opwallet's counterpart)".into(),
        url: "https://github.com/chris13524/opwallet".into(),
        icons: vec![],
        verify_url: None,
    }
}

/// A wallet's answer that was an error.
#[derive(Debug)]
pub struct WalletError {
    pub wallet: String,
    pub code: i64,
    pub message: String,
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} refused: {} (code {})", self.wallet, self.message, self.code)
    }
}

impl std::error::Error for WalletError {}

/// The saved state, locked, with a relay connection opened on first use.
pub struct Dapp<'a> {
    store: SessionStore,
    pub state: DappState,
    relay: Option<Relay>,
    opts: DappOptions,
    note: &'a mut dyn FnMut(&str),
}

impl<'a> Dapp<'a> {
    /// Lock the state directory (waiting for another command to finish
    /// with it) and load it. `note` receives progress for the user.
    pub fn open(dir: &Path, opts: DappOptions, note: &'a mut dyn FnMut(&str)) -> Result<Self> {
        let store = SessionStore::open_waiting(dir, || {
            note("waiting for another wcapp command to finish");
        })?;
        let state = read_state(dir)?;
        let mut dapp = Self { store, state, relay: None, opts, note };
        dapp.drop_expired()?;
        Ok(dapp)
    }

    fn save(&mut self) -> Result<()> {
        self.state.version = VERSION;
        self.store.save_json(STATE_FILE, &self.state)
    }

    fn relay(&mut self) -> Result<&mut Relay> {
        if self.relay.is_none() {
            let key = match self.state.relay_key.as_deref().map(relay::client_key_from_hex) {
                Some(Ok(k)) => k,
                _ => relay::new_client_key()?,
            };
            let relay = Relay::connect_as(&self.opts.relay_url, &self.opts.project_id, key)?;
            let hex = relay.client_key_hex().to_string();
            if self.state.relay_key.as_deref() != Some(hex.as_str()) {
                self.state.relay_key = Some(hex);
                self.save()?;
            }
            self.relay = Some(relay);
        }
        Ok(self.relay.as_mut().expect("just connected"))
    }

    fn drop_expired(&mut self) -> Result<()> {
        let now = now();
        let before = (self.state.sessions.len(), self.state.pending.len());
        for s in self.state.sessions.iter().filter(|s| s.expiry <= now) {
            (self.note)(&format!("the session with {} has expired", s.name()));
        }
        self.state.sessions.retain(|s| s.expiry > now);
        // An approved proposal is kept until its settle arrives, however late.
        self.state.pending.retain(|p| p.expiry > now || p.session_key.is_some());
        if before != (self.state.sessions.len(), self.state.pending.len()) {
            self.save()?;
        }
        Ok(())
    }

    /// Propose a session asking for `chains`; returns the pairing URI.
    pub fn pair(&mut self, chains: &[u64]) -> Result<String> {
        let pairing_key = SymKey::from_bytes(*random_array::<32>()?);
        let topic = pairing_key.topic();
        let keypair = KeyPair::generate()?;
        let expiry = now() + PROPOSAL_TTL;
        let chains: Vec<String> = chains.iter().map(|c| format!("eip155:{c}")).collect();
        let proposal_id = new_rpc_id();
        let params = json!({
            "relays": [{ "protocol": "irn" }],
            "proposer": { "publicKey": keypair.public_hex(), "metadata": self.opts.metadata },
            "requiredNamespaces": {},
            "optionalNamespaces": {
                "eip155": { "chains": chains, "methods": DAPP_METHODS, "events": DAPP_EVENTS }
            },
            "pairingTopic": topic,
            "expiryTimestamp": expiry,
        });
        let body = request_json(proposal_id, "wc_sessionPropose", params);
        let relay = self.relay()?;
        relay.subscribe(&topic)?;
        send(relay, &topic, &pairing_key, &body, PROPOSAL_TTL, TAG_SESSION_PROPOSE_REQ)?;
        self.state.pending.push(PendingPairing {
            topic: topic.clone(),
            key: pairing_key.to_hex().to_string(),
            secret: keypair.secret_hex().to_string(),
            proposal_id,
            chains,
            expiry,
            session_key: None,
            responder: None,
        });
        self.save()?;
        let key_hex = pairing_key.to_hex();
        Ok(format!("wc:{topic}@2?relay-protocol=irn&symKey={}&expiryTimestamp={expiry}", *key_hex))
    }

    /// Finish proposals sent earlier. With `wait`, block until each is
    /// settled, refused, or the timeout passes; without, only take what
    /// has already arrived.
    pub fn finish_pairings(&mut self, wait: bool) -> Result<Vec<String>> {
        if self.state.pending.is_empty() {
            return Ok(Vec::new());
        }
        let topics = self.pending_topics();
        let relay = self.relay()?;
        for t in &topics {
            relay.subscribe(t)?;
        }
        if wait {
            (self.note)("waiting for the wallet to approve the connection");
        }
        let deadline = Instant::now() + self.opts.timeout;
        let mut settled = Vec::new();
        while !self.state.pending.is_empty() {
            match self.relay()?.next_incoming()? {
                Some(inc) => {
                    if let Some(name) = self.handle_pairing_message(&inc)? {
                        settled.push(name);
                    } else {
                        self.handle(&inc)?;
                    }
                }
                None if !wait => break,
                None if Instant::now() > deadline => bail!(
                    "the wallet did not approve the connection within {}s",
                    self.opts.timeout.as_secs()
                ),
                None => {}
            }
        }
        Ok(settled)
    }

    /// Pairing topics of pending proposals, and session topics of approved ones.
    fn pending_topics(&self) -> Vec<String> {
        self.state
            .pending
            .iter()
            .flat_map(|p| {
                let session = p
                    .session_key
                    .as_deref()
                    .and_then(|k| SymKey::from_hex(k).ok())
                    .map(|k| k.topic());
                std::iter::once(p.topic.clone()).chain(session)
            })
            .collect()
    }

    /// Handle a message for a pending pairing; `Some(wallet name)` once one settles.
    fn handle_pairing_message(&mut self, inc: &Incoming) -> Result<Option<String>> {
        // The wallet's answer to our proposal, on the pairing topic.
        if let Some(pi) = self.state.pending.iter().position(|p| p.topic == inc.topic) {
            let key = SymKey::from_hex(&self.state.pending[pi].key)?;
            let Some(rpc) = decrypt_rpc(&key, inc) else { return Ok(None) };
            let pending = &self.state.pending[pi];
            if rpc.id != pending.proposal_id || rpc.method.is_some() {
                return Ok(None); // our own proposal echoed back, or a ping
            }
            if let Some(err) = rpc.error {
                self.state.pending.remove(pi);
                self.save()?;
                let message = err["message"].as_str().unwrap_or("no reason given").to_string();
                return Err(WalletError {
                    wallet: "the wallet".into(),
                    code: err["code"].as_i64().unwrap_or(0),
                    message: format!("the connection was rejected: {message}"),
                }
                .into());
            }
            let responder = rpc
                .result
                .as_ref()
                .and_then(|r| r["responderPublicKey"].as_str())
                .ok_or_else(|| anyhow!("the wallet's approval has no responderPublicKey"))?
                .to_string();
            let session_key =
                KeyPair::from_secret_hex(&pending.secret)?.derive_session_key(&responder)?;
            let session_topic = session_key.topic();
            let p = &mut self.state.pending[pi];
            p.session_key = Some(session_key.to_hex().to_string());
            p.responder = Some(responder);
            self.save()?;
            self.relay()?.subscribe(&session_topic)?;
            return Ok(None);
        }
        // The wallet's settlement, on the new session topic.
        let Some(pi) = self.state.pending.iter().position(|p| {
            p.session_key
                .as_deref()
                .and_then(|k| SymKey::from_hex(k).ok())
                .is_some_and(|k| k.topic() == inc.topic)
        }) else {
            return Ok(None);
        };
        let key =
            SymKey::from_hex(self.state.pending[pi].session_key.as_deref().expect("matched"))?;
        let Some(rpc) = decrypt_rpc(&key, inc) else { return Ok(None) };
        if rpc.method.as_deref() != Some("wc_sessionSettle") {
            return Ok(None);
        }
        let session = settle_session(&self.state.pending[pi], &inc.topic, &key, &rpc.params);
        let ack = match &session {
            Ok(_) => result_json(rpc.id, json!(true)),
            Err(e) => error_json(rpc.id, &RpcError::invalid_params(format!("{e:#}"))),
        };
        send(self.relay()?, &inc.topic, &key, &ack, TTL_FIVE_MINUTES, TAG_SESSION_SETTLE_RES)?;
        let pending = self.state.pending.remove(pi);
        let relay = self.relay()?;
        let _ = relay.unsubscribe(&pending.topic);
        let session = match session {
            Ok(s) => s,
            Err(e) => {
                let _ = relay.unsubscribe(&inc.topic);
                self.save()?;
                return Err(e.context("refused the wallet's settlement"));
            }
        };
        let name = session.name();
        (self.note)(&format!(
            "connected to {name} ({}); accounts: {}",
            session.peer.url,
            session.accounts.join(", ")
        ));
        self.state.sessions.push(session);
        self.save()?;
        Ok(Some(name))
    }

    /// Subscribe to every session, take in what the wallets sent while no
    /// command was running, and extend sessions that need it.
    pub fn sync(&mut self) -> Result<()> {
        if self.state.sessions.is_empty() && self.state.pending.is_empty() {
            return Ok(());
        }
        let mut topics: Vec<String> = self.state.sessions.iter().map(|s| s.topic.clone()).collect();
        topics.extend(self.pending_topics());
        let relay = self.relay()?;
        for t in &topics {
            relay.subscribe(t)?;
        }
        // Mailbox messages follow the subscriptions; a quiet tick means they are in.
        while let Some(inc) = self.relay()?.next_incoming()? {
            if self.handle_pairing_message(&inc)?.is_none() {
                self.handle(&inc)?;
            }
        }
        self.extend()
    }

    fn extend(&mut self) -> Result<()> {
        let now = now();
        let due: Vec<usize> = (0..self.state.sessions.len())
            .filter(|&i| self.state.sessions[i].expiry < now + EXTEND_BELOW)
            .collect();
        for i in due {
            let expiry = now + SESSION_LIFETIME;
            let (topic, key) = self.session_key(i)?;
            let body = request_json(new_rpc_id(), "wc_sessionExtend", json!({ "expiry": expiry }));
            send(self.relay()?, &topic, &key, &body, TTL_ONE_DAY, TAG_SESSION_EXTEND_REQ)?;
            self.state.sessions[i].expiry = expiry;
        }
        self.save()
    }

    fn session_key(&self, i: usize) -> Result<(String, SymKey)> {
        let s = &self.state.sessions[i];
        Ok((s.topic.clone(), SymKey::from_hex(&s.key)?))
    }

    /// Handle a message on a session topic. Requests from the wallet are
    /// applied and acknowledged; a response is returned to the caller.
    fn handle(&mut self, inc: &Incoming) -> Result<Option<(String, Rpc)>> {
        let Some(si) = self.state.sessions.iter().position(|s| s.topic == inc.topic) else {
            return Ok(None);
        };
        let (topic, key) = self.session_key(si)?;
        let Some(rpc) = decrypt_rpc(&key, inc) else { return Ok(None) };
        let Some(method) = rpc.method.clone() else { return Ok(Some((topic, rpc))) };
        let outcome = apply_event(&mut self.state.sessions[si], &method, &rpc.params);
        match outcome {
            EventOutcome::Ack { tag, ttl, changed } => {
                let body = result_json(rpc.id, json!(true));
                send(self.relay()?, &topic, &key, &body, ttl, tag)?;
                if changed {
                    self.save()?;
                }
            }
            EventOutcome::Deleted => {
                let body = result_json(rpc.id, json!(true));
                send(self.relay()?, &topic, &key, &body, TTL_ONE_DAY, TAG_SESSION_DELETE_RES)?;
                let s = self.state.sessions.remove(si);
                let _ = self.relay()?.unsubscribe(&topic);
                (self.note)(&format!("{} ended the session", s.name()));
                self.save()?;
            }
            EventOutcome::Unsupported => {
                let err =
                    RpcError::new(ERR_UNSUPPORTED_METHODS, format!("{method} is not supported"));
                let body = error_json(rpc.id, &err);
                send(
                    self.relay()?,
                    &topic,
                    &key,
                    &body,
                    TTL_FIVE_MINUTES,
                    TAG_SESSION_REQUEST_RES,
                )?;
            }
        }
        Ok(None)
    }

    /// Send `method` to the wallet of session `si` on `chain` and wait for
    /// its answer. The request carries an expiry `timeout` from now; past
    /// it the wallet refuses to act on it, so giving up here never leaves
    /// a request that could still be carried out behind our back.
    pub fn request(
        &mut self,
        si: usize,
        chain: &str,
        method: &str,
        params: Value,
    ) -> Result<Value> {
        let name = self.state.sessions[si].name();
        let (topic, key) = self.session_key(si)?;
        let timeout = self.opts.timeout.as_secs().max(TTL_THIRTY_SECONDS);
        let expiry = now() + timeout;
        let id = new_rpc_id();
        let body = request_json(
            id,
            "wc_sessionRequest",
            json!({
                "request": { "method": method, "params": params, "expiryTimestamp": expiry },
                "chainId": chain,
            }),
        );
        let relay = self.relay()?;
        relay.subscribe(&topic)?;
        send(relay, &topic, &key, &body, timeout, TAG_SESSION_REQUEST_REQ)?;
        (self.note)(&format!("waiting for {name} to approve {method} on {chain}"));
        let rpc = self.await_response(&topic, id, Duration::from_secs(timeout) + ANSWER_GRACE)?;
        let rpc = rpc.ok_or_else(|| {
            anyhow!(
                "no answer from {name} within {timeout}s (is the wallet running?); \
                 the request has expired and the wallet will not act on it"
            )
        })?;
        if let Some(err) = rpc.error {
            return Err(WalletError {
                wallet: name,
                code: err["code"].as_i64().unwrap_or(0),
                message: err["message"].as_str().unwrap_or("no reason given").to_string(),
            }
            .into());
        }
        Ok(rpc.result.unwrap_or(Value::Null))
    }

    /// Ping session `si`'s wallet; how long the answer took.
    pub fn ping(&mut self, si: usize) -> Result<Duration> {
        let name = self.state.sessions[si].name();
        let (topic, key) = self.session_key(si)?;
        let id = new_rpc_id();
        let started = Instant::now();
        let relay = self.relay()?;
        relay.subscribe(&topic)?;
        let body = request_json(id, "wc_sessionPing", json!({}));
        send(relay, &topic, &key, &body, TTL_THIRTY_SECONDS, TAG_SESSION_PING_REQ)?;
        match self.await_response(&topic, id, self.opts.timeout)? {
            Some(rpc) if rpc.error.is_none() => Ok(started.elapsed()),
            Some(rpc) => bail!("{name} answered the ping with an error: {}", rpc.error.unwrap()),
            None => bail!("no answer from {name} within {}s", self.opts.timeout.as_secs()),
        }
    }

    /// Wait for the response to request `id` on `topic`, handling everything
    /// else that arrives. `None` on timeout.
    fn await_response(&mut self, topic: &str, id: u64, wait: Duration) -> Result<Option<Rpc>> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(inc) = self.relay()?.next_incoming()? {
                if self.handle_pairing_message(&inc)?.is_some() {
                    continue;
                }
                if let Some((t, rpc)) = self.handle(&inc)?
                    && t == topic
                    && rpc.id == id
                {
                    return Ok(Some(rpc));
                }
                if !self.state.sessions.iter().any(|s| s.topic == topic) {
                    bail!("the wallet ended the session before answering");
                }
            }
            if Instant::now() > deadline {
                return Ok(None);
            }
        }
    }

    /// End sessions (by index), telling each wallet. Returns their names.
    pub fn disconnect(&mut self, indices: &[usize]) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for &i in indices {
            let (topic, key) = self.session_key(i)?;
            let body = request_json(
                new_rpc_id(),
                "wc_sessionDelete",
                json!({ "code": ERR_USER_DISCONNECTED, "message": "User disconnected." }),
            );
            let name = self.state.sessions[i].name();
            send(self.relay()?, &topic, &key, &body, TTL_ONE_DAY, TAG_SESSION_DELETE_REQ)
                .with_context(|| format!("could not tell {name}"))?;
            names.push(name);
        }
        let mut i = 0;
        self.state.sessions.retain(|_| {
            let keep = !indices.contains(&i);
            i += 1;
            keep
        });
        self.save()?;
        Ok(names)
    }
}

fn decrypt_rpc(key: &SymKey, inc: &Incoming) -> Option<Rpc> {
    let plaintext = crypto::decrypt(key, &inc.message).ok()?;
    parse_rpc(std::str::from_utf8(&plaintext).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0x00000000000000000000000000000000000000Aa";
    const B: &str = "0x00000000000000000000000000000000000000bB";
    const C: &str = "0x00000000000000000000000000000000000000cc";

    fn session(name: &str, accounts: &[&str], chains: &[&str]) -> DappSession {
        DappSession {
            topic: format!("topic-{name}"),
            key: "11".repeat(32),
            pairing_topic: String::new(),
            peer: Metadata {
                name: name.into(),
                url: format!("https://{}.example", name.to_lowercase()),
                ..Default::default()
            },
            accounts: accounts.iter().map(|a| a.to_string()).collect(),
            chains: chains.iter().map(|c| c.to_string()).collect(),
            methods: vec![],
            events: vec![],
            expiry: now() + 1000,
            created: 0,
        }
    }

    fn addr(s: &str) -> Address {
        s.parse().unwrap()
    }

    fn state(sessions: Vec<DappSession>) -> DappState {
        DappState { version: 0, relay_key: None, pending: vec![], sessions }
    }

    #[test]
    fn account_selection() {
        let one = state(vec![session("opwallet", &[A, B], &["eip155:1"])]);
        assert_eq!(resolve_account(&one, None).unwrap(), (0, addr(A)));
        assert_eq!(resolve_account(&one, Some("2")).unwrap().1, addr(B));
        assert_eq!(resolve_account(&one, Some(&B.to_lowercase())).unwrap().1, addr(B));
        assert_eq!(
            resolve_account(&one, Some("0x00000000000000000000000000000000000000b")).unwrap().1,
            addr(B)
        );
        assert!(
            resolve_account(&one, Some("0x0000")).unwrap_err().to_string().contains("matches 2")
        );
        assert!(resolve_account(&one, Some("3")).is_err());
        assert!(resolve_account(&one, Some("0")).is_err());
        assert_eq!(resolve_account(&one, Some("OPWALLET")).unwrap().1, addr(A));

        let two = state(vec![
            session("opwallet", &[A, B], &["eip155:1"]),
            session("Phone", &[C, A], &["eip155:1"]),
        ]);
        let err = resolve_account(&two, None).unwrap_err().to_string();
        assert!(err.contains("2 wallets are connected"), "{err}");
        assert_eq!(resolve_account(&two, Some("phone")).unwrap(), (1, addr(C)));
        assert_eq!(resolve_account(&two, Some("4")).unwrap(), (1, addr(A)));
        // The same address through two wallets is one account: the first wallet's.
        assert_eq!(resolve_account(&two, Some(A)).unwrap(), (0, addr(A)));
        assert!(
            resolve_account(&two, Some("example")).unwrap_err().to_string().contains("matches 2")
        );
        assert!(
            resolve_account(&state(vec![]), None)
                .unwrap_err()
                .to_string()
                .contains("wcapp connect")
        );

        let rows = account_rows(&two);
        assert_eq!(rows.len(), 4);
        assert!(rows[0].active && !rows[1].active && rows[2].active);
        assert_eq!(rows[3].number, 4);
    }

    #[test]
    fn chain_selection() {
        let s = session("w", &[A], &["eip155:1", "eip155:10"]);
        assert_eq!(pick_chain(&s, Some(10), None).unwrap(), "eip155:10");
        let err = pick_chain(&s, Some(137), None).unwrap_err().to_string();
        assert!(err.contains("--chain 137"), "{err}");
        assert_eq!(pick_chain(&s, None, Some(10)).unwrap(), "eip155:10");
        assert_eq!(pick_chain(&s, None, Some(5)).unwrap(), "eip155:1");
        assert_eq!(pick_chain(&s, None, None).unwrap(), "eip155:1");
    }

    #[test]
    fn wallet_events_update_the_session() {
        let mut s = session("w", &[A, B], &["eip155:1"]);
        // The wallet switched to B: it comes first now.
        let out = apply_event(
            &mut s,
            "wc_sessionEvent",
            &json!({ "event": { "name": "accountsChanged", "data": [B, A] }, "chainId": "eip155:1" }),
        );
        assert_eq!(
            out,
            EventOutcome::Ack { tag: TAG_SESSION_EVENT_RES, ttl: TTL_FIVE_MINUTES, changed: true }
        );
        assert_eq!(s.accounts, [B, A]);
        // An update that drops A and adds C keeps the selected B first.
        let ns = json!({ "namespaces": { "eip155": {
            "accounts": [format!("eip155:1:{C}"), format!("eip155:1:{B}"), format!("eip155:10:{B}")],
            "methods": ["personal_sign"], "events": [], "chains": ["eip155:1", "eip155:10"] } } });
        assert!(matches!(
            apply_event(&mut s, "wc_sessionUpdate", &ns),
            EventOutcome::Ack { changed: true, .. }
        ));
        assert_eq!(s.accounts, [B, C]);
        assert_eq!(s.chains, ["eip155:1", "eip155:10"]);
        // Extensions within the lifetime are taken; absurd ones ignored.
        let e = now() + 5000;
        apply_event(&mut s, "wc_sessionExtend", &json!({ "expiry": e }));
        assert_eq!(s.expiry, e);
        apply_event(
            &mut s,
            "wc_sessionExtend",
            &json!({ "expiry": now() + 10 * SESSION_LIFETIME }),
        );
        assert_eq!(s.expiry, e);
        assert_eq!(apply_event(&mut s, "wc_sessionDelete", &json!({})), EventOutcome::Deleted);
        assert_eq!(apply_event(&mut s, "eth_sign", &json!([])), EventOutcome::Unsupported);
    }

    #[test]
    fn settlement_is_checked_against_the_approval() {
        let pending = PendingPairing {
            topic: "p".into(),
            key: "22".repeat(32),
            secret: "33".repeat(32),
            proposal_id: 1,
            chains: vec![],
            expiry: now() + 300,
            session_key: None,
            responder: Some("wallet-pk".into()),
        };
        let key = SymKey::from_hex(&"44".repeat(32)).unwrap();
        let params = |pk: &str, expiry: u64| {
            json!({
                "controller": { "publicKey": pk, "metadata": { "name": "opwallet", "url": "https://w" } },
                "namespaces": { "eip155": { "accounts": [format!("eip155:1:{A}"), format!("eip155:10:{A}")],
                    "methods": ["personal_sign"], "events": ["accountsChanged"] } },
                "expiry": expiry,
            })
        };
        let s = settle_session(&pending, "t", &key, &params("wallet-pk", now() + 600)).unwrap();
        assert_eq!(s.accounts, [A]);
        assert_eq!(
            s.chains,
            ["eip155:1", "eip155:10"],
            "chains come from accounts when not listed"
        );
        assert_eq!(s.name(), "opwallet");
        assert!(settle_session(&pending, "t", &key, &params("someone-else", now() + 600)).is_err());
        assert!(settle_session(&pending, "t", &key, &params("wallet-pk", now() - 1)).is_err());
        let capped = settle_session(
            &pending,
            "t",
            &key,
            &params("wallet-pk", now() + 99 * SESSION_LIFETIME),
        )
        .unwrap();
        assert!(capped.expiry <= now() + SESSION_LIFETIME);
    }
}
