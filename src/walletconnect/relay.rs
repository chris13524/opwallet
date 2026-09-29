//! Minimal blocking client for the WalletConnect relay ("irn" protocol).
//!
//! Handles relay authentication (an Ed25519-signed JWT identifying this
//! client), subscriptions, publishing, and delivery of encrypted messages.
//! It knows nothing about message contents.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::TcpStream,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tungstenite::{Message, WebSocket, stream::MaybeTlsStream};

use super::crypto::random_array;

/// Default public relay.
pub const DEFAULT_RELAY_URL: &str = "wss://relay.walletconnect.com";

/// How long to wait for the relay to answer an RPC before giving up.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Socket read timeout; bounds how often the caller's loop gets control back.
const READ_TIMEOUT: Duration = Duration::from_secs(1);

/// An encrypted message delivered for one of our subscriptions.
#[derive(Debug, Clone)]
pub struct Incoming {
    pub topic: String,
    pub message: String,
    pub tag: u64,
    /// WalletConnect Verify v3 attestation JWT the relay attached, if any.
    pub attestation: Option<String>,
}

enum Frame {
    Response { id: u64, result: Option<Value>, error: Option<Value> },
    Subscription(Incoming),
    Timeout,
}

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

/// A relay JSON-RPC error (as opposed to a connection failure).
#[derive(Debug)]
pub struct Rejected {
    pub method: String,
    pub error: Value,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relay rejected {}: {}", self.method, self.error)
    }
}

impl std::error::Error for Rejected {}

pub struct Relay {
    /// Client identity for relay auth. The relay ties topic participation to
    /// it, so it must stay the same across reconnects.
    client_key: SigningKey,
    url: String,
    project_id: String,
    ws: Socket,
    pending: VecDeque<Incoming>,
    subscriptions: HashMap<String, String>,
    seen: HashSet<[u8; 32]>,
}

/// A fresh relay client identity.
pub fn new_client_key() -> Result<SigningKey> {
    let seed = random_array::<32>()?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Parse a client identity saved by [`Relay::client_key_hex`].
pub fn client_key_from_hex(hex: &str) -> Result<SigningKey> {
    let bytes = zeroize::Zeroizing::new(
        alloy_primitives::hex::decode(hex).context("relay key is not valid hex")?,
    );
    let seed: &[u8; 32] =
        bytes.as_slice().try_into().map_err(|_| anyhow!("relay key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(seed))
}

/// Build the relay auth JWT (`did:key` issuer, EdDSA signature).
pub fn auth_jwt(aud: &str, key: &SigningKey) -> Result<String> {
    let mut multicodec = vec![0xed, 0x01];
    multicodec.extend_from_slice(key.verifying_key().as_bytes());
    let iss = format!("did:key:z{}", bs58::encode(multicodec).into_string());
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sub = alloy_primitives::hex::encode(&random_array::<32>()?[..]);

    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        json!({ "iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": now + 86_400 }).to_string(),
    );
    let signing_input = format!("{header}.{payload}");
    let signature = URL_SAFE_NO_PAD.encode(key.sign(signing_input.as_bytes()).to_bytes());
    Ok(format!("{signing_input}.{signature}"))
}

fn now_micros() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

/// Relay-style JSON-RPC id: microsecond timestamp with random low digits.
pub fn new_rpc_id() -> u64 {
    let rand = random_array::<2>().map(|r| u16::from_be_bytes(*r) % 1000).unwrap_or(0);
    (now_micros() / 1000) * 1000 + u64::from(rand)
}

fn set_read_timeout(ws: &mut Socket, timeout: Option<Duration>) -> Result<()> {
    match ws.get_mut() {
        MaybeTlsStream::Plain(s) => s.set_read_timeout(timeout)?,
        MaybeTlsStream::Rustls(s) => s.sock.set_read_timeout(timeout)?,
        _ => {}
    }
    Ok(())
}

fn open_socket(url: &str, project_id: &str, key: &SigningKey) -> Result<Socket> {
    let jwt = auth_jwt(url, key)?;
    // The request line needs a path: `wss://host?x` is not a valid URI.
    let has_path = url.split_once("://").map(|(_, rest)| rest.contains('/')).unwrap_or(true);
    let base = if has_path { url.to_string() } else { format!("{url}/") };
    let sep = if base.contains('?') { '&' } else { '?' };
    let full = format!(
        "{base}{sep}auth={jwt}&projectId={project_id}&ua=wc-2%2Frs-{}%2Fopwallet",
        env!("CARGO_PKG_VERSION")
    );
    let (mut ws, _response) =
        tungstenite::connect(&full).with_context(|| format!("could not connect to relay {url}"))?;
    set_read_timeout(&mut ws, Some(READ_TIMEOUT))?;
    Ok(ws)
}

impl Relay {
    pub fn connect(url: &str, project_id: &str) -> Result<Self> {
        Self::connect_as(url, project_id, new_client_key()?)
    }

    /// Connect with an existing client identity (restored from a previous run).
    pub fn connect_as(url: &str, project_id: &str, client_key: SigningKey) -> Result<Self> {
        let ws = open_socket(url, project_id, &client_key)?;
        Ok(Self {
            client_key,
            url: url.to_string(),
            project_id: project_id.to_string(),
            ws,
            pending: VecDeque::new(),
            subscriptions: HashMap::new(),
            seen: HashSet::new(),
        })
    }

    /// The client identity's Ed25519 seed, hex, so the next run can reuse it.
    pub fn client_key_hex(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(alloy_primitives::hex::encode(self.client_key.to_bytes()))
    }

    /// Re-open the socket and restore every subscription.
    pub fn reconnect(&mut self) -> Result<()> {
        let _ = self.ws.close(None);
        self.ws = open_socket(&self.url, &self.project_id, &self.client_key)?;
        let topics: Vec<String> = self.subscriptions.keys().cloned().collect();
        self.subscriptions.clear();
        for topic in topics {
            self.subscribe(&topic)?;
        }
        Ok(())
    }

    pub fn subscribe(&mut self, topic: &str) -> Result<()> {
        if self.subscriptions.contains_key(topic) {
            return Ok(());
        }
        let id = self.call("irn_subscribe", json!({ "topic": topic }))?;
        let id = id.as_str().map(str::to_string).unwrap_or_else(|| id.to_string());
        self.subscriptions.insert(topic.to_string(), id);
        Ok(())
    }

    pub fn unsubscribe(&mut self, topic: &str) -> Result<()> {
        if let Some(id) = self.subscriptions.remove(topic) {
            self.call("irn_unsubscribe", json!({ "topic": topic, "id": id }))?;
        }
        Ok(())
    }

    pub fn publish(&mut self, topic: &str, message: &str, ttl: u64, tag: u64) -> Result<()> {
        let params = json!({ "topic": topic, "message": message, "ttl": ttl, "tag": tag, "prompt": tag == 1108 });
        match self.call("irn_publish", params.clone()) {
            Ok(_) => Ok(()),
            // A relay-level rejection is final; a dead connection is retried
            // once on a fresh socket so the message is not lost.
            Err(e) if e.downcast_ref::<Rejected>().is_some() => Err(e),
            Err(e) => {
                self.reconnect()
                    .with_context(|| format!("publish failed ({e:#}) and reconnect failed"))?;
                self.call("irn_publish", params)?;
                Ok(())
            }
        }
    }

    /// Next delivered message, or `None` after a quiet read-timeout tick.
    pub fn next_incoming(&mut self) -> Result<Option<Incoming>> {
        if let Some(inc) = self.pending.pop_front() {
            return Ok(Some(inc));
        }
        match self.read_frame()? {
            Frame::Subscription(inc) => Ok(Some(inc)),
            Frame::Response { .. } | Frame::Timeout => Ok(None),
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = new_rpc_id();
        let req = json!({ "id": id, "jsonrpc": "2.0", "method": method, "params": params });
        self.ws.send(Message::text(req.to_string())).context("failed to send to relay")?;
        let started = Instant::now();
        loop {
            match self.read_frame()? {
                Frame::Response { id: rid, result, error } if rid == id => {
                    if let Some(err) = error {
                        return Err(Rejected { method: method.to_string(), error: err }.into());
                    }
                    return Ok(result.unwrap_or(Value::Null));
                }
                Frame::Response { .. } => {}
                Frame::Subscription(inc) => self.pending.push_back(inc),
                Frame::Timeout => {
                    if started.elapsed() > CALL_TIMEOUT {
                        bail!("relay did not answer {method} within {CALL_TIMEOUT:?}");
                    }
                }
            }
        }
    }

    fn read_frame(&mut self) -> Result<Frame> {
        loop {
            let text = match self.ws.read() {
                Ok(Message::Text(t)) => t,
                Ok(Message::Close(frame)) => {
                    bail!(
                        "relay closed the connection: {}",
                        frame.map(|f| f.reason.to_string()).unwrap_or_default()
                    )
                }
                Ok(_) => continue,
                // A signal (Ctrl-C) interrupts the read; the socket is fine.
                Err(tungstenite::Error::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(Frame::Timeout);
                }
                Err(e) => return Err(anyhow!("relay connection error: {e}")),
            };
            let v: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let id = v.get("id").and_then(Value::as_u64);
            match v.get("method").and_then(Value::as_str) {
                Some("irn_subscription") => {
                    if let Some(id) = id {
                        let ack = json!({ "id": id, "jsonrpc": "2.0", "result": true });
                        self.ws
                            .send(Message::text(ack.to_string()))
                            .context("failed to ack relay")?;
                    }
                    let data = &v["params"]["data"];
                    let (Some(topic), Some(message)) =
                        (data["topic"].as_str(), data["message"].as_str())
                    else {
                        continue;
                    };
                    let digest: [u8; 32] = Sha256::digest(message.as_bytes()).into();
                    if !self.seen.insert(digest) {
                        continue;
                    }
                    return Ok(Frame::Subscription(Incoming {
                        topic: topic.to_string(),
                        message: message.to_string(),
                        tag: data["tag"].as_u64().unwrap_or(0),
                        attestation: data["attestation"].as_str().map(str::to_string),
                    }));
                }
                Some(_) => continue,
                None => {
                    if let Some(id) = id {
                        return Ok(Frame::Response {
                            id,
                            result: v.get("result").cloned(),
                            error: v.get("error").cloned(),
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    #[test]
    fn auth_jwt_is_well_formed_and_self_consistent() {
        let key = new_client_key().unwrap();
        let jwt = auth_jwt("wss://relay.walletconnect.com", &key).unwrap();
        // The identity is stable: a second token from the same key has the same issuer.
        let again = auth_jwt("wss://relay.walletconnect.com", &key).unwrap();
        let iss = |t: &str| {
            let p: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD.decode(t.split('.').nth(1).unwrap()).unwrap(),
            )
            .unwrap();
            p["iss"].as_str().unwrap().to_string()
        };
        assert_eq!(iss(&jwt), iss(&again));
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["aud"], "wss://relay.walletconnect.com");
        assert_eq!(payload["sub"].as_str().unwrap().len(), 64);
        assert_eq!(payload["exp"].as_u64().unwrap() - payload["iat"].as_u64().unwrap(), 86_400);

        // did:key:z<base58btc(0xed01 || pubkey)> must verify the signature.
        let iss = payload["iss"].as_str().unwrap();
        let raw = bs58::decode(iss.strip_prefix("did:key:z").unwrap()).into_vec().unwrap();
        assert_eq!(&raw[..2], &[0xed, 0x01]);
        let vk = VerifyingKey::from_bytes(raw[2..].try_into().unwrap()).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap())
            .unwrap();
        vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).unwrap();
    }

    #[test]
    fn rpc_ids_are_unique_and_large() {
        let a = new_rpc_id();
        let b = new_rpc_id();
        assert!(a > 1_000_000_000_000_000);
        assert_ne!(a, b);
    }
}
