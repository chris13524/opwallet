//! WalletConnect Verify: a second opinion on where a proposal or request
//! came from.
//!
//! A dapp's metadata URL is whatever the dapp claims. Verify has the dapp's
//! page register each message it sends with the Verify server: the JS
//! `core` `Verify.register` loads a hidden Verify iframe, passing
//! `window.location.origin` in its URL, and the server records that origin.
//! This only means something when the sender is an honest browser. Any
//! other client (a scripted or server-side browser, or code faking
//! `window`) can register a message under whatever origin it names. So a
//! mismatch or a scam flag is a strong warning, while a match is not proof
//! that the user is on that site.
//!
//! The wallet learns the recorded origin in one of two ways, tried in the
//! order the JS `core` `Verify.resolve` uses:
//!
//! * v3: the relay delivers an `attestation` JWT with the message, signed
//!   (ES256) by the Verify server, whose `id` is the sha256 of the encrypted
//!   message. It is checked against the server's published P-256 key.
//! * v1/v2: look the message up by the sha256 of its plaintext at
//!   `GET {verifyUrl}/attestation/{hash}?v2Supported=true`.
//!
//! The outcome is shown in approval prompts; it never approves or rejects
//! anything on its own.

use std::{
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{
    session::Metadata,
    ui::{Ui, run_busy},
};

/// The public Verify server.
pub const VERIFY_SERVER: &str = "https://verify.walletconnect.org";
/// Verify servers a dapp may pick through its metadata `verifyUrl`.
const TRUSTED_VERIFY_URLS: &[&str] = &["https://verify.walletconnect.com", VERIFY_SERVER];
/// Upper bound on each call to the Verify server.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Whether the origin Verify saw matches the dapp's metadata URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validation {
    Valid,
    Invalid,
    Unknown,
}

/// What Verify says about one proposal or request (`Verify.Context`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub validation: Validation,
    /// The origin Verify saw, or the claimed metadata URL when unknown.
    pub origin: String,
    pub is_scam: bool,
    /// False when verification is turned off.
    pub checked: bool,
}

impl Context {
    fn unknown(meta: &Metadata, checked: bool) -> Self {
        Self { validation: Validation::Unknown, origin: meta.url.clone(), is_scam: false, checked }
    }

    /// Worth a warning in the log as well as in the prompt.
    pub fn alarming(&self) -> bool {
        self.is_scam || self.validation == Validation::Invalid
    }

    /// Prompt lines describing this context, each ending in a newline.
    pub fn lines(&self, claimed_url: &str) -> String {
        let mut out = String::new();
        if self.is_scam {
            out.push_str(&format!(
                "DANGER:      WalletConnect Verify flags {} as a known scam; do not approve\n",
                self.origin
            ));
        }
        out.push_str(&match (self.validation, self.checked) {
            (Validation::Valid, _) => {
                format!("origin:      {} (WalletConnect Verify agrees; not proof)\n", self.origin)
            }
            (Validation::Invalid, _) => format!(
                "WARNING:     origin mismatch: the dapp claims {claimed_url:?} but WalletConnect \
                 Verify recorded {:?}\n",
                self.origin
            ),
            (Validation::Unknown, true) => {
                "origin:      unknown (WalletConnect Verify has no record)\n".to_string()
            }
            (Validation::Unknown, false) => "origin:      not checked (--no-verify)\n".to_string(),
        });
        out
    }

    /// A prompt title, flagged when Verify reports a scam.
    pub fn title(&self, title: &str) -> String {
        if self.is_scam { format!("SCAM WARNING: {title}") } else { title.to_string() }
    }

    /// The extra prompt a connection needs when this context is alarming.
    pub fn reconfirm(&self, dapp_name: &str, claimed_url: &str) -> Option<(String, String)> {
        if !self.alarming() {
            return None;
        }
        let why = if self.is_scam {
            "WalletConnect Verify reports this site as a known scam."
        } else {
            "WalletConnect Verify recorded a different site than this dapp claims to be."
        };
        let body = format!(
            "{}\n{why} Connecting lets it ask your wallets for signatures.\n\n\
             Answer y only if you are sure you want to connect.\n",
            self.lines(claimed_url)
        );
        Some((self.title(&format!("Really connect to {dapp_name}?")), body))
    }

    /// Put this context in front of an approval prompt.
    pub fn decorate(&self, title: &str, body: &str, claimed_url: &str) -> (String, String) {
        (self.title(title), format!("{}\n{body}", self.lines(claimed_url)))
    }
}

/// What a delivered message carries for Verify to look up.
#[derive(Debug, Clone)]
pub struct Evidence {
    /// The relay's `attestation` JWT (v3), if the message came with one.
    pub attestation: Option<String>,
    /// sha256 (hex) of the encrypted message as published: the v3 JWT's `id`.
    pub encrypted_id: String,
    /// sha256 (hex) of the plaintext JSON-RPC payload: the v1/v2 lookup key.
    pub hash: String,
}

impl Evidence {
    pub fn new(message: &str, plaintext: &[u8], attestation: Option<String>) -> Self {
        Self {
            attestation,
            encrypted_id: sha256_hex(message.as_bytes()),
            hash: sha256_hex(plaintext),
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    alloy_primitives::hex::encode(Sha256::digest(data))
}

/// An origin Verify vouches for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub origin: String,
    pub is_scam: bool,
}

/// The Verify server's signing key (`GET /v3/public-key`).
#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    #[serde(rename = "publicKey")]
    public_key: JwkKey,
    #[serde(rename = "expiresAt", default)]
    expires_at: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkKey {
    #[serde(default)]
    crv: String,
    x: String,
    y: String,
}

#[derive(Debug, Deserialize)]
struct JwtPayload {
    #[serde(default)]
    exp: u64,
    #[serde(default)]
    id: String,
    #[serde(default)]
    origin: String,
    #[serde(rename = "isScam", default)]
    is_scam: Option<bool>,
    #[serde(rename = "isVerified", default)]
    is_verified: Option<bool>,
}

/// v1/v2 lookup response.
#[derive(Debug, Deserialize)]
struct Lookup {
    origin: Option<String>,
    #[serde(rename = "isScam", default)]
    is_scam: Option<bool>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Seconds from a timestamp that may be in seconds or milliseconds.
fn as_secs(t: u64) -> u64 {
    if t > 100_000_000_000 { t / 1000 } else { t }
}

fn jwt_payload(token: &str) -> Result<JwtPayload> {
    let payload = token.split('.').nth(1).ok_or_else(|| anyhow!("attestation is not a JWT"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .context("attestation payload is not base64url")?;
    serde_json::from_slice(&bytes).context("attestation payload is not JSON")
}

fn verifying_key(jwk: &JwkKey) -> Result<VerifyingKey> {
    if !jwk.crv.is_empty() && jwk.crv != "P-256" {
        bail!("Verify key is on {:?}, not P-256", jwk.crv);
    }
    let coord = |c: &str| URL_SAFE_NO_PAD.decode(c.trim_end_matches('='));
    let (x, y) = (coord(&jwk.x)?, coord(&jwk.y)?);
    if x.len() != 32 || y.len() != 32 {
        bail!("Verify key coordinates have the wrong length");
    }
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1).context("Verify key is not a P-256 point")
}

/// Check an ES256 attestation JWT against `key` (`verifyP256Jwt` plus the
/// expiry check of `validateAttestation`) and return its payload.
fn check_jwt(token: &str, key: &JwkKey, now: u64) -> Result<JwtPayload> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("attestation is not a JWT");
    };
    let sig =
        URL_SAFE_NO_PAD.decode(sig.trim_end_matches('=')).context("bad signature encoding")?;
    let sig = Signature::from_slice(&sig).context("attestation signature is not 64 bytes")?;
    verifying_key(key)?
        .verify(format!("{header}.{payload}").as_bytes(), &sig)
        .map_err(|_| anyhow!("attestation signature is invalid"))?;
    let claims = jwt_payload(token)?;
    if as_secs(claims.exp) < now {
        bail!("attestation has expired");
    }
    Ok(claims)
}

/// Origin of an http(s) URL as a browser reports it (`new URL(u).origin`):
/// lowercase scheme and host, port only when not the default.
pub fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?.to_ascii_lowercase();
    if host_port.is_empty() {
        return None;
    }
    let host_port = match (scheme.as_str(), host_port.rsplit_once(':')) {
        ("https", Some((h, "443"))) | ("http", Some((h, "80"))) => h.to_string(),
        _ => host_port,
    };
    Some(format!("{scheme}://{host_port}"))
}

/// Resolves [`Evidence`] against a Verify server.
pub struct Verifier {
    /// Base URL, or `None` when verification is turned off.
    server: Option<String>,
    agent: ureq::Agent,
    key: Mutex<Option<Jwk>>,
}

impl Verifier {
    pub fn new(server: Option<String>) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .build();
        Self {
            server: server.map(|s| s.trim_end_matches('/').to_string()),
            agent: ureq::Agent::new_with_config(config),
            key: Mutex::new(None),
        }
    }

    pub fn enabled(&self) -> bool {
        self.server.is_some()
    }

    /// The Verify context for a message from the dapp described by `meta`.
    /// Failures leave it `Unknown`, as in the JS `getVerifyContext`; the
    /// error, if any, comes back alongside for the log.
    pub fn context(&self, evidence: &Evidence, meta: &Metadata) -> (Context, Option<String>) {
        if !self.enabled() {
            return (Context::unknown(meta, false), None);
        }
        match self.resolve(evidence, meta.verify_url.as_deref()) {
            Ok(Some(att)) => {
                let claimed = origin_of(&meta.url);
                let seen = origin_of(&att.origin).unwrap_or_else(|| att.origin.clone());
                let validation = if claimed.as_deref() == Some(seen.as_str()) {
                    Validation::Valid
                } else {
                    Validation::Invalid
                };
                (
                    Context { validation, origin: att.origin, is_scam: att.is_scam, checked: true },
                    None,
                )
            }
            Ok(None) => (Context::unknown(meta, true), None),
            Err(e) => (Context::unknown(meta, true), Some(format!("{e:#}"))),
        }
    }

    /// `Verify.resolve`: the v3 JWT when the relay delivered one, otherwise
    /// (or when it cannot be validated) the v1/v2 lookup by plaintext hash.
    pub fn resolve(
        &self,
        evidence: &Evidence,
        verify_url: Option<&str>,
    ) -> Result<Option<Attestation>> {
        let Some(server) = self.server.as_deref() else { return Ok(None) };
        match evidence.attestation.as_deref() {
            // The dapp tried to register and failed: nothing to look up.
            Some("") => return Ok(None),
            Some(jwt) => {
                // An attestation for some other message proves nothing.
                if jwt_payload(jwt)?.id != evidence.encrypted_id {
                    return Ok(None);
                }
                if let Some(claims) = self.check_attestation(server, jwt) {
                    if claims.is_verified != Some(true) {
                        return Ok(None);
                    }
                    return Ok(Some(Attestation {
                        origin: claims.origin,
                        is_scam: claims.is_scam.unwrap_or(false),
                    }));
                }
            }
            None => {}
        }
        self.lookup(&self.lookup_url(server, verify_url), &evidence.hash)
    }

    /// Where to look up v1/v2 attestations: the dapp's `verifyUrl` if it is
    /// a trusted one and the default server is in use, else our server.
    fn lookup_url(&self, server: &str, verify_url: Option<&str>) -> String {
        match verify_url.map(|u| u.trim_end_matches('/')) {
            Some(u) if server == VERIFY_SERVER && TRUSTED_VERIFY_URLS.contains(&u) => u.to_string(),
            _ => server.to_string(),
        }
    }

    /// Validate with the cached key, then once more with a freshly fetched
    /// one (the server may have rotated it). `None` if neither works.
    fn check_attestation(&self, server: &str, jwt: &str) -> Option<JwtPayload> {
        let now = now();
        let mut cached = self.key.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(key) = cached.as_ref() {
            if key.expires_at.is_some_and(|t| as_secs(t) < now) {
                *cached = None;
            } else if let Ok(claims) = check_jwt(jwt, &key.public_key, now) {
                return Some(claims);
            }
        }
        let fresh = self.fetch_key(server).ok()?;
        let claims = check_jwt(jwt, &fresh.public_key, now).ok();
        *cached = Some(fresh);
        claims
    }

    fn fetch_key(&self, server: &str) -> Result<Jwk> {
        let url = format!("{server}/v3/public-key");
        let mut response =
            self.agent.get(&url).call().with_context(|| format!("could not reach {url}"))?;
        if !response.status().is_success() {
            bail!("{url} answered {}", response.status());
        }
        response.body_mut().read_json().context("Verify public key is not valid JSON")
    }

    fn lookup(&self, base: &str, hash: &str) -> Result<Option<Attestation>> {
        let url = format!("{base}/attestation/{hash}?v2Supported=true");
        let mut response =
            self.agent.get(&url).call().with_context(|| format!("could not reach {base}"))?;
        if response.status() != 200 {
            return Ok(None);
        }
        let found: Lookup =
            response.body_mut().read_json().context("Verify lookup is not valid JSON")?;
        Ok(found
            .origin
            .map(|origin| Attestation { origin, is_scam: found.is_scam.unwrap_or(false) }))
    }
}

/// Look up a Verify context behind a busy indicator, logging what is worth
/// knowing about it.
pub fn resolve(
    ui: &mut dyn Ui,
    verifier: &Verifier,
    evidence: &Evidence,
    meta: &Metadata,
) -> Context {
    if !verifier.enabled() {
        return Context::unknown(meta, false);
    }
    let (context, error) = run_busy(ui, "Checking the origin with WalletConnect Verify", || {
        verifier.context(evidence, meta)
    });
    if let Some(e) = error {
        ui.log(&format!("WalletConnect Verify: {e}"));
    }
    if context.alarming() {
        ui.warn(context.lines(&meta.url).trim_end());
    }
    context
}

/// A request's Verify context, looked up the first time a prompt needs it
/// so requests answered without asking cost no round trip.
pub struct Deferred<'a> {
    verifier: &'a Verifier,
    evidence: Evidence,
    meta: &'a Metadata,
    resolved: Option<Context>,
}

impl<'a> Deferred<'a> {
    pub fn new(verifier: &'a Verifier, evidence: Evidence, meta: &'a Metadata) -> Self {
        Self { verifier, evidence, meta, resolved: None }
    }

    /// [`Context::decorate`] with this request's context.
    pub fn decorate(&mut self, ui: &mut dyn Ui, title: &str, body: &str) -> (String, String) {
        let context = self
            .resolved
            .get_or_insert_with(|| resolve(ui, self.verifier, &self.evidence, self.meta));
        context.decorate(title, body, &self.meta.url)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
    };

    use p256::ecdsa::{SigningKey, signature::Signer};
    use serde_json::{Value, json};

    use super::*;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_slice(&[byte; 32]).unwrap()
    }

    fn jwk(key: &SigningKey) -> Value {
        let point = key.verifying_key().to_encoded_point(false);
        json!({ "publicKey": {
            "crv": "P-256", "ext": true, "key_ops": ["verify"], "kty": "EC",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }, "expiresAt": now() + 3600 })
    }

    fn jwt(key: &SigningKey, payload: Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(payload.to_string())
        );
        let sig: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn claims(id: &str, origin: &str, exp: u64) -> Value {
        json!({ "exp": exp, "id": id, "origin": origin, "isScam": false, "isVerified": true })
    }

    /// A Verify server answering `routes` (path → (status, body)); returns
    /// its base URL and the paths requested so far.
    fn serve(routes: Vec<(String, u16, Value)>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut line = String::new();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                reader.read_line(&mut line).unwrap();
                while reader.read_line(&mut String::new()).unwrap() > 2 {}
                let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                log.lock().unwrap().push(path.clone());
                let (status, body) = routes
                    .iter()
                    .find(|(p, ..)| *p == path)
                    .map(|(_, s, b)| (*s, b.to_string()))
                    .unwrap_or((404, "{}".into()));
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (base, seen)
    }

    fn evidence(attestation: Option<String>) -> Evidence {
        Evidence::new("ENCRYPTED", br#"{"id":1}"#, attestation)
    }

    fn meta(url: &str) -> Metadata {
        Metadata { url: url.into(), ..Default::default() }
    }

    fn lookup_path(hash: &str) -> String {
        format!("/attestation/{hash}?v2Supported=true")
    }

    #[test]
    fn evidence_hashes_match_the_js_client() {
        let e = evidence(None);
        // hashMessage(message) and hashMessage(JSON.stringify(payload)).
        assert_eq!(e.encrypted_id, sha256_hex(b"ENCRYPTED"));
        assert_eq!(e.hash, sha256_hex(br#"{"id":1}"#));
        assert_eq!(e.hash.len(), 64);
    }

    #[test]
    fn origins_are_normalized_like_a_browser() {
        assert_eq!(origin_of("https://App.Example.com/path?q").unwrap(), "https://app.example.com");
        assert_eq!(origin_of("https://a.example:443/").unwrap(), "https://a.example");
        assert_eq!(origin_of("http://a.example:80").unwrap(), "http://a.example");
        assert_eq!(origin_of("https://a.example:8443").unwrap(), "https://a.example:8443");
        assert_eq!(origin_of("https://user@a.example#x").unwrap(), "https://a.example");
        assert!(origin_of("a.example").is_none());
        assert!(origin_of("https://").is_none());
    }

    #[test]
    fn jwt_checks_signature_key_and_expiry() {
        let key = signing_key(7);
        let public: Jwk = serde_json::from_value(jwk(&key)).unwrap();
        let token = jwt(&key, claims("abc", "https://a.example", now() + 60));
        let payload = check_jwt(&token, &public.public_key, now()).unwrap();
        assert_eq!((payload.id.as_str(), payload.origin.as_str()), ("abc", "https://a.example"));

        let other: Jwk = serde_json::from_value(jwk(&signing_key(8))).unwrap();
        assert!(check_jwt(&token, &other.public_key, now()).is_err());

        let mut parts: Vec<&str> = token.split('.').collect();
        let forged =
            URL_SAFE_NO_PAD.encode(claims("abc", "https://evil.example", now() + 60).to_string());
        parts[1] = &forged;
        assert!(check_jwt(&parts.join("."), &public.public_key, now()).is_err());

        let expired = jwt(&key, claims("abc", "https://a.example", now() - 1));
        assert!(check_jwt(&expired, &public.public_key, now()).is_err());
        // Millisecond timestamps are accepted too.
        let ms = jwt(&key, claims("abc", "https://a.example", (now() + 60) * 1000));
        assert!(check_jwt(&ms, &public.public_key, now()).is_ok());
    }

    #[test]
    fn v3_attestation_resolves_without_a_lookup() {
        let key = signing_key(7);
        let e = evidence(None);
        let token = jwt(&key, claims(&e.encrypted_id, "https://a.example", now() + 60));
        let (base, seen) = serve(vec![("/v3/public-key".into(), 200, jwk(&key))]);
        let v = Verifier::new(Some(base));
        let e = Evidence { attestation: Some(token.clone()), ..e };

        let (ctx, err) = v.context(&e, &meta("https://A.example/app"));
        assert_eq!(err, None);
        assert_eq!(ctx.validation, Validation::Valid);
        assert_eq!(ctx.origin, "https://a.example");
        // The key is fetched once and cached.
        assert_eq!(v.context(&e, &meta("https://a.example")).0.validation, Validation::Valid);
        assert_eq!(*seen.lock().unwrap(), ["/v3/public-key"]);

        let (ctx, _) = v.context(&e, &meta("https://b.example"));
        assert_eq!(ctx.validation, Validation::Invalid);
        assert!(ctx.lines("https://b.example").contains("WARNING:     origin mismatch"));
    }

    #[test]
    fn v3_attestation_for_another_message_or_unverified_origin_is_unknown() {
        let key = signing_key(7);
        let e = evidence(None);
        let (base, seen) = serve(vec![
            ("/v3/public-key".into(), 200, jwk(&key)),
            (lookup_path(&e.hash), 200, json!({ "origin": "https://a.example" })),
        ]);
        let v = Verifier::new(Some(base));

        let other = jwt(&key, claims("not-this-message", "https://a.example", now() + 60));
        let e1 = Evidence { attestation: Some(other), ..e.clone() };
        assert_eq!(v.resolve(&e1, None).unwrap(), None);

        let mut unverified = claims(&e.encrypted_id, "https://a.example", now() + 60);
        unverified["isVerified"] = json!(false);
        let e2 = Evidence { attestation: Some(jwt(&key, unverified)), ..e.clone() };
        assert_eq!(v.resolve(&e2, None).unwrap(), None);

        // The dapp failed to register: nothing to look up.
        let e3 = Evidence { attestation: Some(String::new()), ..e };
        assert_eq!(v.resolve(&e3, None).unwrap(), None);
        assert!(!seen.lock().unwrap().iter().any(|p| p.starts_with("/attestation/")));
    }

    #[test]
    fn invalid_v3_attestation_falls_back_to_the_hash_lookup() {
        let e = evidence(None);
        let forged = jwt(&signing_key(9), claims(&e.encrypted_id, "https://a.example", now() + 60));
        let (base, seen) = serve(vec![
            ("/v3/public-key".into(), 200, jwk(&signing_key(7))),
            (
                lookup_path(&e.hash),
                200,
                json!({ "origin": "https://evil.example", "isScam": true }),
            ),
        ]);
        let v = Verifier::new(Some(base));
        let e = Evidence { attestation: Some(forged), ..e };
        let (ctx, err) = v.context(&e, &meta("https://a.example"));
        assert_eq!(err, None);
        assert_eq!(ctx.validation, Validation::Invalid);
        assert!(ctx.is_scam && ctx.alarming());
        assert_eq!(ctx.origin, "https://evil.example");
        let (title, body) = ctx.decorate("Dapp: Sign", "account: x", "https://a.example");
        assert_eq!(title, "SCAM WARNING: Dapp: Sign");
        assert!(body.starts_with("DANGER:") && body.ends_with("\naccount: x"), "{body}");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.last().unwrap(), &lookup_path(&e.hash));
    }

    #[test]
    fn only_alarming_contexts_need_a_second_confirmation() {
        let ctx = |validation, is_scam| Context {
            validation,
            origin: "https://evil.example".into(),
            is_scam,
            checked: true,
        };
        assert_eq!(ctx(Validation::Valid, false).reconfirm("D", "https://a.example"), None);
        assert_eq!(ctx(Validation::Unknown, false).reconfirm("D", "https://a.example"), None);
        let (title, body) =
            ctx(Validation::Invalid, false).reconfirm("D", "https://a.example").unwrap();
        assert_eq!(title, "Really connect to D?");
        assert!(
            body.starts_with("WARNING:     origin mismatch")
                && body.contains("recorded a different site")
        );
        let (title, body) =
            ctx(Validation::Valid, true).reconfirm("D", "https://evil.example").unwrap();
        assert_eq!(title, "SCAM WARNING: Really connect to D?");
        assert!(body.starts_with("DANGER:") && body.contains("known scam."), "{body}");
    }

    #[test]
    fn v1_lookup_by_hash() {
        let e = evidence(None);
        let (base, _) = serve(vec![(
            lookup_path(&e.hash),
            200,
            json!({ "origin": "https://a.example", "isScam": null }),
        )]);
        let v = Verifier::new(Some(format!("{base}/")));
        let (ctx, _) = v.context(&e, &meta("https://a.example/"));
        assert_eq!(
            ctx,
            Context {
                validation: Validation::Valid,
                origin: "https://a.example".into(),
                is_scam: false,
                checked: true
            }
        );
        // Not registered: unknown, and the claimed URL is kept.
        let other = Evidence::new("x", b"y", None);
        let (ctx, err) = v.context(&other, &meta("https://a.example"));
        assert_eq!((ctx.validation, err), (Validation::Unknown, None));
        assert!(ctx.lines("https://a.example").contains("unknown"));
    }

    #[test]
    fn failures_and_disabled_verification_are_unknown() {
        let v = Verifier::new(None);
        let (ctx, err) = v.context(&evidence(None), &meta("https://a.example"));
        assert_eq!((ctx.validation, ctx.checked, err), (Validation::Unknown, false, None));
        assert!(ctx.lines("").contains("not checked"));

        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let v = Verifier::new(Some(format!("http://{dead}")));
        let (ctx, err) = v.context(&evidence(None), &meta("https://a.example"));
        assert_eq!(ctx.validation, Validation::Unknown);
        assert!(err.unwrap().contains("could not reach"));
    }

    #[test]
    fn dapp_verify_url_is_used_only_if_trusted() {
        let v = Verifier::new(Some(VERIFY_SERVER.into()));
        let com = "https://verify.walletconnect.com";
        assert_eq!(v.lookup_url(VERIFY_SERVER, Some(com)), com);
        assert_eq!(v.lookup_url(VERIFY_SERVER, Some("https://evil.example")), VERIFY_SERVER);
        assert_eq!(v.lookup_url(VERIFY_SERVER, None), VERIFY_SERVER);
        // A server chosen by the user wins over the dapp's choice.
        assert_eq!(v.lookup_url("http://local", Some(com)), "http://local");
    }
}
