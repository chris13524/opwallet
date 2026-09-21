//! Sign-In with Ethereum for session proposals.
//!
//! Dapps can attach `requests.authentication[]` (CAIP-122 payloads) to
//! `wc_sessionPropose`; the wallet signs one EIP-4361 message per requested
//! chain and returns the CACAOs (CAIP-74) in `proposalRequestsResponses` of
//! `wc_sessionSettle`. Message formatting is a port of `formatMessage` in
//! `@walletconnect/utils` so the dapp's verifier rebuilds identical bytes.

use alloy_primitives::Address;
use anyhow::{Result, anyhow, bail};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub const RECAP_PREFIX: &str = "urn:recap:";
const RECAP_STATEMENT_BASE: &str =
    "I further authorize the stated URI to perform the following actions on my behalf: ";

/// One entry of `requests.authentication` (`AuthTypes.AuthenticateParams`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthPayload {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    pub chains: Vec<String>,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    pub version: String,
    pub nonce: String,
    pub iat: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
}

impl AuthPayload {
    /// The EVM chains this wallet can sign for.
    pub fn evm_chains(&self) -> Vec<String> {
        self.chains
            .iter()
            .filter(|c| c.strip_prefix("eip155:").is_some_and(|n| n.parse::<u64>().is_ok()))
            .cloned()
            .collect()
    }

    pub fn uri(&self) -> Option<&str> {
        self.aud
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(self.uri.as_deref().filter(|s| !s.is_empty()))
    }
}

/// `did:pkh` issuer for an account on a chain.
pub fn issuer(chain: &str, address: &Address) -> String {
    format!("did:pkh:{chain}:{address}")
}

/// Split `did:pkh:eip155:1:0xabc` into (`eip155:1`, address).
pub fn parse_issuer(iss: &str) -> Result<(String, Address)> {
    let rest = iss.strip_prefix("did:pkh:").ok_or_else(|| anyhow!("iss is not a did:pkh"))?;
    let (chain, addr) = rest.rsplit_once(':').ok_or_else(|| anyhow!("malformed did:pkh"))?;
    Ok((chain.to_string(), addr.parse()?))
}

pub fn is_recap(resource: &str) -> bool {
    resource.starts_with(RECAP_PREFIX)
}

/// Decode a `urn:recap:` resource (any base64 flavour) into its JSON.
pub fn decode_recap(resource: &str) -> Option<Value> {
    let b64 = resource.strip_prefix(RECAP_PREFIX)?;
    let bytes = [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD, &STANDARD, &URL_SAFE]
        .iter()
        .find_map(|e| e.decode(b64).ok())?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("att")?.as_object()?;
    Some(v)
}

pub fn encode_recap(recap: &Value) -> String {
    format!("{RECAP_PREFIX}{}", STANDARD_NO_PAD.encode(recap.to_string()))
}

/// Port of `formatStatementFromRecap` from `@walletconnect/utils`.
pub fn format_statement_from_recap(statement: &str, recap: &Value) -> String {
    if statement.contains(RECAP_STATEMENT_BASE) {
        return statement.to_string();
    }
    let mut counter = 0;
    let mut per_resource = Vec::new();
    if let Some(att) = recap["att"].as_object() {
        for (resource, abilities) in att {
            let mut actions: Vec<(String, String)> = abilities
                .as_object()
                .map(|o| {
                    o.keys()
                        .map(|k| {
                            let (ability, action) = k.split_once('/').unwrap_or((k, ""));
                            (ability.to_string(), action.to_string())
                        })
                        .collect()
                })
                .unwrap_or_default();
            actions.sort_by(|a, b| a.1.cmp(&b.1));
            let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
            for (ability, action) in actions {
                match grouped.iter_mut().find(|(a, _)| *a == ability) {
                    Some((_, list)) => list.push(action),
                    None => grouped.push((ability, vec![action])),
                }
            }
            let parts: Vec<String> = grouped
                .into_iter()
                .map(|(ability, actions)| {
                    counter += 1;
                    format!("({counter}) '{ability}': '{}' for '{resource}'.", actions.join("', '"))
                })
                .collect();
            per_resource.push(parts.join(", ").replacen(".,", ".", 1));
        }
    }
    let recap_statement = format!("{RECAP_STATEMENT_BASE}{}", per_resource.join(" "));
    if statement.is_empty() { recap_statement } else { format!("{statement} {recap_statement}") }
}

/// EIP-4361 message text for `iss`, byte-identical to the SDK's `formatMessage`.
pub fn format_message(p: &AuthPayload, iss: &str) -> Result<String> {
    let (chain, address) = parse_issuer(iss)?;
    let chain_id = chain
        .strip_prefix("eip155:")
        .ok_or_else(|| anyhow!("only eip155 chains can sign in with Ethereum"))?;
    let Some(uri) = p.uri() else { bail!("auth request has neither aud nor uri") };

    let mut statement = p.statement.clone().filter(|s| !s.is_empty());
    if let Some(recap) = p
        .resources
        .as_ref()
        .and_then(|r| r.last())
        .filter(|r| is_recap(r))
        .and_then(|r| decode_recap(r))
    {
        statement = Some(format_statement_from_recap(statement.as_deref().unwrap_or(""), &recap));
    }
    if statement.as_deref().is_some_and(|s| s.contains(['\r', '\n'])) {
        bail!("statement must not contain line breaks");
    }

    let mut lines: Vec<String> = vec![
        format!("{} wants you to sign in with your Ethereum account:", p.domain),
        address.to_string(),
        String::new(),
    ];
    if let Some(s) = statement {
        lines.push(s);
    }
    lines.push(String::new());
    lines.push(format!("URI: {uri}"));
    lines.push(format!("Version: {}", p.version));
    lines.push(format!("Chain ID: {chain_id}"));
    lines.push(format!("Nonce: {}", p.nonce));
    lines.push(format!("Issued At: {}", p.iat));
    if let Some(exp) = &p.exp {
        lines.push(format!("Expiration Time: {exp}"));
    }
    if let Some(nbf) = &p.nbf {
        lines.push(format!("Not Before: {nbf}"));
    }
    if let Some(id) = &p.request_id {
        lines.push(format!("Request ID: {id}"));
    }
    if let Some(res) = &p.resources {
        let items: Vec<String> = res.iter().map(|r| format!("\n- {r}")).collect();
        lines.push(format!("Resources:{}", items.join("")));
    }
    Ok(lines.join("\n"))
}

/// A signed CACAO for one chain, with the field order of `buildAuthObject`.
pub fn build_cacao(p: &AuthPayload, iss: &str, signature_hex: &str) -> Value {
    let mut payload = Map::new();
    payload.insert("iss".into(), json!(iss));
    payload.insert("domain".into(), json!(p.domain));
    if let Some(aud) = p.uri() {
        payload.insert("aud".into(), json!(aud));
    }
    payload.insert("version".into(), json!(p.version));
    payload.insert("nonce".into(), json!(p.nonce));
    payload.insert("iat".into(), json!(p.iat));
    for (key, value) in [("statement", &p.statement), ("requestId", &p.request_id)] {
        if let Some(v) = value {
            payload.insert(key.into(), json!(v));
        }
    }
    if let Some(res) = &p.resources {
        payload.insert("resources".into(), json!(res));
    }
    for (key, value) in [("nbf", &p.nbf), ("exp", &p.exp)] {
        if let Some(v) = value {
            payload.insert(key.into(), json!(v));
        }
    }
    json!({ "h": { "t": "caip122" }, "p": payload, "s": { "t": "eip191", "s": signature_hex } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recap_roundtrip_and_statement() {
        let recap = json!({ "att": { "eip155": {
            "request/personal_sign": [{ "chains": ["eip155:1"] }],
            "request/eth_sendTransaction": [{ "chains": ["eip155:1"] }]
        } } });
        let encoded = encode_recap(&recap);
        assert!(encoded.starts_with("urn:recap:") && !encoded.contains('='));
        assert_eq!(decode_recap(&encoded).unwrap(), recap);
        assert!(decode_recap("urn:recap:!!!").is_none());
        assert!(decode_recap("https://x").is_none());
        assert_eq!(
            format_statement_from_recap("", &recap),
            "I further authorize the stated URI to perform the following actions on my behalf: (1) 'request': 'eth_sendTransaction', 'personal_sign' for 'eip155'."
        );
        let s = format_statement_from_recap("Hi", &recap);
        assert!(s.starts_with("Hi I further authorize"));
        assert_eq!(format_statement_from_recap(&s, &recap), s, "must be idempotent");

        // Two abilities under one resource: the SDK joins with ", " then fixes the first ".,".
        let two = json!({ "att": { "eip155": { "request/a": [], "sign/b": [] } } });
        assert_eq!(
            format_statement_from_recap("", &two),
            "I further authorize the stated URI to perform the following actions on my behalf: (1) 'request': 'a' for 'eip155'. (2) 'sign': 'b' for 'eip155'."
        );
    }

    #[test]
    fn message_matches_sdk_format_message() {
        let addr: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".parse().unwrap();
        let mut p = AuthPayload {
            domain: "example.com".into(),
            aud: Some("https://example.com/login".into()),
            version: "1".into(),
            nonce: "abc123".into(),
            iat: "2024-01-01T00:00:00Z".into(),
            exp: Some("2024-01-02T00:00:00Z".into()),
            request_id: Some("r1".into()),
            resources: Some(vec!["https://example.com/tos".into()]),
            chains: vec!["eip155:1".into(), "solana:mainnet".into(), "eip155:x".into()],
            ..Default::default()
        };
        assert_eq!(p.evm_chains(), ["eip155:1"]);
        let iss = issuer("eip155:1", &addr);
        assert_eq!(iss, format!("did:pkh:eip155:1:{addr}"));
        assert_eq!(parse_issuer(&iss).unwrap(), ("eip155:1".to_string(), addr));
        let msg = format_message(&p, &iss).unwrap();
        assert_eq!(
            msg,
            format!(
                "example.com wants you to sign in with your Ethereum account:\n{addr}\n\n\nURI: https://example.com/login\nVersion: 1\nChain ID: 1\nNonce: abc123\nIssued At: 2024-01-01T00:00:00Z\nExpiration Time: 2024-01-02T00:00:00Z\nRequest ID: r1\nResources:\n- https://example.com/tos"
            )
        );
        p.statement = Some("Hello".into());
        p.resources = Some(vec![]);
        p.exp = None;
        p.request_id = None;
        let msg = format_message(&p, &iss).unwrap();
        assert_eq!(
            msg,
            format!(
                "example.com wants you to sign in with your Ethereum account:\n{addr}\n\nHello\n\nURI: https://example.com/login\nVersion: 1\nChain ID: 1\nNonce: abc123\nIssued At: 2024-01-01T00:00:00Z\nResources:"
            )
        );
        p.resources = None;
        assert!(!format_message(&p, &iss).unwrap().contains("Resources"));
        assert!(format_message(&p, "did:pkh:solana:x:abc").is_err());
        p.statement = Some("bad\nline".into());
        assert!(format_message(&p, &iss).is_err());
        p.statement = Some("Hello".into());
        p.aud = None;
        assert!(format_message(&p, &iss).is_err());
        p.uri = Some("https://example.com/alt".into());
        assert!(format_message(&p, &iss).unwrap().contains("URI: https://example.com/alt"));

        // Recap resources contribute to the statement and to the Resources list.
        let recap = encode_recap(&json!({ "att": { "eip155": { "request/personal_sign": [] } } }));
        p.resources = Some(vec![recap.clone()]);
        let msg = format_message(&p, &iss).unwrap();
        assert!(msg.contains("Hello I further authorize the stated URI to perform the following actions on my behalf: (1) 'request': 'personal_sign' for 'eip155'."), "{msg}");
        assert!(msg.ends_with(&format!("Resources:\n- {recap}")));

        let cacao = build_cacao(&p, &iss, "0xsig");
        assert_eq!(cacao["h"]["t"], "caip122");
        assert_eq!(cacao["s"]["t"], "eip191");
        let mut keys: Vec<&String> = cacao["p"].as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            ["aud", "domain", "iat", "iss", "nonce", "resources", "statement", "version"]
        );
        assert_eq!(cacao["p"]["aud"], "https://example.com/alt");
        // A CACAO payload must round-trip into an AuthPayload the way a verifier reads it.
        let back: AuthPayload = serde_json::from_value(cacao["p"].clone()).unwrap();
        assert_eq!(format_message(&back, &iss).unwrap(), msg);
    }
}
