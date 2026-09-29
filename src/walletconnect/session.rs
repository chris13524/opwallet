//! WalletConnect Sign API types: session proposals, namespace approval and
//! the JSON-RPC envelopes exchanged over encrypted topics.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::auth::AuthPayload;

// Message tags (used by the relay for push routing) and TTLs, per the spec.
pub const TAG_SESSION_PROPOSE_RES: u64 = 1101;
pub const TAG_SESSION_SETTLE_REQ: u64 = 1102;
pub const TAG_SESSION_UPDATE_REQ: u64 = 1104;
pub const TAG_SESSION_UPDATE_RES: u64 = 1105;
pub const TAG_SESSION_EXTEND_REQ: u64 = 1106;
pub const TAG_SESSION_EXTEND_RES: u64 = 1107;
pub const TAG_SESSION_REQUEST_RES: u64 = 1109;
pub const TAG_SESSION_EVENT_REQ: u64 = 1110;
pub const TAG_SESSION_EVENT_RES: u64 = 1111;
pub const TAG_SESSION_DELETE_REQ: u64 = 1112;
pub const TAG_SESSION_DELETE_RES: u64 = 1113;
pub const TAG_SESSION_PING_RES: u64 = 1115;
pub const TAG_PAIRING_DELETE_RES: u64 = 1001;
pub const TAG_PAIRING_PING_RES: u64 = 1003;

pub const TTL_FIVE_MINUTES: u64 = 300;
pub const TTL_THIRTY_SECONDS: u64 = 30;
pub const TTL_ONE_DAY: u64 = 86_400;
pub const SESSION_LIFETIME: u64 = 7 * 86_400;

/// Methods this wallet can execute.
pub const SUPPORTED_METHODS: &[&str] = &[
    "personal_sign",
    "eth_sign",
    "eth_signTypedData",
    "eth_signTypedData_v3",
    "eth_signTypedData_v4",
    "eth_signTransaction",
    "eth_sendTransaction",
    "eth_sendRawTransaction",
    "eth_accounts",
    "eth_requestAccounts",
    "eth_chainId",
    "wallet_switchEthereumChain",
    "wallet_addEthereumChain",
];

/// Events this wallet declares. It emits `accountsChanged` when the active
/// account switches; every requested chain is approved up front.
pub const SUPPORTED_EVENTS: &[&str] = &["chainChanged", "accountsChanged"];

/// Error codes from the Sign API spec.
pub const ERR_USER_REJECTED: i64 = 5000;
pub const ERR_UNSUPPORTED_METHODS: i64 = 5101;
pub const ERR_UNSUPPORTED_NAMESPACE_KEY: i64 = 5104;
pub const ERR_INVALID_PARAMS: i64 = -32602;
pub const ERR_INTERNAL: i64 = -32603;
pub const ERR_USER_DISCONNECTED: i64 = 6000;

#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
    pub fn user_rejected() -> Self {
        Self::new(ERR_USER_REJECTED, "User rejected.")
    }
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(ERR_INVALID_PARAMS, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ERR_INTERNAL, msg)
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code {})", self.message, self.code)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Metadata {
    pub name: String,
    pub description: String,
    pub url: String,
    pub icons: Vec<String>,
    /// Verify server the dapp registers its messages with.
    #[serde(rename = "verifyUrl", skip_serializing_if = "Option::is_none")]
    pub verify_url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ProposedNamespace {
    pub chains: Option<Vec<String>>,
    pub methods: Vec<String>,
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Proposer {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(default)]
    pub metadata: Metadata,
}

/// Extra requests a dapp can attach to a proposal (`ProposalTypes.Struct.requests`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ProposalRequests {
    pub authentication: Vec<AuthPayload>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionProposal {
    pub proposer: Proposer,
    #[serde(default)]
    pub requests: ProposalRequests,
    #[serde(default, rename = "requiredNamespaces")]
    pub required_namespaces: BTreeMap<String, ProposedNamespace>,
    #[serde(default, rename = "optionalNamespaces")]
    pub optional_namespaces: BTreeMap<String, ProposedNamespace>,
    #[serde(default, rename = "expiryTimestamp")]
    pub expiry_timestamp: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovedNamespace {
    pub chains: Vec<String>,
    pub accounts: Vec<String>,
    pub methods: Vec<String>,
    pub events: Vec<String>,
}

/// What we will approve for a proposal.
#[derive(Debug, Clone)]
pub struct ApprovalPlan {
    pub namespaces: BTreeMap<String, ApprovedNamespace>,
    pub chains: Vec<String>,
    pub methods: Vec<String>,
    pub events: Vec<String>,
}

fn push_unique(list: &mut Vec<String>, item: &str) {
    if !list.iter().any(|x| x == item) {
        list.push(item.to_string());
    }
}

fn chains_of(key: &str, ns: &ProposedNamespace) -> Vec<String> {
    if key.contains(':') { vec![key.to_string()] } else { ns.chains.clone().unwrap_or_default() }
}

fn is_eip155_chain(chain: &str) -> bool {
    chain.strip_prefix("eip155:").is_some_and(|n| n.parse::<u64>().is_ok())
}

/// Decide which chains/methods/events to approve, honouring every required
/// item and whatever optional items we support.
pub fn plan_approval(p: &SessionProposal, addresses: &[String]) -> Result<ApprovalPlan, RpcError> {
    let mut chains = Vec::new();
    let mut methods: Vec<String> = SUPPORTED_METHODS.iter().map(|s| s.to_string()).collect();
    let mut events: Vec<String> = SUPPORTED_EVENTS.iter().map(|s| s.to_string()).collect();

    for (key, ns) in &p.required_namespaces {
        if key != "eip155" && !key.starts_with("eip155:") {
            return Err(RpcError::new(
                ERR_UNSUPPORTED_NAMESPACE_KEY,
                format!("Unsupported namespace {key}; only eip155 (EVM) is supported"),
            ));
        }
        let unsupported: Vec<&str> = ns
            .methods
            .iter()
            .filter(|m| !SUPPORTED_METHODS.contains(&m.as_str()))
            .map(String::as_str)
            .collect();
        if !unsupported.is_empty() {
            return Err(RpcError::new(
                ERR_UNSUPPORTED_METHODS,
                format!("Unsupported methods: {}", unsupported.join(", ")),
            ));
        }
        for chain in chains_of(key, ns) {
            if !is_eip155_chain(&chain) {
                return Err(RpcError::new(
                    ERR_UNSUPPORTED_NAMESPACE_KEY,
                    format!("Unsupported chain {chain}"),
                ));
            }
            push_unique(&mut chains, &chain);
        }
        for e in &ns.events {
            push_unique(&mut events, e);
        }
    }
    for (key, ns) in &p.optional_namespaces {
        if key != "eip155" && !key.starts_with("eip155:") {
            continue;
        }
        for chain in chains_of(key, ns) {
            if is_eip155_chain(&chain) {
                push_unique(&mut chains, &chain);
            }
        }
        for m in &ns.methods {
            if SUPPORTED_METHODS.contains(&m.as_str()) {
                push_unique(&mut methods, m);
            }
        }
        for e in &ns.events {
            push_unique(&mut events, e);
        }
    }
    if chains.is_empty() {
        chains.push("eip155:1".to_string());
    }
    let namespaces = namespaces(&chains, &methods, &events, addresses);
    Ok(ApprovalPlan { namespaces, chains, methods, events })
}

/// The `eip155` namespace offering every address on every chain, as sent in
/// `wc_sessionSettle` and `wc_sessionUpdate`.
pub fn namespaces(
    chains: &[String],
    methods: &[String],
    events: &[String],
    addresses: &[String],
) -> BTreeMap<String, ApprovedNamespace> {
    let accounts =
        chains.iter().flat_map(|c| addresses.iter().map(move |a| format!("{c}:{a}"))).collect();
    BTreeMap::from([(
        "eip155".to_string(),
        ApprovedNamespace {
            chains: chains.to_vec(),
            accounts,
            methods: methods.to_vec(),
            events: events.to_vec(),
        },
    )])
}

/// Parameters of the `wc_sessionSettle` request the wallet sends.
pub fn settle_params(
    self_public_hex: &str,
    metadata: &Metadata,
    plan: &ApprovalPlan,
    expiry: u64,
    authentication: &[Value],
) -> Value {
    let mut params = json!({
        "relay": { "protocol": "irn" },
        "controller": { "publicKey": self_public_hex, "metadata": metadata },
        "namespaces": plan.namespaces,
        "expiry": expiry,
    });
    if !authentication.is_empty() {
        params["proposalRequestsResponses"] = json!({ "authentication": authentication });
    }
    params
}

/// Params of a `wc_sessionEvent` telling the dapp the selected account changed.
pub fn accounts_changed_params(chain: &str, addresses: &[String]) -> Value {
    json!({ "event": { "name": "accountsChanged", "data": addresses }, "chainId": chain })
}

/// A decoded JSON-RPC message from the peer.
#[derive(Debug, Clone)]
pub struct Rpc {
    pub id: u64,
    pub method: Option<String>,
    pub params: Value,
    pub result: Option<Value>,
    pub error: Option<Value>,
}

pub fn parse_rpc(text: &str) -> Option<Rpc> {
    let v: Value = serde_json::from_str(text).ok()?;
    Some(Rpc {
        id: v.get("id")?.as_u64()?,
        method: v.get("method").and_then(Value::as_str).map(str::to_string),
        params: v.get("params").cloned().unwrap_or(Value::Null),
        result: v.get("result").cloned(),
        error: v.get("error").cloned(),
    })
}

pub fn request_json(id: u64, method: &str, params: Value) -> String {
    json!({ "id": id, "jsonrpc": "2.0", "method": method, "params": params }).to_string()
}

pub fn result_json(id: u64, result: Value) -> String {
    json!({ "id": id, "jsonrpc": "2.0", "result": result }).to_string()
}

pub fn error_json(id: u64, err: &RpcError) -> String {
    json!({ "id": id, "jsonrpc": "2.0", "error": { "code": err.code, "message": err.message } })
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(required: Value, optional: Value) -> SessionProposal {
        serde_json::from_value(json!({
            "proposer": { "publicKey": "aa", "metadata": { "name": "dapp" } },
            "requiredNamespaces": required,
            "optionalNamespaces": optional,
        }))
        .unwrap()
    }

    #[test]
    fn approves_required_and_supported_optional() {
        let p = proposal(
            json!({ "eip155": { "chains": ["eip155:1"], "methods": ["personal_sign", "eth_sendTransaction"], "events": ["chainChanged"] } }),
            json!({ "eip155": { "chains": ["eip155:10", "eip155:1"], "methods": ["eth_signTypedData_v4", "wallet_getCapabilities"], "events": ["accountsChanged"] },
                    "solana": { "chains": ["solana:mainnet"], "methods": ["solana_signMessage"], "events": [] } }),
        );
        let plan = plan_approval(&p, &["0xabc".into()]).unwrap();
        assert_eq!(plan.chains, ["eip155:1", "eip155:10"]);
        let ns = &plan.namespaces["eip155"];
        assert_eq!(ns.accounts, ["eip155:1:0xabc", "eip155:10:0xabc"]);
        let multi = plan_approval(&p, &["0xa".into(), "0xb".into()]).unwrap();
        assert_eq!(
            multi.namespaces["eip155"].accounts,
            ["eip155:1:0xa", "eip155:1:0xb", "eip155:10:0xa", "eip155:10:0xb"]
        );
        assert!(ns.methods.iter().any(|m| m == "personal_sign"));
        assert!(!ns.methods.iter().any(|m| m == "wallet_getCapabilities"));
        assert!(ns.events.contains(&"chainChanged".to_string()));
        assert!(!plan.namespaces.contains_key("solana"));
    }

    #[test]
    fn caip2_namespace_keys_and_defaults() {
        let p = proposal(
            json!({ "eip155:137": { "methods": ["personal_sign"], "events": [] } }),
            json!({}),
        );
        let plan = plan_approval(&p, &["0xabc".into()]).unwrap();
        assert_eq!(plan.chains, ["eip155:137"]);

        let p = proposal(json!({}), json!({}));
        assert_eq!(plan_approval(&p, &["0xabc".into()]).unwrap().chains, ["eip155:1"]);
    }

    #[test]
    fn rejects_unsupported_required_items() {
        let p = proposal(
            json!({ "solana": { "chains": ["solana:x"], "methods": [], "events": [] } }),
            json!({}),
        );
        assert_eq!(
            plan_approval(&p, &["0x".into()]).unwrap_err().code,
            ERR_UNSUPPORTED_NAMESPACE_KEY
        );
        let p = proposal(
            json!({ "eip155": { "chains": ["eip155:1"], "methods": ["eth_magic"], "events": [] } }),
            json!({}),
        );
        assert_eq!(plan_approval(&p, &["0x".into()]).unwrap_err().code, ERR_UNSUPPORTED_METHODS);
        let p = proposal(
            json!({ "eip155": { "chains": ["eip155:abc"], "methods": [], "events": [] } }),
            json!({}),
        );
        assert!(plan_approval(&p, &["0x".into()]).is_err());
    }

    #[test]
    fn settle_params_carry_authentication_responses() {
        let p = proposal(json!({}), json!({}));
        let plan = plan_approval(&p, &["0xabc".into()]).unwrap();
        let meta = Metadata::default();
        let v = settle_params("pk", &meta, &plan, 1, &[]);
        assert!(v.get("proposalRequestsResponses").is_none());
        let v = settle_params("pk", &meta, &plan, 1, &[json!({ "h": {} })]);
        assert_eq!(v["proposalRequestsResponses"]["authentication"].as_array().unwrap().len(), 1);

        let with_auth: SessionProposal = serde_json::from_value(json!({
            "proposer": { "publicKey": "aa" },
            "requests": { "authentication": [{ "domain": "d", "chains": ["eip155:1"], "nonce": "n", "aud": "https://d", "version": "1", "iat": "t" }] }
        }))
        .unwrap();
        assert_eq!(with_auth.requests.authentication[0].domain, "d");
        assert!(p.requests.authentication.is_empty());
    }

    #[test]
    fn accounts_changed_event_shape() {
        let v = accounts_changed_params("eip155:1", &["0xa".into(), "0xb".into()]);
        assert_eq!(v["event"]["name"], "accountsChanged");
        assert_eq!(v["event"]["data"], json!(["0xa", "0xb"]));
        assert_eq!(v["chainId"], "eip155:1");
    }

    #[test]
    fn rpc_roundtrip() {
        let text = request_json(7, "wc_sessionPing", json!({}));
        let rpc = parse_rpc(&text).unwrap();
        assert_eq!(rpc.id, 7);
        assert_eq!(rpc.method.as_deref(), Some("wc_sessionPing"));
        let err = parse_rpc(&error_json(7, &RpcError::user_rejected())).unwrap();
        assert_eq!(err.error.unwrap()["code"], 5000);
        assert!(parse_rpc("nope").is_none());
    }
}
