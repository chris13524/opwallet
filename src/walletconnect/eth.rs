//! Execution of Ethereum JSON-RPC requests received over a session: message
//! and typed-data signing, transaction preparation/signing/broadcast.
//!
//! Every signing operation opens the wallet (fetch from 1Password, derive,
//! verify address), signs, and drops the key again immediately.

use std::collections::HashMap;

use alloy_consensus::{TxEip1559, TxEnvelope, TxLegacy, transaction::SignableTransaction};
use alloy_dyn_abi::TypedData;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256, hex};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use super::{
    session::RpcError,
    tenderly::{self, SimulationRequest, TenderlyProject},
    ui::{Ui, run_busy},
};
use crate::wallet::Wallet;

/// A wallet taking part in the session: its 1Password item title and address.
#[derive(Debug, Clone)]
pub struct Account {
    pub name: String,
    pub address: Address,
}

/// Opens a wallet's key material on demand (fetch, derive, verify).
pub trait Opener {
    fn open(&self, name: &str) -> Result<Wallet>;
}

impl<F: Fn(&str) -> Result<Wallet>> Opener for F {
    fn open(&self, name: &str) -> Result<Wallet> {
        self(name)
    }
}

/// JSON-RPC client for chain reads and broadcasts.
pub struct RpcClient {
    project_id: String,
    overrides: HashMap<u64, String>,
    agent: ureq::Agent,
}

impl RpcClient {
    pub fn new(project_id: &str, overrides: HashMap<u64, String>) -> Self {
        Self {
            project_id: project_id.to_string(),
            overrides,
            agent: ureq::Agent::new_with_defaults(),
        }
    }

    pub fn url(&self, chain_id: u64) -> String {
        self.overrides.get(&chain_id).cloned().unwrap_or_else(|| {
            format!(
                "https://rpc.walletconnect.com/v1?chainId=eip155:{chain_id}&projectId={}",
                self.project_id
            )
        })
    }

    pub fn call(&self, chain_id: u64, method: &str, params: Value) -> Result<Value> {
        let url = self.url(chain_id);
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let mut response = self
            .agent
            .post(&url)
            .send_json(&body)
            .with_context(|| format!("RPC {method} to chain {chain_id} failed"))?;
        let v: Value = response.body_mut().read_json().context("RPC returned invalid JSON")?;
        if let Some(err) = v.get("error") {
            bail!("RPC {method} error: {err}");
        }
        v.get("result").cloned().ok_or_else(|| anyhow!("RPC {method} returned no result"))
    }
}

/// Everything a request handler needs.
pub struct RequestContext<'a> {
    /// Name of the dapp asking, shown in every approval prompt.
    pub dapp: &'a str,
    pub accounts: &'a [Account],
    /// Index into `accounts` of the account requests default to.
    pub active: usize,
    pub chain_id: u64,
    pub opener: &'a (dyn Opener + Sync),
    pub rpc: &'a RpcClient,
    /// Tenderly project that simulation links open in.
    pub tenderly: Option<&'a TenderlyProject>,
    pub ui: &'a mut dyn Ui,
}

fn internal(e: anyhow::Error) -> RpcError {
    RpcError::internal(format!("{e:#}"))
}

fn hex_quantity<T: TryFrom<u128>>(v: &Value, name: &str) -> Result<Option<T>, RpcError> {
    let Some(v) = v.get(name) else { return Ok(None) };
    if v.is_null() {
        return Ok(None);
    }
    let n: u128 = match v {
        Value::String(s) => {
            let s = s.trim();
            match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                Some("") => 0,
                Some(h) => u128::from_str_radix(h, 16)
                    .map_err(|_| RpcError::invalid_params(format!("{name} is not valid hex")))?,
                None => s
                    .parse()
                    .map_err(|_| RpcError::invalid_params(format!("{name} is not a number")))?,
            }
        }
        Value::Number(n) => n
            .as_u64()
            .map(u128::from)
            .ok_or_else(|| RpcError::invalid_params(format!("{name} is not a number")))?,
        _ => return Err(RpcError::invalid_params(format!("{name} has the wrong type"))),
    };
    T::try_from(n).map(Some).map_err(|_| RpcError::invalid_params(format!("{name} is too large")))
}

fn parse_address(v: &Value, name: &str) -> Result<Option<Address>, RpcError> {
    match v.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => s
            .parse()
            .map(Some)
            .map_err(|_| RpcError::invalid_params(format!("{name} is not a valid address"))),
        Some(_) => Err(RpcError::invalid_params(format!("{name} has the wrong type"))),
    }
}

fn parse_bytes(v: &Value) -> Result<Vec<u8>, RpcError> {
    match v {
        Value::Null => Ok(Vec::new()),
        Value::String(s) => {
            hex::decode(s).map_err(|_| RpcError::invalid_params("data is not valid hex"))
        }
        _ => Err(RpcError::invalid_params("data has the wrong type")),
    }
}

/// Wei to a human ETH string ("1.5", "0.000021").
pub fn format_ether(wei: U256) -> String {
    format_units(wei, 18)
}

fn format_gwei(wei: u128) -> String {
    format_units(U256::from(wei), 9)
}

fn format_units(v: U256, decimals: usize) -> String {
    let s = v.to_string();
    if s.len() <= decimals {
        let frac = format!("{s:0>width$}", width = decimals);
        let frac = frac.trim_end_matches('0');
        if frac.is_empty() { "0".into() } else { format!("0.{frac}") }
    } else {
        let (whole, frac) = s.split_at(s.len() - decimals);
        let frac = frac.trim_end_matches('0');
        if frac.is_empty() { whole.into() } else { format!("{whole}.{frac}") }
    }
}

/// Bytes a dapp asked us to sign, plus how to show them to the user.
fn message_bytes(v: &Value) -> Result<(Vec<u8>, String), RpcError> {
    let s = v.as_str().ok_or_else(|| RpcError::invalid_params("message must be a string"))?;
    let bytes = if let Some(h) = s.strip_prefix("0x") {
        hex::decode(h).unwrap_or_else(|_| s.as_bytes().to_vec())
    } else {
        s.as_bytes().to_vec()
    };
    let display = match std::str::from_utf8(&bytes) {
        Ok(text) if text.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') => {
            text.to_string()
        }
        _ => hex::encode_prefixed(&bytes),
    };
    Ok((bytes, display))
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max { text.to_string() } else { format!("{}…", &text[..max]) }
}

/// Handle one session request. Returns the JSON-RPC result or an error the
/// dapp will receive.
pub fn handle(
    method: &str,
    params: &Value,
    ctx: &mut RequestContext<'_>,
) -> Result<Value, RpcError> {
    match method {
        "eth_accounts" | "eth_requestAccounts" => {
            Ok(json!(ordered_addresses(ctx.accounts, ctx.active)))
        }
        "eth_chainId" => Ok(json!(format!("0x{:x}", ctx.chain_id))),
        "wallet_switchEthereumChain" | "wallet_addEthereumChain" => Ok(Value::Null),
        "personal_sign" | "eth_sign" => sign_message(method, params, ctx),
        "eth_signTypedData" | "eth_signTypedData_v3" | "eth_signTypedData_v4" => {
            sign_typed_data(params, ctx)
        }
        "eth_signTransaction" => transaction(params, ctx, false),
        "eth_sendTransaction" => transaction(params, ctx, true),
        "eth_sendRawTransaction" => send_raw(params, ctx),
        other => Err(RpcError::new(
            super::session::ERR_UNSUPPORTED_METHODS,
            format!("Method {other} is not supported"),
        )),
    }
}

/// Addresses with the active account first (dapps treat index 0 as selected).
pub fn ordered_addresses(accounts: &[Account], active: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(accounts.len());
    if let Some(a) = accounts.get(active) {
        out.push(a.address.to_string());
    }
    for (i, a) in accounts.iter().enumerate() {
        if i != active {
            out.push(a.address.to_string());
        }
    }
    out
}

/// Pick the connected account a request is for.
fn resolve_account<'a>(
    ctx: &'a RequestContext<'_>,
    requested: Option<Address>,
) -> Result<&'a Account, RpcError> {
    match requested {
        Some(a) => ctx.accounts.iter().find(|acc| acc.address == a).ok_or_else(|| {
            RpcError::invalid_params(format!("{a} is not one of the connected accounts"))
        }),
        None => ctx
            .accounts
            .get(ctx.active)
            .or(ctx.accounts.first())
            .ok_or_else(|| RpcError::internal("no accounts connected")),
    }
}

fn with_wallet<T>(
    ctx: &mut RequestContext<'_>,
    account: &Account,
    f: impl FnOnce(&Wallet) -> Result<T>,
) -> Result<T, RpcError> {
    let opener = ctx.opener;
    let name = account.name.clone();
    let wallet =
        run_busy(ctx.ui, &format!("Waiting for 1Password to unlock {name:?}"), move || {
            opener.open(&name)
        })
        .map_err(internal)?;
    if wallet.address() != account.address {
        return Err(RpcError::internal(format!(
            "1Password item {:?} no longer derives {}",
            account.name, account.address
        )));
    }
    let out = f(&wallet).map_err(internal);
    drop(wallet);
    out
}

fn sign_message(
    method: &str,
    params: &Value,
    ctx: &mut RequestContext<'_>,
) -> Result<Value, RpcError> {
    let list =
        params.as_array().ok_or_else(|| RpcError::invalid_params("params must be an array"))?;
    // personal_sign is [message, address]; eth_sign is [address, message].
    // Be tolerant: pick whichever element parses as an address.
    let (msg, addr) = match list.as_slice() {
        [a, b] => {
            let is_addr = |v: &Value| v.as_str().is_some_and(|s| s.parse::<Address>().is_ok());
            if is_addr(a) && (method == "eth_sign" || !is_addr(b)) { (b, a) } else { (a, b) }
        }
        [a] => (a, &Value::Null),
        _ => return Err(RpcError::invalid_params("expected [message, address]")),
    };
    let account = resolve_account(ctx, addr.as_str().and_then(|s| s.parse().ok()))?.clone();
    let (bytes, display) = message_bytes(msg)?;

    let title = format!("Sign message ({} bytes) with {}", bytes.len(), account.name);
    let body = format!("account: {}\n\n{}", account.address, truncate(&display, 4000));
    if !ctx.ui.confirm(&format!("{}: {title}", ctx.dapp), &body).map_err(internal)? {
        return Err(RpcError::user_rejected());
    }
    let sig = with_wallet(ctx, &account, |w| w.sign_message(&bytes))?;
    Ok(json!(sig))
}

fn sign_typed_data(params: &Value, ctx: &mut RequestContext<'_>) -> Result<Value, RpcError> {
    let list =
        params.as_array().ok_or_else(|| RpcError::invalid_params("params must be an array"))?;
    let (addr, data) = match list.as_slice() {
        [a, d] => (parse_address(&json!({ "a": a }), "a")?, d),
        _ => return Err(RpcError::invalid_params("expected [address, typedData]")),
    };
    let account = resolve_account(ctx, addr)?.clone();
    let data: Value = match data {
        Value::String(s) => serde_json::from_str(s)
            .map_err(|e| RpcError::invalid_params(format!("typed data is not valid JSON: {e}")))?,
        other => other.clone(),
    };
    let typed: TypedData = serde_json::from_value(data.clone())
        .map_err(|e| RpcError::invalid_params(format!("invalid EIP-712 typed data: {e}")))?;
    let hash: B256 = typed
        .eip712_signing_hash()
        .map_err(|e| RpcError::invalid_params(format!("cannot hash typed data: {e}")))?;

    let msg = serde_json::to_string_pretty(&data["message"]).unwrap_or_default();
    let title = format!("Sign EIP-712 typed data with {}", account.name);
    let body = format!(
        "account:      {}\ndomain:       {}\nprimary type: {}\nmessage:\n{}\ndigest:       {hash}",
        account.address,
        truncate(&data["domain"].to_string(), 500),
        typed.primary_type,
        truncate(&msg, 4000)
    );
    if !ctx.ui.confirm(&format!("{}: {title}", ctx.dapp), &body).map_err(internal)? {
        return Err(RpcError::user_rejected());
    }
    let sig = with_wallet(ctx, &account, |w| w.sign_hash(&hash))?;
    Ok(json!(hex::encode_prefixed(sig.as_bytes())))
}

enum Prepared {
    Legacy(TxLegacy),
    Eip1559(TxEip1559),
}

fn prepare_transaction(
    tx: &Value,
    rpc: &RpcClient,
    chain_id: u64,
    account: &Account,
) -> Result<Prepared, RpcError> {
    let to = parse_address(tx, "to")?;
    let value: U256 = match tx.get("value") {
        None | Some(Value::Null) => U256::ZERO,
        Some(Value::String(s)) => {
            let s = s.trim();
            match s.strip_prefix("0x") {
                Some("") => U256::ZERO,
                Some(h) => U256::from_str_radix(h, 16)
                    .map_err(|_| RpcError::invalid_params("value is not valid hex"))?,
                None => s.parse().map_err(|_| RpcError::invalid_params("value is not a number"))?,
            }
        }
        Some(_) => return Err(RpcError::invalid_params("value has the wrong type")),
    };
    let data = parse_bytes(tx.get("data").or_else(|| tx.get("input")).unwrap_or(&Value::Null))?;
    let requested_chain: Option<u64> = hex_quantity(tx, "chainId")?;
    if let Some(c) = requested_chain
        && c != chain_id
    {
        return Err(RpcError::invalid_params(format!(
            "transaction chainId {c} does not match session chain {}",
            chain_id
        )));
    }
    let from_addr = account.address;

    let nonce: u64 = match hex_quantity(tx, "nonce")? {
        Some(n) => n,
        None => {
            let v = rpc
                .call(chain_id, "eth_getTransactionCount", json!([from_addr, "pending"]))
                .map_err(internal)?;
            hex_quantity(&json!({ "n": v }), "n")?.ok_or_else(|| RpcError::internal("bad nonce"))?
        }
    };
    let gas_limit: u64 = match hex_quantity(tx, "gas")?.or(hex_quantity(tx, "gasLimit")?) {
        Some(g) => g,
        None => {
            let mut call = json!({ "from": from_addr, "value": format!("0x{value:x}"), "data": hex::encode_prefixed(&data) });
            if let Some(to) = to {
                call["to"] = json!(to);
            }
            let v = rpc.call(chain_id, "eth_estimateGas", json!([call])).map_err(internal)?;
            let est: u64 = hex_quantity(&json!({ "g": v }), "g")?
                .ok_or_else(|| RpcError::internal("bad gas estimate"))?;
            est + est / 5 // 20% headroom
        }
    };

    let gas_price: Option<u128> = hex_quantity(tx, "gasPrice")?;
    let max_fee: Option<u128> = hex_quantity(tx, "maxFeePerGas")?;
    let max_priority: Option<u128> = hex_quantity(tx, "maxPriorityFeePerGas")?;
    let tx_type: Option<u8> = hex_quantity(tx, "type")?;

    let input = Bytes::from(data);
    let to_kind = to.map(TxKind::Call).unwrap_or(TxKind::Create);
    let gas_price_call = || -> Result<u128, RpcError> {
        let v = rpc.call(chain_id, "eth_gasPrice", json!([])).map_err(internal)?;
        hex_quantity(&json!({ "p": v }), "p")?.ok_or_else(|| RpcError::internal("bad gas price"))
    };
    let legacy_tx = |gas_price: u128, input: Bytes| {
        Prepared::Legacy(TxLegacy {
            chain_id: Some(chain_id),
            nonce,
            gas_price,
            gas_limit,
            to: to_kind,
            value,
            input,
        })
    };

    let legacy = gas_price.is_some() && max_fee.is_none() || tx_type == Some(0);
    if legacy {
        let gas_price = match gas_price {
            Some(p) => p,
            None => gas_price_call()?,
        };
        return Ok(legacy_tx(gas_price, input));
    }

    let (max_fee, max_priority) = match (max_fee, max_priority) {
        (Some(f), Some(p)) => (f, p),
        (Some(f), None) => (f, f.min(1_000_000_000)),
        (None, prio) => {
            let block = rpc
                .call(chain_id, "eth_getBlockByNumber", json!(["latest", false]))
                .map_err(internal)?;
            match hex_quantity::<u128>(&block, "baseFeePerGas")? {
                Some(base) => {
                    let prio = match prio {
                        Some(p) => p,
                        None => rpc
                            .call(chain_id, "eth_maxPriorityFeePerGas", json!([]))
                            .ok()
                            .and_then(|v| {
                                hex_quantity::<u128>(&json!({ "p": v }), "p").ok().flatten()
                            })
                            .unwrap_or(1_000_000_000),
                    };
                    (base * 2 + prio, prio)
                }
                // Pre-London chain: fall back to a legacy transaction.
                None => return Ok(legacy_tx(gas_price_call()?, input)),
            }
        }
    };
    Ok(Prepared::Eip1559(TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: max_priority,
        to: to_kind,
        value,
        access_list: Default::default(),
        input,
    }))
}

fn describe(p: &Prepared, chain_id: u64, from: &Account) -> String {
    let (nonce, gas, to, value, input, fee_line, max_fee) = match p {
        Prepared::Legacy(t) => (
            t.nonce,
            t.gas_limit,
            t.to,
            t.value,
            &t.input,
            format!("gas price {} gwei (legacy)", format_gwei(t.gas_price)),
            t.gas_price,
        ),
        Prepared::Eip1559(t) => (
            t.nonce,
            t.gas_limit,
            t.to,
            t.value,
            &t.input,
            format!(
                "max fee {} gwei, priority {} gwei (EIP-1559)",
                format_gwei(t.max_fee_per_gas),
                format_gwei(t.max_priority_fee_per_gas)
            ),
            t.max_fee_per_gas,
        ),
    };
    let to = match to {
        TxKind::Call(a) => a.to_string(),
        TxKind::Create => "<contract creation>".to_string(),
    };
    let data = if input.is_empty() {
        "none".to_string()
    } else if input.len() >= 4 {
        format!("{} bytes, selector {}", input.len(), hex::encode_prefixed(&input[..4]))
    } else {
        hex::encode_prefixed(input)
    };
    let max_cost = U256::from(gas) * U256::from(max_fee) + value;
    format!(
        "chain:     eip155:{chain_id}\nfrom:      {} ({})\nto:        {to}\nvalue:     {} ETH\ndata:      {data}\ngas limit: {gas}\nfees:      {fee_line}\nnonce:     {nonce}\nmax cost:  {} ETH (value + gas)",
        from.address,
        from.name,
        format_ether(value),
        format_ether(max_cost)
    )
}

/// Link that opens `p` pre-filled in Tenderly's simulator (none for
/// contract creation, which the simulator cannot take).
fn tenderly_link(p: &Prepared, from: Address, project: Option<&TenderlyProject>) -> Option<String> {
    let (chain_id, to, value, input, gas_limit, gas_price) = match p {
        Prepared::Legacy(t) => {
            (t.chain_id.unwrap_or_default(), t.to, t.value, &t.input, t.gas_limit, t.gas_price)
        }
        Prepared::Eip1559(t) => {
            (t.chain_id, t.to, t.value, &t.input, t.gas_limit, t.max_fee_per_gas)
        }
    };
    let req =
        SimulationRequest { chain_id, from, to: *to.to()?, value, input, gas_limit, gas_price };
    Some(tenderly::simulator_link(&req, project))
}

fn sign_prepared(
    p: Prepared,
    ctx: &mut RequestContext<'_>,
    account: &Account,
) -> Result<Vec<u8>, RpcError> {
    let mut sign = |hash: B256| -> Result<Signature, RpcError> {
        with_wallet(ctx, account, |w| w.sign_hash(&hash))
    };
    let envelope: TxEnvelope = match p {
        Prepared::Legacy(t) => {
            let sig = sign(t.signature_hash())?;
            TxEnvelope::Legacy(t.into_signed(sig))
        }
        Prepared::Eip1559(t) => {
            let sig = sign(t.signature_hash())?;
            TxEnvelope::Eip1559(t.into_signed(sig))
        }
    };
    Ok(envelope.encoded_2718())
}

fn transaction(
    params: &Value,
    ctx: &mut RequestContext<'_>,
    broadcast: bool,
) -> Result<Value, RpcError> {
    let tx = params
        .as_array()
        .and_then(|a| a.first())
        .filter(|v| v.is_object())
        .ok_or_else(|| RpcError::invalid_params("expected [transaction]"))?;
    let account = resolve_account(ctx, parse_address(tx, "from")?)?.clone();
    let (rpc, chain_id) = (ctx.rpc, ctx.chain_id);
    let prepared = run_busy(ctx.ui, "Fetching nonce, gas and fees from the chain", || {
        prepare_transaction(tx, rpc, chain_id, &account)
    })?;
    let verb = if broadcast { "Send" } else { "Sign" };
    let title = format!("{verb} transaction from {}", account.name);
    let mut body = describe(&prepared, ctx.chain_id, &account);
    if let Some(link) = tenderly_link(&prepared, account.address, ctx.tenderly) {
        ctx.ui.copyable(&format!("Tenderly simulation link (eip155:{})", ctx.chain_id), &link);
        body.push_str(&format!("\n\nsimulate this transaction in Tenderly:\n{link}"));
    }
    if !ctx.ui.confirm(&format!("{}: {title}", ctx.dapp), &body).map_err(internal)? {
        return Err(RpcError::user_rejected());
    }
    let raw = sign_prepared(prepared, ctx, &account)?;
    let raw_hex = hex::encode_prefixed(&raw);
    if !broadcast {
        ctx.ui.copyable(&format!("signed transaction for eip155:{}", ctx.chain_id), &raw_hex);
        return Ok(json!(raw_hex));
    }
    let hash = run_busy(ctx.ui, "Broadcasting transaction", || {
        rpc.call(chain_id, "eth_sendRawTransaction", json!([raw_hex]))
    })
    .map_err(internal)?;
    ctx.ui.log(&format!("broadcast transaction {hash}"));
    if let Some(h) = hash.as_str() {
        ctx.ui.copyable(&format!("tx hash on eip155:{}", ctx.chain_id), h);
    }
    Ok(hash)
}

fn send_raw(params: &Value, ctx: &mut RequestContext<'_>) -> Result<Value, RpcError> {
    let raw = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("expected [rawTransaction]"))?;
    let title = format!("Broadcast pre-signed transaction on eip155:{}", ctx.chain_id);
    let body = format!("{} hex characters\n{}", raw.len(), truncate(raw, 2000));
    if !ctx.ui.confirm(&format!("{}: {title}", ctx.dapp), &body).map_err(internal)? {
        return Err(RpcError::user_rejected());
    }
    let (rpc, chain_id) = (ctx.rpc, ctx.chain_id);
    run_busy(ctx.ui, "Broadcasting transaction", || {
        rpc.call(chain_id, "eth_sendRawTransaction", json!([raw]))
    })
    .map_err(internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_formatting() {
        assert_eq!(format_ether(U256::from(1_500_000_000_000_000_000u128)), "1.5");
        assert_eq!(format_ether(U256::from(21_000_000_000_000u128)), "0.000021");
        assert_eq!(format_ether(U256::ZERO), "0");
        assert_eq!(format_ether(U256::from(10u8).pow(U256::from(18))), "1");
        assert_eq!(format_gwei(1_000_000_000), "1");
        assert_eq!(format_gwei(1_250_000_000), "1.25");
    }

    #[test]
    fn quantities_and_messages() {
        let v = json!({ "a": "0x10", "b": "16", "c": 16, "d": "0x", "e": null, "f": "0xzz" });
        assert_eq!(hex_quantity::<u64>(&v, "a").unwrap(), Some(16));
        assert_eq!(hex_quantity::<u64>(&v, "b").unwrap(), Some(16));
        assert_eq!(hex_quantity::<u64>(&v, "c").unwrap(), Some(16));
        assert_eq!(hex_quantity::<u64>(&v, "d").unwrap(), Some(0));
        assert_eq!(hex_quantity::<u64>(&v, "e").unwrap(), None);
        assert_eq!(hex_quantity::<u64>(&v, "missing").unwrap(), None);
        assert!(hex_quantity::<u64>(&v, "f").is_err());
        assert!(hex_quantity::<u8>(&json!({ "x": "0x1ff" }), "x").is_err());

        let (b, d) = message_bytes(&json!("0x68656c6c6f")).unwrap();
        assert_eq!(b, b"hello");
        assert_eq!(d, "hello");
        let (b, d) = message_bytes(&json!("0x00ff")).unwrap();
        assert_eq!(b, [0, 0xff]);
        assert_eq!(d, "0x00ff");
        let (b, _) = message_bytes(&json!("plain text")).unwrap();
        assert_eq!(b, b"plain text");
    }
}
