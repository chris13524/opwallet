//! Command-line definitions for both programs built from this crate:
//! `opwallet` (the wallet, keys in 1Password) and `wcapp` (the same actions
//! performed through any wallet over WalletConnect).
//!
//! The two are meant to be interchangeable for scripts and agents, so the
//! arguments they share are defined once here, and `tests/parity.rs` fails
//! when a command or flag exists in one but not the other without being on
//! its list of deliberate differences.

pub mod opwallet;
pub mod wcapp;

use std::io::Read;

use alloy_primitives::{Address, U256, hex};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Command, CommandFactory, FromArgMatches};
use serde_json::{Map, Value, json};

/// Arguments that can also come from an environment variable, named
/// `<PREFIX>_<ARG ID IN UPPER CASE>` (`OPWALLET_VAULT`, `WCAPP_STATE_DIR`).
/// Each program applies its own prefix, so shared definitions stay shared.
const ENV_ARGS: &[&str] = &[
    "op_bin",
    "vault",
    "no_relock",
    "state_dir",
    "project_id",
    "relay_url",
    "tenderly_project",
    "verify_url",
    "no_verify",
    "name",
    "timeout",
];

/// `C`'s command with every [`ENV_ARGS`] argument bound to `PREFIX_<ID>`.
pub fn command<C: CommandFactory>(prefix: &str) -> Command {
    with_env(C::command(), prefix)
}

/// Parse the process arguments into `C`, with environment variables
/// prefixed by `prefix`.
pub fn parse<C: CommandFactory + FromArgMatches>(prefix: &str) -> C {
    let matches = command::<C>(prefix).get_matches();
    C::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

fn with_env(mut cmd: Command, prefix: &str) -> Command {
    let ids: Vec<String> = cmd
        .get_arguments()
        .map(|a| a.get_id().to_string())
        .filter(|id| ENV_ARGS.contains(&id.as_str()))
        .collect();
    for id in ids {
        // clap wants a 'static name; this runs once per process.
        let var: &'static str = Box::leak(format!("{prefix}_{}", id.to_uppercase()).into());
        cmd = cmd.mut_arg(id, |a| a.env(var));
    }
    let subs: Vec<String> = cmd.get_subcommands().map(|s| s.get_name().to_string()).collect();
    for name in subs {
        cmd = cmd.mut_subcommand(name, |sub| with_env(sub, prefix));
    }
    cmd
}

/// A WalletConnect project ID: the flag (or its variable), else the first
/// of `fallback_vars` that is set.
pub fn project_id(given: Option<String>, fallback_vars: &[&str]) -> Option<String> {
    given
        .into_iter()
        .chain(fallback_vars.iter().filter_map(|v| std::env::var(v).ok()))
        .map(|p| p.trim().to_string())
        .find(|p| !p.is_empty())
}

/// [`project_id`], or an error saying how to get one.
pub fn require_project_id(
    given: Option<String>,
    fallback_vars: &[&str],
    flag_var: &str,
) -> Result<String> {
    project_id(given, fallback_vars).ok_or_else(|| {
        anyhow!(
            "no WalletConnect project ID: pass --project-id or set {flag_var} \
             (free at https://dashboard.walletconnect.com)"
        )
    })
}

#[derive(Args, Debug)]
pub struct RelayArgs {
    /// WalletConnect project ID (free at https://dashboard.walletconnect.com).
    #[arg(long)]
    pub project_id: Option<String>,

    /// Relay websocket URL.
    #[arg(long, default_value = crate::walletconnect::DEFAULT_RELAY_URL)]
    pub relay_url: String,
}

#[derive(Args, Debug)]
pub struct MessageArgs {
    /// Message to sign (EIP-191 `personal_sign`). Prefix with 0x to sign
    /// raw bytes instead of UTF-8 text.
    #[arg(long, short = 'm')]
    pub message: String,
}

impl MessageArgs {
    /// The bytes to sign.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        match self.message.strip_prefix("0x") {
            Some(h) => hex::decode(h).context("message is not valid hex"),
            None => Ok(self.message.as_bytes().to_vec()),
        }
    }
}

#[derive(Args, Debug)]
pub struct TypedDataArgs {
    /// EIP-712 typed data to sign (`eth_signTypedData_v4`): the JSON itself,
    /// @FILE to read it from a file, or - to read it from stdin.
    #[arg(long, short = 'd', value_name = "JSON|@FILE|-")]
    pub data: String,
}

impl TypedDataArgs {
    /// The typed data as JSON (not yet validated as EIP-712).
    pub fn json(&self) -> Result<Value> {
        let text = if self.data == "-" {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).context("could not read stdin")?;
            s
        } else if let Some(path) = self.data.strip_prefix('@') {
            std::fs::read_to_string(path).with_context(|| format!("could not read {path}"))?
        } else {
            self.data.clone()
        };
        serde_json::from_str(&text).context("typed data is not valid JSON")
    }
}

/// A transaction, as flags. Whatever is left out (nonce, gas limit, fees)
/// is filled in from the chain by the wallet that signs it.
#[derive(Args, Debug, Clone)]
pub struct TxArgs {
    /// Chain ID of the network the transaction is for.
    #[arg(long, default_value_t = 1)]
    pub chain: u64,

    /// Recipient. Omit to deploy a contract.
    #[arg(long, value_parser = parse_address)]
    pub to: Option<Address>,

    /// Amount to send: wei, or with a unit (`0.1eth`, `20gwei`).
    #[arg(long, default_value = "0", value_parser = parse_amount)]
    pub value: U256,

    /// Calldata, hex.
    #[arg(long, value_name = "HEX", value_parser = parse_hex)]
    pub data: Option<String>,

    /// Gas limit (default: estimated, plus 20%).
    #[arg(long)]
    pub gas: Option<u64>,

    /// Nonce (default: the account's next pending nonce).
    #[arg(long)]
    pub nonce: Option<u64>,

    /// Gas price for a legacy transaction: wei, or with a unit (`3gwei`).
    #[arg(long, value_parser = parse_fee, conflicts_with = "max_fee")]
    pub gas_price: Option<u128>,

    /// EIP-1559 maximum fee per gas: wei, or with a unit (default: twice
    /// the base fee plus the priority fee).
    #[arg(long, value_parser = parse_fee)]
    pub max_fee: Option<u128>,

    /// EIP-1559 priority fee per gas: wei, or with a unit (default: what
    /// the chain suggests).
    #[arg(long, value_parser = parse_fee)]
    pub priority_fee: Option<u128>,
}

impl TxArgs {
    /// The transaction as an `eth_sendTransaction` parameter object. Both
    /// programs hand exactly this to the same preparation code, locally or
    /// on the far side of the WalletConnect session.
    pub fn to_json(&self, from: Address) -> Value {
        let q = |n: u128| json!(format!("0x{n:x}"));
        let mut tx = Map::new();
        tx.insert("from".into(), json!(from));
        if let Some(to) = self.to {
            tx.insert("to".into(), json!(to));
        }
        tx.insert("value".into(), json!(format!("0x{:x}", self.value)));
        if let Some(d) = &self.data {
            tx.insert("data".into(), json!(d));
        }
        tx.insert("chainId".into(), q(self.chain.into()));
        let optional = [
            ("gas", self.gas.map(u128::from)),
            ("nonce", self.nonce.map(u128::from)),
            ("gasPrice", self.gas_price),
            ("maxFeePerGas", self.max_fee),
            ("maxPriorityFeePerGas", self.priority_fee),
        ];
        for (k, v) in optional {
            if let Some(v) = v {
                tx.insert(k.into(), q(v));
            }
        }
        Value::Object(tx)
    }
}

#[derive(Args, Debug)]
pub struct OutputArgs {
    /// Print JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DisconnectArgs {
    /// Sessions to end: a number from `sessions`, part of the peer's name or
    /// URL, or a topic prefix.
    pub session: Vec<String>,

    /// End every saved session.
    #[arg(long, conflicts_with = "session")]
    pub all: bool,
}

fn parse_address(s: &str) -> Result<Address, String> {
    s.trim().parse().map_err(|_| format!("{s:?} is not an address"))
}

fn parse_hex(s: &str) -> Result<String, String> {
    let s = s.trim();
    let body = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(body).map_err(|_| format!("{s:?} is not hex"))?;
    Ok(format!("0x{body}"))
}

/// `1000` (wei), `0x3e8` (wei), `1.5eth`, `20gwei`, `7wei`.
pub fn parse_amount(s: &str) -> Result<U256, String> {
    amount(s).map_err(|e| format!("{e:#}"))
}

fn parse_fee(s: &str) -> Result<u128, String> {
    let v = parse_amount(s)?;
    u128::try_from(v).map_err(|_| format!("{s:?} is too large"))
}

fn amount(s: &str) -> Result<U256> {
    let s = s.trim().to_ascii_lowercase().replace('_', "");
    if let Some(h) = s.strip_prefix("0x") {
        return U256::from_str_radix(h, 16).map_err(|_| anyhow!("{s:?} is not valid hex"));
    }
    let (number, decimals) = if let Some(n) = s.strip_suffix("gwei") {
        (n, 9)
    } else if let Some(n) = s.strip_suffix("wei") {
        (n, 0)
    } else if let Some(n) = s.strip_suffix("eth").or_else(|| s.strip_suffix("ether")) {
        (n, 18)
    } else {
        (s.as_str(), 0)
    };
    let number = number.trim();
    let (whole, frac) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty() && frac.is_empty() {
        bail!("{s:?} is not an amount");
    }
    if !whole.chars().chain(frac.chars()).all(|c| c.is_ascii_digit()) {
        bail!("{s:?} is not an amount (use wei, or a number with eth or gwei)");
    }
    if decimals == 0 && !frac.is_empty() {
        bail!(
            "{s:?} is in wei, which has no fractions; give a unit (`{number}eth` or `{number}gwei`)"
        );
    }
    if frac.len() > decimals {
        bail!("{s:?} has more decimals than its unit allows");
    }
    let digits = format!("{whole}{frac:0<decimals$}");
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(digits, 10).map_err(|_| anyhow!("{s:?} is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts() {
        let eth = U256::from(10u64).pow(U256::from(18));
        assert_eq!(parse_amount("1eth").unwrap(), eth);
        assert_eq!(parse_amount("1.5ETH").unwrap(), eth * U256::from(3) / U256::from(2));
        assert_eq!(parse_amount("0.000000000000000001eth").unwrap(), U256::from(1));
        assert_eq!(parse_amount("20gwei").unwrap(), U256::from(20_000_000_000u64));
        assert_eq!(parse_amount(".5gwei").unwrap(), U256::from(500_000_000u64));
        assert_eq!(parse_amount("1_000").unwrap(), U256::from(1000));
        assert_eq!(parse_amount("7wei").unwrap(), U256::from(7));
        assert_eq!(parse_amount("0x3e8").unwrap(), U256::from(1000));
        assert_eq!(parse_amount("0").unwrap(), U256::ZERO);
        for bad in ["", "eth", "1.5", "1.5wei", "-1", "1e18", "0.0000000000000000001eth", "abc"] {
            assert!(parse_amount(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn tx_json_carries_exactly_the_given_fields() {
        let from: Address = "0x00000000000000000000000000000000000000aa".parse().unwrap();
        let mut tx = TxArgs {
            chain: 10,
            to: Some("0x00000000000000000000000000000000000000bb".parse().unwrap()),
            value: U256::from(1000),
            data: Some("0xdeadbeef".into()),
            gas: None,
            nonce: Some(7),
            gas_price: None,
            max_fee: Some(30_000_000_000),
            priority_fee: None,
        };
        let v = tx.to_json(from);
        assert_eq!(v["chainId"], "0xa");
        assert_eq!(v["value"], "0x3e8");
        assert_eq!(v["nonce"], "0x7");
        assert_eq!(v["maxFeePerGas"], "0x6fc23ac00");
        assert_eq!(v["data"], "0xdeadbeef");
        assert!(v.get("gas").is_none() && v.get("gasPrice").is_none());
        tx.to = None;
        assert!(tx.to_json(from).get("to").is_none(), "contract creation has no to");
    }

    #[test]
    fn hex_and_message_inputs() {
        assert_eq!(parse_hex("deadBEEF").unwrap(), "0xdeadBEEF");
        assert!(parse_hex("0xzz").is_err());
        let m = MessageArgs { message: "0x6869".into() };
        assert_eq!(m.bytes().unwrap(), b"hi");
        let m = MessageArgs { message: "hi there".into() };
        assert_eq!(m.bytes().unwrap(), b"hi there");
        assert!(MessageArgs { message: "0xnope".into() }.bytes().is_err());
    }

    #[test]
    fn both_commands_are_well_formed_and_take_their_own_env_prefix() {
        let op = command::<opwallet::Cli>("OPWALLET");
        op.clone().debug_assert();
        let wc = command::<wcapp::Cli>("WCAPP");
        wc.clone().debug_assert();
        let env_of = |cmd: &Command, sub: &str, id: &str| {
            let sub = cmd.find_subcommand(sub).unwrap();
            sub.get_arguments()
                .find(|a| a.get_id() == id)
                .and_then(|a| a.get_env())
                .map(|e| e.to_string_lossy().into_owned())
        };
        assert_eq!(env_of(&op, "sign", "name").as_deref(), Some("OPWALLET_NAME"));
        assert_eq!(env_of(&wc, "sign", "name").as_deref(), Some("WCAPP_NAME"));
        assert_eq!(env_of(&wc, "sign", "project_id").as_deref(), Some("WCAPP_PROJECT_ID"));
        assert_eq!(env_of(&op, "sign", "message"), None, "a message never comes from the env");
    }
}
