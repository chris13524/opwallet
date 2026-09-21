//! Links that open a transaction pre-filled in Tenderly's web simulator, so
//! it can be simulated in the browser before it is approved. Nothing is sent
//! anywhere by the wallet itself and no Tenderly API key is needed.

use alloy_primitives::{Address, U256, hex};
use anyhow::{Result, bail};

const DASHBOARD: &str = "https://dashboard.tenderly.co";

/// Tenderly account and project to open simulations in. Without one the
/// link uses Tenderly's generic simulator URL, which opens in whichever
/// project the browser is signed in to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenderlyProject {
    pub account: String,
    pub project: String,
}

impl TenderlyProject {
    /// Parse `ACCOUNT/PROJECT`, as shown in Tenderly dashboard URLs, or a
    /// dashboard URL itself (`https://dashboard.tenderly.co/ACCOUNT/PROJECT/...`).
    pub fn parse(s: &str) -> Result<Self> {
        let input = s.trim();
        let (s, from_url) = match input
            .strip_prefix("https://")
            .or_else(|| input.strip_prefix("http://"))
            .and_then(|rest| rest.strip_prefix("dashboard.tenderly.co/"))
        {
            Some(path) => (path.split(['?', '#']).next().unwrap_or_default(), true),
            None => (input, false),
        };
        let mut parts = s.trim_matches('/').split('/');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(account), Some(project), rest)
                if !account.is_empty() && !project.is_empty() && (from_url || rest.is_none()) =>
            {
                Ok(Self { account: account.to_string(), project: project.to_string() })
            }
            _ => bail!(
                "--tenderly-project (or OPWALLET_TENDERLY_PROJECT) expects ACCOUNT/PROJECT, \
                 got {input:?}; both appear in your Tenderly dashboard URL \
                 (https://dashboard.tenderly.co/ACCOUNT/PROJECT/...), which can also be \
                 passed as is"
            ),
        }
    }
}

/// A transaction as it will be signed.
#[derive(Debug, Clone)]
pub struct SimulationRequest<'a> {
    pub chain_id: u64,
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub input: &'a [u8],
    pub gas_limit: u64,
    /// Legacy gas price, or the EIP-1559 max fee (what the sender must afford).
    pub gas_price: u128,
}

/// Simulator URL with every field of `req` filled in (amounts in wei).
pub fn simulator_link(req: &SimulationRequest<'_>, project: Option<&TenderlyProject>) -> String {
    let base = match project {
        Some(p) => format!("{DASHBOARD}/{}/{}/simulator/new", p.account, p.project),
        None => format!("{DASHBOARD}/simulator/new"),
    };
    let lower = |a: Address| a.to_string().to_lowercase();
    format!(
        "{base}?network={}&from={}&contractAddress={}&value={}&gas={}&gasPrice={}&rawFunctionInput={}",
        req.chain_id,
        lower(req.from),
        lower(req.to),
        req.value,
        req.gas_limit,
        req.gas_price,
        hex::encode_prefixed(req.input),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_parsing() {
        assert_eq!(
            TenderlyProject::parse(" acct/proj/ ").unwrap(),
            TenderlyProject { account: "acct".into(), project: "proj".into() }
        );
        assert!(TenderlyProject::parse("acct").is_err());
        assert!(TenderlyProject::parse("/proj").is_err());
        assert!(TenderlyProject::parse("a/b/c").is_err());
        assert_eq!(
            TenderlyProject::parse("https://dashboard.tenderly.co/acct/proj/simulator/new?x=1")
                .unwrap(),
            TenderlyProject { account: "acct".into(), project: "proj".into() }
        );
        assert!(TenderlyProject::parse("https://dashboard.tenderly.co/acct").is_err());
        let err = TenderlyProject::parse("PROJECT").unwrap_err().to_string();
        assert!(err.contains("dashboard.tenderly.co/ACCOUNT/PROJECT"), "{err}");
    }

    #[test]
    fn link_carries_every_field() {
        let req = SimulationRequest {
            chain_id: 10,
            from: "0x1111111111111111111111111111111111111111".parse().unwrap(),
            to: "0x000000000000000000000000000000000000dEaD".parse().unwrap(),
            value: U256::from(1_000_000_000_000_000_000u128),
            input: &[0xab, 0xcd],
            gas_limit: 21_000,
            gas_price: 7,
        };
        assert_eq!(
            simulator_link(&req, None),
            "https://dashboard.tenderly.co/simulator/new?network=10\
             &from=0x1111111111111111111111111111111111111111\
             &contractAddress=0x000000000000000000000000000000000000dead\
             &value=1000000000000000000&gas=21000&gasPrice=7&rawFunctionInput=0xabcd"
        );
        let project = TenderlyProject::parse("acct/proj").unwrap();
        assert!(
            simulator_link(&req, Some(&project))
                .starts_with("https://dashboard.tenderly.co/acct/proj/simulator/new?network=10&")
        );
    }
}
