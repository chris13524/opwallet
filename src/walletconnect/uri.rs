//! WalletConnect v2 pairing URI parsing.

use anyhow::{Result, bail};

/// Parsed form of a `wc:` pairing URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingUri {
    pub topic: String,
    pub version: String,
    pub relay_protocol: String,
    pub sym_key: String,
}

/// Parse a WalletConnect v2 pairing URI of the form
/// `wc:<topic>@2?relay-protocol=irn&symKey=<hex>[&expiryTimestamp=...]`.
pub fn parse_pairing_uri(uri: &str) -> Result<PairingUri> {
    let rest = uri.strip_prefix("wc:").ok_or_else(|| {
        anyhow::anyhow!("not a WalletConnect URI (expected it to start with wc:)")
    })?;
    let (head, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (topic, version) = head
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("malformed WalletConnect URI: missing @version"))?;
    if version != "2" {
        bail!("only WalletConnect v2 URIs are supported (got version {version})");
    }
    let mut relay_protocol = None;
    let mut sym_key = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "relay-protocol" => relay_protocol = Some(v.to_string()),
            "symKey" => sym_key = Some(v.to_string()),
            _ => {}
        }
    }
    Ok(PairingUri {
        topic: topic.to_string(),
        version: version.to_string(),
        relay_protocol: relay_protocol
            .ok_or_else(|| anyhow::anyhow!("URI missing relay-protocol"))?,
        sym_key: sym_key.ok_or_else(|| anyhow::anyhow!("URI missing symKey"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2_uri() {
        let uri = "wc:7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9@2?relay-protocol=irn&symKey=587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303&expiryTimestamp=1700000000";
        let p = parse_pairing_uri(uri).unwrap();
        assert_eq!(p.topic, "7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9");
        assert_eq!(p.relay_protocol, "irn");
        assert_eq!(p.sym_key.len(), 64);
    }

    #[test]
    fn rejects_bad_uris() {
        assert!(parse_pairing_uri("https://example.com").is_err());
        assert!(parse_pairing_uri("wc:abc@1?bridge=x&key=y").is_err());
        assert!(parse_pairing_uri("wc:abc@2?relay-protocol=irn").is_err());
    }
}
