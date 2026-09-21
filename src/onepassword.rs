//! 1Password integration.
//!
//! Talks to the locally running 1Password desktop app through the official
//! `op` CLI (with "Integrate with 1Password CLI" enabled in the app, `op`
//! unlocks via the app / biometrics and needs no long-lived tokens). The same
//! code also works unattended with `OP_SERVICE_ACCOUNT_TOKEN` set, since the
//! CLI handles that transparently.
//!
//! Secret handling:
//! * item JSON is passed to `op` over stdin, never on the command line, so it
//!   is not visible in process listings or shell history;
//! * everything `op` prints is read straight into a locked [`SecretBuf`];
//! * the seed phrase is deserialized by *borrowing* from that buffer
//!   (no heap copy) and then copied into its own locked buffer;
//! * listings only ever request the public `wallet address` field.
//!
//! Wallets are stored as native **Crypto Wallet** items using the built-in
//! `recovery phrase` (1Password's label for the seed phrase) and
//! `wallet address` fields, so they render properly in the 1Password apps.

use std::{
    borrow::Cow,
    ffi::OsStr,
    io::{Read, Write},
    process::{Command, Stdio},
    sync::Mutex,
    thread,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Map, Value, json};
use zeroize::Zeroize;

use crate::secret::SecretBuf;

/// Item category used for wallets.
pub const CATEGORY: &str = "Crypto Wallet";
/// Label of the built-in field holding the BIP-39 seed phrase (1Password
/// names it "recovery phrase", so the label must stay as is).
pub const FIELD_SEED_PHRASE: &str = "recovery phrase";
/// Label of the built-in field holding the public address.
pub const FIELD_WALLET_ADDRESS: &str = "wallet address";
/// Custom field we add to remember which path the address was derived at.
pub const FIELD_DERIVATION_PATH: &str = "derivation path";
/// Tag applied to every item this tool creates.
pub const TAG: &str = "opwallet";

/// Initial size of the locked buffer `op` output is read into.
const OUTPUT_CAPACITY: usize = 64 * 1024;

/// Parallel `op` invocations used when the batched address lookup is unavailable.
const LOOKUP_THREADS: usize = 8;

/// What we need to (re)create a wallet. Deliberately has no `Debug` impl.
pub struct NewWallet<'a> {
    pub title: &'a str,
    pub vault: Option<&'a str>,
    pub seed_phrase: &'a str,
    pub address: &'a str,
    pub derivation_path: &'a str,
}

/// A wallet item as stored in 1Password.
pub struct StoredWallet {
    pub id: String,
    pub title: String,
    pub vault: Option<String>,
    pub seed_phrase: SecretBuf,
    pub address: Option<String>,
    pub derivation_path: Option<String>,
}

/// Non-secret summary used by `list`.
#[derive(Debug, Clone)]
pub struct WalletSummary {
    pub id: String,
    pub title: String,
    pub vault: Option<String>,
    pub address: Option<String>,
}

/// Compare wallet names the way people read them: case-insensitive, with
/// embedded numbers compared numerically ("Vault 2" before "Vault 10").
pub fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn chunks(s: &str) -> Vec<(bool, String)> {
        let mut out: Vec<(bool, String)> = Vec::new();
        for c in s.chars() {
            let digit = c.is_ascii_digit();
            match out.last_mut() {
                Some((d, text)) if *d == digit => text.push(c),
                _ => out.push((digit, c.to_string())),
            }
        }
        out
    }
    let (ca, cb) = (chunks(a), chunks(b));
    for (x, y) in ca.iter().zip(cb.iter()) {
        let ord = match (x.0, y.0) {
            (true, true) => {
                let (nx, ny) = (x.1.trim_start_matches('0'), y.1.trim_start_matches('0'));
                nx.len().cmp(&ny.len()).then_with(|| nx.cmp(ny))
            }
            _ => x.1.to_lowercase().cmp(&y.1.to_lowercase()),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    ca.len().cmp(&cb.len()).then_with(|| a.cmp(b))
}

/// Sort wallets by title using [`natural_cmp`].
pub fn sort_wallets(wallets: &mut [WalletSummary]) {
    wallets.sort_by(|a, b| natural_cmp(&a.title, &b.title));
}

/// Reference returned after creating an item.
#[derive(Debug, Clone)]
pub struct ItemRef {
    pub id: String,
    pub title: String,
    pub vault: Option<String>,
}

/// Abstraction over the secret backend so the wallet logic never depends on
/// `op` directly (and so a different 1Password transport can be added later).
pub trait SecretStore {
    /// Human-readable description of who we are signed in as.
    fn whoami(&self) -> Result<String>;
    /// True if an item with this title exists (in the vault, if given).
    fn wallet_exists(&self, title: &str, vault: Option<&str>) -> Result<bool>;
    fn create_wallet(&self, wallet: &NewWallet<'_>) -> Result<ItemRef>;
    /// Fetch the whole item including the seed phrase.
    fn get_wallet(&self, title: &str, vault: Option<&str>) -> Result<StoredWallet>;
    /// Fetch only the public address field of an item (no secret leaves 1Password).
    fn get_address(&self, title: &str, vault: Option<&str>) -> Result<Option<String>>;
    fn list_wallets(&self, vault: Option<&str>) -> Result<Vec<WalletSummary>>;
}

// ---------------------------------------------------------------------------
// JSON shapes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct VaultRef {
    name: Option<String>,
}

#[derive(Deserialize)]
struct ItemHeader {
    id: String,
    title: String,
    vault: Option<VaultRef>,
}

/// A string that borrows from the input when serde_json can (no escapes),
/// and is zeroized on drop when it had to be copied.
struct SecretStr<'a>(Cow<'a, str>);

impl Drop for SecretStr<'_> {
    fn drop(&mut self) {
        if let Cow::Owned(s) = &mut self.0 {
            s.zeroize();
        }
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for SecretStr<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> de::Visitor<'de> for V {
            type Value = SecretStr<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(SecretStr(Cow::Borrowed(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(SecretStr(Cow::Owned(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(SecretStr(Cow::Owned(v)))
            }
        }
        d.deserialize_str(V)
    }
}

#[derive(Deserialize)]
struct FieldRead<'a> {
    id: Option<String>,
    label: Option<String>,
    #[serde(borrow, default)]
    value: Option<SecretStr<'a>>,
}

#[derive(Deserialize)]
struct ItemRead<'a> {
    id: String,
    title: String,
    vault: Option<VaultRef>,
    #[serde(borrow, default)]
    fields: Vec<FieldRead<'a>>,
}

#[derive(Serialize)]
struct FieldWrite<'a> {
    /// Everything from the template field except `value` (id, type, label, section...).
    #[serde(flatten)]
    meta: Map<String, Value>,
    value: &'a str,
}

#[derive(Serialize)]
struct ItemWrite<'a> {
    title: &'a str,
    category: &'static str,
    tags: [&'static str; 1],
    #[serde(skip_serializing_if = "Option::is_none")]
    sections: Option<Value>,
    fields: Vec<FieldWrite<'a>>,
}

/// Case/whitespace-insensitive field-label comparison, so `recovery phrase`,
/// `Recovery Phrase` and `recoveryPhrase` all match.
fn normalize_label(label: &str) -> String {
    label.chars().filter(|c| c.is_alphanumeric()).flat_map(char::to_lowercase).collect()
}

fn meta_matches(meta: &Map<String, Value>, wanted: &str) -> bool {
    let wanted = normalize_label(wanted);
    ["label", "id"].iter().any(|k| {
        meta.get(*k).and_then(Value::as_str).map(normalize_label).as_deref() == Some(&wanted)
    })
}

fn field_matches(field: &FieldRead<'_>, wanted: &str) -> bool {
    let wanted = normalize_label(wanted);
    [&field.label, &field.id]
        .iter()
        .any(|v| v.as_deref().map(normalize_label).as_deref() == Some(&wanted))
}

/// Build the JSON body for `op item create` from a template's fields plus our
/// values. Template fields keep their metadata (so the built-in Crypto Wallet
/// fields are reused); missing ones are appended.
fn build_item<'a>(template: &Value, w: &NewWallet<'a>) -> ItemWrite<'a> {
    let mut fields: Vec<FieldWrite<'a>> = template
        .get("fields")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_object)
                .map(|obj| {
                    let mut meta = obj.clone();
                    meta.remove("value");
                    FieldWrite { meta, value: "" }
                })
                .collect()
        })
        .unwrap_or_default();

    let wanted: [(&str, &'a str, bool); 3] = [
        (FIELD_SEED_PHRASE, w.seed_phrase, true),
        (FIELD_WALLET_ADDRESS, w.address, false),
        (FIELD_DERIVATION_PATH, w.derivation_path, false),
    ];
    for (label, value, concealed) in wanted {
        if let Some(f) = fields.iter_mut().find(|f| meta_matches(&f.meta, label)) {
            f.value = value;
            if concealed {
                f.meta.insert("type".into(), json!("CONCEALED"));
            }
        } else {
            let mut meta = Map::new();
            meta.insert("id".into(), json!(normalize_label(label)));
            meta.insert("type".into(), json!(if concealed { "CONCEALED" } else { "STRING" }));
            meta.insert("label".into(), json!(label));
            fields.push(FieldWrite { meta, value });
        }
    }

    ItemWrite {
        title: w.title,
        category: "CRYPTO_WALLET",
        tags: [TAG],
        sections: template.get("sections").cloned(),
        fields,
    }
}

// ---------------------------------------------------------------------------
// op CLI transport
// ---------------------------------------------------------------------------

/// [`SecretStore`] backed by the `op` command line tool.
pub struct OpCli {
    binary: String,
    /// Run `op signout` after every secret read so the next read needs a
    /// fresh unlock (biometric prompt) from the desktop app.
    relock: bool,
    /// Serialises secret reads so a relock cannot race another read.
    secret_lock: Mutex<()>,
}

impl OpCli {
    pub fn new(binary: impl Into<String>) -> Self {
        Self { binary: binary.into(), relock: false, secret_lock: Mutex::new(()) }
    }

    /// Sign the CLI out after each secret read (see [`OpCli::relock`]).
    pub fn with_relock(mut self, relock: bool) -> Self {
        self.relock = relock;
        self
    }

    /// Whether reads are followed by `op signout`.
    pub fn relock(&self) -> bool {
        self.relock
    }

    /// Best-effort `op signout`; errors are reported, never fatal.
    fn signout(&self) {
        if let Err(e) = self.run(["signout"], None) {
            eprintln!("warning: could not sign the 1Password CLI out after use: {e:#}");
        }
    }

    /// Non-secret headers of every Crypto Wallet item.
    fn list_headers(&self, vault: Option<&str>) -> Result<Vec<ItemHeader>> {
        let mut args = vec![
            "item".to_string(),
            "list".to_string(),
            "--categories".to_string(),
            CATEGORY.to_string(),
        ];
        args.extend(vault_args(vault));
        args.extend(["--format".into(), "json".into()]);
        let items = self.run_value(&args, None)?;
        serde_json::from_value(items).context("unexpected item list JSON from op")
    }

    /// One `op item get <ref> --fields label=<label>` returning the field value.
    fn field_of(&self, item_ref: &str, label: &str) -> Result<Option<String>> {
        let args =
            ["item", "get", item_ref, "--fields", &format!("label={label}"), "--format", "json"];
        let v = self.run_value(args, None)?;
        Ok(first_field_value(v))
    }

    /// Addresses for many items in one `op` call (`op item get -` reads a JSON
    /// list from stdin). Returns `None` if the output cannot be matched to
    /// the items unambiguously, in which case the caller falls back.
    fn batch_addresses(&self, items: &[ItemHeader]) -> Option<Vec<Option<String>>> {
        let ids: Vec<Value> = items.iter().map(|i| json!({ "id": i.id })).collect();
        let stdin = serde_json::to_vec(&ids).ok()?;
        let args = [
            "item",
            "get",
            "-",
            "--fields",
            &format!("label={FIELD_WALLET_ADDRESS}"),
            "--format",
            "json",
        ];
        let out = self.run(args, Some(&stdin)).ok()?;
        // op prints one JSON value per item (an object, or an array of field
        // objects); a single wrapping array is tolerated as well.
        let mut values: Vec<Value> = serde_json::Deserializer::from_slice(out.as_bytes())
            .into_iter::<Value>()
            .collect::<Result<_, _>>()
            .ok()?;
        if values.len() == 1
            && items.len() != 1
            && let Value::Array(inner) = &values[0]
        {
            values = inner.clone();
        }
        if values.len() != items.len() {
            return None;
        }
        let mut out = Vec::with_capacity(items.len());
        for (item, value) in items.iter().zip(values) {
            // Cross-check the secret reference (op://vault/item/field) when present.
            let reference = match &value {
                Value::Array(a) => a.first().and_then(|f| f.get("reference")),
                other => other.get("reference"),
            }
            .and_then(Value::as_str);
            if let Some(r) = reference
                && !r.contains(&item.id)
                && !r.contains(&item.title)
            {
                return None;
            }
            out.push(first_field_value(value));
        }
        Some(out)
    }

    /// Run `op` with `args`, optionally feeding `stdin`, returning stdout in
    /// locked memory.
    fn run<I, S>(&self, args: I, stdin: Option<&[u8]>) -> Result<SecretBuf>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = Command::new(&self.binary);
        cmd.args(args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "could not run {:?}. Is the 1Password CLI installed and on PATH? \
                 See https://developer.1password.com/docs/cli/get-started/",
                self.binary
            )
        })?;

        // Drain stderr concurrently so a chatty op can never deadlock us.
        let mut stderr_pipe = child.stderr.take().expect("stderr was piped");
        let stderr_thread = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut buf);
            buf
        });

        if let Some(data) = stdin {
            let mut pipe = child.stdin.take().expect("stdin was piped");
            pipe.write_all(data).context("failed to write to op stdin")?;
            drop(pipe);
        }

        let mut out = SecretBuf::with_capacity(OUTPUT_CAPACITY)?;
        let mut stdout_pipe = child.stdout.take().expect("stdout was piped");
        loop {
            if out.spare_mut().is_empty() {
                out.reserve(out.capacity())?;
            }
            let n = stdout_pipe.read(out.spare_mut()).context("failed to read op output")?;
            if n == 0 {
                break;
            }
            out.advance(n);
        }
        drop(stdout_pipe);

        let status = child.wait().context("failed waiting for op")?;
        let stderr = stderr_thread.join().unwrap_or_default();
        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr);
            bail!("op exited with {status}: {}", stderr.trim());
        }
        Ok(out)
    }

    fn run_value<I, S>(&self, args: I, stdin: Option<&[u8]>) -> Result<Value>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let out = self.run(args, stdin)?;
        serde_json::from_slice(out.as_bytes()).context("op returned invalid JSON")
    }

    /// Fetch the built-in Crypto Wallet template, falling back to a minimal
    /// hand-rolled one if this `op` version cannot provide it.
    fn wallet_template(&self) -> Value {
        match self.run_value(["item", "template", "get", CATEGORY, "--format", "json"], None) {
            Ok(v) if v.get("fields").is_some_and(Value::is_array) => v,
            _ => json!({ "fields": [] }),
        }
    }
}

fn vault_args(vault: Option<&str>) -> Vec<String> {
    vault.map(|v| vec!["--vault".to_string(), v.to_string()]).unwrap_or_default()
}

/// Value of the first field object in an `op item get --fields` JSON result.
fn first_field_value(v: Value) -> Option<String> {
    let field = match v {
        Value::Array(a) => a.into_iter().next()?,
        other => other,
    };
    field
        .get("value")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

impl SecretStore for OpCli {
    fn whoami(&self) -> Result<String> {
        let v = self.run_value(["whoami", "--format", "json"], None).map_err(|e| {
            anyhow!(
                "{e}\n\nNot signed in. Enable Settings > Developer > \"Integrate with 1Password \
                 CLI\" in the desktop app, or run `op signin`."
            )
        })?;
        let email = v.get("email").and_then(Value::as_str).unwrap_or("?");
        let url = v.get("url").and_then(Value::as_str).unwrap_or("?");
        let acct = v
            .get("account_uuid")
            .and_then(Value::as_str)
            .map(|s| format!(" ({s})"))
            .unwrap_or_default();
        Ok(format!("{email} @ {url}{acct}"))
    }

    fn wallet_exists(&self, title: &str, vault: Option<&str>) -> Result<bool> {
        Ok(self.list_headers(vault)?.iter().any(|w| w.title == title))
    }

    fn create_wallet(&self, w: &NewWallet<'_>) -> Result<ItemRef> {
        let template = self.wallet_template();
        let item = build_item(&template, w);

        // Serialize straight into locked memory; the capacity is generous so
        // the buffer does not need to grow.
        let mut body = SecretBuf::with_capacity(OUTPUT_CAPACITY)?;
        serde_json::to_writer(&mut body, &item).context("failed to encode item JSON")?;
        drop(item);

        // `-` tells op to read the item template from stdin.
        let mut args = vec!["item".to_string(), "create".to_string(), "-".to_string()];
        args.extend(vault_args(w.vault));
        args.extend(["--format".into(), "json".into()]);
        let created = self.run_value(&args, Some(body.as_bytes()))?;
        drop(body);

        let header: ItemHeader =
            serde_json::from_value(created).context("unexpected item JSON from op")?;
        Ok(ItemRef { id: header.id, title: header.title, vault: header.vault.and_then(|v| v.name) })
    }

    fn get_wallet(&self, title: &str, vault: Option<&str>) -> Result<StoredWallet> {
        let _guard = self.secret_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut args = vec!["item".to_string(), "get".to_string(), title.to_string()];
        args.extend(vault_args(vault));
        args.extend(["--format".into(), "json".into(), "--reveal".into()]);
        let raw = self.run(&args, None);
        if self.relock {
            self.signout();
        }
        let raw = raw?;

        let item: ItemRead<'_> =
            serde_json::from_slice(raw.as_bytes()).context("unexpected item JSON from op")?;

        let phrase_field = item
            .fields
            .iter()
            .find(|f| field_matches(f, FIELD_SEED_PHRASE))
            .and_then(|f| f.value.as_ref())
            .ok_or_else(|| anyhow!("item {title:?} has no {FIELD_SEED_PHRASE:?} field"))?;
        let phrase = phrase_field.0.trim();
        if phrase.is_empty() {
            bail!("item {title:?} has an empty {FIELD_SEED_PHRASE:?} field");
        }
        let seed_phrase = SecretBuf::from_slice(phrase.as_bytes())?;

        let plain = |label: &str| {
            item.fields
                .iter()
                .find(|f| field_matches(f, label))
                .and_then(|f| f.value.as_ref())
                .map(|v| v.0.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let stored = StoredWallet {
            id: item.id.clone(),
            title: item.title.clone(),
            vault: item.vault.as_ref().and_then(|v| v.name.clone()),
            seed_phrase,
            address: plain(FIELD_WALLET_ADDRESS),
            derivation_path: plain(FIELD_DERIVATION_PATH),
        };
        drop(item);
        drop(raw);
        Ok(stored)
    }

    fn get_address(&self, title: &str, vault: Option<&str>) -> Result<Option<String>> {
        let mut args = vec!["item".to_string(), "get".to_string(), title.to_string()];
        args.extend(vault_args(vault));
        args.extend([
            "--fields".into(),
            format!("label={FIELD_WALLET_ADDRESS}"),
            "--format".into(),
            "json".into(),
        ]);
        Ok(first_field_value(self.run_value(&args, None)?))
    }

    fn list_wallets(&self, vault: Option<&str>) -> Result<Vec<WalletSummary>> {
        let items = self.list_headers(vault)?;
        if items.is_empty() {
            return Ok(Vec::new());
        }
        // Only the public address field is ever requested, so seeds never
        // leave 1Password just to render a listing. One batched call first;
        // parallel per-item lookups if op's output cannot be matched safely.
        let addresses = match self.batch_addresses(&items) {
            Some(a) => a,
            None => thread::scope(|scope| {
                let chunks: Vec<&[ItemHeader]> =
                    items.chunks(items.len().div_ceil(LOOKUP_THREADS)).collect();
                let handles: Vec<_> = chunks
                    .into_iter()
                    .map(|chunk| {
                        scope.spawn(move || {
                            chunk
                                .iter()
                                .map(|h| self.field_of(&h.id, FIELD_WALLET_ADDRESS).ok().flatten())
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
            }),
        };
        Ok(items
            .into_iter()
            .zip(addresses)
            .map(|(header, address)| WalletSummary {
                id: header.id,
                title: header.title,
                vault: header.vault.and_then(|v| v.name),
                address,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn natural_ordering() {
        let mut names = vec!["Vault 10", "vault 2", "Savings", "Vault 1", "Alpha", "beta"];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(names, ["Alpha", "beta", "Savings", "Vault 1", "vault 2", "Vault 10"]);
        assert_eq!(natural_cmp("a", "a"), std::cmp::Ordering::Equal);
        assert_eq!(
            natural_cmp("a07", "a7"),
            std::cmp::Ordering::Less,
            "ties break on the raw string"
        );
    }

    #[test]
    fn label_normalization() {
        assert_eq!(normalize_label("Recovery Phrase"), "recoveryphrase");
        assert_eq!(normalize_label("recoveryPhrase"), "recoveryphrase");
        let mut m = Map::new();
        m.insert("id".into(), json!("walletAddress"));
        m.insert("label".into(), json!("wallet address"));
        assert!(meta_matches(&m, "Wallet Address"));
        assert!(!meta_matches(&m, "password"));
    }

    #[test]
    fn build_item_reuses_template_fields_and_appends_missing() {
        let template = json!({
            "sections": [{"id": "wallet"}],
            "fields": [
                {"id": "recoveryPhrase", "type": "STRING", "label": "recovery phrase", "value": "", "section": {"id": "wallet"}},
                {"id": "password", "type": "CONCEALED", "label": "password", "value": ""}
            ]
        });
        let w = NewWallet {
            title: "t",
            vault: None,
            seed_phrase: "a b c",
            address: "0xabc",
            derivation_path: "m/0",
        };
        let item = serde_json::to_value(build_item(&template, &w)).unwrap();
        assert_eq!(item["title"], "t");
        assert_eq!(item["category"], "CRYPTO_WALLET");
        assert_eq!(item["tags"], json!(["opwallet"]));
        assert_eq!(item["sections"], json!([{"id": "wallet"}]));
        let fields = item["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0]["id"], "recoveryPhrase");
        assert_eq!(fields[0]["type"], "CONCEALED");
        assert_eq!(fields[0]["value"], "a b c");
        assert_eq!(fields[0]["section"], json!({"id": "wallet"}));
        assert_eq!(fields[1]["value"], "");
        assert_eq!(fields[2]["label"], FIELD_WALLET_ADDRESS);
        assert_eq!(fields[2]["type"], "STRING");
        assert_eq!(fields[3]["label"], FIELD_DERIVATION_PATH);
    }

    #[test]
    fn secret_str_borrows_when_possible() {
        let raw = br#"{"id":"1","title":"t","fields":[{"label":"recovery phrase","value":"a b"},{"label":"x","value":"q\"uote"}]}"#;
        let item: ItemRead<'_> = serde_json::from_slice(raw).unwrap();
        assert!(matches!(item.fields[0].value.as_ref().unwrap().0, Cow::Borrowed("a b")));
        assert!(matches!(item.fields[1].value.as_ref().unwrap().0, Cow::Owned(_)));
    }
}
