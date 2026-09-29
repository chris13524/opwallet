//! End-to-end tests driving the real binary against a fake `op` CLI
//! (tests/fake-op/op) that persists items to a temp dir.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("opwallet-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn fake_op() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fake-op/op")
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, &[])
    }

    fn run_with(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_opwallet"));
        cmd.args(args)
            .env("OPWALLET_OP_BIN", Self::fake_op())
            .env("FAKE_OP_DIR", &self.dir)
            .env("OPWALLET_STATE_DIR", self.dir.join("state"))
            .env_remove("OPWALLET_VAULT")
            .env_remove("OPWALLET_NAME")
            .env_remove("OPWALLET_PROJECT_ID")
            .env_remove("OPWALLET_WC_PROJECT_ID");
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.output().expect("failed to run opwallet")
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
    }

    /// Stored items as raw JSON (what 1Password would hold).
    fn items(&self) -> Vec<serde_json::Value> {
        let mut out = vec![];
        for e in fs::read_dir(&self.dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "json") {
                out.push(serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap());
            }
        }
        out
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}
fn field<'a>(item: &'a serde_json::Value, label: &str) -> &'a str {
    item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .unwrap_or_else(|| panic!("no field {label}"))["value"]
        .as_str()
        .unwrap()
}

#[test]
fn create_stores_crypto_wallet_item_and_verifies_roundtrip() {
    let env = Env::new();
    let out = env.run(&["create", "--name", "Main wallet"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("Created wallet \"Main wallet\""), "{text}");
    assert!(text.contains("Address: 0x"), "{text}");
    assert!(text.contains("stored in 1Password only"), "{text}");

    let items = env.items();
    assert_eq!(items.len(), 1);
    let item = &items[0];
    // How op 2.39 reports a Crypto Wallet.
    assert_eq!(
        (&item["category"], &item["category_id"]),
        (&serde_json::json!("CUSTOM"), &serde_json::json!("115"))
    );
    assert_eq!(item["title"], "Main wallet");
    assert_eq!(item["tags"], serde_json::json!(["opwallet"]));

    let phrase = field(item, "recovery phrase");
    assert_eq!(phrase.split_whitespace().count(), 12);
    // Template field was reused (id from template) and forced concealed.
    let f = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "recovery phrase")
        .unwrap();
    assert_eq!(f["id"], "recoveryPhrase");
    assert_eq!(f["type"], "CONCEALED");

    let address = field(item, "wallet address");
    assert!(address.starts_with("0x") && address.len() == 42);
    assert_eq!(field(item, "derivation path"), "m/44'/60'/0'/0/0");

    // The address printed must be the stored one, and the seed must never
    // appear on the op command line.
    assert!(text.contains(address));
    for word in phrase.split_whitespace() {
        assert!(!env.calls().contains(&format!("\"{word}")), "seed word leaked onto argv");
    }
    // The category goes by name as a flag, and the item JSON arrives on a
    // pipe (fd 3), which op opens as its template.
    let create =
        env.calls().lines().find(|l| l.contains(r#""item", "create""#)).unwrap().to_string();
    assert!(create.contains(r#""--category", "Crypto Wallet""#), "{create}");
    #[cfg(unix)]
    assert!(create.contains(r#""--template", "/dev/fd/3""#), "{create}");

    // `address` re-derives and agrees.
    let out = env.run(&["address", "--name", "Main wallet"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out).trim(), address);
    assert!(stderr(&out).contains("verified"));
}

#[test]
fn create_with_24_words_custom_path_and_reveal() {
    let env = Env::new();
    let out = env.run(&[
        "create",
        "--name",
        "cold",
        "--words",
        "24",
        "--path",
        "m/44'/60'/0'/0/3",
        "--reveal",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let item = env.items().remove(0);
    let phrase = field(&item, "recovery phrase");
    assert_eq!(phrase.split_whitespace().count(), 24);
    assert!(stdout(&out).contains(phrase));
    assert_eq!(field(&item, "derivation path"), "m/44'/60'/0'/0/3");

    // verify honours the stored derivation path.
    let out = env.run(&["verify", "--name", "cold"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("m/44'/60'/0'/0/3"));
}

#[test]
fn create_refuses_duplicate_name() {
    let env = Env::new();
    assert!(env.run(&["create", "--name", "dup"]).status.success());
    let out = env.run(&["create", "--name", "dup"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("already exists"), "{}", stderr(&out));
    assert_eq!(env.items().len(), 1);
}

#[test]
fn create_rejects_invalid_word_count() {
    let env = Env::new();
    let out = env.run(&["create", "--name", "x", "--words", "13"]);
    assert!(!out.status.success());
    assert!(env.items().is_empty());
}

#[test]
fn verify_detects_tampered_address_and_phrase() {
    let env = Env::new();
    assert!(env.run(&["create", "--name", "w"]).status.success());
    let item = env.items().remove(0);
    let path = env.dir.join(format!("{}.json", item["id"].as_str().unwrap()));

    // Tamper with the address field.
    let mut tampered = item.clone();
    for f in tampered["fields"].as_array_mut().unwrap() {
        if f["label"] == "wallet address" {
            f["value"] = serde_json::json!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        }
    }
    fs::write(&path, tampered.to_string()).unwrap();
    for cmd in ["verify", "address", "sign"] {
        let mut args = vec![cmd, "--name", "w"];
        if cmd == "sign" {
            args.extend(["--message", "hi"]);
        }
        let out = env.run(&args);
        assert!(!out.status.success(), "{cmd} should fail");
        assert!(stderr(&out).contains("ADDRESS MISMATCH"), "{}", stderr(&out));
        assert!(stdout(&out).trim().is_empty(), "{cmd} must not print output on mismatch");
    }

    // Tamper with the phrase (bad checksum) instead.
    let mut tampered = item.clone();
    for f in tampered["fields"].as_array_mut().unwrap() {
        if f["label"] == "recovery phrase" {
            f["value"] = serde_json::json!(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            );
        }
    }
    fs::write(&path, tampered.to_string()).unwrap();
    let out = env.run(&["verify", "--name", "w"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("checksum is invalid"), "{}", stderr(&out));
}

#[test]
fn sign_produces_recoverable_signature() {
    use alloy_primitives::{Signature, hex};
    let env = Env::new();
    let out = env.run(&["create", "--name", "signer"]);
    assert!(out.status.success());
    let address: alloy_primitives::Address =
        field(&env.items()[0], "wallet address").parse().unwrap();

    let out = env.run(&["sign", "--name", "signer", "--message", "hello world"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let sig = Signature::from_raw(&hex::decode(stdout(&out).trim()).unwrap()).unwrap();
    assert_eq!(sig.recover_address_from_msg(b"hello world").unwrap(), address);

    let out = env.run(&["sign", "--name", "signer", "--message", "0xdeadbeef"]);
    assert!(out.status.success());
    let sig = Signature::from_raw(&hex::decode(stdout(&out).trim()).unwrap()).unwrap();
    assert_eq!(sig.recover_address_from_msg([0xde, 0xad, 0xbe, 0xef]).unwrap(), address);
}

#[test]
fn list_shows_wallets_without_fetching_seeds() {
    let env = Env::new();
    let out = env.run(&["list"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("No Crypto Wallet items"));

    assert!(env.run(&["create", "--name", "two", "--vault", "Work"]).status.success());
    assert!(env.run(&["create", "--name", "one"]).status.success());
    let _ = fs::remove_file(env.dir.join("calls.log"));

    let out = env.run(&["list"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("one") && text.contains("two"), "{text}");
    assert!(text.find("one").unwrap() < text.find("two").unwrap(), "sorted by name:\n{text}");
    assert!(text.contains("Private") && text.contains("Work"), "{text}");
    for item in env.items() {
        assert!(text.contains(field(&item, "wallet address")));
    }
    // Listing only ever asks op for the address field, never the full item.
    for line in env.calls().lines() {
        let call: Vec<String> = serde_json::from_str(line).unwrap();
        if call.starts_with(&["item".into(), "get".into()]) {
            assert!(call.iter().any(|a| a == "label=wallet address"), "{line}");
        }
    }

    // The listing fetched every address in a single batched `op item get -` call.
    let gets: Vec<String> = env
        .calls()
        .lines()
        .filter(|l| l.starts_with("[\"item\", \"get\""))
        .map(str::to_string)
        .collect();
    assert_eq!(gets.len(), 1, "{gets:?}");
    assert!(gets[0].contains("\"-\""), "{gets:?}");

    // Vault filtering.
    let out = env.run(&["list", "--vault", "Work"]);
    let text = stdout(&out);
    assert!(text.contains("two") && !text.contains("one"), "{text}");
}

#[test]
fn doctor_reports_signed_out() {
    let env = Env::new();
    let out = env.run(&["doctor"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("test@example.com"));

    let out = env.run_with(&["doctor"], &[("FAKE_OP_SIGNED_OUT", "1")]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("Integrate with 1Password CLI"), "{}", stderr(&out));
}

#[test]
fn missing_op_binary_gives_install_hint() {
    let env = Env::new();
    let out = env.run_with(&["doctor"], &[("OPWALLET_OP_BIN", "/nonexistent/op")]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("1Password CLI installed"), "{}", stderr(&out));
}

#[test]
fn connect_rejects_bad_uri_and_unreachable_relay() {
    let env = Env::new();
    let out = env.run(&["connect", "--name", "w", "--project-id", "p", "nope"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not a WalletConnect URI"), "{}", stderr(&out));

    assert!(env.run(&["create", "--name", "w"]).status.success());
    let uri = format!("wc:{}@2?relay-protocol=irn&symKey={}", "a".repeat(64), "b".repeat(64));
    let out = env.run(&[
        "connect",
        "--name",
        "w",
        "--project-id",
        "p",
        "--relay-url",
        "ws://127.0.0.1:1",
        &uri,
    ]);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("wallet \"w\": 0x"), "{}", stdout(&out));
    assert!(stderr(&out).contains("could not connect to relay"), "{}", stderr(&out));

    let out = env.run(&["connect", "--name", "w", "--project-id", "p", "--rpc", "bogus", &uri]);
    assert!(stderr(&out).contains("CHAIN_ID=URL"), "{}", stderr(&out));
}

#[test]
fn seed_reads_sign_the_cli_out_unless_disabled() {
    let env = Env::new();
    assert!(env.run(&["create", "--name", "w"]).status.success());
    // create reads the item back once after storing it.
    assert_eq!(env.calls().lines().filter(|l| *l == "[\"signout\"]").count(), 1);

    let out = env.run(&["verify", "--name", "w"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(env.calls().lines().filter(|l| *l == "[\"signout\"]").count(), 2);
    // The signout follows the secret read, never a listing.
    let calls = env.calls();
    let lines: Vec<&str> = calls.lines().collect();
    let last_get = lines.iter().rposition(|l| l.starts_with("[\"item\", \"get\"")).unwrap();
    assert_eq!(lines[last_get + 1], "[\"signout\"]");

    let out = env.run(&["verify", "--name", "w", "--no-relock"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(env.calls().lines().filter(|l| *l == "[\"signout\"]").count(), 2);
    assert!(
        !env.calls()
            .lines()
            .filter(|l| l.starts_with("[\"item\", \"list\""))
            .any(|l| l.contains("signout"))
    );
}

#[test]
fn project_id_comes_from_env_when_flag_is_absent() {
    let env = Env::new();
    let out = env.run(&["connect", "--name", "w", "nope"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("OPWALLET_PROJECT_ID"), "{}", stderr(&out));

    let out = env.run_with(&["connect", "--name", "w", "nope"], &[("OPWALLET_PROJECT_ID", "p")]);
    assert!(stderr(&out).contains("not a WalletConnect URI"), "{}", stderr(&out));

    // The previous variable name keeps working.
    let out = env.run_with(&["connect", "--name", "w", "nope"], &[("OPWALLET_WC_PROJECT_ID", "p")]);
    assert!(stderr(&out).contains("not a WalletConnect URI"), "{}", stderr(&out));
}

#[test]
fn bare_invocation_without_a_terminal_serves_saved_sessions_only() {
    let env = Env::new();
    // No terminal and nothing saved: nothing to do, and no project ID needed.
    let out = env.run(&[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("No saved sessions"), "{}", stdout(&out));
    assert!(env.calls().is_empty(), "1Password is not touched: {}", env.calls());

    let out = env.run(&["sessions"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("No saved sessions"), "{}", stdout(&out));

    let out = env.run(&["disconnect"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--all"), "{}", stderr(&out));
    let out = env.run(&["disconnect", "--all"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = env.run(&["disconnect", "nope"]);
    assert!(stderr(&out).contains("no saved session matches"), "{}", stderr(&out));
}
