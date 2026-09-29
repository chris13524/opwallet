//! End-to-end WalletConnect test: the test process plays both the relay and
//! a dapp, drives `opwallet connect` through pairing, settlement and several
//! signing requests, and verifies every signature it gets back.

use std::{
    fs,
    io::Write,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_consensus::{TxEnvelope, transaction::SignableTransaction};
use alloy_dyn_abi::TypedData;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, Signature, hex};
use opwallet::walletconnect::{
    auth::{self, AuthPayload},
    crypto::{self, KeyPair, SymKey},
    session::{error_json, parse_rpc, request_json, result_json},
};
use serde_json::{Value, json};
use tungstenite::{
    Message, WebSocket,
    handshake::server::{Request, Response},
    protocol::{CloseFrame, frame::coding::CloseCode},
};

/// The relay/dapp side of the conversation.
struct Peer {
    ws: WebSocket<TcpStream>,
}

impl Peer {
    fn read_json(&mut self) -> Value {
        loop {
            match self.ws.read().expect("relay read") {
                Message::Text(t) => return serde_json::from_str(&t).expect("json from wallet"),
                Message::Close(_) => panic!("wallet closed the socket unexpectedly"),
                _ => {}
            }
        }
    }

    fn send_json(&mut self, v: Value) {
        self.ws.send(Message::text(v.to_string())).expect("relay send");
    }

    /// Wait for a relay RPC with `method`, answer it with `result`, return its params.
    fn expect_call(&mut self, method: &str, result: Value) -> Value {
        let v = self.read_json();
        assert_eq!(v["method"], method, "unexpected relay call: {v}");
        self.send_json(json!({ "id": v["id"], "jsonrpc": "2.0", "result": result }));
        v["params"].clone()
    }

    /// Push an encrypted message to the wallet as an `irn_subscription` and wait for its ack.
    fn deliver(&mut self, topic: &str, key: &SymKey, plaintext: &str, tag: u64) {
        let message = crypto::encrypt(key, plaintext.as_bytes()).unwrap();
        let id = 77_000 + tag;
        self.send_json(json!({
            "id": id, "jsonrpc": "2.0", "method": "irn_subscription",
            "params": { "id": "sub", "data": { "topic": topic, "message": message, "publishedAt": 0, "tag": tag } }
        }));
        let ack = self.read_json();
        assert_eq!(ack["id"], id, "expected ack, got {ack}");
        assert_eq!(ack["result"], true);
    }

    /// [`Peer::deliver`] with the Verify attestation `attest` makes for the
    /// encrypted message.
    fn deliver_attested(
        &mut self,
        topic: &str,
        key: &SymKey,
        plaintext: &str,
        tag: u64,
        attest: impl Fn(&str) -> String,
    ) {
        let message = crypto::encrypt(key, plaintext.as_bytes()).unwrap();
        let id = 78_000 + tag;
        self.send_json(json!({
            "id": id, "jsonrpc": "2.0", "method": "irn_subscription",
            "params": { "id": "sub", "data": { "topic": topic, "message": message, "publishedAt": 0, "tag": tag, "attestation": attest(&message) } }
        }));
        let ack = self.read_json();
        assert_eq!(ack["id"], id, "expected ack, got {ack}");
    }

    /// Wait for the wallet to publish on `topic`, decrypt and parse it.
    fn expect_publish(&mut self, topic: &str, key: &SymKey, tag: u64) -> Value {
        let params = self.expect_call("irn_publish", json!(true));
        assert_eq!(params["topic"], topic, "published on wrong topic");
        assert_eq!(params["tag"], tag, "wrong tag: {params}");
        let plaintext = crypto::decrypt(key, params["message"].as_str().unwrap()).unwrap();
        serde_json::from_slice(&plaintext).unwrap()
    }
}

fn fake_op_env(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("opwallet-wc-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    (Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fake-op/op"), dir)
}

/// Create a wallet through the fake op and return its address.
fn create_wallet(fake_op: &Path, op_dir: &Path) -> Address {
    create_named_wallet(fake_op, op_dir, "wc")
}

fn create_named_wallet(fake_op: &Path, op_dir: &Path, name: &str) -> Address {
    let before: std::collections::HashSet<PathBuf> =
        fs::read_dir(op_dir).unwrap().filter_map(|e| e.ok()).map(|e| e.path()).collect();
    let out = Command::new(env!("CARGO_BIN_EXE_opwallet"))
        .args(["create", "--name", name])
        .env("OPWALLET_OP_BIN", fake_op)
        .env("FAKE_OP_DIR", op_dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let item: Value = fs::read_dir(op_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "json") && !before.contains(p))
        .map(|p| serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap())
        .unwrap();
    item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "wallet address")
        .unwrap()["value"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// Spawn `opwallet connect` against a local mock relay with scripted answers.
fn spawn_connect(
    fake_op: &Path,
    op_dir: &Path,
    port: u16,
    uri: &str,
    answers: &[u8],
) -> std::process::Child {
    spawn_connect_args(fake_op, op_dir, port, &["--name", "wc", uri], answers)
}

fn spawn_connect_args(
    fake_op: &Path,
    op_dir: &Path,
    port: u16,
    extra: &[&str],
    answers: &[u8],
) -> std::process::Child {
    spawn_connect_env(fake_op, op_dir, port, extra, answers, &[("OPWALLET_NO_VERIFY", "true")])
}

fn spawn_connect_env(
    fake_op: &Path,
    op_dir: &Path,
    port: u16,
    extra: &[&str],
    answers: &[u8],
    envs: &[(&str, &str)],
) -> std::process::Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_opwallet"))
        .args([
            "connect",
            "--project-id",
            "test-project",
            "--relay-url",
            &format!("ws://127.0.0.1:{port}"),
        ])
        .args(extra)
        .env_remove("OPWALLET_TENDERLY_PROJECT")
        .env("OPWALLET_OP_BIN", fake_op)
        .env("FAKE_OP_DIR", op_dir)
        .env("OPWALLET_STATE_DIR", op_dir.join("state"))
        .envs(envs.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(answers).unwrap();
    child
}

/// Accept one connection or fail the test after 30 seconds instead of hanging.
fn accept_with_timeout(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "wallet never connected to the mock relay"
                );
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("accept failed: {e}"),
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

const TYPED_DATA: &str = r#"{
  "types": {
    "EIP712Domain": [{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
    "Person": [{"name":"name","type":"string"},{"name":"wallet","type":"address"}],
    "Mail": [{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]
  },
  "primaryType": "Mail",
  "domain": {"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
  "message": {"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}
}"#;

#[test]
fn pairs_settles_and_signs_over_mock_relay() {
    let (fake_op, op_dir) = fake_op_env("propose");
    let address = create_wallet(&fake_op, &op_dir);

    // Pairing URI, as a dapp would show in its QR code.
    let pairing_key = SymKey::from_bytes(*crypto::random_array::<32>().unwrap());
    let pairing_topic = pairing_key.topic();
    let uri = format!(
        "wc:{pairing_topic}@2?relay-protocol=irn&symKey={}&expiryTimestamp={}",
        hex::encode(crypto::decrypt_key_bytes_for_test(&pairing_key)),
        now() + 300
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let relay_thread = thread::spawn(move || {
        let stream = accept_with_timeout(&listener);
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut peer = Peer { ws: tungstenite::accept(stream).unwrap() };

        // 1. Wallet subscribes to the pairing topic.
        let p = peer.expect_call("irn_subscribe", json!("sub-pairing"));
        assert_eq!(p["topic"], pairing_topic);

        // 2. Dapp proposes a session.
        let dapp = KeyPair::generate().unwrap();
        let propose_id = 1_700_000_000_000_001u64;
        let proposal = request_json(
            propose_id,
            "wc_sessionPropose",
            json!({
                "relays": [{ "protocol": "irn" }],
                "proposer": { "publicKey": dapp.public_hex(), "metadata": { "name": "MockDapp", "url": "https://mock.example", "description": "test", "icons": [] } },
                "requiredNamespaces": { "eip155": { "chains": ["eip155:1"], "methods": ["personal_sign", "eth_signTypedData_v4", "eth_sendTransaction"], "events": ["chainChanged"] } },
                "optionalNamespaces": { "eip155": { "chains": ["eip155:10"], "methods": ["eth_signTransaction", "wallet_getCapabilities"], "events": ["accountsChanged"] } },
                "requests": { "authentication": [
                    { "type": "caip122", "domain": "mock.example", "aud": "https://mock.example/login", "version": "1", "nonce": "n0nce", "iat": "2024-02-19T09:29:21.394Z", "statement": "Welcome", "chains": ["eip155:1", "solana:mainnet", "eip155:10"], "resources": ["https://mock.example/tos"] },
                    { "type": "caip122", "domain": "other.example", "aud": "https://other.example", "version": "1", "nonce": "x", "iat": "2024-02-19T09:29:21.394Z", "chains": ["eip155:1"] }
                ] },
                "expiryTimestamp": now() + 300
            }),
        );
        peer.deliver(&pairing_topic, &pairing_key, &proposal, 1100);

        // 3. Wallet subscribes to the session topic, answers the proposal, sends settle.
        let sub = peer.expect_call("irn_subscribe", json!("sub-session"));
        let session_topic = sub["topic"].as_str().unwrap().to_string();

        let response = peer.expect_publish(&pairing_topic, &pairing_key, 1101);
        assert_eq!(response["id"], propose_id);
        let responder = response["result"]["responderPublicKey"].as_str().unwrap();
        let session_key = dapp.derive_session_key(responder).unwrap();
        assert_eq!(session_key.topic(), session_topic, "session topic must be sha256(session key)");

        let settle = peer.expect_publish(&session_topic, &session_key, 1102);
        assert_eq!(settle["method"], "wc_sessionSettle");
        let ns = &settle["params"]["namespaces"]["eip155"];
        let accounts: Vec<&str> =
            ns["accounts"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(accounts, [format!("eip155:1:{address}"), format!("eip155:10:{address}")]);
        let methods: Vec<&str> =
            ns["methods"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert!(
            methods.contains(&"eth_signTransaction")
                && !methods.contains(&"wallet_getCapabilities")
        );
        assert!(settle["params"]["expiry"].as_u64().unwrap() > now() + 6 * 86_400);
        assert_eq!(settle["params"]["controller"]["publicKey"], responder);
        // Sign-in responses ride on the settle: request 1 on both EVM chains, request 2 declined.
        let cacaos =
            settle["params"]["proposalRequestsResponses"]["authentication"].as_array().unwrap();
        assert_eq!(cacaos.len(), 2, "{cacaos:?}");
        for (cacao, chain) in cacaos.iter().zip(["eip155:1", "eip155:10"]) {
            assert_eq!(cacao["h"]["t"], "caip122");
            assert_eq!(cacao["s"]["t"], "eip191");
            let iss = cacao["p"]["iss"].as_str().unwrap();
            assert_eq!(iss, format!("did:pkh:{chain}:{address}"));
            assert_eq!(cacao["p"]["domain"], "mock.example");
            assert_eq!(cacao["p"]["statement"], "Welcome");
            assert!(cacao["p"].get("chains").is_none() && cacao["p"].get("type").is_none());
            let p: AuthPayload = serde_json::from_value(cacao["p"].clone()).unwrap();
            let message = auth::format_message(&p, iss).unwrap();
            assert!(
                message
                    .starts_with("mock.example wants you to sign in with your Ethereum account:"),
                "{message}"
            );
            assert!(
                message.contains(&format!("Chain ID: {}", chain.trim_start_matches("eip155:")))
            );
            assert!(message.ends_with("Resources:\n- https://mock.example/tos"), "{message}");
            let sig = Signature::from_raw(&hex::decode(cacao["s"]["s"].as_str().unwrap()).unwrap())
                .unwrap();
            assert_eq!(sig.recover_address_from_msg(message.as_bytes()).unwrap(), address);
        }
        // Dapp acknowledges settlement.
        peer.deliver(
            &session_topic,
            &session_key,
            &result_json(settle["id"].as_u64().unwrap(), json!(true)),
            1103,
        );

        // 4. personal_sign (approved).
        let req_id = 1_700_000_000_000_002u64;
        let req = request_json(
            req_id,
            "wc_sessionRequest",
            json!({ "chainId": "eip155:1", "request": { "method": "personal_sign", "params": ["0x68656c6c6f", address] } }),
        );
        peer.deliver(&session_topic, &session_key, &req, 1108);
        let res = peer.expect_publish(&session_topic, &session_key, 1109);
        assert_eq!(res["id"], req_id);
        let sig =
            Signature::from_raw(&hex::decode(res["result"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(sig.recover_address_from_msg(b"hello").unwrap(), address);

        // 5. eth_signTypedData_v4 (approved).
        let req_id = 1_700_000_000_000_003u64;
        let req = request_json(
            req_id,
            "wc_sessionRequest",
            json!({ "chainId": "eip155:1", "request": { "method": "eth_signTypedData_v4", "params": [address, TYPED_DATA] } }),
        );
        peer.deliver(&session_topic, &session_key, &req, 1108);
        let res = peer.expect_publish(&session_topic, &session_key, 1109);
        let typed: TypedData = serde_json::from_str(TYPED_DATA).unwrap();
        let digest = typed.eip712_signing_hash().unwrap();
        let sig =
            Signature::from_raw(&hex::decode(res["result"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(sig.recover_address_from_prehash(&digest).unwrap(), address);

        // 6. eth_signTransaction with every field supplied (no RPC needed).
        let req_id = 1_700_000_000_000_004u64;
        let tx = json!({ "from": address, "to": "0x000000000000000000000000000000000000dEaD", "value": "0xde0b6b3a7640000", "data": "0x", "gas": "0x5208", "nonce": "0x7", "maxFeePerGas": "0x3b9aca00", "maxPriorityFeePerGas": "0x3b9aca00" });
        let req = request_json(
            req_id,
            "wc_sessionRequest",
            json!({ "chainId": "eip155:10", "request": { "method": "eth_signTransaction", "params": [tx] } }),
        );
        peer.deliver(&session_topic, &session_key, &req, 1108);
        let res = peer.expect_publish(&session_topic, &session_key, 1109);
        let raw = hex::decode(res["result"].as_str().unwrap()).unwrap();
        let envelope = TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
        let TxEnvelope::Eip1559(signed) = &envelope else { panic!("expected EIP-1559 tx") };
        assert_eq!(signed.tx().chain_id, 10);
        assert_eq!(signed.tx().nonce, 7);
        assert_eq!(
            signed.signature().recover_address_from_prehash(&signed.tx().signature_hash()).unwrap(),
            address
        );

        // 7. Request for a different account is rejected without prompting.
        let req_id = 1_700_000_000_000_005u64;
        let req = request_json(
            req_id,
            "wc_sessionRequest",
            json!({ "chainId": "eip155:1", "request": { "method": "personal_sign", "params": ["0x01", "0x000000000000000000000000000000000000dEaD"] } }),
        );
        peer.deliver(&session_topic, &session_key, &req, 1108);
        let res = peer.expect_publish(&session_topic, &session_key, 1109);
        assert_eq!(res["error"]["code"], -32602, "{res}");

        // 8. User declines (stdin answer "n").
        let req_id = 1_700_000_000_000_006u64;
        let req = request_json(
            req_id,
            "wc_sessionRequest",
            json!({ "chainId": "eip155:1", "request": { "method": "personal_sign", "params": ["0x02", address] } }),
        );
        peer.deliver(&session_topic, &session_key, &req, 1108);
        let res = peer.expect_publish(&session_topic, &session_key, 1109);
        assert_eq!(res["error"]["code"], 5000, "{res}");

        // 9. Ping, then the dapp ends the session; wallet must ack and exit.
        peer.deliver(
            &session_topic,
            &session_key,
            &request_json(9, "wc_sessionPing", json!({})),
            1114,
        );
        let res = peer.expect_publish(&session_topic, &session_key, 1115);
        assert_eq!(res["result"], true);

        let bye = request_json(
            10,
            "wc_sessionDelete",
            json!({ "code": 6000, "message": "User disconnected." }),
        );
        peer.deliver(&session_topic, &session_key, &bye, 1112);
        let res = peer.expect_publish(&session_topic, &session_key, 1113);
        assert_eq!(res["result"], true);
        let p = peer.expect_call("irn_unsubscribe", json!(true));
        assert_eq!(p["topic"], session_topic);
        // The pairing goes with its last session.
        let p = peer.expect_call("irn_unsubscribe", json!(true));
        assert_eq!(p["topic"], pairing_topic);
        // Sanity check the helpers we did not otherwise exercise.
        assert!(
            parse_rpc(&error_json(1, &opwallet::walletconnect::session::RpcError::user_rejected()))
                .is_some()
        );
    });

    // Answers: approve connection, sign-in 1, decline sign-in 2, message, typed data, tx; decline the last message.
    let child = spawn_connect(&fake_op, &op_dir, port, &uri, b"y\ny\nn\ny\ny\ny\nn\n");
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    relay_thread.join().expect("relay/dapp side failed");
    assert!(
        out.status.success(),
        "wallet exited with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert!(stdout.contains("Session proposal from MockDapp"), "{stdout}");
    assert!(stdout.contains("chains:      eip155:1, eip155:10"), "{stdout}");
    assert!(stdout.contains("2 sign-in request(s) follow after approval."), "{stdout}");
    assert!(stdout.contains("the dapp acknowledged the session"), "{stdout}");
    assert!(stdout.contains("Sign in to mock.example (1 of 2, from MockDapp)"), "{stdout}");
    assert!(stdout.contains("signed once per account and chain, 2 signatures"), "{stdout}");
    assert!(stdout.contains("Sign in to other.example (2 of 2, from MockDapp)"), "{stdout}");
    assert!(
        stdout
            .contains("declined sign-in to other.example; the session will be approved without it"),
        "{stdout}"
    );
    assert!(stdout.contains("signed 2 sign-in message(s)"), "{stdout}");
    assert!(
        stdout.contains(
            "WARNING:     domain \"other.example\" does not match the dapp's url host \"mock.example\""
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("Session with MockDapp (https://mock.example) on eip155:1, eip155:10"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Sign message (5 bytes) with wc") && stdout.contains("    hello"),
        "{stdout}"
    );
    assert!(stdout.contains("primary type: Mail"), "{stdout}");
    assert!(
        stdout.contains("value:     1 ETH") && stdout.contains("max cost:  1.000021 ETH"),
        "{stdout}"
    );
    let tenderly = format!(
        "https://dashboard.tenderly.co/simulator/new?network=10&from={}\
         &contractAddress=0x000000000000000000000000000000000000dead\
         &value=1000000000000000000&gas=21000&gasPrice=1000000000&rawFunctionInput=0x",
        address.to_string().to_lowercase()
    );
    assert!(stdout.contains(&tenderly), "{stdout}");
    assert!(stdout.contains("personal_sign: rejected (User rejected. (code 5000))"), "{stdout}");
    assert!(stdout.contains("MockDapp disconnected the session"), "{stdout}");
    assert!(stdout.contains("MockDapp: Sign message"), "prompts name the dapp: {stdout}");
    // The session was saved while it lasted and forgotten when the dapp ended it.
    let saved: Value =
        serde_json::from_str(&fs::read_to_string(op_dir.join("state/sessions.json")).unwrap())
            .unwrap();
    assert_eq!(saved["sessions"], json!([]), "{saved}");
    let _ = fs::remove_dir_all(&op_dir);
}

#[test]
fn connects_two_wallets_with_prompted_uri_and_selection() {
    let (fake_op, op_dir) = fake_op_env("multi");
    let alpha = create_named_wallet(&fake_op, &op_dir, "alpha");
    let beta = create_named_wallet(&fake_op, &op_dir, "beta");

    let pairing_key = SymKey::from_bytes(*crypto::random_array::<32>().unwrap());
    let pairing_topic = pairing_key.topic();
    let uri = format!(
        "wc:{pairing_topic}@2?relay-protocol=irn&symKey={}",
        hex::encode(crypto::decrypt_key_bytes_for_test(&pairing_key))
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let relay_thread = thread::spawn(move || {
        let stream = accept_with_timeout(&listener);
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut peer = Peer { ws: tungstenite::accept(stream).unwrap() };
        peer.expect_call("irn_subscribe", json!("sub-pairing"));

        let dapp = KeyPair::generate().unwrap();
        let propose_id = 1_700_000_000_000_020u64;
        let proposal = request_json(
            propose_id,
            "wc_sessionPropose",
            json!({
                "proposer": { "publicKey": dapp.public_hex(), "metadata": { "name": "MultiDapp", "url": "https://multi.example" } },
                "requiredNamespaces": { "eip155": { "chains": ["eip155:1"], "methods": ["personal_sign"], "events": [] } }
            }),
        );
        peer.deliver(&pairing_topic, &pairing_key, &proposal, 1100);
        let sub = peer.expect_call("irn_subscribe", json!("sub-session"));
        let session_topic = sub["topic"].as_str().unwrap().to_string();
        let response = peer.expect_publish(&pairing_topic, &pairing_key, 1101);
        let session_key = dapp
            .derive_session_key(response["result"]["responderPublicKey"].as_str().unwrap())
            .unwrap();
        let settle = peer.expect_publish(&session_topic, &session_key, 1102);
        let mut accounts: Vec<String> = settle["params"]["namespaces"]["eip155"]["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        accounts.sort();
        let mut expected = vec![format!("eip155:1:{alpha}"), format!("eip155:1:{beta}")];
        expected.sort();
        assert_eq!(accounts, expected);
        assert!(settle["params"].get("proposalRequestsResponses").is_none());

        // eth_accounts lists both (active first); a signature goes to the named account.
        let req = request_json(
            21,
            "wc_sessionRequest",
            json!({ "chainId": "eip155:1", "request": { "method": "eth_accounts", "params": [] } }),
        );
        peer.deliver(&session_topic, &session_key, &req, 1108);
        let accounts_res = peer.expect_publish(&session_topic, &session_key, 1109);
        assert_eq!(accounts_res["result"].as_array().unwrap().len(), 2);
        let active: Address = accounts_res["result"][0].as_str().unwrap().parse().unwrap();

        let req = request_json(
            22,
            "wc_sessionRequest",
            json!({ "chainId": "eip155:1", "request": { "method": "personal_sign", "params": ["0x6869", beta] } }),
        );
        peer.deliver(&session_topic, &session_key, &req, 1108);
        let res = peer.expect_publish(&session_topic, &session_key, 1109);
        let sig =
            Signature::from_raw(&hex::decode(res["result"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(sig.recover_address_from_msg(b"hi").unwrap(), beta);

        // A request naming no account goes to the active one.
        let req = request_json(
            23,
            "wc_sessionRequest",
            json!({ "chainId": "eip155:1", "request": { "method": "personal_sign", "params": ["0x6869"] } }),
        );
        peer.deliver(&session_topic, &session_key, &req, 1108);
        let res = peer.expect_publish(&session_topic, &session_key, 1109);
        let sig =
            Signature::from_raw(&hex::decode(res["result"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(sig.recover_address_from_msg(b"hi").unwrap(), active);

        // A foreign account is rejected without prompting.
        let req = request_json(
            24,
            "wc_sessionRequest",
            json!({ "chainId": "eip155:1", "request": { "method": "eth_signTransaction", "params": [{ "from": "0x000000000000000000000000000000000000dEaD", "to": beta, "gas": "0x5208", "nonce": "0x0", "maxFeePerGas": "0x1", "maxPriorityFeePerGas": "0x1" }] } }),
        );
        peer.deliver(&session_topic, &session_key, &req, 1108);
        let res = peer.expect_publish(&session_topic, &session_key, 1109);
        assert_eq!(res["error"]["code"], -32602, "{res}");

        let bye = request_json(25, "wc_sessionDelete", json!({ "code": 6000, "message": "bye" }));
        peer.deliver(&session_topic, &session_key, &bye, 1112);
        peer.expect_publish(&session_topic, &session_key, 1113);
        peer.expect_call("irn_unsubscribe", json!(true));
        peer.expect_call("irn_unsubscribe", json!(true));
    });

    // No --name and no URI: the URI is pasted (quotes and all), both wallets
    // are ticked, then the proposal and the signature are approved.
    let answers = format!("  \"{uri}\"  \nall\ny\ny\ny\n");
    let child = spawn_connect_args(&fake_op, &op_dir, port, &[], answers.as_bytes());
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    relay_thread.join().expect("relay/dapp side failed");
    assert!(
        out.status.success(),
        "wallet exited with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert!(stdout.contains("Paste the WalletConnect URI"), "{stdout}");
    assert!(stdout.contains("Select the wallet(s) to connect"), "{stdout}");
    assert!(stdout.contains(&format!("alpha  {alpha}")), "{stdout}");
    assert!(stdout.contains(&format!("wallet \"beta\": {beta}")), "{stdout}");
    assert!(stdout.contains("Sign message (2 bytes) with beta"), "{stdout}");
    // Startup never read a seed: the two creates and the one signature did.
    let calls = fs::read_to_string(op_dir.join("calls.log")).unwrap();
    assert_eq!(calls.lines().filter(|l| *l == "[\"signout\"]").count(), 4, "{calls}");
    let _ = fs::remove_dir_all(&op_dir);
}

/// Issuer (client identity) from the auth JWT in a relay connection URL.
fn issuer_from_request(uri: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let jwt = uri.split("auth=").nth(1).unwrap().split('&').next().unwrap();
    let payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).unwrap()).unwrap())
            .unwrap();
    payload["iss"].as_str().unwrap().to_string()
}

/// Accept a connection and record the request URI (which carries the auth JWT).
#[allow(clippy::result_large_err)]
fn accept_recording(listener: &TcpListener) -> (Peer, String) {
    let stream = accept_with_timeout(listener);
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let uri = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let seen = uri.clone();
    let ws = tungstenite::accept_hdr(stream, move |req: &Request, resp: Response| {
        *seen.lock().unwrap() = req.uri().to_string();
        Ok(resp)
    })
    .unwrap();
    let uri = uri.lock().unwrap().clone();
    (Peer { ws }, uri)
}

#[test]
fn reconnects_after_relay_close_with_the_same_identity() {
    let (fake_op, op_dir) = fake_op_env("reconnect");
    let address = create_wallet(&fake_op, &op_dir);

    let pairing_key = SymKey::from_bytes(*crypto::random_array::<32>().unwrap());
    let pairing_topic = pairing_key.topic();
    let uri = format!(
        "wc:{pairing_topic}@2?relay-protocol=irn&symKey={}",
        hex::encode(crypto::decrypt_key_bytes_for_test(&pairing_key))
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let relay_thread = thread::spawn(move || {
        let (mut peer, first_uri) = accept_recording(&listener);
        peer.expect_call("irn_subscribe", json!("sub-pairing"));

        let dapp = KeyPair::generate().unwrap();
        let proposal = request_json(
            1_700_000_000_000_030u64,
            "wc_sessionPropose",
            json!({
                "proposer": { "publicKey": dapp.public_hex(), "metadata": { "name": "FlakyDapp", "url": "https://flaky.example" } },
                "requiredNamespaces": { "eip155": { "chains": ["eip155:1"], "methods": ["personal_sign"], "events": [] } }
            }),
        );
        peer.deliver(&pairing_topic, &pairing_key, &proposal, 1100);
        let sub = peer.expect_call("irn_subscribe", json!("sub-session"));
        let session_topic = sub["topic"].as_str().unwrap().to_string();
        let response = peer.expect_publish(&pairing_topic, &pairing_key, 1101);
        let session_key = dapp
            .derive_session_key(response["result"]["responderPublicKey"].as_str().unwrap())
            .unwrap();
        let settle = peer.expect_publish(&session_topic, &session_key, 1102);
        peer.deliver(
            &session_topic,
            &session_key,
            &result_json(settle["id"].as_u64().unwrap(), json!(true)),
            1103,
        );

        // The relay drops us, as it does for load balancing.
        peer.ws
            .close(Some(CloseFrame {
                code: CloseCode::Away,
                reason: "Disconnecting for load balancing reasons".into(),
            }))
            .unwrap();
        let _ = peer.ws.flush();
        drop(peer);

        // The wallet must come back with the same client identity and
        // re-subscribe to both topics.
        let (mut peer, second_uri) = accept_recording(&listener);
        assert_eq!(issuer_from_request(&first_uri), issuer_from_request(&second_uri));
        let mut topics = vec![
            peer.expect_call("irn_subscribe", json!("re1"))["topic"].as_str().unwrap().to_string(),
            peer.expect_call("irn_subscribe", json!("re2"))["topic"].as_str().unwrap().to_string(),
        ];
        topics.sort();
        let mut expected = vec![pairing_topic.clone(), session_topic.clone()];
        expected.sort();
        assert_eq!(topics, expected);

        // Requests keep working on the new connection.
        let req = request_json(
            31,
            "wc_sessionRequest",
            json!({ "chainId": "eip155:1", "request": { "method": "personal_sign", "params": ["0x6f6b", address] } }),
        );
        peer.deliver(&session_topic, &session_key, &req, 1108);
        let res = peer.expect_publish(&session_topic, &session_key, 1109);
        let sig =
            Signature::from_raw(&hex::decode(res["result"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(sig.recover_address_from_msg(b"ok").unwrap(), address);

        let bye = request_json(32, "wc_sessionDelete", json!({ "code": 6000, "message": "bye" }));
        peer.deliver(&session_topic, &session_key, &bye, 1112);
        peer.expect_publish(&session_topic, &session_key, 1113);
        peer.expect_call("irn_unsubscribe", json!(true));
        peer.expect_call("irn_unsubscribe", json!(true));
    });

    let child = spawn_connect(&fake_op, &op_dir, port, &uri, b"y\ny\n");
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    relay_thread.join().expect("relay/dapp side failed");
    assert!(
        out.status.success(),
        "wallet exited with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert!(stderr.contains("load balancing") && stderr.contains("reconnecting (1/5)"), "{stderr}");
    assert!(!stderr.contains("reconnect failed"), "{stderr}");
    let _ = fs::remove_dir_all(&op_dir);
}

/// Run opwallet with `args` against the fake op and the test's state dir.
fn opwallet(fake_op: &Path, op_dir: &Path, args: &[&str], answers: &[u8]) -> std::process::Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_opwallet"))
        .args(args)
        .env("OPWALLET_OP_BIN", fake_op)
        .env("FAKE_OP_DIR", op_dir)
        .env("OPWALLET_STATE_DIR", op_dir.join("state"))
        .env("OPWALLET_PROJECT_ID", "test-project")
        .env("OPWALLET_NO_VERIFY", "true")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(answers).unwrap();
    child
}

/// Ctrl-C a running wallet and check it exits cleanly.
#[cfg(unix)]
fn interrupt(child: std::process::Child) -> (String, String) {
    let status = Command::new("kill").args(["-INT", &child.id().to_string()]).status().unwrap();
    assert!(status.success());
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "wallet exited with {}\n{stdout}\n{stderr}", out.status);
    (stdout, stderr)
}

#[cfg(unix)]
#[test]
fn sessions_survive_a_restart_and_can_be_disconnected() {
    use std::sync::mpsc;

    let (fake_op, op_dir) = fake_op_env("persist");
    let address = create_wallet(&fake_op, &op_dir);
    let pairing_key = SymKey::from_bytes(*crypto::random_array::<32>().unwrap());
    let pairing_topic = pairing_key.topic();
    let uri = format!(
        "wc:{pairing_topic}@2?relay-protocol=irn&symKey={}",
        hex::encode(crypto::decrypt_key_bytes_for_test(&pairing_key))
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let relay_url = format!("ws://127.0.0.1:{port}");
    // The relay thread says when each run has done its part.
    let (done, phase) = mpsc::channel::<&str>();

    let relay_thread = thread::spawn(move || {
        // Run 1: `opwallet connect` pairs and settles, then is interrupted.
        let (mut peer, first_uri) = accept_recording(&listener);
        peer.expect_call("irn_subscribe", json!("sub-pairing"));
        let dapp = KeyPair::generate().unwrap();
        let proposal = request_json(
            1_700_000_000_000_040u64,
            "wc_sessionPropose",
            json!({
                "proposer": { "publicKey": dapp.public_hex(), "metadata": { "name": "PersistDapp", "url": "https://persist.example" } },
                "requiredNamespaces": { "eip155": { "chains": ["eip155:1"], "methods": ["personal_sign"], "events": [] } }
            }),
        );
        peer.deliver(&pairing_topic, &pairing_key, &proposal, 1100);
        let session_topic = peer.expect_call("irn_subscribe", json!("sub-session"))["topic"]
            .as_str()
            .unwrap()
            .to_string();
        let response = peer.expect_publish(&pairing_topic, &pairing_key, 1101);
        let session_key = dapp
            .derive_session_key(response["result"]["responderPublicKey"].as_str().unwrap())
            .unwrap();
        let settle = peer.expect_publish(&session_topic, &session_key, 1102);
        peer.deliver(
            &session_topic,
            &session_key,
            &result_json(settle["id"].as_u64().unwrap(), json!(true)),
            1103,
        );
        done.send("settled").unwrap();
        // Quitting keeps the session: nothing is published or unsubscribed.
        loop {
            match peer.ws.read() {
                Ok(Message::Text(t)) => panic!("wallet sent {t} while quitting"),
                Ok(Message::Close(_)) => panic!("wallet closed the socket instead of exiting"),
                Ok(_) => {}
                Err(_) => break,
            }
        }
        drop(peer);

        // Run 2: bare `opwallet` resumes with the same relay identity and
        // serves the dapp without pairing again.
        let (mut peer, second_uri) = accept_recording(&listener);
        assert_eq!(issuer_from_request(&first_uri), issuer_from_request(&second_uri));
        let p = peer.expect_call("irn_subscribe", json!("re-session"));
        assert_eq!(p["topic"], session_topic);
        let p = peer.expect_call("irn_subscribe", json!("re-pairing"));
        assert_eq!(p["topic"], pairing_topic);
        let req = request_json(
            41,
            "wc_sessionRequest",
            json!({ "chainId": "eip155:1", "request": { "method": "personal_sign", "params": ["0x6261636b", address] } }),
        );
        peer.deliver(&session_topic, &session_key, &req, 1108);
        let res = peer.expect_publish(&session_topic, &session_key, 1109);
        let sig =
            Signature::from_raw(&hex::decode(res["result"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(sig.recover_address_from_msg(b"back").unwrap(), address);
        done.send("signed").unwrap();
        let _ = peer.ws.read();
        drop(peer);

        // Run 3: `opwallet disconnect` tells the dapp.
        let (mut peer, _) = accept_recording(&listener);
        let bye = peer.expect_publish(&session_topic, &session_key, 1112);
        assert_eq!(bye["method"], "wc_sessionDelete");
        assert_eq!(bye["params"]["code"], 6000);
    });

    let state = op_dir.join("state/sessions.json");
    let child = opwallet(
        &fake_op,
        &op_dir,
        &["connect", "--relay-url", &relay_url, "--name", "wc", &uri],
        b"y\n",
    );
    assert_eq!(phase.recv_timeout(Duration::from_secs(30)).unwrap(), "settled");
    let (stdout, _) = interrupt(child);
    assert!(stdout.contains("1 session(s) saved"), "{stdout}");
    let saved: Value = serde_json::from_str(&fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(saved["sessions"][0]["peer"]["name"], "PersistDapp");
    assert!(!saved.to_string().contains("recovery"), "{saved}");
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let listing = Command::new(env!("CARGO_BIN_EXE_opwallet"))
        .arg("sessions")
        .env("OPWALLET_STATE_DIR", op_dir.join("state"))
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("PersistDapp") && listing.contains(&address.to_string()), "{listing}");

    let seeds_before =
        fs::read_to_string(op_dir.join("calls.log")).unwrap().matches("signout").count();
    let child = opwallet(&fake_op, &op_dir, &["--relay-url", &relay_url], b"y\n");
    assert_eq!(phase.recv_timeout(Duration::from_secs(30)).unwrap(), "signed");
    let (stdout, _) = interrupt(child);
    assert!(stdout.contains("resumed session with PersistDapp"), "{stdout}");
    assert!(stdout.contains("PersistDapp: Sign message (4 bytes) with wc"), "{stdout}");
    // Resuming read no seed; only the one signature did.
    let seeds_after =
        fs::read_to_string(op_dir.join("calls.log")).unwrap().matches("signout").count();
    assert_eq!(seeds_after, seeds_before + 1);
    let saved: Value = serde_json::from_str(&fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(saved["sessions"][0]["requests_approved"], 1);

    let out =
        opwallet(&fake_op, &op_dir, &["disconnect", "persist", "--relay-url", &relay_url], b"")
            .wait_with_output()
            .unwrap();
    relay_thread.join().expect("relay/dapp side failed");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Disconnected PersistDapp"));
    let saved: Value = serde_json::from_str(&fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(saved["sessions"], json!([]));
    let _ = fs::remove_dir_all(&op_dir);
}

/// A WalletConnect Verify server answering `routes` (path → JSON body; 404
/// otherwise). Returns its base URL.
fn fake_verify_server(routes: Vec<(String, Value)>) -> String {
    use std::io::{BufRead, BufReader};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            while reader.read_line(&mut String::new()).unwrap() > 2 {}
            let path = line.split_whitespace().nth(1).unwrap_or("");
            let (status, body) = match routes.iter().find(|(p, _)| p == path) {
                Some((_, body)) => (200, body.to_string()),
                None => (404, "{}".to_string()),
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    base
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

#[test]
fn shows_walletconnect_verify_results_in_prompts() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::Signer};

    let (fake_op, op_dir) = fake_op_env("verify");
    let address = create_wallet(&fake_op, &op_dir);
    let pairing_key = SymKey::from_bytes(*crypto::random_array::<32>().unwrap());
    let pairing_topic = pairing_key.topic();
    let uri = format!(
        "wc:{pairing_topic}@2?relay-protocol=irn&symKey={}",
        hex::encode(crypto::decrypt_key_bytes_for_test(&pairing_key))
    );

    // The Verify server's key, and the v1 record of a request sent from a
    // known scam page rather than the dapp.
    let verify_key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let point = verify_key.verifying_key().to_encoded_point(false);
    let dapp = KeyPair::generate().unwrap();
    let sign_req = request_json(
        1_700_000_000_000_010,
        "wc_sessionRequest",
        json!({ "chainId": "eip155:1", "request": { "method": "personal_sign", "params": ["0x68656c6c6f", address] } }),
    );
    let verify_url = fake_verify_server(vec![
        (
            "/v3/public-key".into(),
            json!({ "publicKey": { "crv": "P-256", "ext": true, "key_ops": ["verify"], "kty": "EC",
                "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()) },
                "expiresAt": now() + 3600 }),
        ),
        (
            format!("/attestation/{}?v2Supported=true", sha256_hex(sign_req.as_bytes())),
            json!({ "origin": "https://evil.example", "isScam": true }),
        ),
    ]);
    // A v3 attestation JWT for one encrypted message.
    let attest = move |message: &str| {
        let claims = json!({ "exp": now() + 60, "id": sha256_hex(message.as_bytes()),
            "origin": "https://mock.example", "isScam": false, "isVerified": true });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let sig: P256Signature = verify_key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    };

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let relay_thread = thread::spawn(move || {
        let stream = accept_with_timeout(&listener);
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut peer = Peer { ws: tungstenite::accept(stream).unwrap() };
        peer.expect_call("irn_subscribe", json!("sub-pairing"));

        // The proposal carries a valid v3 attestation for mock.example.
        let proposal = request_json(
            1_700_000_000_000_001,
            "wc_sessionPropose",
            json!({
                "relays": [{ "protocol": "irn" }],
                "proposer": { "publicKey": dapp.public_hex(), "metadata": { "name": "MockDapp", "url": "https://mock.example/app", "description": "test", "icons": [] } },
                "requiredNamespaces": { "eip155": { "chains": ["eip155:1"], "methods": ["personal_sign"], "events": [] } }
            }),
        );
        peer.deliver_attested(&pairing_topic, &pairing_key, &proposal, 1100, attest);
        let sub = peer.expect_call("irn_subscribe", json!("sub-session"));
        let session_topic = sub["topic"].as_str().unwrap().to_string();
        let response = peer.expect_publish(&pairing_topic, &pairing_key, 1101);
        let responder = response["result"]["responderPublicKey"].as_str().unwrap();
        let session_key = dapp.derive_session_key(responder).unwrap();
        peer.expect_publish(&session_topic, &session_key, 1102);

        // The request has no attestation; the v1/v2 lookup flags it.
        peer.deliver(&session_topic, &session_key, &sign_req, 1108);
        let res = peer.expect_publish(&session_topic, &session_key, 1109);
        assert_eq!(res["error"]["code"], 5000, "{res}");

        let bye = request_json(10, "wc_sessionDelete", json!({ "code": 6000, "message": "bye" }));
        peer.deliver(&session_topic, &session_key, &bye, 1112);
        peer.expect_publish(&session_topic, &session_key, 1113);
        peer.expect_call("irn_unsubscribe", json!(true));
        peer.expect_call("irn_unsubscribe", json!(true));
    });

    // Approve the verified proposal, decline the flagged request.
    let child = spawn_connect_env(
        &fake_op,
        &op_dir,
        port,
        &["--name", "wc", &uri],
        b"y\nn\n",
        &[("OPWALLET_NO_VERIFY", "false"), ("OPWALLET_VERIFY_URL", &verify_url)],
    );
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    relay_thread.join().expect("relay/dapp side failed");
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout
            .contains("origin:      https://mock.example (WalletConnect Verify agrees; not proof)"),
        "{stdout}"
    );
    assert!(stdout.contains("SCAM WARNING: MockDapp: Sign message"), "{stdout}");
    assert!(
        stdout.contains(
            "DANGER:      WalletConnect Verify flags https://evil.example as a known scam"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "WARNING:     origin mismatch: the dapp claims \"https://mock.example/app\" but \
             WalletConnect Verify recorded \"https://evil.example\""
        ),
        "{stdout}"
    );
    let _ = fs::remove_dir_all(&op_dir);
}

#[test]
fn alarming_origin_needs_a_second_yes_to_connect() {
    let (fake_op, op_dir) = fake_op_env("reconfirm");
    create_wallet(&fake_op, &op_dir);
    let pairing_key = SymKey::from_bytes(*crypto::random_array::<32>().unwrap());
    let pairing_topic = pairing_key.topic();
    let uri = format!(
        "wc:{pairing_topic}@2?relay-protocol=irn&symKey={}",
        hex::encode(crypto::decrypt_key_bytes_for_test(&pairing_key))
    );
    let dapp = KeyPair::generate().unwrap();
    let propose = |id: u64| {
        request_json(
            id,
            "wc_sessionPropose",
            json!({
                "relays": [{ "protocol": "irn" }],
                "proposer": { "publicKey": dapp.public_hex(), "metadata": { "name": "MockDapp", "url": "https://mock.example", "description": "test", "icons": [] } },
                "requiredNamespaces": { "eip155": { "chains": ["eip155:1"], "methods": ["personal_sign"], "events": [] } }
            }),
        )
    };
    // The first proposal came from a known scam page, the second from a
    // different site than the dapp claims.
    let (scam, mismatch) = (propose(1_700_000_000_000_001), propose(1_700_000_000_000_002));
    let lookup = |p: &str| format!("/attestation/{}?v2Supported=true", sha256_hex(p.as_bytes()));
    let verify_url = fake_verify_server(vec![
        (lookup(&scam), json!({ "origin": "https://evil.example", "isScam": true })),
        (lookup(&mismatch), json!({ "origin": "https://other.example", "isScam": false })),
    ]);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let relay_thread = thread::spawn(move || {
        let stream = accept_with_timeout(&listener);
        stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut peer = Peer { ws: tungstenite::accept(stream).unwrap() };
        peer.expect_call("irn_subscribe", json!("sub-pairing"));

        // Yes, then no at the second prompt: rejected.
        peer.deliver(&pairing_topic, &pairing_key, &scam, 1100);
        let res = peer.expect_publish(&pairing_topic, &pairing_key, 1101);
        assert_eq!(res["error"]["code"], 5000, "{res}");

        // Yes twice: connected.
        peer.deliver(&pairing_topic, &pairing_key, &mismatch, 1100);
        let sub = peer.expect_call("irn_subscribe", json!("sub-session"));
        let session_topic = sub["topic"].as_str().unwrap().to_string();
        let response = peer.expect_publish(&pairing_topic, &pairing_key, 1101);
        let responder = response["result"]["responderPublicKey"].as_str().unwrap();
        let session_key = dapp.derive_session_key(responder).unwrap();
        peer.expect_publish(&session_topic, &session_key, 1102);

        let bye = request_json(10, "wc_sessionDelete", json!({ "code": 6000, "message": "bye" }));
        peer.deliver(&session_topic, &session_key, &bye, 1112);
        peer.expect_publish(&session_topic, &session_key, 1113);
        peer.expect_call("irn_unsubscribe", json!(true));
        peer.expect_call("irn_unsubscribe", json!(true));
    });

    let child = spawn_connect_env(
        &fake_op,
        &op_dir,
        port,
        &["--name", "wc", &uri],
        b"y\nn\ny\ny\n",
        &[("OPWALLET_NO_VERIFY", "false"), ("OPWALLET_VERIFY_URL", &verify_url)],
    );
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    relay_thread.join().expect("relay/dapp side failed");
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("SCAM WARNING: Really connect to MockDapp?"), "{stdout}");
    assert!(stdout.contains("known scam. Connecting lets it ask"), "{stdout}");
    assert!(stdout.contains("  Really connect to MockDapp?"), "{stdout}");
    assert!(stdout.contains("recorded a different site than this dapp claims"), "{stdout}");
    assert!(stdout.contains("Session with MockDapp (https://mock.example)"), "{stdout}");
    let _ = fs::remove_dir_all(&op_dir);
}
