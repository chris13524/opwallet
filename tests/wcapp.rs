//! `wcapp` against `opwallet`, end to end: both real binaries, talking
//! through a small in-process relay that routes messages between clients
//! and keeps a mailbox for whoever subscribes later (as the real relay
//! does), plus a JSON-RPC stub standing in for the chain.
//!
//! The point of the pair is that an agent gets the same result from either
//! program, so most checks run a command through `wcapp` (signed by
//! opwallet's dashboard after a `y`) and the same command through
//! `opwallet` directly, and require byte-identical output.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{Receiver, Sender, channel},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Address, Signature, hex, keccak256};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use opwallet::walletconnect::{
    crypto::{self, SymKey},
    session::request_json,
};
use serde_json::{Value, json};
use tungstenite::{
    Message,
    handshake::server::{Request, Response},
};

// ---------------------------------------------------------------------------
// A relay for several clients
// ---------------------------------------------------------------------------

struct Stored {
    publisher: String,
    data: Value,
    digest: [u8; 32],
}

#[derive(Default)]
struct Hub {
    /// Connection id → (client identity, outbox).
    conns: HashMap<usize, (String, Sender<String>)>,
    subs: HashMap<String, HashSet<usize>>,
    mailbox: HashMap<String, Vec<Stored>>,
    /// (client identity, message digest) already handed over.
    delivered: HashSet<(String, [u8; 32])>,
    next_id: usize,
}

impl Hub {
    fn deliver(&mut self, conn: usize, topic: &str, stored_index: usize) {
        let (client, out) = self.conns[&conn].clone();
        let s = &self.mailbox[topic][stored_index];
        if s.publisher == client || !self.delivered.insert((client, s.digest)) {
            return;
        }
        let msg = json!({
            "id": 9_000_000 + stored_index as u64, "jsonrpc": "2.0", "method": "irn_subscription",
            "params": { "id": format!("sub-{topic}"), "data": s.data },
        });
        let _ = out.send(msg.to_string());
    }

    fn handle(&mut self, conn: usize, v: Value) {
        let Some(method) = v["method"].as_str() else { return }; // a client's ack
        let out = self.conns[&conn].1.clone();
        let topic = v["params"]["topic"].as_str().unwrap_or("").to_string();
        let reply = |result: Value| {
            let _ =
                out.send(json!({ "id": v["id"], "jsonrpc": "2.0", "result": result }).to_string());
        };
        match method {
            "irn_subscribe" => {
                self.subs.entry(topic.clone()).or_default().insert(conn);
                reply(json!(format!("sub-{topic}")));
                let n = self.mailbox.get(&topic).map_or(0, Vec::len);
                for i in 0..n {
                    self.deliver(conn, &topic, i);
                }
            }
            "irn_unsubscribe" => {
                if let Some(s) = self.subs.get_mut(&topic) {
                    s.remove(&conn);
                }
                reply(json!(true));
            }
            "irn_publish" => {
                let p = &v["params"];
                let message = p["message"].as_str().unwrap_or("").to_string();
                let stored = Stored {
                    publisher: self.conns[&conn].0.clone(),
                    data: json!({ "topic": topic, "message": message, "tag": p["tag"], "publishedAt": 0 }),
                    digest: keccak256(message.as_bytes()).0,
                };
                let list = self.mailbox.entry(topic.clone()).or_default();
                list.push(stored);
                let index = list.len() - 1;
                reply(json!(true));
                let subscribers: Vec<usize> =
                    self.subs.get(&topic).into_iter().flatten().copied().collect();
                for c in subscribers {
                    self.deliver(c, &topic, index);
                }
            }
            other => panic!("unexpected relay call {other}"),
        }
    }
}

/// Client identity from the relay auth JWT in the connection URL.
fn client_of(uri: &str) -> String {
    let jwt = uri.split("auth=").nth(1).unwrap().split('&').next().unwrap();
    let payload = URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).unwrap()).unwrap();
    serde_json::from_slice::<Value>(&payload).unwrap()["iss"].as_str().unwrap().to_string()
}

fn start_relay() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hub = Arc::new(Mutex::new(Hub::default()));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let hub = hub.clone();
            thread::spawn(move || serve_conn(stream, hub));
        }
    });
    port
}

#[allow(clippy::result_large_err)] // the handshake callback's signature is tungstenite's
fn serve_conn(stream: TcpStream, hub: Arc<Mutex<Hub>>) {
    let mut uri = String::new();
    let mut ws = tungstenite::accept_hdr(stream, |req: &Request, resp: Response| {
        uri = req.uri().to_string();
        Ok(resp)
    })
    .unwrap();
    ws.get_mut().set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let (tx, rx): (Sender<String>, Receiver<String>) = channel();
    let id = {
        let mut h = hub.lock().unwrap();
        h.next_id += 1;
        let id = h.next_id;
        h.conns.insert(id, (client_of(&uri), tx));
        id
    };
    loop {
        match ws.read() {
            Ok(Message::Text(t)) => {
                let v: Value = serde_json::from_str(&t).unwrap();
                hub.lock().unwrap().handle(id, v);
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
        while let Ok(out) = rx.try_recv() {
            if ws.send(Message::text(out)).is_err() {
                break;
            }
        }
    }
    let mut h = hub.lock().unwrap();
    h.conns.remove(&id);
    for subs in h.subs.values_mut() {
        subs.remove(&id);
    }
}

// ---------------------------------------------------------------------------
// A chain that accepts raw transactions
// ---------------------------------------------------------------------------

/// Returns the port and every raw transaction it has been sent.
fn start_chain() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let req: Value = serde_json::from_slice(&body).unwrap();
            let result = match req["method"].as_str().unwrap() {
                "eth_sendRawTransaction" => {
                    let raw = req["params"][0].as_str().unwrap().to_string();
                    let hash = keccak256(hex::decode(&raw).unwrap());
                    log.lock().unwrap().push(raw);
                    json!(hash.to_string())
                }
                other => panic!("unexpected chain call {other}"),
            };
            let body = json!({ "jsonrpc": "2.0", "id": req["id"], "result": result }).to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (port, seen)
}

// ---------------------------------------------------------------------------
// Running the two programs
// ---------------------------------------------------------------------------

struct Env {
    dir: PathBuf,
    relay: String,
    chain: u16,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("opwallet-wcapp-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("op")).unwrap();
        fs::create_dir_all(dir.join("files")).unwrap();
        Self { dir, relay: format!("ws://127.0.0.1:{}", start_relay()), chain: 0 }
    }

    fn fake_op() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fake-op/op")
    }

    fn opwallet_cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_opwallet"));
        cmd.args(args)
            .env("OPWALLET_OP_BIN", Self::fake_op())
            .env("FAKE_OP_DIR", self.dir.join("op"))
            .env("OPWALLET_STATE_DIR", self.dir.join("opwallet-state"))
            .env("OPWALLET_NO_VERIFY", "true")
            .env_remove("OPWALLET_VAULT")
            .env_remove("OPWALLET_NAME")
            .env_remove("OPWALLET_PROJECT_ID")
            .env_remove("OPWALLET_TENDERLY_PROJECT");
        cmd
    }

    fn opwallet(&self, args: &[&str]) -> Output {
        self.opwallet_cmd(args).output().unwrap()
    }

    fn wcapp(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_wcapp"))
            .args(args)
            .env("WCAPP_STATE_DIR", self.dir.join("wcapp-state"))
            .env("WCAPP_PROJECT_ID", "test-project")
            .env("WCAPP_RELAY_URL", &self.relay)
            .env("WCAPP_TIMEOUT", "60")
            .env_remove("WCAPP_NAME")
            .output()
            .unwrap()
    }

    /// `opwallet connect` serving `uri`, answering its prompts from `answers`.
    fn serve(&self, uri: &str, answers: &str) -> Child {
        let rpc = format!("1=http://127.0.0.1:{}", self.chain);
        let mut child = self
            .opwallet_cmd(&[
                "connect",
                "--name",
                "agent",
                "--project-id",
                "test-project",
                "--relay-url",
                &self.relay,
                "--rpc",
                &rpc,
                uri,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(answers.as_bytes()).unwrap();
        child
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn ok(out: &Output) -> String {
    assert!(
        out.status.success(),
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn wait_exit(child: &mut Child, within: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

const TYPED_DATA: &str = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],"Order":[{"name":"amount","type":"uint256"},{"name":"memo","type":"string"}]},"primaryType":"Order","domain":{"name":"Agent Desk","chainId":1},"message":{"amount":"42","memo":"rebalance"}}"#;

#[test]
fn wcapp_does_what_opwallet_does_through_opwallet() {
    let (chain, broadcasts) = start_chain();
    let mut env = Env::new("parity");
    env.chain = chain;
    ok(&env.opwallet(&["create", "--name", "agent"]));
    let address: Address = ok(&env.opwallet(&["address", "--name", "agent"])).parse().unwrap();

    // Pair without waiting, as an agent would: hand the URI over, carry on.
    let uri = ok(&env.wcapp(&["connect", "--no-wait", "--chain", "1,10"]));
    assert!(uri.starts_with("wc:") && uri.contains("symKey="), "{uri}");
    assert!(ok(&env.wcapp(&["sessions"])).contains("waiting for approval"));
    let out = env.wcapp(&["address"]);
    assert!(!out.status.success() && stderr(&out).contains("not approved"), "{}", stderr(&out));

    // The wallet: approve the connection, then four requests, then refuse one.
    let mut wallet = env.serve(&uri, "y\ny\ny\ny\ny\nn\n");

    // A message, through the wallet and locally: the same signature.
    let via_wallet = ok(&env.wcapp(&["sign", "-m", "hello from the agent"]));
    let local = ok(&env.opwallet(&["sign", "-n", "agent", "-m", "hello from the agent"]));
    assert_eq!(via_wallet, local);
    let sig = Signature::from_raw(&hex::decode(&via_wallet).unwrap()).unwrap();
    assert_eq!(sig.recover_address_from_msg(b"hello from the agent").unwrap(), address);

    // The session is known now, with the wallet's account.
    assert_eq!(ok(&env.wcapp(&["address"])), address.to_string());
    let list: Value = serde_json::from_str(&ok(&env.wcapp(&["list", "--json"]))).unwrap();
    assert_eq!(list[0]["address"], address.to_string());
    assert_eq!(list[0]["wallet"], "opwallet");
    assert_eq!(list[0]["chains"], json!(["eip155:1", "eip155:10"]));

    // Typed data from a file.
    let file = env.dir.join("files/order.json");
    fs::write(&file, TYPED_DATA).unwrap();
    let data = format!("@{}", file.display());
    let via_wallet = ok(&env.wcapp(&["sign-typed-data", "-n", "1", "-d", &data]));
    let local = ok(&env.opwallet(&["sign-typed-data", "-n", "agent", "-d", &data]));
    assert_eq!(via_wallet, local);

    // A transaction with every field given: identical raw bytes.
    let to = "0x00000000000000000000000000000000000000bb";
    let tx = [
        "--to",
        to,
        "--value",
        "0.01eth",
        "--gas",
        "21000",
        "--max-fee",
        "30gwei",
        "--priority-fee",
        "1gwei",
    ];
    let signed_args = [&["sign-tx", "--nonce", "3"][..], &tx].concat();
    let via_wallet = ok(&env.wcapp(&signed_args));
    let local = ok(&env.opwallet(&[&signed_args[..], &["-n", "agent"]].concat()));
    assert_eq!(via_wallet, local);

    // Broadcast: the chain gets the same transaction either way.
    let send_args = [&["send-tx", "--nonce", "4"][..], &tx].concat();
    let hash_via_wallet = ok(&env.wcapp(&[&send_args[..], &["-n", &address.to_string()]].concat()));
    let rpc = format!("1=http://127.0.0.1:{chain}");
    let hash_local = ok(&env.opwallet(&[&send_args[..], &["-n", "agent", "--rpc", &rpc]].concat()));
    assert_eq!(hash_via_wallet, hash_local);
    let sent = broadcasts.lock().unwrap().clone();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[0], sent[1]);
    assert_eq!(keccak256(hex::decode(&sent[0]).unwrap()).to_string(), hash_via_wallet);

    // A chain the session does not have is refused here, without asking the wallet.
    let out = env.wcapp(&[&["sign-tx", "--chain", "137", "--nonce", "1"][..], &tx].concat());
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--chain 137"), "{}", stderr(&out));

    // The wallet says no: exit status 2 and the wallet's reason.
    let out = env.wcapp(&["sign", "-m", "not this one"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("User rejected"), "{}", stderr(&out));

    // The wallet answers pings without asking anyone.
    let doctor = ok(&env.wcapp(&["doctor"]));
    assert!(doctor.contains("opwallet") && doctor.contains("answering"), "{doctor}");

    // Disconnecting tells the wallet, which then has nothing left to serve.
    assert!(ok(&env.wcapp(&["disconnect", "opwallet"])).contains("Disconnected opwallet"));
    let status = wait_exit(&mut wallet, Duration::from_secs(20));
    if status.is_none() {
        let _ = wallet.kill();
    }
    let output = wallet.wait_with_output().unwrap();
    let log = String::from_utf8_lossy(&output.stdout);
    assert!(
        status.is_some_and(|s| s.success()),
        "the wallet keeps running:\n{log}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(log.contains("wcapp disconnected the session"), "{log}");
    assert!(ok(&env.wcapp(&["sessions"])).contains("No saved sessions"));
}

#[test]
fn the_wallet_refuses_a_request_that_expired_before_anyone_approved_it() {
    let mut env = Env::new("expiry");
    env.chain = start_chain().0;
    ok(&env.opwallet(&["create", "--name", "agent"]));
    let uri = ok(&env.wcapp(&["connect", "--no-wait", "--chain", "1"]));
    // One `y` for the connection, one that an expired request must not consume.
    let mut wallet = env.serve(&uri, "y\ny\n");
    ok(&env.wcapp(&["doctor"])); // finishes the pairing

    // Act as wcapp would after its timeout: a request whose expiry has passed.
    let state: Value = serde_json::from_str(
        &fs::read_to_string(env.dir.join("wcapp-state/dapp-sessions.json")).unwrap(),
    )
    .unwrap();
    let session = &state["sessions"][0];
    let topic = session["topic"].as_str().unwrap();
    let key = SymKey::from_hex(session["key"].as_str().unwrap()).unwrap();
    let address = session["accounts"][0].as_str().unwrap();

    let (mut ws, _) = tungstenite::connect(format!(
        "{}/?auth={}&projectId=x",
        env.relay,
        opwallet::walletconnect::relay::auth_jwt(
            &env.relay,
            &opwallet::walletconnect::relay::new_client_key().unwrap()
        )
        .unwrap()
    ))
    .unwrap();
    let call = |ws: &mut tungstenite::WebSocket<_>, method: &str, params: Value| {
        ws.send(Message::text(request_json(1, method, params))).unwrap();
    };
    call(&mut ws, "irn_subscribe", json!({ "topic": topic }));
    let request = request_json(
        77,
        "wc_sessionRequest",
        json!({
            "request": { "method": "personal_sign", "params": ["0x6869", address], "expiryTimestamp": now() - 1 },
            "chainId": "eip155:1",
        }),
    );
    let message = crypto::encrypt(&key, request.as_bytes()).unwrap();
    call(
        &mut ws,
        "irn_publish",
        json!({ "topic": topic, "message": message, "ttl": 300, "tag": 1108 }),
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let answer = loop {
        assert!(Instant::now() < deadline, "the wallet never answered");
        let Message::Text(t) = ws.read().unwrap() else { continue };
        let v: Value = serde_json::from_str(&t).unwrap();
        if v["method"] != "irn_subscription" {
            continue;
        }
        let plain =
            crypto::decrypt(&key, v["params"]["data"]["message"].as_str().unwrap()).unwrap();
        let rpc: Value = serde_json::from_slice(&plain).unwrap();
        if rpc["id"] == 77 {
            break rpc;
        }
    };
    assert_eq!(answer["error"]["code"], 8000, "{answer}");
    assert!(answer.get("result").is_none());

    // The second `y` is still unread: a fresh request takes it and is signed.
    let sig = ok(&env.wcapp(&["sign", "-m", "fresh"]));
    assert!(sig.starts_with("0x"), "{sig}");
    ok(&env.wcapp(&["disconnect", "--all"]));
    if wait_exit(&mut wallet, Duration::from_secs(20)).is_none() {
        let _ = wallet.kill();
        panic!("the wallet did not exit after the disconnect");
    }
}

#[test]
fn listings_work_offline_and_say_what_to_do_next() {
    let env = Env::new("offline");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_wcapp"))
            .args(args)
            .env("WCAPP_STATE_DIR", env.dir.join("wcapp-state"))
            .env_remove("WCAPP_PROJECT_ID")
            .env_remove("OPWALLET_PROJECT_ID")
            .output()
            .unwrap()
    };
    assert!(ok(&run(&["list"])).contains("wcapp connect"));
    assert_eq!(serde_json::from_str::<Value>(&ok(&run(&["list", "--json"]))).unwrap(), json!([]));
    assert!(ok(&run(&["sessions"])).contains("No saved sessions"));
    assert!(ok(&run(&["disconnect", "--all"])).contains("No saved sessions"));
    let out = run(&["address"]);
    assert!(!out.status.success() && stderr(&out).contains("wcapp connect"), "{}", stderr(&out));
    // Talking to a wallet needs a project ID, and says where to get one.
    let out = run(&["sign", "-m", "hi"]);
    assert!(stderr(&out).contains("WCAPP_PROJECT_ID"), "{}", stderr(&out));
    // No command: the help, not an error about a missing wallet.
    let out = run(&[]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("Usage: wcapp"));
}
