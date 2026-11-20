//! `opwallet` and `wcapp` must stay interchangeable: same commands, same
//! flags, except for the differences listed here on purpose. Adding a
//! command or flag to one program without the other fails this test until
//! the other gets it too, or the difference is written down below.

use std::collections::BTreeSet;

use ::opwallet::cli::{self, opwallet, wcapp};
use clap::Command;

/// Commands only one program has.
const ONLY_OPWALLET: &[&str] = &["create", "verify"];
const ONLY_WCAPP: &[&str] = &[];

/// Flags each program has everywhere, about how it reaches its keys.
const OPWALLET_EVERYWHERE: &[&str] = &["--op-bin", "--vault", "--no-relock"];
const WCAPP_EVERYWHERE: &[&str] = &["--timeout"];

/// Per command: (command, only in opwallet, only in wcapp).
const DIFFERENCES: &[(&str, &[&str], &[&str])] = &[
    // wcapp needs the relay for anything that reaches the wallet.
    ("doctor", &[], &["--project-id", "--relay-url"]),
    ("sign", &[], &["--project-id", "--relay-url"]),
    ("sign-typed-data", &[], &["--project-id", "--relay-url"]),
    // opwallet talks to the chain itself; wcapp's wallet does that.
    ("sign-tx", &["--rpc"], &["--relay-url"]),
    ("send-tx", &["--rpc"], &["--relay-url"]),
    // Opposite ends of a pairing: opwallet takes a dapp's URI and serves
    // it; wcapp makes a URI for a wallet.
    (
        "connect",
        &[
            "--name",
            "<uri>",
            "--plain",
            "--rpc",
            "--tenderly-project",
            "--verify-url",
            "--no-verify",
        ],
        &["--chain", "--no-wait"],
    ),
];

fn built(mut cmd: Command) -> Command {
    cmd.build();
    cmd
}

/// `--long` flags and `<positional>` arguments of a command, with shorts.
fn args(cmd: &Command) -> BTreeSet<(String, Option<char>)> {
    cmd.get_arguments()
        .filter(|a| !matches!(a.get_id().as_str(), "help" | "version"))
        .map(|a| {
            let name = match a.get_long() {
                Some(l) => format!("--{l}"),
                None => format!("<{}>", a.get_id()),
            };
            (name, a.get_short())
        })
        .collect()
}

fn names(set: &BTreeSet<(String, Option<char>)>) -> BTreeSet<String> {
    set.iter().map(|(n, _)| n.clone()).collect()
}

#[test]
fn commands_and_flags_match_except_where_documented() {
    let op = built(cli::command::<opwallet::Cli>(opwallet::ENV_PREFIX));
    let wc = built(cli::command::<wcapp::Cli>(wcapp::ENV_PREFIX));
    let subs = |c: &Command| -> BTreeSet<String> {
        c.get_subcommands().map(|s| s.get_name().to_string()).filter(|n| n != "help").collect()
    };
    let (op_subs, wc_subs) = (subs(&op), subs(&wc));

    let only_op: BTreeSet<String> = op_subs.difference(&wc_subs).cloned().collect();
    let only_wc: BTreeSet<String> = wc_subs.difference(&op_subs).cloned().collect();
    assert_eq!(only_op, ONLY_OPWALLET.iter().map(|s| s.to_string()).collect());
    assert_eq!(only_wc, ONLY_WCAPP.iter().map(|s| s.to_string()).collect());

    for name in op_subs.intersection(&wc_subs) {
        let a = args(op.find_subcommand(name).unwrap());
        let b = args(wc.find_subcommand(name).unwrap());
        let (op_only, wc_only) = DIFFERENCES
            .iter()
            .find(|(c, _, _)| c == name)
            .map(|(_, o, w)| (o.to_vec(), w.to_vec()))
            .unwrap_or_default();
        let expect_op: BTreeSet<String> =
            OPWALLET_EVERYWHERE.iter().chain(&op_only).map(|s| s.to_string()).collect();
        let expect_wc: BTreeSet<String> =
            WCAPP_EVERYWHERE.iter().chain(&wc_only).map(|s| s.to_string()).collect();
        let (na, nb) = (names(&a), names(&b));
        assert_eq!(
            na.difference(&nb).cloned().collect::<BTreeSet<_>>(),
            expect_op,
            "`{name}`: flags only opwallet has"
        );
        assert_eq!(
            nb.difference(&na).cloned().collect::<BTreeSet<_>>(),
            expect_wc,
            "`{name}`: flags only wcapp has"
        );
        // Shared flags have the same short form too.
        for (flag, short) in &a {
            if let Some((_, other)) = b.iter().find(|(f, _)| f == flag) {
                assert_eq!(short, other, "`{name} {flag}`: short forms differ");
            }
        }
    }
}

#[test]
fn every_documented_difference_names_a_real_command() {
    let op = built(cli::command::<opwallet::Cli>(opwallet::ENV_PREFIX));
    for (name, _, _) in DIFFERENCES {
        assert!(op.find_subcommand(name).is_some(), "stale entry for `{name}`");
    }
}
