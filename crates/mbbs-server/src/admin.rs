//! Account administration: the commands `mbbs-user` runs, applied by
//! whichever process has the account files open.
//!
//! Spec: `docs/superpowers/specs/2026-09-05-live-account-admin-design.md`.
//!
//! Two processes can have the pair open, never at once: a running
//! `mbbs-server`, or `mbbs-user` against a stopped board. Both call
//! [`apply`] with the same [`Request`] and get the same [`Reply`], so a
//! sysop types one command and gets one answer whichever it was. What
//! differs is only how the request reaches the files: over the socket
//! [`serve`] binds under the board root, or by `mbbs-user` opening the
//! pair itself.

use mbbs::abi::Abi;
use mbbs::accounts::{self, flags, Refusal};
use mbbs::Host;

/// One `mbbs-user` command, parsed and with every default already applied.
///
/// `Add::keys` is the ring to write: the caller resolves the board's
/// default, so a new account's ring reaches the file through one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Add { userid: String, password: String, keys: Vec<String> },
    Passwd { userid: String, password: String },
    Keys { userid: String, add: Vec<String>, remove: Vec<String> },
    Master { userid: String, on: bool },
    List,
    Delete { userid: String },
}

/// One account as `list` reports it: the name, the whole flags word, and
/// the ring as the key file holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub userid: String,
    pub flags: u16,
    pub ring: Vec<String>,
}

/// What a [`Request`] came to.
///
/// `Refused` is the sysop's mistake, worded for a sysop (exit 1 at the
/// CLI). `Faulted` is the engine or the files (exit 2). `Listed` answers
/// `List`; `Ring` answers `Keys` with the ring read back from the file, so
/// what the sysop is shown is what the next login will load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Done,
    Refused(String),
    Faulted(String),
    Listed(Vec<Row>),
    Ring(Vec<String>),
}

/// Apply one request to the host that has the account files open.
///
/// The one place the commands are implemented. `mbbs-user` calls this
/// directly against a stopped board, and the host thread calls it for a
/// request that arrived over the socket, so the two can never disagree.
///
/// `passwd`, `keys`, `master` and `delete` are refused while the account
/// has a session (`Host::account_online`): the logoff write-back would put
/// the in-memory record back over whatever was written here.
pub fn apply<A: Abi>(host: &mut Host<A>, machine: &mut A::Cpu, request: Request) -> Reply {
    match request {
        Request::List => match host.account_list() {
            Ok(listed) => Reply::Listed(
                listed
                    .into_iter()
                    .map(|(record, ring)| Row {
                        userid: record.userid().to_owned(),
                        flags: record.flags(),
                        ring,
                    })
                    .collect(),
            ),
            Err(why) => Reply::Faulted(why),
        },
        Request::Add { userid, password, keys } => {
            accept(&userid, host.account_add(machine, &userid, &password, &keys))
        }
        Request::Passwd { userid, password } => {
            if let Some(reply) = online(host, &userid) {
                return reply;
            }
            accept(&userid, host.account_set_password(&userid, &password))
        }
        Request::Keys { userid, add, remove } => {
            if let Some(reply) = online(host, &userid) {
                return reply;
            }
            keys(host, &userid, &add, &remove)
        }
        Request::Master { userid, on } => {
            if let Some(reply) = online(host, &userid) {
                return reply;
            }
            master(host, &userid, on)
        }
        Request::Delete { userid } => {
            if let Some(reply) = online(host, &userid) {
                return reply;
            }
            accept(&userid, host.account_tag_deleted(&userid))
        }
    }
}

/// The online refusal, or `None` when the edit may go ahead.
fn online<A: Abi>(host: &mut Host<A>, userid: &str) -> Option<Reply> {
    match host.account_online(userid) {
        Ok(true) => Some(Reply::Refused(format!("{userid} is online"))),
        Ok(false) => None,
        Err(why) => Some(Reply::Faulted(why)),
    }
}

/// Turn one account-layer answer into a reply.
fn accept(userid: &str, answer: Result<Result<(), Refusal>, String>) -> Reply {
    match answer {
        Ok(Ok(())) => Reply::Done,
        Ok(Err(refusal)) => Reply::Refused(refused(userid, refusal)),
        Err(why) => Reply::Faulted(why),
    }
}

/// What each refusal is called on a sysop's terminal.
///
/// The listeners have their own vocabulary for these
/// (`mbbs_server::conn::refusal_line`) and it is the wrong one here: a caller
/// is told "No account by that name.", where a sysop is told which name. The
/// last six arms cannot be reached from any command in this program -- they are a
/// listener's answers to a claim -- and are spelled out anyway because
/// `Refusal` is closed, so a new variant lands here as a compile error rather
/// than as a wrong sentence.
pub fn refused(userid: &str, refusal: Refusal) -> String {
    match refusal {
        Refusal::Unknown => format!("no account named {userid}"),
        Refusal::Exists => format!("{userid} already has an account"),
        Refusal::Invalid(why) => why.to_string(),
        Refusal::BadPassword => format!("{userid}'s password does not match"),
        Refusal::NoPassword => format!("{userid} has no password"),
        Refusal::Deleted => format!("{userid} is tagged for deletion"),
        Refusal::Suspended => format!("{userid} is suspended"),
        Refusal::Full => "the board is full".to_owned(),
        Refusal::Maintenance => "the board is in maintenance".to_owned(),
    }
}

/// `keys`: the removals first, then the additions, then the file.
///
/// Removals before additions so that `--remove SYSOP --add SYSOP` is a way to
/// move a key to the end of the ring rather than a way to lose it, and so
/// that the order does not depend on the order the two flags were typed in.
///
/// An added key has to be one word of at most `KEYSIZ - 1` characters, and
/// anything else is refused before the ring is touched -- see the check
/// itself for what a space or a long name would do to a stored ring.
fn keys<A: Abi>(host: &mut Host<A>, userid: &str, add: &[String], remove: &[String]) -> Reply {
    // Asked first: `account_ring` answers `None` both for an account with no
    // ring record and for no account at all, and those are different
    // sentences.
    match host.account_find(userid) {
        Ok(None) => return Reply::Refused(refused(userid, Refusal::Unknown)),
        Ok(Some(_)) => {}
        Err(why) => return Reply::Faulted(why),
    }

    // A key name is one word, short enough for `keys[KEYSIZ]`. A ring is
    // stored space-separated and split on spaces when it is loaded, so a key
    // with a space in it is two keys the moment it is read back, and one
    // longer than `KEYSIZ - 1` is silently cut short by whatever reads it
    // into that array. Both are refused here rather than written: the
    // removal side needs no such check, since a name that cannot be stored
    // cannot be on a ring to remove.
    for key in add {
        if key.is_empty()
            || key.chars().any(char::is_whitespace)
            || key.len() > accounts::KEYSIZ - 1
        {
            return Reply::Refused(format!(
                "a key name is one word of at most {} characters",
                accounts::KEYSIZ - 1
            ));
        }
    }

    // A `keys USERID` with neither flag is a question, and a question does
    // not rewrite the record it is asking about: writing a ring is a delete
    // and an insert (see `Accounts::write_ring`), which is not a thing to do
    // to a file for no reason.
    if !add.is_empty() || !remove.is_empty() {
        let mut ring = match ring_of(host, userid) {
            Ok(ring) => ring,
            Err(why) => return Reply::Faulted(why),
        };
        ring.retain(|key| !remove.iter().any(|gone| gone.eq_ignore_ascii_case(key)));
        ring.extend(add.iter().map(|key| key.to_ascii_uppercase()));
        if let reply @ (Reply::Refused(_) | Reply::Faulted(_)) =
            accept(userid, host.account_write_ring(userid, &ring))
        {
            return reply;
        }
    }

    // Read back out of the file rather than the ring just written: what
    // the sysop is shown is what the next login will load.
    match ring_of(host, userid) {
        Ok(now) => Reply::Ring(now),
        Err(why) => Reply::Faulted(why),
    }
}

fn ring_of<A: Abi>(host: &mut Host<A>, userid: &str) -> Result<Vec<String>, String> {
    Ok(host.account_ring(userid)?.map_or_else(Vec::new, |ring| ring.keys))
}

/// `master`: set or clear `HASMST`, leaving the other three bits alone.
fn master<A: Abi>(host: &mut Host<A>, userid: &str, on: bool) -> Reply {
    let record = match host.account_find(userid) {
        Ok(Some((_, record))) => record,
        Ok(None) => return Reply::Refused(refused(userid, Refusal::Unknown)),
        Err(why) => return Reply::Faulted(why),
    };
    // The whole word, with one bit changed: the other three are the sysop's
    // and this command has no business touching them.
    let word = if on { record.flags() | flags::HASMST } else { record.flags() & !flags::HASMST };
    accept(userid, host.account_set_flags(userid, word))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs::accounts::{Login, Terminal};
    use mbbs::testing::{scratch, Fixture};

    fn opened(name: &str) -> Fixture {
        let mut f = Fixture::rooted_with_terms(scratch(name), mbbs::Terms::new(2));
        f.host
            .open_accounts(&mut f.machine, crate::conn::default_keys())
            .expect("opened");
        f
    }

    fn add(f: &mut Fixture, userid: &str, password: &str) {
        let reply = apply(
            &mut f.host,
            &mut f.machine,
            Request::Add {
                userid: userid.into(),
                password: password.into(),
                keys: crate::conn::default_keys(),
            },
        );
        assert_eq!(reply, Reply::Done, "{userid} added");
    }

    fn rows(f: &mut Fixture) -> Vec<Row> {
        match apply(&mut f.host, &mut f.machine, Request::List) {
            Reply::Listed(rows) => rows,
            other => panic!("list answered {other:?}"),
        }
    }

    #[test]
    fn add_then_list_shows_the_ring_and_no_flags() {
        let mut f = opened("admin-add");
        add(&mut f, "Dan", "hunter2");
        assert_eq!(
            rows(&mut f),
            vec![Row {
                userid: "Dan".into(),
                flags: 0,
                ring: vec!["DEMO".into(), "NORMAL".into(), "USER".into()]
            }]
        );
    }

    #[test]
    fn add_refuses_a_taken_name_in_the_sysops_words() {
        let mut f = opened("admin-add-taken");
        add(&mut f, "Dan", "hunter2");
        let again = apply(
            &mut f.host,
            &mut f.machine,
            Request::Add { userid: "dan".into(), password: "x".into(), keys: vec![] },
        );
        assert_eq!(again, Reply::Refused("dan already has an account".into()));
    }

    #[test]
    fn passwd_changes_what_a_login_accepts() {
        let mut f = opened("admin-passwd");
        add(&mut f, "Dan", "hunter2");
        let reply = apply(
            &mut f.host,
            &mut f.machine,
            Request::Passwd { userid: "Dan".into(), password: "newpw".into() },
        );
        assert_eq!(reply, Reply::Done);
        let (_, record) = f.host.account_find("Dan").expect("no fault").expect("exists");
        assert_eq!(record.password(), "newpw");
    }

    #[test]
    fn keys_removes_then_adds_and_answers_the_ring_read_back() {
        let mut f = opened("admin-keys");
        add(&mut f, "Dan", "hunter2");
        let reply = apply(
            &mut f.host,
            &mut f.machine,
            Request::Keys { userid: "Dan".into(), add: vec!["sysop".into()], remove: vec!["DEMO".into()] },
        );
        assert_eq!(reply, Reply::Ring(vec!["NORMAL".into(), "USER".into(), "SYSOP".into()]));

        // Neither flag: a question, answered with the same ring.
        let asked = apply(
            &mut f.host,
            &mut f.machine,
            Request::Keys { userid: "Dan".into(), add: vec![], remove: vec![] },
        );
        assert_eq!(asked, Reply::Ring(vec!["NORMAL".into(), "USER".into(), "SYSOP".into()]));
    }

    #[test]
    fn keys_refuses_a_name_that_is_not_one_short_word() {
        let mut f = opened("admin-keys-bad");
        add(&mut f, "Dan", "hunter2");
        for bad in ["TWO WORDS", "SIXTEENCHARSXXXX", ""] {
            let reply = apply(
                &mut f.host,
                &mut f.machine,
                Request::Keys { userid: "Dan".into(), add: vec![bad.into()], remove: vec![] },
            );
            assert_eq!(
                reply,
                Reply::Refused("a key name is one word of at most 15 characters".into()),
                "{bad:?}"
            );
        }
        assert_eq!(rows(&mut f)[0].ring, vec!["DEMO", "NORMAL", "USER"], "the ring is untouched");
    }

    #[test]
    fn keys_for_an_unknown_account_says_which_name() {
        let mut f = opened("admin-keys-unknown");
        let reply = apply(
            &mut f.host,
            &mut f.machine,
            Request::Keys { userid: "Nobody".into(), add: vec![], remove: vec![] },
        );
        assert_eq!(reply, Reply::Refused("no account named Nobody".into()));
    }

    #[test]
    fn master_sets_and_clears_one_bit_and_leaves_the_others() {
        use mbbs::accounts::flags;
        let mut f = opened("admin-master");
        add(&mut f, "Dan", "hunter2");
        f.host.account_set_flags("Dan", flags::UNDAXS).expect("no fault").expect("exists");

        let on = apply(&mut f.host, &mut f.machine, Request::Master { userid: "Dan".into(), on: true });
        assert_eq!(on, Reply::Done);
        assert_eq!(rows(&mut f)[0].flags, flags::HASMST | flags::UNDAXS);

        let off = apply(&mut f.host, &mut f.machine, Request::Master { userid: "Dan".into(), on: false });
        assert_eq!(off, Reply::Done);
        assert_eq!(rows(&mut f)[0].flags, flags::UNDAXS, "the other bit survives");
    }

    #[test]
    fn delete_tags_and_refuses_an_unknown_account() {
        use mbbs::accounts::flags;
        let mut f = opened("admin-delete");
        add(&mut f, "Dan", "hunter2");
        assert_eq!(
            apply(&mut f.host, &mut f.machine, Request::Delete { userid: "Dan".into() }),
            Reply::Done
        );
        assert_eq!(rows(&mut f)[0].flags & flags::DELTAG, flags::DELTAG);
        assert_eq!(
            apply(&mut f.host, &mut f.machine, Request::Delete { userid: "Nobody".into() }),
            Reply::Refused("no account named Nobody".into())
        );
    }

    /// The logoff write-back puts the whole in-memory record back over the
    /// file, so an edit to an account somebody is logged in as would be
    /// undone at their logoff. All four editing commands are refused while
    /// the account has a session, and allowed again once it has gone.
    #[test]
    fn editing_an_online_account_is_refused_until_it_logs_off() {
        let mut f = opened("admin-online");
        add(&mut f, "Dan", "hunter2");
        let module = f.registered_module();
        let chan = f.host.users().terms().chan(0).expect("channel 0");
        f.host
            .login(
                &mut f.machine,
                &module,
                chan,
                &Login::Password { userid: "Dan".into(), password: "hunter2".into() },
                Terminal { ansi: true, width: 80, height: 24 },
            )
            .expect("no io error")
            .expect("accepted");

        let edits = [
            Request::Passwd { userid: "dan".into(), password: "x".into() },
            Request::Keys { userid: "Dan".into(), add: vec!["SYSOP".into()], remove: vec![] },
            Request::Master { userid: "Dan".into(), on: true },
            Request::Delete { userid: "Dan".into() },
        ];
        for request in &edits {
            let reply = apply(&mut f.host, &mut f.machine, request.clone());
            assert_eq!(reply, Reply::Refused(format!("{} is online", request_userid(request))), "{request:?}");
        }
        let (_, record) = f.host.account_find("Dan").expect("no fault").expect("exists");
        assert_eq!(record.password(), "hunter2", "nothing was written");
        assert_eq!(rows(&mut f)[0].ring, vec!["DEMO", "NORMAL", "USER"]);

        // `list` and `add` are never refused for this reason.
        assert_eq!(rows(&mut f).len(), 1);
        add(&mut f, "Beef", "beef1");

        f.host.hangup(&mut f.machine, &module, chan).expect("hung up");
        assert_eq!(
            apply(&mut f.host, &mut f.machine, Request::Passwd { userid: "Dan".into(), password: "x".into() }),
            Reply::Done,
            "logged off, so the edit lands"
        );
    }

    fn request_userid(request: &Request) -> &str {
        match request {
            Request::Passwd { userid, .. }
            | Request::Keys { userid, .. }
            | Request::Master { userid, .. }
            | Request::Delete { userid }
            | Request::Add { userid, .. } => userid,
            Request::List => "",
        }
    }
}
