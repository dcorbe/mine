//! The account database, as this host keeps it on disk.
//!
//! [`record`] is the pure half: the bytes of a `usracc` and a `keyrec`, with
//! no [`Abi`](crate::abi::Abi) and no I/O anywhere in it. This file is the
//! half that touches the board directory -- which two files a generation opens
//! ([`file_names`]), the shape a board with none gets created for it
//! ([`account_spec`] and [`key_spec`]), the advisory lock the server and the
//! `mbbs-user` CLI share ([`lock_file`]), and the [`Accounts`] handle a
//! running host keeps for the life of the board.
//!
//! Opening happens in the board's own startup, after `finish_init`, through
//! [`Host::open_accounts`](crate::Host::open_accounts) -- never in
//! [`Host::new`](crate::Host::new). A `Host` a test builds has no account
//! files and a null `accbb`, exactly as it had before this existed, which is
//! why the whole existing suite goes on running with no account file in any
//! of its scratch directories.

pub mod record;
pub use record::*;

use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;

use crate::abi::Abi;
use crate::btrieve::{AbiMem, Btrieve, Op};

/// One host generation's files, and what a refusal calls it.
///
/// A MajorBBS 6 or Worldgroup 2 host opens `bbsusr.dat` (`ACCOUNT.C:108`)
/// and `bbsk.dat` (`LOCKNKEY.C:42`); a Worldgroup 3 host opens `wgsusr2.dat`
/// (`ACCOUNT.C:102`) and `wgskey2.dat` (`LOCKNKEY.C:46`). Which pair this
/// host opens follows from [`Abi::GCV2`] and nothing else -- the same flag
/// [`crate::users::AccountLayout::of`] already reads to decide the record
/// stride -- so a board configures no ABI flag of its own and cannot get the
/// two answers out of step.
///
/// The class file is deliberately absent. It only resolves a class name to a
/// class table entry, and this host reads no class table.
pub(crate) struct Generation {
    /// The account file: one `usracc` per record, keyed on `userid`.
    pub(crate) account: &'static str,
    /// The key file: one `keyrec` per ring, keyed on its owner.
    pub(crate) keys: &'static str,
    /// What a boot refusal calls this generation.
    pub(crate) name: &'static str,
}

const WG16: Generation = Generation {
    account: "bbsusr.dat",
    keys: "bbsk.dat",
    name: "Wg16",
};
const WG32: Generation = Generation {
    account: "wgsusr2.dat",
    keys: "wgskey2.dat",
    name: "Wg32",
};

/// This host's generation first, the other one second.
pub(crate) fn generations<A: Abi>() -> (&'static Generation, &'static Generation) {
    if A::GCV2 {
        (&WG16, &WG32)
    } else {
        (&WG32, &WG16)
    }
}

/// The names one ABI's host opens: the account file, then the key file.
///
/// The single source for the pair.
/// [`Host::open_accounts`](crate::Host::open_accounts) takes both names from
/// here, and so does the `mbbs-user` CLI, so a board and the tool that edits
/// it can never disagree about which two files they mean.
#[must_use]
pub fn file_names<A: Abi>() -> (&'static str, &'static str) {
    let (this, _) = generations::<A>();
    (this.account, this.keys)
}

/// `sizeof(struct keyrec)`: `userid[30]` then `keys[1]`, which is the key
/// file's fixed record length. The ring itself is the variable tail, so a
/// blank ring is exactly this long -- the kit's own `Ml` record is 31 bytes.
pub(crate) const KEYREC: u16 = KLSTOF as u16 + 1;

/// `DFAST_ZSTRING`: a NUL-terminated string. Both files key on one.
const ZSTRING: u8 = 0x0b;

/// The one key both files carry: `userid`, 30 bytes at offset 0, a ZSTRING
/// collated through `ALLCAPS`.
///
/// Measured off the kit's `BBSUSR.DAT` and `BBSK.DAT` (spec section 0): key 0
/// attributes `0x0120` on both, extended type plus alternate collating. The
/// ALLCAPS sequence is what makes every userid lookup case-insensitive, and
/// it is why the vendor compares userids with `sameas` everywhere and never
/// uppercases a name on the way in.
fn userid_key() -> btrieve::KeySpec {
    btrieve::KeySpec {
        segments: vec![btrieve::SegmentSpec {
            offset: 0,
            length: KLSTOF as u16,
            kind: ZSTRING,
            descending: false,
        }],
        duplicates: false,
        modifiable: false,
        acs: true,
    }
}

/// The account file a board with none gets created for it: `stride`-byte
/// fixed records, 1024-byte pages, [`userid_key`].
///
/// `stride` is [`crate::users::AccountLayout::stride`] -- 338 under `Wg16`,
/// 304 under `Wg32` -- and is a parameter rather than a second `A` so that
/// the wrong-stride refusal has a way to build a file to be refused.
#[must_use]
pub fn account_spec(stride: u16) -> btrieve::FileSpec {
    btrieve::FileSpec {
        record_length: stride,
        page_size: 1024,
        keys: vec![userid_key()],
        acs: Some(btrieve::acs::allcaps()),
        variable: false,
    }
}

/// The key file a board with none gets created for it: a 31-byte fixed head
/// and a variable tail, 1024-byte pages, [`userid_key`].
#[must_use]
pub fn key_spec() -> btrieve::FileSpec {
    btrieve::FileSpec {
        record_length: KEYREC,
        page_size: 1024,
        keys: vec![userid_key()],
        acs: Some(btrieve::acs::allcaps()),
        variable: true,
    }
}

/// A board holding one of the two files and not the other, said in the one
/// sentence that names both.
///
/// Never a repair: the two files are one database, and a host that quietly
/// created the missing half would either serve an account file whose rings
/// had all vanished or a ring file for accounts that no longer exist. What
/// went missing is a question for the sysop's backups.
pub(crate) fn half_a_pair(present: &str, absent: &str) -> io::Error {
    io::Error::other(format!(
        "{present} exists but {absent} does not; a board has both or neither"
    ))
}

/// Lay a fresh pair down in `root`, and answer where the two files are.
///
/// If the key file cannot be created, the account file this just made is
/// removed again: a board left holding one of the two would refuse every
/// boot afterwards through [`half_a_pair`], for a reason that has nothing to
/// do with what actually went wrong here.
///
/// # Errors
///
/// Whatever [`btrieve::create`] refused, which includes `root` not being
/// writable and either file already existing.
pub(crate) fn create_pair(
    root: &Path,
    stride: u16,
    names: (&str, &str),
) -> io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let account = root.join(names.0);
    let keys = root.join(names.1);
    btrieve::create(&account, &account_spec(stride)).map_err(|e| io::Error::other(e.to_string()))?;
    if let Err(e) = btrieve::create(&keys, &key_spec()) {
        let _ = std::fs::remove_file(&account);
        return Err(io::Error::other(format!(
            "{e}; the {} just created has been removed, so the board is not left holding \
             half a pair",
            names.0
        )));
    }
    Ok((account, keys))
}

/// Take the advisory lock the server and the `mbbs-user` CLI share over the
/// account file at `path`.
///
/// Spec section 4 "Exclusion". The server holds this for its whole life and
/// the CLI takes the same lock before it edits anything, so the two can never
/// write the same record at once. `flock` rather than `fcntl` because the
/// lock belongs to the open file description: dropping the returned [`File`]
/// releases it and nothing else in the process can release it by accident,
/// which is exactly the lifetime [`Accounts`]'s own `lock` field wants.
///
/// [`File`]: std::fs::File
///
/// # Errors
///
/// [`io::ErrorKind::WouldBlock`], naming the path, when another open file
/// description already holds the lock. Whatever opening `path` read-write
/// failed with, otherwise.
pub fn lock_file(path: &Path) -> io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    // SAFETY: `file` is open for the whole call, so the descriptor is live.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(file);
    }
    let why = io::Error::last_os_error();
    if why.raw_os_error() == Some(libc::EWOULDBLOCK) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("another process has {} open", path.display()),
        ));
    }
    Err(why)
}

/// The account and key files this host has open, and the state that hangs
/// off them.
///
/// One per [`Host`](crate::Host), built by
/// [`Host::open_accounts`](crate::Host::open_accounts) and dropped with the
/// host. Its presence is what tells the rest of the host that this board has
/// an account database at all: a fixture host has `None` here and connects
/// channels from a bare [`Connection`](crate::Connection), as it always did.
pub struct Accounts<A: Abi> {
    /// The account file's open block -- what the `accbb` global holds, and
    /// what every `usracc` read and write goes through.
    pub(crate) accbb: A::Ptr,
    /// The key file's open block. Deliberately not published as a global:
    /// `LOCKNKEY.C` keeps its `keysbb` file-local and exports nothing, so no
    /// module can address it.
    pub(crate) keysbb: A::Ptr,
    /// `sizeof(struct usracc)` for this ABI: 338 or 304. The account file's
    /// record length was checked against it at open.
    pub(crate) stride: u16,
    /// The ring a newly written account is given. `DEMO NORMAL USER` unless
    /// the board says otherwise.
    pub(crate) default_ring: Vec<String>,
    /// Holds the advisory lock on the account file for the life of the host.
    /// Never read: the value *is* the lock, and dropping it is what releases
    /// it. See [`lock_file`].
    // Read by nothing, ever, by design: the doc above says why. The lint is
    // right about the letter of it and wrong about what the field is for.
    #[allow(dead_code)]
    pub(crate) lock: std::fs::File,
    /// Each channel's account session, indexed by [`Chan::index`](crate::Chan::index).
    // Written and read by `Host::login`/`Host::disconnect`, which do not
    // exist yet. Comes off with them.
    #[allow(dead_code)]
    pub(crate) sessions: Vec<Option<Session>>,
    /// 30 bytes of module memory holding the userid `dlarou` is called with
    /// during the maintenance purge.
    ///
    /// Reserved once here rather than per call because the purge dispatches
    /// it inside a sweep over every deleted account in every module, and a
    /// fresh allocation per call would draw on the same finite descriptor
    /// pool the module's own heap grows from.
    // Read by the maintenance purge, which does not exist yet. Comes off
    // with it.
    #[allow(dead_code)]
    pub(crate) userid_scratch: A::Ptr,
}

/// What a logged-in channel's account is, beyond the record already copied
/// into its `usracc` slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    /// The account record's Btrieve position, remembered at login so that
    /// the logoff write-back can find the record again without a second
    /// lookup -- the vendor's `usaptr`/`updacc` pair, `MAJORBBS.C:5305`.
    pub position: u32,
}

/// The keys a door session's sysop is given on top of the ring in the file.
///
/// Session-only, and deliberately never written to the key file: the BBS in
/// front of the door decides who is a sysop from its own level scale, which
/// changes when the sysop says so, and a grant this host persisted would
/// outlive that decision. `crates/mbbs-server/src/door.rs` holds the same two
/// names today and stops owning them once it resolves its claims through
/// here.
pub const SYSOP_KEYS: [&str; 2] = ["SYSOP", "WCCSYSOP"];

/// What a claim resolved to.
///
/// The connection carries the ring, so [`Host::connect`](crate::Host::connect)
/// needs nothing else; `record` is the account as the file holds it, which is
/// what the login path copies into the channel's `usracc` slot; `position` is
/// where to write it back at logoff.
pub struct Resolved {
    pub connection: crate::Connection,
    pub record: Usracc,
    pub position: u32,
}

/// Written out rather than derived, and short on purpose: a `usracc`'s 338
/// bytes are not a useful thing to read in a failing assertion, and what a
/// reader of one wants is which account resolved and what it may do.
impl std::fmt::Debug for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolved")
            .field("userid", &self.connection.userid)
            .field("position", &self.position)
            .field("flags", &format_args!("{:#06x}", self.record.flags()))
            .field("keys", &self.connection.keys)
            .finish()
    }
}

/// Whether an account's own flags refuse it before its password is ever
/// looked at. `USRACC.H:64-68`.
///
/// Deleted before suspended, because `DELTAG` is the stronger fact: an
/// account carrying both is gone, not merely stopped, and telling its owner
/// "suspended" would invite them to ask when it comes back.
fn standing(record: &Usracc) -> Option<Refusal> {
    if record.flags() & flags::DELTAG != 0 {
        return Some(Refusal::Deleted);
    }
    if record.flags() & flags::SUSPEN != 0 {
        return Some(Refusal::Suspended);
    }
    None
}

/// Everything that reads or writes the two open files.
///
/// Each of these takes the host's [`Btrieve`] session as an argument rather
/// than reaching it through a `Host`, because a `Host` cannot lend out its
/// `accounts` and its `btrieve` at once. The caller destructures the host
/// once -- `let Host { btrieve, accounts, .. } = self` -- and every borrow
/// below is then trivially disjoint.
///
/// Nothing here uppercases a userid. Both files key on a `ZSTRING` collated
/// through `ALLCAPS` (see [`userid_key`]), so the engine already compares
/// case-insensitively, which is exactly why the vendor compares userids with
/// `sameas` (`MAJORBBS.C:2967`) and stores whatever case the user typed.
impl<A: Abi> Accounts<A> {
    /// The account record for `userid`, and where it sits.
    ///
    /// A get-equal on key 0 with the 30-byte NUL-padded userid, which is how
    /// the vendor's `loadup`/`loadacc` pair (`SIGNUP.C:897-935`) finds an
    /// account too. Deleted and suspended accounts are found like any other:
    /// this answers what the file holds, and [`standing`] decides what that
    /// means.
    ///
    /// # Errors
    ///
    /// Whatever the engine refused. A record found and then unreadable is an
    /// error too, not a `None`: the file said the userid is there.
    pub(crate) fn find_account(
        &self,
        btrieve: &mut Btrieve<AbiMem<A>>,
        userid: &str,
    ) -> Result<Option<(u32, Usracc)>, String> {
        let block = btrieve.block_mut(self.accbb)?;
        if !block
            .query(0, Op::Equal, &Usracc::key(userid))
            .map_err(|why| format!("looking up the account {userid}: {why}"))?
        {
            return Ok(None);
        }
        let record = block.current().ok_or_else(|| {
            format!("the account file matched {userid} and then had no record to read")
        })?;
        Ok(Some((record.position, Usracc::from_bytes(record.bytes))))
    }

    /// Add one account, and answer where it landed.
    ///
    /// # Errors
    ///
    /// Whatever the engine refused, which includes a userid already in the
    /// file: key 0 permits no duplicates. Callers check for that first, so
    /// reaching it here is a race with another writer rather than a claim to
    /// be refused.
    pub(crate) fn insert_account(
        &self,
        btrieve: &mut Btrieve<AbiMem<A>>,
        record: &Usracc,
    ) -> Result<u32, String> {
        btrieve
            .block_mut(self.accbb)?
            .insert(&record.bytes)
            .map_err(|why| format!("writing the account {}: {why}", record.userid()))
    }

    /// The key ring `owner` owns, and where it sits.
    ///
    /// `owner` is a userid for a user's own ring and `&`-prefixed for a
    /// class ring (`LOCKNKEY.C:162`). The two cannot collide: `valuid`
    /// refuses a userid starting with punctuation, so no user is ever named
    /// `&STAFF`.
    ///
    /// # Errors
    ///
    /// Whatever the engine refused.
    pub(crate) fn find_ring(
        &self,
        btrieve: &mut Btrieve<AbiMem<A>>,
        owner: &str,
    ) -> Result<Option<(u32, Keyrec)>, String> {
        let block = btrieve.block_mut(self.keysbb)?;
        if !block
            .query(0, Op::Equal, &Usracc::key(owner))
            .map_err(|why| format!("looking up the key ring {owner}: {why}"))?
        {
            return Ok(None);
        }
        let record = block.current().ok_or_else(|| {
            format!("the key file matched {owner} and then had no record to read")
        })?;
        Ok(Some((record.position, Keyrec::from_bytes(&record.bytes))))
    }

    /// Write `ring`, replacing whatever ring its owner has now.
    ///
    /// **Delete then insert, not update.** A `keyrec` is the variable tail of
    /// a 31-byte head, and the engine rewrites a variable-length record only
    /// in place at the same length; a ring gains and loses keys, so its
    /// length is exactly the thing that changes. The delete is positioned by
    /// a get-equal first, because a delete acts on the record the file is
    /// positioned on.
    ///
    /// # Errors
    ///
    /// A ring longer than `RINGSZ`, or whatever the engine refused.
    pub(crate) fn write_ring(
        &self,
        btrieve: &mut Btrieve<AbiMem<A>>,
        ring: &Keyrec,
    ) -> Result<(), String> {
        // `Refusal` is the listener's vocabulary, not a sysop's; a ring this
        // host built and could not write is a fault, so the refusal is
        // reported rather than returned.
        let bytes = ring
            .to_bytes()
            .map_err(|why| format!("the key ring {} does not fit: {why:?}", ring.owner))?;

        let key = Usracc::key(&ring.owner);
        let block = btrieve.block_mut(self.keysbb)?;
        if block
            .query(0, Op::Equal, &key)
            .map_err(|why| format!("looking up the key ring {}: {why}", ring.owner))?
        {
            let position = block
                .current()
                .ok_or_else(|| {
                    format!(
                        "the key file matched {} and then had no record to replace",
                        ring.owner
                    )
                })?
                .position;
            block
                .delete(position)
                .map_err(|why| format!("replacing the key ring {}: {why}", ring.owner))?;
        }
        block
            .insert(&bytes)
            .map_err(|why| format!("writing the key ring {}: {why}", ring.owner))?;
        Ok(())
    }

    /// `loadkeys`, `LOCKNKEY.C:137-176`: the user's own ring, then their
    /// class's.
    ///
    /// A user with no ring of their own is given a blank one, written to the
    /// file, and the console is told -- the vendor's `shocst` at
    /// `LOCKNKEY.C:150-152`. A class naming a ring that does not exist is
    /// only reported (`:162-166`) and the login continues, because a class
    /// with no ring grants nothing and refusing the login over it would lock
    /// every member of that class out of the board.
    ///
    /// The notes go into `notes` rather than straight to
    /// [`Host::note`](crate::Host::note) because this borrows the host's
    /// `btrieve` and cannot also borrow the host.
    ///
    /// # Errors
    ///
    /// Whatever the engine refused, including failing to write the blank
    /// ring -- a ring this host believes it wrote and did not would hand the
    /// user a different set of keys on their next call.
    pub(crate) fn load_keys(
        &self,
        btrieve: &mut Btrieve<AbiMem<A>>,
        record: &Usracc,
        notes: &mut Vec<String>,
    ) -> Result<Vec<String>, String> {
        let userid = record.userid().to_string();
        let mut keys = match self.find_ring(btrieve, &userid)? {
            Some((_, ring)) => ring.keys,
            None => {
                self.write_ring(btrieve, &Keyrec { owner: userid.clone(), keys: Vec::new() })?;
                notes.push(format!(
                    "MISSING A USER'S KEYRING RECORD ({userid} has been given a blank \
                     keyring record.)"
                ));
                Vec::new()
            }
        };

        let class = record.curcls().to_string();
        if !class.is_empty() {
            match self.find_ring(btrieve, &Keyrec::class_ring_name(&class))? {
                Some((_, ring)) => keys.extend(ring.keys),
                None => notes.push(format!(
                    "MISSING A CLASS KEYRING RECORD ({class} class has no keyring record.)"
                )),
            }
        }

        Ok(keys)
    }

    /// Resolve one claim. Spec section 3, and the body of
    /// [`Host::resolve_login`](crate::Host::resolve_login).
    ///
    /// # Errors
    ///
    /// Whatever the engine refused. A claim the *board* refuses is
    /// `Ok(Err(refusal))` instead: the listener says one line to whoever
    /// called and keeps the channel, where an `Err` stops the module.
    pub(crate) fn resolve(
        &self,
        btrieve: &mut Btrieve<AbiMem<A>>,
        login: &Login,
        terminal: Terminal,
        today: u16,
        notes: &mut Vec<String>,
    ) -> Result<Result<Resolved, Refusal>, String> {
        let (position, record) = match login {
            Login::Password { userid, password } => {
                let Some((position, record)) = self.find_account(btrieve, userid)? else {
                    return Ok(Err(Refusal::Unknown));
                };
                if let Some(refusal) = standing(&record) {
                    return Ok(Err(refusal));
                }
                // Before the comparison, not as part of it: an account with
                // no password is one nothing has ever set a password on, and
                // an empty offer would otherwise match it.
                if record.password().is_empty() {
                    return Ok(Err(Refusal::NoPassword));
                }
                if !record.password_matches(password) {
                    return Ok(Err(Refusal::BadPassword));
                }
                (position, record)
            }
            Login::Signup { userid, password } => {
                if let Err(refusal) = validate_userid(userid) {
                    return Ok(Err(refusal));
                }
                if let Err(refusal) = validate_password(password) {
                    return Ok(Err(refusal));
                }
                if self.find_account(btrieve, userid)?.is_some() {
                    return Ok(Err(Refusal::Exists));
                }
                self.provision(btrieve, userid, password, terminal, today)?
            }
            Login::Trusted { userid, .. } => {
                if let Err(refusal) = validate_userid(userid) {
                    return Ok(Err(refusal));
                }
                match self.find_account(btrieve, userid)? {
                    Some((position, record)) => {
                        if let Some(refusal) = standing(&record) {
                            return Ok(Err(refusal));
                        }
                        (position, record)
                    }
                    // The account the BBS in front of this host already
                    // authenticated. It gets an empty password, which is
                    // what makes a later `Password` claim against it answer
                    // `NoPassword` rather than letting anyone in who guesses
                    // the empty string.
                    None => self.provision(btrieve, userid, "", terminal, today)?,
                }
            }
        };

        let mut keys = self.load_keys(btrieve, &record, notes)?;
        if matches!(login, Login::Trusted { sysop: true, .. }) {
            keys.extend(SYSOP_KEYS.iter().map(|key| (*key).to_string()));
        }

        let connection = crate::Connection {
            // The file's spelling, not the claim's: both are the same name
            // to the engine, and the record is what the board shows.
            userid: record.userid().to_string(),
            ansi: terminal.ansi,
            width: terminal.width,
            height: terminal.height,
            keys: crate::KeySet::new(keys).master(record.flags() & flags::HASMST != 0),
        };
        Ok(Ok(Resolved { connection, record, position }))
    }

    /// Write a brand-new account and its default ring, and answer the
    /// record.
    ///
    /// The record is `SIGNUP.C:1204`'s, built by [`Usracc::new`].
    ///
    /// **Two writes, two files, no transaction, and the account goes
    /// first.** A crash between the two leaves an account with no ring: its
    /// owner's next login gets a *blank* ring from
    /// [`Accounts::load_keys`] -- not the default one this would have
    /// written -- along with the console note that says so, and the sysop
    /// puts the default ring back with the `mbbs-user` CLI. The other order
    /// leaves a ring owned by an account that does not exist, which nothing
    /// will ever look up and no login will ever report.
    ///
    /// The engine does have transactions --
    /// [`Btrieve::begin`](crate::btrieve::Btrieve::begin),
    /// [`end`](crate::btrieve::Btrieve::end) and
    /// [`abort`](crate::btrieve::Btrieve::abort) -- and they are
    /// deliberately not used here: these two writes go to two different
    /// files, and what the real engine did with a transaction spanning two
    /// files is unmeasured. Wrapping them in one on the strength of the
    /// name would be a guess in the one place where being wrong loses an
    /// account.
    ///
    /// # Errors
    ///
    /// Whatever the engine refused.
    fn provision(
        &self,
        btrieve: &mut Btrieve<AbiMem<A>>,
        userid: &str,
        password: &str,
        terminal: Terminal,
        today: u16,
    ) -> Result<(u32, Usracc), String> {
        let record = Usracc::new(self.stride, userid, password, terminal, today);
        let position = self.insert_account(btrieve, &record)?;
        let ring = Keyrec {
            // The record's own spelling, which is the claim's truncated to
            // `UIDSIZ`. Taking it from here rather than from `userid` is what
            // keeps the ring findable by the name the account file holds.
            owner: record.userid().to_string(),
            keys: self.default_ring.clone(),
        };
        self.write_ring(btrieve, &ring)?;
        Ok((position, record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{Abi, Wg16};
    use crate::testing::{scratch, Fixture};
    use crate::Host;

    fn board(name: &str) -> Fixture {
        let root = scratch(name);
        Fixture::rooted(root)
    }

    /// A board whose pair is open, with the ring a new account gets.
    fn opened(name: &str) -> Fixture {
        let mut f = board(name);
        f.host
            .open_accounts(
                &mut f.machine,
                vec!["DEMO".into(), "NORMAL".into(), "USER".into()],
            )
            .expect("opened");
        f
    }

    fn term() -> Terminal {
        Terminal { ansi: true, width: 80, height: 24 }
    }

    fn signup(f: &mut Fixture, who: &str, pw: &str) -> Resolved {
        f.host
            .resolve_login(
                &mut f.machine,
                &Login::Signup { userid: who.into(), password: pw.into() },
                term(),
            )
            .expect("no engine fault")
            .expect("accepted")
    }

    /// Change one account record in the file itself, the way the `mbbs-user`
    /// CLI will: read it, change it, write it back at the same position. A
    /// `usracc` is fixed-length, so this is an in-place update.
    fn amend(f: &mut Fixture, userid: &str, change: impl FnOnce(&mut Usracc)) {
        let Host { btrieve, accounts, .. } = &mut f.host;
        let accounts = accounts.as_mut().expect("accounts are open");
        let (position, mut record) = accounts
            .find_account(btrieve, userid)
            .expect("no engine fault")
            .expect("the account exists");
        change(&mut record);
        btrieve
            .block_mut(accounts.accbb)
            .expect("the account block")
            .update(position, &record.bytes)
            .expect("written back");
    }

    fn set_flags(f: &mut Fixture, userid: &str, flags: u16) {
        amend(f, userid, |record| record.set_flags(flags));
    }

    fn set_curcls(f: &mut Fixture, userid: &str, class: &str) {
        amend(f, userid, |record| {
            let field = &mut record.bytes[at::CURCLS..at::CURCLS + KEYSIZ];
            field.fill(0);
            field[..class.len()].copy_from_slice(class.as_bytes());
        });
    }

    fn write_ring(f: &mut Fixture, owner: &str, keys: &[&str]) {
        let Host { btrieve, accounts, .. } = &mut f.host;
        let accounts = accounts.as_mut().expect("accounts are open");
        let ring = Keyrec {
            owner: owner.to_string(),
            keys: keys.iter().map(|key| (*key).to_string()).collect(),
        };
        accounts.write_ring(btrieve, &ring).expect("written");
    }

    fn read_ring(f: &mut Fixture, owner: &str) -> Keyrec {
        let Host { btrieve, accounts, .. } = &mut f.host;
        let accounts = accounts.as_mut().expect("accounts are open");
        accounts
            .find_ring(btrieve, owner)
            .expect("no engine fault")
            .expect("a ring")
            .1
    }

    /// Every ring in the key file, in key order. What proves a replaced ring
    /// left nothing behind.
    fn rings(f: &mut Fixture) -> Vec<Keyrec> {
        let Host { btrieve, accounts, .. } = &mut f.host;
        let accounts = accounts.as_mut().expect("accounts are open");
        let block = btrieve.block_mut(accounts.keysbb).expect("the key block");
        let mut found = Vec::new();
        let mut op = Op::Lowest;
        while block.query(0, op, &[]).expect("no engine fault") {
            let record = block.current().expect("the record just found");
            found.push(Keyrec::from_bytes(&record.bytes));
            op = Op::Next;
        }
        found
    }

    fn delete_ring(f: &mut Fixture, owner: &str) {
        let Host { btrieve, accounts, .. } = &mut f.host;
        let accounts = accounts.as_mut().expect("accounts are open");
        let (position, _) = accounts
            .find_ring(btrieve, owner)
            .expect("no engine fault")
            .expect("a ring");
        btrieve
            .block_mut(accounts.keysbb)
            .expect("the key block")
            .delete(position)
            .expect("deleted");
    }

    #[test]
    fn a_fresh_board_gets_both_files_created_and_accbb_published() {
        let mut f = board("accounts-fresh");
        f.host
            .open_accounts(&mut f.machine, vec!["DEMO".into()])
            .expect("opened");
        let root = f.host.root.clone();
        assert!(root.join("bbsusr.dat").is_file());
        assert!(root.join("bbsk.dat").is_file());
        let accbb = f
            .host
            .globals()
            .pointer_mem(Wg16::mem_ref(&f.machine), "accbb")
            .expect("accbb readable");
        assert_ne!(accbb, Wg16::null_ptr(), "accbb points at the open block");
        assert_eq!(f.host.accounts().expect("open").stride, 338);
    }

    #[test]
    fn a_half_pair_refuses_by_name() {
        let mut f = board("accounts-half");
        std::fs::write(f.host.root.join("bbsk.dat"), b"").expect("stub");
        let err = f
            .host
            .open_accounts(&mut f.machine, vec![])
            .expect_err("refused");
        assert!(
            err.to_string()
                .contains("bbsk.dat exists but bbsusr.dat does not"),
            "{err}"
        );
    }

    #[test]
    fn the_other_abis_file_refuses_by_name() {
        let mut f = board("accounts-wrong-abi");
        std::fs::write(f.host.root.join("wgsusr2.dat"), b"").expect("stub");
        let err = f
            .host
            .open_accounts(&mut f.machine, vec![])
            .expect_err("refused");
        assert!(
            err.to_string().contains("wgsusr2.dat belongs to a Wg32 board"),
            "{err}"
        );
    }

    #[test]
    fn a_wrong_record_length_refuses_before_serving() {
        let mut f = board("accounts-wrong-stride");
        let mut spec = super::account_spec(304);
        spec.acs = Some(btrieve::acs::allcaps());
        btrieve::create(&f.host.root.join("bbsusr.dat"), &spec).expect("wrong-stride file");
        btrieve::create(&f.host.root.join("bbsk.dat"), &super::key_spec()).expect("key file");
        let err = f
            .host
            .open_accounts(&mut f.machine, vec![])
            .expect_err("refused");
        assert!(
            err.to_string()
                .contains("304-byte records; this host's usracc is 338"),
            "{err}"
        );
    }

    #[test]
    fn the_second_opener_is_refused_by_the_lock() {
        let mut f = board("accounts-lock");
        f.host
            .open_accounts(&mut f.machine, vec![])
            .expect("opened");
        let err = super::lock_file(&f.host.root.join("bbsusr.dat")).expect_err("held");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn the_other_abis_file_is_named_before_a_half_pair_is() {
        let mut f = board("accounts-order");
        std::fs::write(f.host.root.join("wgsusr2.dat"), b"").expect("stub");
        std::fs::write(f.host.root.join("bbsk.dat"), b"").expect("stub");
        let err = f
            .host
            .open_accounts(&mut f.machine, vec![])
            .expect_err("refused");
        assert!(
            err.to_string().contains("wgsusr2.dat belongs to a Wg32 board"),
            "a foreign account file beside our key file is the wrong generation, \
             not half a pair: {err}"
        );
    }

    #[test]
    fn a_second_open_is_refused() {
        let mut f = board("accounts-twice");
        f.host
            .open_accounts(&mut f.machine, vec![])
            .expect("opened");
        let err = f
            .host
            .open_accounts(&mut f.machine, vec![])
            .expect_err("refused");
        assert!(err.to_string().contains("already open"), "{err}");
    }

    #[test]
    fn a_created_pair_has_the_kits_measured_shape() {
        let mut f = board("accounts-shape");
        f.host
            .open_accounts(&mut f.machine, vec![])
            .expect("opened");
        let account = btrieve::Geometry::read("bbsusr.dat", &f.host.root.join("bbsusr.dat"))
            .expect("readable");
        assert_eq!((account.reclen, account.page, account.keys), (338, 1024, 1));
        assert!(!account.variable, "a usracc is fixed-length");
        let keys =
            btrieve::Geometry::read("bbsk.dat", &f.host.root.join("bbsk.dat")).expect("readable");
        assert_eq!((keys.reclen, keys.page, keys.keys), (31, 1024, 1));
        assert!(keys.variable, "a key ring is the variable tail of a keyrec");
    }

    #[test]
    fn the_open_pair_is_remembered_whole() {
        let mut f = board("accounts-remembered");
        let terms = f.host.users().terms().count();
        f.host
            .open_accounts(&mut f.machine, vec!["DEMO".into(), "NORMAL".into()])
            .expect("opened");
        let accounts = f.host.accounts().expect("open");
        assert_ne!(accounts.keysbb, Wg16::null_ptr(), "the key block is open");
        assert_ne!(
            accounts.userid_scratch,
            Wg16::null_ptr(),
            "dlarou has its 30 bytes"
        );
        assert_eq!(accounts.default_ring, ["DEMO", "NORMAL"]);
        assert_eq!(accounts.sessions.len(), usize::from(terms));
    }

    #[test]
    fn signup_then_password_login_round_trips_the_default_ring() {
        let mut f = opened("resolve-signup");
        let r = signup(&mut f, "Dan", "hunter2");
        assert_eq!(r.connection.userid, "Dan");
        assert!(r.connection.keys.evaluate("NORMAL"));
        assert!(!r.connection.keys.evaluate("SYSOP"));
        let again = f
            .host
            .resolve_login(
                &mut f.machine,
                &Login::Password { userid: "dan".into(), password: "HUNTER2".into() },
                term(),
            )
            .expect("no fault")
            .expect("case-insensitive on both");
        assert_eq!(again.position, r.position);
    }

    #[test]
    fn every_refusal_has_a_cause() {
        let mut f = opened("resolve-refusals");
        let pw = |u: &str, p: &str| Login::Password { userid: u.into(), password: p.into() };
        assert_eq!(
            f.host
                .resolve_login(&mut f.machine, &pw("Nobody", "x"), term())
                .unwrap()
                .unwrap_err(),
            Refusal::Unknown
        );
        signup(&mut f, "Dan", "hunter2");
        assert_eq!(
            f.host
                .resolve_login(&mut f.machine, &pw("Dan", "wrong"), term())
                .unwrap()
                .unwrap_err(),
            Refusal::BadPassword
        );
        assert_eq!(
            f.host
                .resolve_login(
                    &mut f.machine,
                    &Login::Signup { userid: "Dan".into(), password: "x".into() },
                    term()
                )
                .unwrap()
                .unwrap_err(),
            Refusal::Exists
        );
        // A provisioned account has no password and telnet is refused.
        f.host
            .resolve_login(
                &mut f.machine,
                &Login::Trusted { userid: "Guest".into(), sysop: false },
                term(),
            )
            .unwrap()
            .expect("provisioned");
        assert_eq!(
            f.host
                .resolve_login(&mut f.machine, &pw("Guest", ""), term())
                .unwrap()
                .unwrap_err(),
            Refusal::NoPassword
        );
        // Flags. Set them straight in the file through the block.
        set_flags(&mut f, "Dan", flags::DELTAG);
        assert_eq!(
            f.host
                .resolve_login(&mut f.machine, &pw("Dan", "hunter2"), term())
                .unwrap()
                .unwrap_err(),
            Refusal::Deleted
        );
        assert_eq!(
            f.host
                .resolve_login(
                    &mut f.machine,
                    &Login::Trusted { userid: "Dan".into(), sysop: false },
                    term()
                )
                .unwrap()
                .unwrap_err(),
            Refusal::Deleted
        );
        set_flags(&mut f, "Dan", flags::SUSPEN);
        assert_eq!(
            f.host
                .resolve_login(&mut f.machine, &pw("Dan", "hunter2"), term())
                .unwrap()
                .unwrap_err(),
            Refusal::Suspended
        );
        assert_eq!(
            f.host
                .resolve_login(
                    &mut f.machine,
                    &Login::Signup { userid: "&Ring".into(), password: "x".into() },
                    term()
                )
                .unwrap()
                .unwrap_err(),
            Refusal::Invalid("a user ID must start with a letter or digit")
        );
    }

    #[test]
    fn master_comes_from_hasmst_and_the_door_grant_is_session_only() {
        let mut f = opened("resolve-master");
        signup(&mut f, "Dan", "hunter2");
        set_flags(&mut f, "Dan", flags::HASMST);
        let r = f
            .host
            .resolve_login(
                &mut f.machine,
                &Login::Password { userid: "Dan".into(), password: "hunter2".into() },
                term(),
            )
            .unwrap()
            .unwrap();
        assert!(r.connection.keys.is_master());
        let d = f
            .host
            .resolve_login(
                &mut f.machine,
                &Login::Trusted { userid: "Door".into(), sysop: true },
                term(),
            )
            .unwrap()
            .unwrap();
        assert!(d.connection.keys.evaluate("WCCSYSOP"));
        let ring = read_ring(&mut f, "Door");
        assert_eq!(
            ring.keys,
            ["DEMO", "NORMAL", "USER"],
            "the door's sysop keys were not written to the file"
        );
    }

    #[test]
    fn the_class_ring_is_loaded_when_curcls_names_one() {
        let mut f = opened("resolve-class-ring");
        signup(&mut f, "Dan", "hunter2");
        write_ring(&mut f, "&STAFF", &["MODERATE", "MASS_MAIL"]);
        set_curcls(&mut f, "Dan", "STAFF");
        let r = f
            .host
            .resolve_login(
                &mut f.machine,
                &Login::Password { userid: "Dan".into(), password: "hunter2".into() },
                term(),
            )
            .unwrap()
            .unwrap();
        assert!(r.connection.keys.evaluate("MASS_MAIL"));
        set_curcls(&mut f, "Dan", "NOSUCH");
        let r = f
            .host
            .resolve_login(
                &mut f.machine,
                &Login::Password { userid: "Dan".into(), password: "hunter2".into() },
                term(),
            )
            .unwrap()
            .unwrap();
        assert!(
            !r.connection.keys.evaluate("MASS_MAIL"),
            "a missing class ring is skipped, not fatal"
        );
    }

    #[test]
    fn a_missing_own_ring_is_written_blank() {
        let mut f = opened("resolve-blank-ring");
        signup(&mut f, "Dan", "hunter2");
        delete_ring(&mut f, "Dan");
        let r = f
            .host
            .resolve_login(
                &mut f.machine,
                &Login::Password { userid: "Dan".into(), password: "hunter2".into() },
                term(),
            )
            .unwrap()
            .unwrap();
        assert!(!r.connection.keys.evaluate("DEMO"));
        assert_eq!(
            read_ring(&mut f, "Dan").keys,
            Vec::<String>::new(),
            "a blank record now exists, as loadkeys writes one"
        );
    }

    #[test]
    fn replacing_a_ring_writes_one_record_and_not_two() {
        let mut f = opened("resolve-replace-ring");
        write_ring(&mut f, "Dan", &["DEMO"]);
        write_ring(&mut f, "Dan", &["DEMO", "NORMAL", "USER"]);
        assert_eq!(read_ring(&mut f, "Dan").keys, ["DEMO", "NORMAL", "USER"]);
        assert_eq!(
            rings(&mut f).len(),
            1,
            "a longer ring replaced the shorter one rather than joining it"
        );
    }

    #[test]
    fn the_console_hears_about_both_missing_rings() {
        let mut f = opened("resolve-ring-notes");
        signup(&mut f, "Dan", "hunter2");
        delete_ring(&mut f, "Dan");
        set_curcls(&mut f, "Dan", "STAFF");
        let _ = f.host.drain_notes();
        f.host
            .resolve_login(
                &mut f.machine,
                &Login::Password { userid: "Dan".into(), password: "hunter2".into() },
                term(),
            )
            .unwrap()
            .unwrap();
        let notes = f.host.drain_notes();
        assert!(
            notes.iter().any(|note| note
                == "MISSING A USER'S KEYRING RECORD (Dan has been given a blank keyring record.)"),
            "{notes:?}"
        );
        assert!(
            notes
                .iter()
                .any(|note| note
                    == "MISSING A CLASS KEYRING RECORD (STAFF class has no keyring record.)"),
            "{notes:?}"
        );
    }

    #[test]
    fn a_board_with_no_account_files_says_so_rather_than_resolving() {
        let mut f = board("resolve-unopened");
        let why = f
            .host
            .resolve_login(
                &mut f.machine,
                &Login::Password { userid: "Dan".into(), password: "hunter2".into() },
                term(),
            )
            .expect_err("a host that never opened a pair cannot answer");
        assert_eq!(why, "accounts are not open");
    }

    /// `DELTAG` and `SUSPEN` are separate bits and an account can carry
    /// both. Which of the two is reported is a rule, not an accident of
    /// which arm happens to run first.
    #[test]
    fn deletion_is_reported_before_suspension_when_an_account_has_both() {
        let mut f = opened("resolve-deleted-and-suspended");
        signup(&mut f, "Dan", "hunter2");
        set_flags(&mut f, "Dan", flags::DELTAG | flags::SUSPEN);
        assert_eq!(
            f.host
                .resolve_login(
                    &mut f.machine,
                    &Login::Password { userid: "Dan".into(), password: "hunter2".into() },
                    term()
                )
                .unwrap()
                .unwrap_err(),
            Refusal::Deleted,
            "a deleted account is gone, not merely stopped"
        );
        assert_eq!(
            f.host
                .resolve_login(
                    &mut f.machine,
                    &Login::Trusted { userid: "Dan".into(), sysop: false },
                    term()
                )
                .unwrap()
                .unwrap_err(),
            Refusal::Deleted
        );
    }
}
