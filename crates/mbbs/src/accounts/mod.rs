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
// Every field here is written by `Host::open_accounts` and read by the steps
// that follow it: accbb and keysbb by the claim and ring paths, stride and
// default_ring by the record writer, sessions by the login path,
// userid_scratch by the maintenance purge. None of those exist yet. And lock
// is never read by anything, ever: the value is the lock, and dropping it is
// what releases it. So the lint is right about today and wrong about the
// design. This says so rather than widening the fields to pub to keep it
// quiet, and it comes off with the login path.
#[allow(dead_code)]
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
    pub(crate) lock: std::fs::File,
    /// Each channel's account session, indexed by [`Chan::index`](crate::Chan::index).
    pub(crate) sessions: Vec<Option<Session>>,
    /// 30 bytes of module memory holding the userid `dlarou` is called with
    /// during the maintenance purge.
    ///
    /// Reserved once here rather than per call because the purge dispatches
    /// it inside a sweep over every deleted account in every module, and a
    /// fresh allocation per call would draw on the same finite descriptor
    /// pool the module's own heap grows from.
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

#[cfg(test)]
mod tests {
    use crate::abi::{Abi, Wg16};
    use crate::testing::{scratch, Fixture};

    fn board(name: &str) -> Fixture {
        let root = scratch(name);
        Fixture::rooted(root)
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
}
