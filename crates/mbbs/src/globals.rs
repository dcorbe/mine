//! The host's globals, in memory the module can address.
//!
//! These are the imports a module never *calls*. `MAJORBBS.H` declares them,
//! `MAJORBBS.DLL` exports them, and a module's fixups take their
//! `selector:offset` and read and write them directly. The host is never told
//! when that happens, so a global is not a Rust value with a mirror in module
//! memory -- it is *in* module memory, and the host reads and writes it there.
//! Keeping a second copy on the Rust side is the bug this module is shaped to
//! prevent: the module updates `margc` and `prfptr` without telling anyone.
//!
//! # Where the sizes come from
//!
//! `archive/galacticomm/extract/wg1/GALDSRC/SRC/` -- Galacticomm's own
//! Worldgroup 1.01 host source, the version whose export table
//! [`Exports::wg101`](crate::Exports::wg101) resolves against. `MAJORBBS.H`,
//! `GCOMM.H`, `FSD.H` and `DOSFACE.H` between them declare every one of these
//! with its exact type, so none of it is guesswork.
//!
//! # Why the order is not arbitrary
//!
//! Every global has a fixup of its own, so the host is free to place each one
//! anywhere -- with one exception it cannot see coming. `WCCMMUD.DLL` addresses
//! `margv` with an addend of `0xfffe`, which is `-2`: the word *before* it.
//! Whether that is a genuine read or a folded `margv[n-1]` index, laying the
//! globals out in the order `MAJORBBS.H` declares them serves both readings,
//! because it puts the last word of `input[INPSIZ]` exactly where the module
//! looks. The cost of honouring the declaration order is nothing; the cost of
//! not is a wrong word read silently.
//!
//! So the groups below are the C declarations, kept together and in sequence.
//! Globals `WCCMMUD.DLL` never mentions are laid out anyway when they share a
//! declaration with one it does, because that is what makes the order real.

use std::collections::HashMap;
use std::io;

use mbbs16::{FarPtr, Machine};

use crate::abi::{Abi, ModuleMem, Wg16};

/// `MAJORBBS.H:23` -- input buffer size for each channel.
const INPSIZ: u16 = 256;
/// `MAJORBBS.H:398` -- max number of global command handlers.
const GLBMAX: u16 = 50;
/// `FSD.H:243` -- maximum length of a help field, which sizes `fsdemg`.
const MAXHLP: u16 = 80;
/// `TFSCAN.H:14` -- max characters per line, plus the NUL.
const MAXTFS: u16 = 129;
/// `GALACTH.H:18` -- sysid size.
const SIDSIZ: u16 = 5;
/// `BBSUTILS.H:18` -- size of the ASCII rendition of a version.
const VERSIZ: u16 = 9;

/// A far pointer, as 16-bit C stores one: offset then selector.
const PTR: u16 = 4;
/// An `int`, which is 16 bits in every compiler that ever built one of these.
const INT: u16 = 2;
/// A `long`.
const LONG: u16 = 4;

/// `MAJORBBS.H:287` -- `struct sysvbl`, the system-variable Btrieve record.
/// Its own `spare[]` field pads it to exactly this, so the number is the
/// struct's and not a guess at it.
const SYSVBL: u16 = 1300;

/// One host global: the DLL and name a module imports it by, and how many
/// bytes it is.
pub struct Global {
    pub dll: &'static str,
    pub name: &'static str,
    pub size: u16,
}

/// A `MAJORBBS` global.
const fn g(name: &'static str, size: u16) -> Global {
    Global {
        dll: crate::exports::MAJORBBS,
        name,
        size,
    }
}

/// A `GALGSBL` global -- the serial-board library's, not the executive's.
const fn s(name: &'static str, size: u16) -> Global {
    Global {
        dll: crate::exports::GALGSBL,
        name,
        size,
    }
}

/// Every global the host places, in `MAJORBBS.H` declaration order.
///
/// The comment on each group names the declaration it came from, so that a
/// disagreement with the header is visible without opening the header.
pub const GLOBALS: &[Global] = &[
    // MAJORBBS.H:384 -- char input[INPSIZ], *margv[INPSIZ/2], *margn[INPSIZ/2],
    // *nxtcmd; ... and the reason this file cares about order at all.
    g("input", INPSIZ),
    g("margv", INPSIZ / 2 * PTR),
    g("margn", INPSIZ / 2 * PTR),
    g("nxtcmd", PTR),
    // MAJORBBS.H:389 -- int margc, inplen, pfnlvl, pfceil, status, shortm,
    // numcat;
    g("margc", INT),
    g("inplen", INT),
    g("pfnlvl", INT),
    g("pfceil", INT),
    g("status", INT),
    g("shortm", INT),
    g("numcat", INT),
    // MAJORBBS.H:339 -- int nterms, hichp1, usrnum, othusn, uisusn;
    g("nterms", INT),
    g("hichp1", INT),
    g("usrnum", INT),
    g("othusn", INT),
    g("uisusn", INT),
    // MAJORBBS.H:345 -- struct user *user, *usrptr, *othusp;
    g("user", PTR),
    g("usrptr", PTR),
    g("othusp", PTR),
    // MAJORBBS.H:400 -- int nglobs, (*globs[GLBMAX])();
    g("nglobs", INT),
    g("globs", GLBMAX * PTR),
    // GCOMM.H:449 -- char *prfbuf, *prfptr;
    g("prfbuf", PTR),
    g("prfptr", PTR),
    // GCOMM.H:282 -- FILE *curmbk; the message block `stgopt` and the rest
    // read from. `WCCMMUD.DLL` does not address it -- the load check would say
    // so -- but it is placed here anyway, because a host global belongs in
    // module memory whether or not this particular module looks at it. Keeping
    // it Rust-side instead is the exact shape of the bug that rule prevents.
    g("curmbk", PTR),
    // MAJORBBS.H:443 -- char *vdaptr, *vdatmp;
    g("vdaptr", PTR),
    g("vdatmp", PTR),
    // MAJORBBS.H:440 -- int vdasiz;
    g("vdasiz", INT),
    // MAJORBBS.H:74 -- struct usracc *usaptr;
    g("usaptr", PTR),
    // MAJORBBS.H:156, :489 -- BTVFILE *accbb, *genbb;
    g("accbb", PTR),
    g("genbb", PTR),
    // BTVSTF.H:36 -- struct btvblk *bb; the Btrieve file every one of `opnbtv`,
    // `setbtv`, `cntrbtv` and the rest works on. `WCCMMUD.DLL` does not address
    // it, the same as `curmbk`, and it is placed here for the same reason: a
    // host global belongs in module memory whether or not this module reads it,
    // and the stack behind it in `PLBTVSTF.C` is a `static` that does not.
    g("bb", PTR),
    // MAJORBBS.H:286 -- struct sysvbl sv; addressed with addends up to 452, so
    // this one has to be the field-accurate 1,300 and not merely large enough.
    g("sv", SYSVBL),
    // MAJORBBS.H:282 -- struct textvar *txtvars;
    g("txtvars", PTR),
    // MAJORBBS.H:356 -- int *channel;
    g("channel", PTR),
    // MAJORBBS.H:614 -- void (*syscyc)(void);
    g("syscyc", PTR),
    // FSD.H:417, :423 -- struct fsdscb *fsdscb; char fsdemg[MAXHLP];
    g("fsdscb", PTR),
    g("fsdemg", MAXHLP),
    // FSD.H:54 -- int (*bgnedt)(...);
    g("bgnedt", PTR),
    // TFSCAN.H:17 -- int tfstate; char *tfspst; char tfsbuf[MAXTFS];
    g("tfstate", INT),
    g("tfspst", PTR),
    g("tfsbuf", MAXTFS),
    // GALACTH.H:33 -- char msysid[SIDSIZ];
    g("msysid", SIDSIZ),
    // BBSUTILS.H:29 -- char version[VERSIZ];
    g("version", VERSIZ),
    // DSKUTL.H:23-26 -- long numfils, numbyts, numbytp, numdirs; the counters
    // `cntdir` and `cntdirs` report through. `WCCMMUD.DLL` addresses only
    // `numbyts`, and the other three are placed anyway for the reason `curmbk`
    // and `bb` are: they are one routine's output, and keeping part of it
    // Rust-side is the bug this file is shaped to prevent.
    //
    // `ztzone` on the line above them is not placed. It is not `cntdir`'s, and
    // nothing in this host knows what to put in it.
    g("numfils", LONG),
    g("numbyts", LONG),
    g("numbytp", LONG),
    g("numdirs", LONG),
    // SAPUTL.H:93 -- struct saunam *namtmp;
    g("namtmp", PTR),
    // USRACC.H:59 -- a pointer to the array of user IDs.
    g("uidarr", PTR),
    // Borland's own ctype table: 257 bytes, indexed from -1, so that
    // `(_ctype+1)[c]` is in range for every `char` and for EOF.
    g("_ctype", CTYPE_LEN),
    // Borland's exit hooks. C0 leaves them null and stdio fills them in; a
    // module that never calls exit() never looks. Placed because the module
    // imports them, and zero is what they legitimately hold.
    g("_exitbuf", PTR),
    g("_exitfopen", PTR),
    g("_exitopen", PTR),
    // BRKTHU.H:108 -- char bturno[]; the GSBL registration number, unsized in
    // the header and printed as `%.9s` at ABOUT.C:85. MajorMUD reads it at
    // 1,096 sites: its activation code is a function of the board's serial.
    s("bturno", BTURNO),
];

/// Bytes of `bturno`. Eight digits and a NUL, which is what `%.9s` prints.
const BTURNO: u16 = 9;

/// Bytes in Borland's `_ctype` table: one per `char`, plus the entry at index
/// -1 that makes `(_ctype+1)[EOF]` legal.
const CTYPE_LEN: u16 = 257;

/// Bits in a `_ctype` entry, as Borland's `CTYPE.H` defines them.
///
/// The layout is not derivable from anything in this repository -- Borland's
/// headers are not among the recovered sources -- so it is taken from MBBSEmu's
/// reading of `CTYPE.H`, which is the only independent transcription available.
/// What is *not* taken from there is the table's contents: MBBSEmu builds it
/// with a chain of mutually exclusive branches, so its digits are not hex
/// digits, its letters `A`-`F` are not hex digits, and its control characters
/// carry no flag at all. Those are bugs in a lookup table, and a module asking
/// `isxdigit('c')` would get the wrong answer from it.
mod ctype {
    pub const SPACE: u8 = 0x01;
    pub const DIGIT: u8 = 0x02;
    pub const UPPER: u8 = 0x04;
    pub const LOWER: u8 = 0x08;
    pub const HEX: u8 = 0x10;
    pub const CONTROL: u8 = 0x20;
    pub const PUNCT: u8 = 0x40;

    /// The space character itself, and nothing else -- a tab has [`SPACE`] and
    /// not this. `isprint` tests it and `isspace` does not, which is the whole
    /// reason it is a separate bit.
    ///
    /// Not in MBBSEmu's reading of `CTYPE.H`, and the one entry of 257 that the
    /// reconstruction below got wrong before the binary was measured. See
    /// `ctype_is_the_table_the_host_binary_carries`.
    pub const SPACE_CHAR: u8 = 0x80;
}

/// Borland's `_ctype` table, built from what the C library's predicates mean.
///
/// `(_ctype+1)[c]` is what the macros index, so entry 0 stands for `EOF` and
/// entry `c + 1` for character `c`.
///
/// **Checked against the host binary, not merely reasoned about.** The 257
/// bytes at `DGROUP:0x1a08` of `MAJORBBS-wg101.EXE` are pinned by
/// `ctype_is_the_table_the_host_binary_carries`, and the construction below
/// agreed with 256 of them. The one it did not is the space -- see
/// [`ctype::SPACE_CHAR`].
fn ctype_table() -> [u8; CTYPE_LEN as usize] {
    let mut table = [0u8; CTYPE_LEN as usize];
    for c in 0u8..=255 {
        let mut bits = 0;
        if c.is_ascii_digit() {
            bits |= ctype::DIGIT | ctype::HEX;
        }
        if c.is_ascii_uppercase() {
            bits |= ctype::UPPER;
        }
        if c.is_ascii_lowercase() {
            bits |= ctype::LOWER;
        }
        if c.is_ascii_hexdigit() {
            bits |= ctype::HEX;
        }
        if c.is_ascii_punctuation() {
            bits |= ctype::PUNCT;
        }
        if c.is_ascii_whitespace() || c == 0x0b {
            bits |= ctype::SPACE;
        }
        if c == b' ' {
            bits |= ctype::SPACE_CHAR;
        }
        if c.is_ascii_control() {
            bits |= ctype::CONTROL;
        }
        table[usize::from(c) + 1] = bits;
    }
    table
}

/// How large the print buffer is.
///
/// `MAJORBBS.C:572` reads it as `outbsz=numopt(OUTBSZ,4096,16384)` -- a config
/// option with those bounds. Reading the config needs the message-file parser,
/// which does not exist yet, so this is the low end of the range the host
/// itself would accept. A module that sizes something off `PFBSIZ` would
/// notice, which is the one way this guess is observable.
pub const OUTBSZ: u16 = 4096;

/// The single-channel case: what `nterms` is on a host with only its console.
///
/// **Not "how many channels this host has"** -- a host has as many as the
/// caller handed [`Host::new`](crate::Host::new), which takes a
/// [`Terms`](crate::Terms) and reads no constant of its own. What this is
/// instead is the *one-channel* shape, and it is worth a name for two reasons:
/// it is what `MAJORBBS.C:80` and `GMEOFF.C:23` say the offline host always
/// has, and it is the count every meter in this crate was measured against.
/// `Terms::new(NTERMS)` at a call site says "one channel, deliberately" where a
/// bare `1` would say nothing.
///
/// `nterms` is what the module bounds its own loops by -- and what `curusr`'s
/// `uno < nterms` guard admits -- so a per-channel table shorter than `nterms`
/// is a table the module indexes past the end of, with no error anywhere. That
/// is why the count reaches the globals, [`Users`](crate::Users)' tables and
/// [`Gsbl`](crate::gsbl::Gsbl)'s channels as one `Terms` value threaded from
/// one place, rather than as three separate reads of this constant, which is
/// how three copies of one number came to agree only by convention -- see
/// [`crate::chan`].
///
/// One is not a placeholder; see the `nterms` write in [`Globals::new`] for
/// where that comes from.
pub const NTERMS: u16 = 1;

/// The host's globals, placed in a region the module can address.
///
/// # Generic type, `Wg16`-concrete body
///
/// `base` and `prf` are typed `A::Ptr` rather than `FarPtr` so this struct is
/// genuinely `Globals<A>` -- but every method stays in `impl Globals<Wg16>`
/// below, using `&mut Machine` exactly as before. Nothing here places more
/// than two regions, ever (the globals block, and `prfbuf`'s own small one),
/// so unlike `Heap`/`Arena` there is no growable-pool algorithm worth writing
/// once and sharing; the only thing this task's scope actually requires is
/// that construction goes through
/// [`ModuleMem::alloc_region`](crate::abi::ModuleMem::alloc_region) rather
/// than `Machine::alloc_segment` directly, which it now does. `A` defaults to
/// [`Wg16`] so every existing caller keeps naming this type as plain
/// `Globals`.
pub struct Globals<A: Abi = Wg16> {
    base: A::Ptr,
    offsets: HashMap<&'static str, u16>,
    sizes: HashMap<&'static str, u16>,
    /// Where `prfbuf` points: the print buffer, in a region of its own so that
    /// a module overrunning it cannot reach the globals.
    prf: A::Ptr,
}

impl Globals<Wg16> {
    /// Place every global, and initialise the ones that are not zero.
    ///
    /// # Errors
    ///
    /// If the regions cannot be mapped.
    pub fn new(machine: &mut Machine, terms: crate::Terms) -> io::Result<Self> {
        let mut offsets = HashMap::with_capacity(GLOBALS.len());
        let mut sizes = HashMap::with_capacity(GLOBALS.len());
        let mut at = 0u16;
        for global in GLOBALS {
            // Even addresses, as a 16-bit compiler would place them. The 286
            // does not care, but a layout that matches the one the header
            // describes is one fewer difference to reason about.
            at = at.next_multiple_of(2);
            offsets.insert(global.name, at);
            sizes.insert(global.name, global.size);
            at += global.size;
        }

        let base = machine.mem_mut().alloc_region(usize::from(at))?;
        let prf = machine.mem_mut().alloc_region(usize::from(OUTBSZ))?;

        let globals = Self {
            base,
            offsets,
            sizes,
            prf,
        };

        // `prfbuf` and `prfptr` are `char *`, not the buffer -- GCOMM.H:449.
        // The module reads `prfbuf[0]` to ask whether anything is queued, so
        // they have to be real far pointers into real memory from the start.
        globals.write(machine, "prfbuf", &prf.to_bytes())?;
        globals.write(machine, "prfptr", &prf.to_bytes())?;
        globals.write(machine, "_ctype", &ctype_table())?;

        // MAJORBBS.C:80-81 -- `int nterms=1, hichp1=1;`. Both were set before
        // any module's init ran, `:557` only ever adds configured groups to
        // `nterms`, and `:569` catastros above 256. There is no path to zero,
        // so leaving these at the zero they are born with hands the module a
        // number the real host never produced.
        //
        // One is not a placeholder. `GMEOFF.C:23` is Galacticomm's *offline*
        // host -- modules initialised with nobody connected, which is exactly
        // what this host is -- and it declares
        // `int nterms;  /* number of channels (always 1) */`, set by
        // `iniogme()`. When this host learns what a channel is, that is what
        // changes this.
        //
        // `terms` is passed in rather than read from `NTERMS` here, so that the
        // number the module sees and the number the host's tables are sized by
        // are the same value and not two reads of one constant.
        globals.write(machine, "nterms", &terms.count().to_le_bytes())?;
        globals.write(machine, "hichp1", &terms.count().to_le_bytes())?;

        // MAJORBBS.C:882 -- `usrnum=-1;`, set immediately before `inimod()`
        // runs every module's init routine. See the test for why the zero it
        // is born with is a lie and not a placeholder.
        globals.write(machine, "usrnum", &(-1i16).to_le_bytes())?;

        Ok(globals)
    }

    /// The segment the globals live in.
    pub fn selector(&self) -> u16 {
        self.base.selector
    }

    /// Where the print buffer starts.
    pub fn prf_buffer(&self) -> FarPtr {
        self.prf
    }

    /// Where a global lives, or `None` for a name the host does not place.
    pub fn address(&self, name: &str) -> Option<FarPtr> {
        Some(FarPtr {
            offset: *self.offsets.get(name)?,
            selector: self.base.selector,
        })
    }

    /// How many bytes a global occupies, or `None` for one the host does not
    /// place.
    pub fn size(&self, name: &str) -> Option<u16> {
        self.sizes.get(name).copied()
    }

    /// Overwrite a global.
    ///
    /// # Errors
    ///
    /// If `name` is not a global, or `bytes` is longer than it.
    pub fn write(&self, machine: &mut Machine, name: &str, bytes: &[u8]) -> io::Result<()> {
        let at = self
            .address(name)
            .ok_or_else(|| io::Error::other(format!("{name} is not a host global")))?;
        let size = usize::from(self.size(name).expect("placed, so it has a size"));
        if bytes.len() > size {
            return Err(io::Error::other(format!(
                "{} bytes will not fit in {name}, which is {size}",
                bytes.len()
            )));
        }
        machine.write(at, bytes).map_err(io::Error::other)
    }

    /// Read a global as a word.
    ///
    /// Read rather than remembered. `margc` and `tfstate` are the host's
    /// globals but the module's to change.
    ///
    /// # Errors
    ///
    /// If `name` is not a global.
    pub fn word(&self, machine: &Machine, name: &str) -> io::Result<u16> {
        let at = self
            .address(name)
            .ok_or_else(|| io::Error::other(format!("{name} is not a host global")))?;
        let bytes = machine.resolve(at, 2).map_err(io::Error::other)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a global as a `long`.
    ///
    /// Signed, because C's `long` is: `numfils` and the rest are declared
    /// `long` in `DSKUTL.H`, and a reader that widened them as unsigned would
    /// report `4294967295` where the module would read `-1`.
    ///
    /// # Errors
    ///
    /// If `name` is not a global.
    pub fn long(&self, machine: &Machine, name: &str) -> io::Result<i32> {
        let at = self
            .address(name)
            .ok_or_else(|| io::Error::other(format!("{name} is not a host global")))?;
        let bytes = machine.resolve(at, 4).map_err(io::Error::other)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a global as a far pointer.
    ///
    /// # Errors
    ///
    /// If `name` is not a global.
    pub fn pointer(&self, machine: &Machine, name: &str) -> io::Result<FarPtr> {
        let at = self
            .address(name)
            .ok_or_else(|| io::Error::other(format!("{name} is not a host global")))?;
        let bytes = machine.resolve(at, 4).map_err(io::Error::other)?;
        Ok(FarPtr {
            offset: u16::from_le_bytes([bytes[0], bytes[1]]),
            selector: u16::from_le_bytes([bytes[2], bytes[3]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cntdirs_counters_are_placed_in_declaration_order() {
        // DSKUTL.H:23-26 declares numfils, numbyts, numbytp, numdirs, in that
        // order and as four longs. `cntdir` writes the first three and
        // `cntdirs` the fourth, so all four belong in module memory whether or
        // not this module addresses them -- WCCMMUD.DLL addresses only
        // `numbyts`, at six sites.
        let f = crate::testing::Fixture::new();
        let g = f.host.globals();
        let at = |name| g.address(name).expect("placed").offset;
        for name in ["numfils", "numbyts", "numbytp", "numdirs"] {
            assert_eq!(g.size(name), Some(4), "{name} is a long");
        }
        assert!(at("numfils") < at("numbyts"));
        assert!(at("numbyts") < at("numbytp"));
        assert!(at("numbytp") < at("numdirs"));
    }

    #[test]
    fn a_long_global_reads_back_signed() {
        // `long` is signed, and the counters are the only globals this host
        // reads four bytes of. A reader that widened them as unsigned would
        // agree with a writer that overflowed.
        let mut f = crate::testing::Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "numbyts", &(-1i32).to_le_bytes())
            .expect("write");
        assert_eq!(
            f.host.globals().long(&f.machine, "numbyts").expect("read"),
            -1
        );
    }

    #[test]
    fn the_channel_count_is_one_before_a_module_reads_it() {
        // `MAJORBBS.C:80-81` declares both of these `=1` and the real host had
        // them set long before any module's init ran. Zero is a value neither
        // ever held -- and MajorMUD's initialisation multiplies `nterms` by 8
        // and hands the result to `alczer`, so a zero here is an allocation of
        // nothing that the module then indexes.
        let f = crate::testing::Fixture::new();
        assert_eq!(f.host.globals().word(&f.machine, "nterms").expect("nterms"), 1);
        assert_eq!(f.host.globals().word(&f.machine, "hichp1").expect("hichp1"), 1);
    }

    #[test]
    fn nobody_is_the_current_user_before_one_connects() {
        // `MAJORBBS.C:882` -- `usrnum=-1;`, three lines above the `inimod()`
        // that runs every module's init routine. Zero is not "no current user":
        // it is channel 0, and `WCCMMUD.DLL` indexes its own per-channel tables
        // by `usrnum` at 61 sites. A module initialising with `usrnum == 0`
        // writes into the slot belonging to whoever connects first.
        //
        // -1 is safe to read because `channel[]` carries sentinels for exactly
        // this -- see `the_channel_table_has_three_sentinels_before_it`.
        let f = crate::testing::Fixture::new();
        let usrnum = f.host.globals().word(&f.machine, "usrnum").expect("usrnum");
        assert_eq!(usrnum as i16, -1);
    }

    #[test]
    fn the_globals_fit_in_one_segment() {
        let total: u32 = GLOBALS
            .iter()
            .map(|g| u32::from(g.size).next_multiple_of(2))
            .sum();
        assert!(total < 64 * 1024, "{total} bytes of globals");
    }

    #[test]
    fn no_global_is_placed_twice() {
        let mut names: Vec<&str> = GLOBALS.iter().map(|g| g.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "a global is in the table twice");
    }

    #[test]
    fn input_ends_where_margv_begins() {
        // The `0xfffe` addend on `margv` reaches the word before it. This is
        // the layout that makes that word the end of `input` rather than
        // whatever happened to be placed there.
        let mut at = 0u16;
        let mut placed = Vec::new();
        for global in GLOBALS {
            at = at.next_multiple_of(2);
            placed.push((global.name, at, global.size));
            at += global.size;
        }
        let input = placed.iter().find(|p| p.0 == "input").expect("input");
        let margv = placed.iter().find(|p| p.0 == "margv").expect("margv");
        assert_eq!(input.1 + input.2, margv.1, "margv must follow input");
        assert!(margv.1 >= 2, "margv[-1] must be inside the segment");
    }

    #[test]
    fn ctype_classifies_the_way_the_c_library_does() {
        let table = ctype_table();
        let of = |c: char| table[c as usize + 1];

        assert_eq!(of('0') & ctype::DIGIT, ctype::DIGIT);
        assert_eq!(of('A') & ctype::UPPER, ctype::UPPER);
        assert_eq!(of('a') & ctype::LOWER, ctype::LOWER);
        assert_eq!(of(' ') & ctype::SPACE, ctype::SPACE);
        assert_eq!(of(',') & ctype::PUNCT, ctype::PUNCT);
        assert_eq!(table[0x08 + 1] & ctype::CONTROL, ctype::CONTROL);

        // The three MBBSEmu's chain of mutually exclusive branches gets wrong.
        assert_eq!(of('7') & ctype::HEX, ctype::HEX, "a digit is a hex digit");
        assert_eq!(of('c') & ctype::HEX, ctype::HEX, "so is 'c'");
        assert_eq!(of('g') & ctype::HEX, 0, "'g' is not");

        // Nothing is both upper and lower, and a letter is not punctuation.
        for c in 0u8..=255 {
            let bits = table[usize::from(c) + 1];
            assert_ne!(
                bits & (ctype::UPPER | ctype::LOWER),
                ctype::UPPER | ctype::LOWER,
                "{c} is both cases"
            );
            if bits & (ctype::UPPER | ctype::LOWER | ctype::DIGIT) != 0 {
                assert_eq!(bits & ctype::PUNCT, 0, "{c} is a letter and punctuation");
            }
        }
    }

    #[test]
    fn ctype_is_the_table_the_host_binary_carries() {
        // No longer a reconstruction. These are the 257 bytes at
        // `DGROUP:0x1a08` of `MAJORBBS-wg101.EXE` (NE autodata segment 151,
        // file offset 0xd5008), and they are identical in wg200. The table is
        // what `toupper` indexes -- `test byte [es:bx+0x1a09],0x8` at
        // `seg 1:0x54a9` -- and what the module indexes itself through the
        // `__CTYPE` datum, so a host that built its own opinion of it would
        // give two answers to one question.
        //
        // The one entry no amount of reasoning from `isspace`/`isprint` would
        // have produced is the space: `0x81`, not `0x01`. The extra bit is
        // Borland's `_IS_SPC`, "is the space character", which `isprint` tests
        // and `isspace` does not.
        #[rustfmt::skip]
        const MEASURED: [u8; CTYPE_LEN as usize] = [
            0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x21, 0x21, 0x21, 0x21, 0x21, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x20, 0x81, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
            0x40, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x40, 0x40, 0x40, 0x40, 0x40,
            0x40, 0x40, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x40, 0x40, 0x40, 0x40,
            0x40, 0x40, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x40, 0x40, 0x40, 0x40,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        assert_eq!(ctype_table(), MEASURED);
    }

    #[test]
    fn ctype_leaves_room_before_the_table_for_eof() {
        // Every predicate indexes `(_ctype+1)[c]`, so entry 0 is what
        // `isalpha(EOF)` reads and must be the entry that classifies as
        // nothing at all.
        assert_eq!(ctype_table()[0], 0);
    }
}
