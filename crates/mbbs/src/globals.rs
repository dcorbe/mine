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

use mbbs_machine::ptr::ModulePtr;

use crate::abi::{Abi, ModuleMem};

/// `MAJORBBS.H:23` -- input buffer size for each channel.
const INPSIZ: u16 = 256;
/// `MAJORBBS.H:398` -- max number of global command handlers.
pub(crate) const GLBMAX: u16 = 50;
/// `FSD.H:243` -- maximum length of a help field, which sizes `fsdemg`.
const MAXHLP: u16 = 80;
/// `TFSCAN.H:14` -- max characters per line, plus the NUL.
const MAXTFS: u16 = 129;
/// `GALACTH.H:18` -- sysid size.
const SIDSIZ: u16 = 5;
/// `BBSUTILS.H:18` -- size of the ASCII rendition of a version.
const VERSIZ: u16 = 9;
/// `UStructs.h:14` -- maximum size for user-id cross reference strings.
const XRFSIZ: u16 = 15;
/// `UStructs.h:10` -- user-id size, *including* the trailing zero.
const UIDSIZ: u16 = 30;

/// A far pointer, as 16-bit C stores one: offset then selector. Four bytes
/// under both ABIs ([`Abi::PTR_WIDTH`]), so it needs no [`Width`] of its own.
const PTR: u16 = 4;
/// A `long`. Four bytes under both ABIs ([`Abi::LONG_WIDTH`]).
const LONG: u16 = 4;

/// How wide a global is.
///
/// Almost every global in this table is the same size under both ABIs:
/// `PTR_WIDTH` and `LONG_WIDTH` are 4 for `Wg16` and `Wg32` alike, and a
/// `char buf[N]` is `N` bytes wherever it is compiled. `int` is the sole
/// exception, and the sole reason this type exists -- 2 bytes for 16-bit
/// Borland, 4 for 32-bit. See [`Abi::INT_WIDTH`], which this defers to
/// rather than restating.
///
/// # Why this is not just a `u16`
///
/// It was, and that was a bug. A `const INT: u16 = 2` is *correct* for the
/// only ABI that existed when the table was written, and silently wrong for
/// the second: it placed `usrnum`, `margc`, `status` and twelve others two
/// bytes apart in a 32-bit module's address space, so the module's own
/// four-byte write to any of them ran into its neighbour. Nothing caught it,
/// because nothing had ever asked the table what width it meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    /// A C `int`: [`Abi::INT_WIDTH`] bytes.
    Int,
    /// A width both ABIs agree on, in bytes -- pointers, longs, arrays,
    /// structs, and the two single-byte flags.
    Bytes(u16),
}

impl Width {
    /// This width in bytes, for `A`.
    pub const fn bytes<A: Abi>(self) -> u16 {
        match self {
            // `INT_WIDTH` is 2 or 4; the cast cannot lose anything.
            Self::Int => A::INT_WIDTH as u16,
            Self::Bytes(n) => n,
        }
    }
}

/// `MAJORBBS.H:287` -- `struct sysvbl`, the system-variable Btrieve record.
/// Its own `spare[]` field pads it to exactly this, so the number is the
/// struct's and not a guess at it.
const SYSVBL: u16 = 1300;

/// One host global: the DLL and name a module imports it by, and how many
/// bytes it is.
pub struct Global {
    pub dll: &'static str,
    pub name: &'static str,
    pub size: Width,
}

/// A `MAJORBBS` global of a width both ABIs agree on.
const fn g(name: &'static str, size: u16) -> Global {
    Global {
        dll: crate::exports::MAJORBBS,
        name,
        size: Width::Bytes(size),
    }
}

/// A `MAJORBBS` global declared `int`, and so [`Abi::INT_WIDTH`] bytes wide
/// rather than a fixed number of them.
///
/// Spelled as its own constructor instead of `g(name, INT)` so that the
/// fifteen declarations that follow the compiler's `int` are visibly a
/// different kind of thing from the ones that do not -- the distinction the
/// old `const INT: u16 = 2` erased at the point of use.
const fn gi(name: &'static str) -> Global {
    Global {
        dll: crate::exports::MAJORBBS,
        name,
        size: Width::Int,
    }
}

/// A `GALGSBL` global -- the serial-board library's, not the executive's.
const fn s(name: &'static str, size: u16) -> Global {
    Global {
        dll: crate::exports::GALGSBL,
        name,
        size: Width::Bytes(size),
    }
}

/// A `GALME` global -- the Messaging Engine's.
const fn m(name: &'static str, size: u16) -> Global {
    Global {
        dll: crate::exports::GALME,
        name,
        size: Width::Bytes(size),
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
    gi("margc"),
    gi("inplen"),
    gi("pfnlvl"),
    gi("pfceil"),
    gi("status"),
    gi("shortm"),
    gi("numcat"),
    // MAJORBBS.H:339 -- int nterms, hichp1, usrnum, othusn, uisusn;
    gi("nterms"),
    gi("hichp1"),
    gi("usrnum"),
    gi("othusn"),
    gi("uisusn"),
    // MAJORBBS.H:345 -- struct user *user, *usrptr, *othusp;
    g("user", PTR),
    g("usrptr", PTR),
    g("othusp", PTR),
    // MAJORBBS.H:351-352 -- the next `extern` statement, declaring two names:
    //   struct extusr *extptr,        /* global pointer to extra info about cur usr*/
    //                 *othexp;        /* gen purp other-user user structre ptr     */
    // `extptr` is not placed: `curusr`'s own doc comment already declines it
    // system-wide (`WCCMMUD.DLL` addresses neither `extusr` nor `extptr`).
    // `othexp` is needed anyway -- RTSLORD-NE (Twilight Lord) imports it
    // directly, 15 sites (`re/ne_arity.py 826 tmp/gapsurvey/tlord_ne/
    // RTSLORD.DLL` reports "cleans void" at every one -- the signature of a
    // data fixup with no call after it, confirming it is addressed, never
    // called). Like `othuap`, it needs no host-side value: the caller sets
    // it itself with `othexp=extoff(othusn)` (`MAJORBBS.C:3023` &c.,
    // `crate::shims::user::extoff` implements `extoff` itself) and then
    // reads fields off it -- this only has to be a real 4-byte slot in
    // module memory for that write to land on, the same role `othuap`
    // already plays for `struct usracc *`. GCV2-only in practice
    // (`crate::users::extusr_stride`'s own doc comment: `struct extusr` is a
    // GCV2 invention), but the slot itself is placed for every ABI the same
    // way every other global here is -- a `Wg32` module simply never writes
    // anything useful through it.
    g("othexp", PTR),
    // MAJORBBS.H:314 -- struct module **module; the host's module table,
    // counted by `nmods` two lines below it. This host does not build one,
    // so the pointer addresses a real, empty region instead of NULL -- the
    // same reasoning `bbsttl` and its neighbours above already established.
    // Safe only because `nmods` (right below) is zero; see the write beside
    // `nterms` for where that pairing is enforced.
    g("module", PTR),
    // MAJORBBS.H:316 -- int nmods; not a config value, the host knows this
    // exactly. See the write beside `nterms`.
    gi("nmods"),
    // MAJORBBS.H:400 -- int nglobs, (*globs[GLBMAX])();
    gi("nglobs"),
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
    gi("vdasiz"),
    // USRACC.H:73-76, one `extern` statement declaring three names:
    //   struct usracc *usaptr,   /* user accounting block ptr for usrnum */
    //                 *othuap,   /* gen purp other-user accounting ptr   */
    //                  acctmp;   /* temporary user account storage       */
    // (`acctmp` is a value, not a pointer, and is not placed here.)
    // Reached through MAJORBBS.H:15's `#include "usracc.h"` -- the citation
    // this row used to carry, MAJORBBS.H:74, is `struct user`, not `usaptr`.
    //
    // `othuap` needs no host-side value: the module sets it itself with
    // `othuap=uacoff(othusn)` (Tele-Arena does exactly that at
    // re/tasrc/tsgarn-4.c:629) and then reads fields off it. It only has to
    // be a real 4-byte slot in module memory for those writes to land on --
    // the same role `usaptr` already plays for the same type. Needed by 17
    // modules in the corpus census, 522 call sites.
    g("usaptr", PTR),
    // USRACC.H:23 -- struct usracc *othuap; the account-side twin of
    // `othusp` (`MAJORBBS.H:345`, placed above), written on every iteration
    // of `instat`'s and `onsysn`'s scan the same way `othusn`/`othusp` are --
    // see `shims::user::write_oth_globals`.
    g("othuap", PTR),
    // FILEXFER.H / FTG.H (wg1) -- the File Transfer Framework's two live
    // pointers and its "tag scan header" message buffer. Placed as data, not
    // implemented as routines: 7 modules address `ftgptr` (210 sites) and 6
    // address `ftfscb` (70) and `tshmsg` (82). The framework's ROUTINES
    // (`ftgnew`/`ftgsbm`) refuse loudly -- none of `ftuser`/`ftgblok`/
    // `scbblok`/`maxtags` exists here -- but a module that only reads these
    // pointers needs a real slot to read, not a missing global.
    //   FTG.H:97-98   extern struct ftg *ftgptr;
    //   FTF.C:26-27   extern struct ftfscb *ftfscb;
    //   FTG.H:74,:66  extern char tshmsg[TSHLEN+1];  TSHLEN == 80
    g("ftgptr", PTR),
    g("ftfscb", PTR),
    g("tshmsg", 81),
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
    gi("tfstate"),
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
    // USRACC.H:39 -- struct uidxrf uidxrf; the struct BY VALUE, not a
    // pointer, so all of it lives here. The GCV2 `spare[6]` arm is not taken.
    g("uidxrf", (XRFSIZ + 1) + UIDSIZ),
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
    // FSDBBS.H:225 -- extern struct fsdbbs *fsdusr; "above info for current
    // user." A module *addresses* this rather than calling it -- The Rose
    // reads it at 12 sites -- so it belongs here, not in the routine table:
    // registering it as a `Routine` would leave the fixup pointing at a
    // dispatch thunk, and the module would read a function address where it
    // expected the current user's FSD state. Unchanged in wg33
    // (`EXPWGSV(struct fsdbbs*) fsdusr;`, `re/wg33src/INC/FSDBBS.H:232`).
    g("fsdusr", PTR),
    // MAJORBBS.H:461 -- one `extern` statement declaring three function
    // pointers; this places only the third:
    //   void (*tjoinrou)(),           /* teleconference "join from other" */
    //        (*ntfysopr)(char *audrec),   /* notify remote sysop routine */
    //        (*emlsdrou)();       /* Send Email to Sysop/New User routine */
    // `tjoinrou`/`ntfysopr` are not placed: nothing in the corpus addresses
    // them, and unlike `curmbk`/`bb` this group has no single call site
    // forcing the whole declaration in. `emlsdrou` alone is needed -- The
    // Rose addresses it at 6 sites -- and, like `fsdusr`, is data a module
    // reaches for by address, never a call. Unchanged in wg33
    // (`EXPWGSF(VOID,emlsdrou)(VOID);`, `re/wg33src/INC/MAJORBBS.H:527`).
    g("emlsdrou", PTR),
    // MAJORBBS.H:558-567 -- CHAR *bbsttl, *company, *addres1, *addres2,
    // *dataph, *liveph, *syskey. Host identity, displayed to users. Not
    // strictly consecutive in the header -- *chghour, *chgmin and *chgtime
    // interleave between `liveph` and `syskey`, and are not placed, the same
    // as `sampln`/`outata` a few rows below (no corpus module imports them).
    // This host has no configuration for any of the seven placed, so
    // `Globals::new` points each at a defined string; see the allocation
    // there for what a module will show.
    g("bbsttl", PTR),
    g("company", PTR),
    g("addres1", PTR),
    g("addres2", PTR),
    g("dataph", PTR),
    g("liveph", PTR),
    g("syskey", PTR),
    // MAJORBBS.H:579-581 -- int outbsz, sampln, mmucrr, outata;
    //   outbsz is the output buffer size per channel, and PFBSIZ
    //   (MAJORBBS.H:507) is #define'd to it. sampln and outata are not placed
    //   here; no corpus module imports them.
    gi("outbsz"),
    // MAJORBBS.H:581 -- int mmucrr; main-menu credit consumption rate per
    // min. Same declaration block as `outbsz` above, two members over
    // (`sampln` between them is not placed -- no corpus module imports it).
    gi("mmucrr"),
    // MAJORBBS.H:592 -- CHAR eurmsk; 0x7F if U.S.A. only, 0xFF if European.
    // A CHAR, one byte -- not an `int` -- so it gets its own constructor
    // rather than `gi`; see that constructor's own doc comment.
    g("eurmsk", 1),
    // REMOTE.H:10-17 -- one `extern` statement declaring seven remote-sysop
    // ints, in this order:
    //   int kilipg,   /* kill-system command in progress           */
    //       errcod,   /* MS-DOS exit codes (for batch files)       */
    //       kilsrc,   /* kill-command source (-1=console, -2=MCU,  */
    //                 /* -3=timed event, >=0=chan #)               */
    //       kilctr, rsetop, chnemd, rmtsys;
    // This places the first three -- `kilctr`/`rsetop`/`chnemd`/`rmtsys` are
    // not addressed by anything in the corpus this host was built against.
    // All three are plain `int` globals, not routines: `EXPWGSV(INT)` is
    // `EXPORT_VARIABLE(...)` (`GCOMM.H:20`), a data export, and `grep -a
    // "kilipg("|"kilsrc(" --include=*.C --include=*.H re/wg33src` finds zero
    // call-syntax uses anywhere -- every real site is a bare read or a plain
    // assignment (`re/wg33src/SRC/server/wgserver/MAJORBBS.C:160`: `INT
    // kilipg=0;`, `:2360`: `kilipg=1;`). Registering either as a routine
    // would be the exact trap this table exists to avoid: the module would
    // get a dispatch thunk's address where it expected an `int`, and the
    // routine would look implemented while nothing ever happened -- the same
    // reasoning `fsdusr`/`emlsdrou` above already established for pointers.
    //
    // `kilipg` ("kill-system command in progress") and `kilsrc`
    // ("kill-command source") are both `MAJORBBS` ordinal data imports in
    // Rose32 (`tmp/gapsurvey/round2/out_rose_pe.txt`, one site each) --
    // 32-bit only, unlike `errcod` (The Rose, 16-bit, 4 sites), but placed
    // for every ABI the same way every other global here is.
    // Unchanged in wg33 (`EXPWGSV(INT) kilipg/errcod/kilsrc;`,
    // `re/wg33src/INC/MAJORBBS.H:590` and `re/wg33src/INC/REMOTE.H:44-47`).
    gi("kilipg"),
    gi("errcod"),
    gi("kilsrc"),
    // MAJORBBS.H:653 -- int digalw; digits allowed in User-IDs? A native
    // MAJORBBS.H field again (unlike the REMOTE.H trio just above, which is
    // its own header with no fixed position relative to this one), placed
    // after it rather than disturbing that group's own established spot.
    gi("digalw"),
    // LINGO.H:40 -- int nlingo; number of languages. Placed in declaration
    // order ahead of `clingo`, which is what LINGO.H does.
    //
    // No corpus module imports `nlingo`, and until Phase 2 it was left out
    // for that reason. What changed is that `languages` stopped being empty:
    // an array with an entry in it and no count beside it is the exact hazard
    // the comment here used to describe, so the count is now placed and held
    // at the array's real length. `nlingo` is to `languages` what `nmods` is
    // to `module`.
    gi("nlingo"),
    // LINGO.H:41 -- int clingo; current language.
    gi("clingo"),
    // LINGO.H:42 -- struct lingo **languages; dynamic array of lingo
    // structs. One entry, and `nlingo == 1` says so; see `Globals::place`
    // for why the entry is a populated record rather than the NULL slot it
    // was through Phase 1.
    g("languages", PTR),
    // GME.H:199 -- UINT _txtlen; message text buffer size, reached through
    // the TXTLEN macro. GALME's, not MAJORBBS's -- it is not part of the
    // MAJORBBS.H sequence above, so declaration order does not bind it.
    m("txtlen", 2),
];

/// Bytes of `bturno`. Eight digits and a NUL, which is what `%.9s` prints.
const BTURNO: u16 = 9;

/// The fields of `struct lingo` (`LINGO.H:29-37`), each as its offset and its
/// declared width.
///
/// Every member is a `CHAR` array, so the struct packs with no padding under
/// any alignment setting and the offsets are running sums of the widths:
/// `LNGSIZ 16`, `LNGDSC 51`, `LNGEXT 5` three times, `LNGEDT 41`, `LNGYN 13`
/// twice (`LINGO.H:23-27`).
///
/// Named rather than written into `default_lingo` as literals because
/// `cncyesno` reads `yes` and `no` back out of module memory at these
/// offsets, and one table both writers use is the only way the two agree.
const LINGO_YES: u16 = 123;
const LINGO_NO: u16 = 136;

/// Bytes in `struct lingo`: `16+51+5+5+5+41+13+13`.
const LINGO: u16 = LINGO_NO + 13;

/// `struct lingo dftlang` as Galacticomm declares it, laid out for module
/// memory.
///
/// Not a value this host chose. `SRC/server/utils/wgsint/INTEGROU.C:39-40`
/// is the vendor's own statically-initialised default record --
/// `{DFTLNG,DFTDSC,DFTEXTANS,DFTEXTASC,DFTEXTIBM,DFTEDR,DFTYES,DFTNO}` --
/// and six of those eight macros are in `INC/LINGO.H` itself (`:44-49`).
/// `DFTDSC` and the three extensions are defined at the top of that same
/// `INTEGROU.C` (`:33-36`) rather than in a header, which is why they carry
/// the longer citation.
///
/// `yes`/`no` matter most: `cncyesno` compares the user's keystroke against
/// `toupper(lptr->yes[0])` and `toupper(lptr->no[0])`, so `"YES"`/`"NO"` are
/// what makes `Y` and `N` the answers a module gets. `LINGO.H:36` requires
/// the two to have unique first letters, and these do.
fn default_lingo() -> Vec<u8> {
    // Offset, width, value -- in declaration order, so this reads against
    // `LINGO.H:29-37` line by line.
    const FIELDS: &[(u16, u16, &str)] = &[
        (0, 16, "English/ANSI"),                             // name,   DFTLNG
        (16, 51, "English version of BBS-ANSI (or ASCII)"),   // desc,   DFTDSC
        (67, 5, ".ans"),                                     // extans, DFTEXTANS
        (72, 5, ".asc"),                                     // extasc, DFTEXTASC
        (77, 5, ".ibm"),                                     // extibm, DFTEXTIBM
        (82, 41, "wgsdraw %s"),                              // editor, DFTEDR
        (LINGO_YES, 13, "YES"),                              // yes,    DFTYES
        (LINGO_NO, 13, "NO"),                                // no,     DFTNO
    ];

    let mut out = vec![0u8; usize::from(LINGO)];
    for &(at, width, value) in FIELDS {
        // A C string initialiser fills the rest of the array with NULs, which
        // is what the zeroed buffer already holds. The assertion is the part
        // that matters: a value too long for its field would be silently
        // truncated into the field beside it.
        assert!(
            value.len() < usize::from(width),
            "{value:?} does not fit in {width} bytes with its NUL"
        );
        let at = usize::from(at);
        out[at..at + value.len()].copy_from_slice(value.as_bytes());
    }
    out
}

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
/// # Generic top to bottom, `Wg16`-facade names elsewhere
///
/// `base` and `prf` are typed `A::Ptr`, so this struct is genuinely
/// `Globals<A>` -- and since Task 13 of
/// `docs/plans/2026-08-12-abi-border-implementation.md`, so is
/// [`Globals::new`]: it reaches memory through [`Abi::mem`] and writes
/// through the generic [`Globals::write_mem`] core below, the same as every
/// other constructor in this crate. `address`, `size` and `prf_buffer` were
/// generic outright before that, and stayed unchanged: none ever touched a
/// `Machine`.
///
/// What is genuinely `Wg16`-specific does not live in this file any more.
/// [`Globals::word`]/[`Globals::write`] are `&Machine`/`&mut Machine`
/// facades over [`Globals::word_mem`]/[`Globals::write_mem`] -- kept, under
/// their original names and signatures, for the dozens of shim call sites
/// built against them (the same reborrow-facade shape `Heap::alloc` used to
/// give `Heap::reserve`) -- and [`Globals::selector`] returns `base.selector`,
/// which is 16-bit in *substance* and not merely by signature: a flat 32-bit
/// pointer has no selector to return. All three, plus `long`/`pointer`
/// (the same `&Machine` shape), now live in `crates/mbbs/src/abi/wg16.rs`,
/// beside the ABI they are specific to, rather than here -- this file names
/// no ABI at all.
pub struct Globals<A: Abi> {
    base: A::Ptr,
    offsets: HashMap<&'static str, u16>,
    sizes: HashMap<&'static str, u16>,
    /// Where `prfbuf` points: the print buffer, in a region of its own so that
    /// a module overrunning it cannot reach the globals.
    prf: A::Ptr,
}

impl<A: Abi> Globals<A> {
    /// The region every [`Globals::address`] offsets from.
    ///
    /// `pub(crate)`, not exposed at the crate boundary: the one caller that
    /// needs the raw base rather than a named global's address is
    /// [`Globals::selector`] in `abi/wg16.rs`, which is 16-bit in substance
    /// and lives outside this module for exactly that reason -- see this
    /// struct's own doc comment.
    pub(crate) fn base(&self) -> A::Ptr {
        self.base
    }

    /// Where the print buffer starts.
    ///
    /// Generic outright, for the same reason [`Globals::address`] is: it
    /// never touched a `Machine`. It returns the `prf` field verbatim, and
    /// that field has been `A::Ptr` since this struct was parameterised --
    /// so the `FarPtr` in its old signature was pinning the *return type* of
    /// an already-generic value, and nothing else.
    pub fn prf_buffer(&self) -> A::Ptr {
        self.prf
    }

    /// Where a global lives, or `None` for a name the host does not place.
    ///
    /// Generic outright: this never touched a `Machine`, only the offsets
    /// table built at construction and `A::ptr_offset` to place the result
    /// relative to `base`. `base.offset` is always 0 -- every `Globals<A>` is
    /// built from a single fresh [`ModuleMem::alloc_region`] -- so this is the
    /// same address `impl Globals<Wg16>`'s hand-built `FarPtr` used to
    /// compute, expressed through the ABI's own offsetting rule instead of
    /// naming `FarPtr`'s fields directly.
    pub fn address(&self, name: &str) -> Option<A::Ptr> {
        let offset = *self.offsets.get(name)?;
        Some(A::ptr_offset(self.base, offset))
    }

    /// How many bytes a global occupies, or `None` for one the host does not
    /// place.
    ///
    /// Generic outright: a lookup in a table keyed by name, with nothing
    /// ABI-shaped in it at all.
    pub fn size(&self, name: &str) -> Option<u16> {
        self.sizes.get(name).copied()
    }

    /// Read a global as a word, against memory directly rather than a whole
    /// `Machine`.
    ///
    /// The generic core [`Globals::word`]'s `Wg16` facade delegates into --
    /// see the struct's own doc comment for why the two need different names.
    ///
    /// # Errors
    ///
    /// If `name` is not a global.
    pub fn word_mem(&self, mem: &A::Mem, name: &str) -> io::Result<u16> {
        let at = self
            .address(name)
            .ok_or_else(|| io::Error::other(format!("{name} is not a host global")))?;
        let bytes = at.resolve(mem, 2).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Overwrite a global, against memory directly rather than a whole
    /// `Machine`.
    ///
    /// The generic core [`Globals::write`]'s `Wg16` facade delegates into --
    /// see the struct's own doc comment for why the two need different names.
    ///
    /// # Errors
    ///
    /// If `name` is not a global, or `bytes` is longer than it.
    pub fn write_mem(&self, mem: &mut A::Mem, name: &str, bytes: &[u8]) -> io::Result<()> {
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
        at.write(mem, bytes).map_err(|e| io::Error::other(e.to_string()))
    }

    /// Overwrite a global declared `int`, at `A`'s own int width.
    ///
    /// # Why `write_mem` is not enough for these
    ///
    /// [`write_mem`](Globals::write_mem) writes the bytes it is handed and
    /// leaves the rest of the global alone -- correct for a `char[]` being
    /// filled in piecewise, and wrong for a scalar. Under `Wg16` an `int` is
    /// two bytes and every caller handed it exactly two, so the distinction
    /// never came up. Under `Wg32` an `int` is four, and a two-byte write
    /// leaves the top half *whatever it was before*.
    ///
    /// That is not hypothetical. `Globals::new` seeds `usrnum` to all-ones
    /// (`-1`, MAJORBBS.C:882); the first two-byte write of channel `0` on top
    /// of it would leave `0xFFFF0000`, which is neither `0` nor `-1` and
    /// which no reader could recognise as wrong.
    ///
    /// `value` is taken as `u32` and narrowed, so a caller with a negative
    /// number passes it already sign-extended to 32 bits (`x as u32` on an
    /// `i32`) and gets the right bytes at either width -- the same reason
    /// [`Abi::int_from_u32`] exists rather than a `From<u16>`.
    ///
    /// # Errors
    ///
    /// If `name` is not a global.
    pub fn write_int_mem(&self, mem: &mut A::Mem, name: &str, value: u32) -> io::Result<()> {
        debug_assert_eq!(
            self.size(name),
            Some(A::INT_WIDTH as u16),
            "{name} is not an int global",
        );
        self.write_mem(mem, name, &A::int_to_bytes(A::int_from_u32(value)))
    }

    /// Read a global as a pointer, against memory directly rather than a
    /// whole `Machine`.
    ///
    /// The generic core [`Globals::pointer`]'s `Wg16` facade delegates into --
    /// see the struct's own doc comment for why the two need different names.
    /// Added for `shims::msg`'s Task 5 conversion, which reads `curmbk` (and
    /// `shims::text`'s `prfptr`, once that file converts) as a pointer rather
    /// than a word.
    ///
    /// # Errors
    ///
    /// If `name` is not a global.
    pub fn pointer_mem(&self, mem: &A::Mem, name: &str) -> io::Result<A::Ptr> {
        let at = self
            .address(name)
            .ok_or_else(|| io::Error::other(format!("{name} is not a host global")))?;
        let bytes = at
            .resolve(mem, A::PTR_WIDTH)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(A::ptr_from_bytes(bytes))
    }

    /// Place every global, and initialise the ones that are not zero.
    ///
    /// Generic since Task 13 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md`: `cpu: &mut
    /// A::Cpu` reaches memory through [`Abi::mem`], the same reborrow every
    /// other generic core in this crate uses, and every write below goes
    /// through [`Globals::write_mem`] rather than the `Wg16` `write` facade
    /// (`abi/wg16.rs`) -- that facade exists for the dozens of call sites
    /// still built against `&mut Machine`, not for construction.
    ///
    /// # Errors
    ///
    /// If the regions cannot be mapped.
    pub fn new(cpu: &mut A::Cpu, terms: crate::Terms) -> io::Result<Self> {
        let mut offsets = HashMap::with_capacity(GLOBALS.len());
        let mut sizes = HashMap::with_capacity(GLOBALS.len());
        let mut at = 0u16;
        for global in GLOBALS {
            // Every width resolved once, here, against `A` -- and stored
            // resolved, so that `Globals::size` answers in bytes and no
            // caller has to know `Width` exists. Only `Width::Int` actually
            // varies; see that type's own doc comment.
            let size = global.size.bytes::<A>();

            // Even addresses, as a 16-bit compiler would place them. The 286
            // does not care, but a layout that matches the one the header
            // describes is one fewer difference to reason about.
            //
            // Deliberately still 2 and not `A::INT_WIDTH`: alignment is the
            // one part of this layout nothing reads. Each global is addressed
            // through its own fixup, never as a field at a fixed offset in a
            // struct, and x86 does not fault on an unaligned dword. Holding
            // it at 2 keeps every `Wg16` offset byte-identical to what it was
            // before widths became a per-ABI question, which is what makes
            // the 16-bit half of this change provably a no-op.
            at = at.next_multiple_of(2);
            offsets.insert(global.name, at);
            sizes.insert(global.name, size);
            at += size;
        }

        let mem = A::mem(cpu);
        let base = mem.alloc_region(usize::from(at))?;
        let prf_len = usize::from(OUTBSZ);
        let prf = mem.alloc_region(prf_len)?;

        let globals = Self {
            base,
            offsets,
            sizes,
            prf,
        };

        // `prfbuf` and `prfptr` are `char *`, not the buffer -- GCOMM.H:449.
        // The module reads `prfbuf[0]` to ask whether anything is queued, so
        // they have to be real far pointers into real memory from the start.
        globals.write_mem(mem, "prfbuf", &A::ptr_to_bytes(prf))?;
        globals.write_mem(mem, "prfptr", &A::ptr_to_bytes(prf))?;
        globals.write_mem(mem, "_ctype", &ctype_table())?;

        // The identity strings. Each global is a pointer, so the string needs
        // storage of its own, and the pointer is written to address it.
        //
        // These values are not read from configuration anywhere -- this host
        // has none -- so a module that displays the BBS title displays exactly
        // what is here. They are deliberately not empty for the two that name
        // a *thing* rather than a contact detail, because an empty title
        // renders as a blank line that looks like a bug in the module.
        //
        // `syskey` is `"SYSOP"` rather than empty because `LOCKNKEY.C`
        // compares against it to decide sysop-ness; an empty key would make
        // the comparison match unpredictably. That is reasoning from the
        // header comment, not a measured value, so it carries this comment
        // rather than a citation.
        const IDENTITY: &[(&str, &str)] = &[
            ("bbsttl", "Worldgroup"),
            ("company", ""),
            ("addres1", ""),
            ("addres2", ""),
            ("dataph", ""),
            ("liveph", ""),
            ("syskey", "SYSOP"),
        ];
        for (name, value) in IDENTITY {
            let mut bytes = value.as_bytes().to_vec();
            bytes.push(0);
            let at = mem.alloc_region(bytes.len())?;
            at.write(mem, &bytes).map_err(|e| io::Error::other(e.to_string()))?;
            globals.write_mem(mem, name, &A::ptr_to_bytes(at))?;
        }

        // An array this host does not build. The pointer addresses a real
        // empty region rather than NULL, so a module that dereferences
        // without checking does not fault.
        //
        // SAFETY OF THE EMPTY ARRAY IS `nmods == 0`. A module iterating
        // `module[0..nmods]` iterates nothing. If `nmods` ever becomes
        // non-zero, `module` must point at a table with that many entries
        // first -- otherwise the module walks whatever the arena holds next.
        {
            // One pointer slot, zeroed. `Abi` has no NULL constant, and an
            // all-zero far pointer is what NULL is under both ABIs anyway.
            let at = mem.alloc_region(A::PTR_WIDTH)?;
            at.write(mem, &vec![0u8; A::PTR_WIDTH]).map_err(|e| io::Error::other(e.to_string()))?;
            globals.write_mem(mem, "module", &A::ptr_to_bytes(at))?;
        }

        // `languages` is the same shape and is NOT empty, because a module
        // dereferences it without asking anyone's permission first.
        //
        // `cncyesno` (`SRC/server/wgserver/CNCUTL.C:112`) opens with
        // `lptr=languages[clingo]` and reads `lptr->yes[0]` on the very next
        // line. Through Phase 1 `languages` addressed a single zeroed pointer
        // slot, so that read would have dereferenced NULL *inside module
        // code* -- a fault with the module's own address on it and nothing
        // pointing back at the host gap that caused it. One real record is
        // what makes the routine answerable at all.
        //
        // The record's contents are Galacticomm's own defaults, not this
        // host's invention -- see [`default_lingo`]. A real host builds this
        // array in `inilingo()` by reading `LNG` lines out of `wgserv.cfg`
        // (`LINGO.H:50`); this host has no configuration, so it stands on the
        // literal the vendor ships for exactly that case.
        let record = mem.alloc_region(usize::from(LINGO))?;
        record.write(mem, &default_lingo()).map_err(|e| io::Error::other(e.to_string()))?;
        let array = mem.alloc_region(A::PTR_WIDTH)?;
        array
            .write(mem, &A::ptr_to_bytes(record))
            .map_err(|e| io::Error::other(e.to_string()))?;
        globals.write_mem(mem, "languages", &A::ptr_to_bytes(array))?;

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
        //
        // Written through `A::int_to_bytes`, not `to_le_bytes`: these are
        // `int`s, and an `int` is not always two bytes. See that method's own
        // doc comment.
        globals.write_mem(mem, "nterms", &A::int_to_bytes(terms.count().into()))?;
        globals.write_mem(mem, "hichp1", &A::int_to_bytes(terms.count().into()))?;

        // `MAJORBBS.C:572` -- outbsz=numopt(OUTBSZ,4096,16384). The config
        // read is not implemented, so this is OUTBSZ, the low end of the range
        // the real host accepts -- and, critically, the same constant `prf`
        // was allocated with above, so the two cannot drift.
        globals.write_mem(mem, "outbsz", &A::int_to_bytes(OUTBSZ.into()))?;

        // No config read for the messaging engine's buffer size; TXTLEN is
        // what a module sizes a message body against, so it must be
        // non-zero. `txtlen` is `Width::Bytes(2)`, not `Width::Int`, so this
        // goes through `write_mem` directly rather than `int_to_bytes`.
        globals.write_mem(mem, "txtlen", &OUTBSZ.to_le_bytes())?;

        // `nmods` is a count the host owns, not a config value. A freshly
        // built `Globals` has nothing loaded; `Host::load` is what moves it.
        globals.write_mem(mem, "nmods", &A::int_to_bytes(0u16.into()))?;
        // Defaults for the three whose config read is not implemented. Each
        // cites the declaration whose comment names the meaning.
        globals.write_mem(mem, "mmucrr", &A::int_to_bytes(0u16.into()))?;   // MAJORBBS.H:581
        globals.write_mem(mem, "digalw", &A::int_to_bytes(1u16.into()))?;   // MAJORBBS.H:653
        globals.write_mem(mem, "clingo", &A::int_to_bytes(0u16.into()))?;   // LINGO.H:41
        // LINGO.H:40 -- the count beside `languages`, and the one thing that
        // makes walking that array safe. One record is allocated above, so
        // this is 1; the two are written in the same constructor so they
        // cannot drift.
        globals.write_mem(mem, "nlingo", &A::int_to_bytes(1u16.into()))?;
        // `uidxrf` needs no write: all-zero is a valid empty cross reference,
        // and `alloc_region` already zeroes -- confirmed against both ABIs'
        // `ModuleMem` impls: `Wg16`'s `Segments::alloc_region` maps a fresh
        // `MAP_ANONYMOUS` mmap (`m16/seg.rs`'s `Mapping::new`), and `Wg32`'s
        // `Memory::alloc_region` bumps a pointer through one such mapping
        // made once at construction (`m32/mem.rs`) -- the OS zeroes both, and
        // neither ever reuses a byte range once handed out.
        // A CHAR, so written as one byte rather than through int_to_bytes.
        globals.write_mem(mem, "eurmsk", &[0x7F])?;

        // MAJORBBS.C:882 -- `usrnum=-1;`, set immediately before `inimod()`
        // runs every module's init routine. See the test for why the zero it
        // is born with is a lie and not a placeholder.
        // `-1` in `A::INT_WIDTH` bytes: `0xFFFF` under `Wg16`, `0xFFFFFFFF`
        // under `Wg32`. Writing two bytes unconditionally left a 32-bit
        // module reading `usrnum` as `65535` -- a perfectly plausible channel
        // number -- instead of the "nobody" the real host means by it.
        //
        // All-ones rather than `A::int_to_bytes(A::Int::from(..))`: `A::Int`
        // is built from a `u16` by *zero* extension, so `From<u16>` can only
        // ever produce `65535` under `Wg32` -- the exact wrong answer this
        // line exists to stop. Two's complement `-1` is every bit set at any
        // width, and needs no extension rule to be right.
        globals.write_mem(mem, "usrnum", &vec![0xFF; A::INT_WIDTH])?;

        Ok(globals)
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

    /// `outbsz` is the print buffer's size, and the module reads it to size its
    /// own work -- `PFBSIZ` is `#define`d to it (`MAJORBBS.H:507`). It must hold
    /// the same number `Globals::new` allocated `prf` with, or a module that
    /// fills `prfbuf` up to `outbsz` overruns a buffer the host made smaller.
    #[test]
    fn outbsz_is_the_size_the_print_buffer_was_actually_allocated_with() {
        // Deliberately not compared against `OUTBSZ`, and deliberately not
        // against `prf_len` either: both name the byte count `Globals::new`
        // *asked* `ModuleMem::alloc_region` for, not what it actually got
        // back. A test built against either would still pass if
        // `mem.alloc_region(prf_len)` were mutated to
        // `mem.alloc_region(prf_len * 2)` -- doubling the real allocation
        // while leaving `prf_len` itself untouched -- because nothing above
        // read the allocation back. This instead asks the segment
        // `prf_buffer()` actually names for its own real length, through
        // `Segments::region_len` -- the same bound `resolve`/`read_cstr`
        // already check every module read against -- so a divergence
        // between what was requested and what was really allocated is
        // exactly what this assertion catches.
        let f = crate::testing::Fixture::new();
        let g = f.host.globals();
        let allocated = f
            .machine
            .mem()
            .region_len(g.prf_buffer())
            .expect("prf_buffer names a real segment");
        assert_eq!(
            u64::from(g.word(&f.machine, "outbsz").expect("outbsz")),
            allocated as u64,
            "outbsz must agree with the prf segment's real, allocated length"
        );
    }

    /// `MAJORBBS.H:592` -- CHAR eurmsk, "0x7F if U.S.A. only, 0xFF if European".
    /// One byte, not an int: it masks a character, and the host is U.S.A. by
    /// default. Placing it two bytes wide would overlap whatever follows.
    #[test]
    fn eurmsk_is_one_byte_and_masks_to_ascii() {
        let f = crate::testing::Fixture::new();
        let g = f.host.globals();
        assert_eq!(g.size("eurmsk").expect("eurmsk is placed"), 1,
                   "CHAR, not INT");
        let at = g.address("eurmsk").expect("eurmsk is placed");
        let byte = f.machine.resolve(at, 1).expect("readable")[0];
        assert_eq!(byte, 0x7F, "U.S.A. only by default");
    }

    /// The seven `CHAR *` identity globals must point at readable NUL-terminated
    /// storage, not at NULL.
    ///
    /// A module that does `prf("%s", bbsttl)` dereferences the pointer. A NULL
    /// there faults inside module code, which is the hardest kind of failure to
    /// attribute back to a missing host global -- so what is asserted is that the
    /// pointer resolves and the byte it addresses is readable.
    #[test]
    fn the_identity_strings_point_at_readable_storage() {
        const NAMES: &[&str] = &[
            "bbsttl", "company", "addres1", "addres2", "dataph", "liveph", "syskey",
        ];
        let f = crate::testing::Fixture::new();
        let g = f.host.globals();
        for name in NAMES {
            assert_eq!(g.size(name).expect(name), PTR, "{name} is a CHAR *");
            let target = g.pointer(&f.machine, name).expect(name);
            assert_ne!(
                target,
                mbbs_machine::m16::FarPtr::NULL,
                "{name} must not be a NULL pointer"
            );
            // Readable, and terminated: reading it must not fault and must find a
            // NUL within the arena.
            let s = f.read(target);
            assert!(s.len() < 256, "{name} is NUL-terminated within reason");
        }
    }

    /// `module` is a pointer to an array the host does not build.
    ///
    /// It is placed and points at real, empty storage rather than NULL. What
    /// makes that safe is `nmods == 0`: a module iterating `module[0..nmods]`
    /// iterates nothing. This test pins the pairing, because the day `nmods`
    /// becomes non-zero without a table behind `module` is the day a module walks
    /// garbage.
    ///
    /// `languages` used to be checked here as the second empty array. It is no
    /// longer empty -- see
    /// [`languages_zero_is_a_readable_lingo_with_distinct_yes_and_no`], which
    /// owns it and its `nlingo` counter now.
    #[test]
    fn the_pointer_arrays_are_empty_and_nmods_agrees() {
        let f = crate::testing::Fixture::new();
        let g = f.host.globals();
        assert_eq!(g.size("module").expect("module"), PTR, "module is a **");
        assert_ne!(
            g.pointer(&f.machine, "module").expect("module"),
            mbbs_machine::m16::FarPtr::NULL,
            "module must not be NULL even when the array is empty"
        );
        assert_eq!(
            g.word(&f.machine, "nmods").expect("nmods"), 0,
            "an empty `module` array is only safe while nmods is zero"
        );
    }

    /// The `struct lingo` behind `languages[0]`, read exactly the way
    /// `cncyesno` reads it: the pointer stored in `languages`, then the
    /// pointer in that array's slot zero, then the record itself.
    ///
    /// Goes through `Abi::ptr_from_bytes` rather than picking the two words
    /// apart by hand, so this is not a second way to decode a far pointer.
    fn read_lingo_zero(f: &crate::testing::Fixture) -> Vec<u8> {
        use crate::abi::Abi;

        let g = f.host.globals();
        let array = g.pointer(&f.machine, "languages").expect("languages");
        assert_ne!(array, mbbs_machine::m16::FarPtr::NULL, "languages must not be NULL");

        let slot = f
            .machine
            .resolve(array, crate::abi::Wg16::PTR_WIDTH)
            .expect("languages[0] is readable");
        let record = crate::abi::Wg16::ptr_from_bytes(slot);
        assert_ne!(record, mbbs_machine::m16::FarPtr::NULL, "languages[0] must not be NULL");

        f.machine
            .resolve(record, usize::from(LINGO))
            .expect("the whole lingo record is readable")
            .to_vec()
    }

    /// One NUL-terminated field of a `struct lingo`, by the offsets the host
    /// wrote it with.
    fn lingo_field(record: &[u8], at: u16, width: u16) -> String {
        let field = &record[usize::from(at)..usize::from(at + width)];
        let end = field.iter().position(|&b| b == 0).expect("NUL-terminated");
        String::from_utf8_lossy(&field[..end]).into_owned()
    }

    /// `languages[clingo]` must be a readable `struct lingo`, not a NULL slot.
    ///
    /// `cncyesno` (`CNCUTL.C:112`) does `lptr=languages[clingo]` and
    /// dereferences `lptr->yes[0]` on the next line. Phase 1 placed
    /// `languages` pointing at one zeroed pointer, which would have faulted
    /// inside module code. This pins that the slot resolves and that the
    /// record carries Galacticomm's own defaults.
    ///
    /// `LINGO.H:36` also requires `yes` and `no` to have unique first letters,
    /// because `cncyesno`'s two-branch compare is wrong without it. That is
    /// **not** asserted separately here: `"YES"` and `"NO"` are pinned by
    /// value, which implies it, so a `assert_ne!` on the two first letters
    /// could never fire. An assertion that cannot fail reads like coverage
    /// and is not.
    #[test]
    fn languages_zero_is_a_readable_lingo_with_distinct_yes_and_no() {
        let f = crate::testing::Fixture::new();
        let g = f.host.globals();

        assert_eq!(g.size("languages").expect("languages"), PTR, "languages is a **");
        assert_eq!(g.word(&f.machine, "clingo").expect("clingo"), 0);
        assert_eq!(
            g.word(&f.machine, "nlingo").expect("nlingo"), 1,
            "one language is configured, and nlingo is what says so"
        );

        let record = read_lingo_zero(&f);
        let yes = lingo_field(&record, LINGO_YES, 13);
        let no = lingo_field(&record, LINGO_NO, 13);

        // Compared against the vendor macros by name, not against whatever
        // `default_lingo` happens to hold -- otherwise both sides of the
        // assertion would move together and it would pin nothing.
        assert_eq!(yes, "YES", "LINGO.H:48 -- DFTYES");
        assert_eq!(no, "NO", "LINGO.H:49 -- DFTNO");
        assert_eq!(lingo_field(&record, 0, 16), "English/ANSI", "LINGO.H:44 -- DFTLNG");
    }

    /// `USRACC.H:39` -- `struct uidxrf uidxrf`, the struct by value, not a
    /// pointer. 46 bytes: `CHAR xrfstg[XRFSIZ+1]` (16) plus `CHAR userid[UIDSIZ]`
    /// (30), with the `#ifdef GCV2 CHAR spare[6]` arm NOT taken -- `struct user`
    /// measures 88 bytes non-GCV2 for these targets, so GCV2 is off here too.
    ///
    /// The width is the whole assertion. A pointer-sized placement would be four
    /// bytes and would silently overlap whatever follows.
    #[test]
    fn uidxrf_is_the_struct_by_value_at_forty_six_bytes() {
        let f = crate::testing::Fixture::new();
        assert_eq!(
            f.host.globals().size("uidxrf").expect("uidxrf is placed"),
            (XRFSIZ + 1) + UIDSIZ,
            "xrfstg[XRFSIZ+1] + userid[UIDSIZ], non-GCV2"
        );
        assert_eq!((XRFSIZ + 1) + UIDSIZ, 46, "the arithmetic, spelled out once");
    }

    /// `GME.H:199` -- `extern UINT GMEEXP _txtlen`, the message text buffer size,
    /// with `#define TXTLEN _txtlen` beside it.
    ///
    /// It belongs to GALME, not MAJORBBS. Registering it under the wrong library
    /// means the import does not resolve at all, and the failure looks like a
    /// missing symbol rather than a misfiled one.
    #[test]
    fn txtlen_is_a_galme_global() {
        let f = crate::testing::Fixture::new();
        let g = f.host.globals();
        assert_eq!(g.size("txtlen").expect("txtlen is placed"), 2, "UINT");
        assert_eq!(
            GLOBALS.iter().find(|x| x.name == "txtlen").expect("txtlen").dll,
            crate::exports::GALME,
            "the Messaging Engine's, not the executive's"
        );
    }

    /// `nmods` is not a configuration value -- it is how many modules are online,
    /// which the host knows exactly. A fixture with no modules loaded must read
    /// zero, and the number must move when a module lands.
    #[test]
    fn nmods_counts_the_modules_actually_online() {
        let f = crate::testing::Fixture::new();
        assert_eq!(
            f.host.globals().word(&f.machine, "nmods").expect("nmods"),
            0,
            "a fixture loads no modules"
        );
    }

    /// The three defaults, each the value a real host holds on a default install.
    /// `MAJORBBS.H:581` (mmucrr), `:653` (digalw), `LINGO.H:41` (clingo).
    #[test]
    fn the_int_globals_hold_their_documented_defaults() {
        let f = crate::testing::Fixture::new();
        let g = f.host.globals();
        assert_eq!(g.word(&f.machine, "mmucrr").expect("mmucrr"), 0,
                   "no main-menu credit consumption by default");
        assert_eq!(g.word(&f.machine, "digalw").expect("digalw"), 1,
                   "digits are allowed in User-IDs by default");
        assert_eq!(g.word(&f.machine, "clingo").expect("clingo"), 0,
                   "the first language is current");
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

    /// The whole table, laid out the way [`Globals::new`] lays it out, for
    /// `A`. Kept in step with that loop by hand -- there is no way to ask
    /// `Globals` for a layout without a `Cpu` to place it in, and building a
    /// `Wg32` one means building a real `m32::Machine`, which arms this
    /// thread's fault recovery and so cannot happen inside `--lib`.
    fn layout<A: Abi>() -> Vec<(&'static str, u16, u16)> {
        let mut at = 0u16;
        let mut placed = Vec::new();
        for global in GLOBALS {
            let size = global.size.bytes::<A>();
            at = at.next_multiple_of(2);
            placed.push((global.name, at, size));
            at += size;
        }
        placed
    }

    #[test]
    fn the_globals_fit_in_one_segment() {
        // A `Wg16` question and only a `Wg16` question: 16-bit modules
        // address these through one selector, and `Wg32`'s live in a flat
        // arena with no 64 KiB anything. Checked for both anyway -- the
        // 32-bit total is the same table 30 bytes wider (fifteen `int`s
        // gaining two bytes each), so if it ever stopped fitting, the reason
        // would be worth knowing before a flat-memory assumption hid it.
        for (abi, total) in [
            ("Wg16", layout::<crate::abi::Wg16>()),
            ("Wg32", layout::<crate::abi::Wg32>()),
        ]
        .map(|(name, placed)| {
            let last = placed.last().expect("the table is not empty");
            (name, u32::from(last.1) + u32::from(last.2))
        }) {
            assert!(total < 64 * 1024, "{abi}: {total} bytes of globals");
        }
    }

    /// The one number this whole `Width` distinction exists for.
    ///
    /// Nineteen globals are declared `int` (eighteen until `outbsz` joined as
    /// MAJORBBS.H:579's placed member; sixteen before that, until
    /// `kilipg`/`kilsrc` joined `errcod` as REMOTE.H's other two placed
    /// members). Under `Wg16` that is two bytes and under `Wg32` it is four,
    /// so the 32-bit table is exactly 38 bytes longer -- and, far more
    /// importantly, a 32-bit module's four-byte write to `usrnum` lands
    /// entirely inside `usrnum`.
    ///
    /// Before this, `const INT: u16 = 2` made both columns 2 and the whole
    /// table one length. Nothing failed, because nothing asked.
    #[test]
    fn an_int_global_is_two_bytes_under_wg16_and_four_under_wg32() {
        let ints: Vec<&str> = GLOBALS
            .iter()
            .filter(|g| g.size == Width::Int)
            .map(|g| g.name)
            .collect();
        assert_eq!(ints.len(), 24, "the int globals: {ints:?}");
        assert!(ints.contains(&"usrnum") && ints.contains(&"margc") && ints.contains(&"nglobs"));
        assert!(ints.contains(&"errcod"), "REMOTE.H:11 declares errcod an int");

        for name in &ints {
            let w16 = GLOBALS.iter().find(|g| &g.name == name).expect("found");
            assert_eq!(w16.size.bytes::<crate::abi::Wg16>(), 2, "{name} under Wg16");
            assert_eq!(w16.size.bytes::<crate::abi::Wg32>(), 4, "{name} under Wg32");
        }

        // Every other global is the same width under both, so the totals
        // differ by exactly two bytes per `int` and nothing else.
        let end = |placed: Vec<(&str, u16, u16)>| {
            let last = *placed.last().expect("non-empty");
            u32::from(last.1) + u32::from(last.2)
        };
        assert_eq!(
            end(layout::<crate::abi::Wg32>()) - end(layout::<crate::abi::Wg16>()),
            2 * ints.len() as u32,
        );
    }

    /// The 16-bit half of the width change is a no-op, stated as a test
    /// rather than as a claim in a comment: every `Wg16` offset is what it
    /// was when the table held plain `u16` sizes.
    ///
    /// Anchored on three globals whose offsets other tests and the module's
    /// own `0xfffe` addend already depend on, plus the table's total length.
    #[test]
    fn the_wg16_layout_is_unchanged_by_widths_becoming_per_abi() {
        let placed = layout::<crate::abi::Wg16>();
        let at = |name: &str| placed.iter().find(|p| p.0 == name).expect("placed").1;
        assert_eq!(at("input"), 0);
        assert_eq!(at("margv"), 256);
        assert_eq!(at("margn"), 256 + 512);
        let last = *placed.last().expect("non-empty");
        // 3415 until 2026-08-14, 3509 until 2026-08-15's first three datums,
        // 3520 until Task 12/13/15's second pass added three more, 3528 until
        // Task 1.1 placed one more, 3530 until Task 1.2 placed four more,
        // 3538 until Task 1.3 placed one, 3540 until Task 1.4 placed seven,
        // 3568 until Task 1.5 placed two more, 3576 until Task 1.6 placed one,
        // 3622 until Task 1.7 placed the last of this batch:
        //   +2 txtlen    (GME.H:199 -- GALME's, not MAJORBBS.H's; `Width::Bytes(2)`
        //                 rather than `Width::Int`, so it is 2 bytes under both ABIs)
        // no new alignment byte: 2 is even -- 3622 + 2 = 3624. Then Phase 2's
        // Task 2.1 placed one more:
        //   +2 nlingo    (LINGO.H:40 -- the count beside `languages`, which
        //                 stopped being an empty array in the same task)
        // no new alignment byte: 2 is even, and `nlingo` sits beside `clingo`,
        // already 2-byte-aligned -- 3624 + 2 = 3626.
        // Before that:
        //   +46 uidxrf   (USRACC.H:39 -- the struct BY VALUE, xrfstg[16] +
        //                 userid[30], non-GCV2)
        // no new alignment byte: 46 is even, so alignment on both sides of it
        // is unchanged -- 3576 + 46 = 3622.
        // Before that:
        //   +4 module    (MAJORBBS.H:314 -- empty, safe only while nmods==0)
        //   +4 languages (LINGO.H:42 -- empty, no counter pairs it)
        // no new alignment byte: both are 4-byte pointers -- 3568 + 4*2 = 3576.
        // Before that:
        //   +28 bbsttl, company, addres1, addres2, dataph, liveph, syskey
        //       (MAJORBBS.H:558-567, seven CHAR * at 4 bytes each)
        // no new alignment byte: all seven are 4 bytes and PTR-width entries
        // stay evenly aligned throughout -- 3540 + 4*7 = 3568.
        // Before that:
        //   +1 eurmsk    (MAJORBBS.H:592, a CHAR -- 1 byte)
        // plus one alignment byte: eurmsk ends on an odd offset and `kilipg`
        // (an int) needs to start on an even one -- 3538 + 1 + 1 = 3540.
        // Before that:
        //   +2 nmods     (MAJORBBS.H:316 -- the count beside `module`, Task 1.5)
        //   +2 mmucrr    (MAJORBBS.H:581 -- same block as `outbsz`)
        //   +2 digalw    (MAJORBBS.H:653)
        //   +2 clingo    (LINGO.H:41)
        // no new alignment byte: each of the four is 2 bytes and lands beside
        // an already 2-byte-aligned neighbour -- 3530 + 2*4 = 3538.
        // Before that:
        //   +2 outbsz    (MAJORBBS.H:579 -- 15 of 43 corpus modules, the most
        //                 widely imported symbol this host did not serve)
        // no new alignment byte: `outbsz` (2 bytes) sits between `emlsdrou`
        // (4-byte-aligned) and `kilipg` (already 2-byte-aligned) --
        // 3528 + 2 = 3530.
        // Before that:
        //   +4 othexp    (MAJORBBS.H:352 -- RTSLORD-NE, 15 sites)
        //   +2 kilipg    (MAJORBBS.H:590/REMOTE.H:44, an int -- Rose32, 1 site)
        //   +2 kilsrc    (REMOTE.H:46 -- 47, an int -- Rose32, 1 site)
        // no new alignment byte: `othexp` (4 bytes) follows `othusp`, itself
        // 4-byte-aligned, and `kilipg`/`kilsrc` (2 bytes each) sit beside
        // `errcod`, already 2-byte-aligned -- 3520 + 4 + 2 + 2 = 3528.
        // Before that:
        //   +4 fsdusr    (FSDBBS.H:225 -- The Rose, 12 sites)
        //   +4 emlsdrou  (MAJORBBS.H:461 -- The Rose, 6 sites)
        //   +2 errcod    (REMOTE.H:11, an int -- The Rose, 4 sites)
        // plus one alignment byte ahead of fsdusr, because bturno (9 bytes)
        // ends on an odd offset. Before that, the corpus survey placed four
        // data the modules address but this host had no slot for:
        //   +4  othuap  (USRACC.H:73-76, beside usaptr -- 17 modules)
        //   +4  ftgptr  (FTG.H:97-98    -- 7 modules, 210 sites)
        //   +4  ftfscb  (FTF.C:26-27    -- 6 modules)
        //   +81 tshmsg  (FTG.H:74,:66, TSHLEN+1 -- 6 modules, 82 sites)
        // plus one alignment byte. A change to this number is only ever
        // legitimate alongside a deliberate change to the table above; it is
        // pinned so that an accidental one is loud.
        assert_eq!(u32::from(last.1) + u32::from(last.2), 3626);
    }

    /// A module *addresses* these -- it never calls them. Registering one as
    /// a `Routine` makes the fixup point at a dispatch thunk, and the module
    /// reads a function address where it expected data.
    #[test]
    fn the_three_rose_datums_are_addressable() {
        for name in ["fsdusr", "emlsdrou", "errcod"] {
            assert!(
                matches!(
                    crate::shims::entry::<crate::abi::Wg16>(crate::exports::MAJORBBS, name),
                    crate::shims::Entry::Datum
                ),
                "{name} must be a Datum, not a Routine"
            );
        }
    }

    /// Storage a module writes must read back what it wrote, not just exist.
    /// `fsdusr` is a far pointer (`struct fsdbbs *`, `FSDBBS.H:225`), so the
    /// round trip goes through [`crate::abi::wg16`]'s `Globals::pointer`
    /// facade rather than a bare word or long -- offset first in memory, per
    /// [`FarPtr::from_bytes`](mbbs_machine::m16::FarPtr::from_bytes).
    #[test]
    fn fsdusr_round_trips_through_module_memory() {
        let mut f = crate::testing::Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "fsdusr", &0x1234_5678u32.to_le_bytes())
            .expect("write fsdusr");
        let back = f
            .host
            .globals()
            .pointer(&f.machine, "fsdusr")
            .expect("read fsdusr");
        assert_eq!(back.offset, 0x5678, "a datum the module writes must read back");
        assert_eq!(back.selector, 0x1234, "a datum the module writes must read back");
    }

    /// The same class of mistake `fsdusr`/`emlsdrou`/`errcod` already guard
    /// against: `othexp`, `kilipg` and `kilsrc` are data a module addresses,
    /// never routines it calls. Registering one under `routines()`/
    /// `WG16_ROUTINES`/`WG32_ROUTINES` instead would leave the fixup pointing
    /// at a dispatch thunk -- the module would read a function address where
    /// it expected a pointer or an `int`, and the "routine" would look
    /// implemented while nothing ever ran.
    #[test]
    fn the_second_pass_datums_are_addressable_not_callable() {
        for name in ["othexp", "kilipg", "kilsrc"] {
            assert!(
                matches!(
                    crate::shims::entry::<crate::abi::Wg16>(crate::exports::MAJORBBS, name),
                    crate::shims::Entry::Datum
                ),
                "{name} must be a Datum, not a Routine"
            );
        }
    }

    /// `othexp` is a far pointer (`struct extusr *`, `MAJORBBS.H:352`), so
    /// this round-trips through [`crate::abi::wg16`]'s `Globals::pointer`
    /// facade, the same shape [`fsdusr_round_trips_through_module_memory`]
    /// already established.
    #[test]
    fn othexp_round_trips_through_module_memory() {
        let mut f = crate::testing::Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "othexp", &0x2222_3333u32.to_le_bytes())
            .expect("write othexp");
        let back = f.host.globals().pointer(&f.machine, "othexp").expect("read othexp");
        assert_eq!(back.offset, 0x3333);
        assert_eq!(back.selector, 0x2222);
    }

    /// `kilipg`/`kilsrc` are plain `int`s (`REMOTE.H:44,46`), so this
    /// round-trips through the `Globals::word` facade rather than
    /// `Globals::pointer` -- the same distinction
    /// [`an_int_global_is_two_bytes_under_wg16_and_four_under_wg32`] tests at
    /// the byte-width level, exercised here through an actual write/read.
    #[test]
    fn kilipg_and_kilsrc_round_trip_through_module_memory_independently() {
        let mut f = crate::testing::Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "kilipg", &1i16.to_le_bytes())
            .expect("write kilipg");
        f.host
            .globals()
            .write(&mut f.machine, "kilsrc", &(-2i16).to_le_bytes())
            .expect("write kilsrc");

        assert_eq!(f.host.globals().word(&f.machine, "kilipg").expect("read kilipg"), 1);
        assert_eq!(
            f.host.globals().word(&f.machine, "kilsrc").expect("read kilsrc") as i16,
            -2,
            "kilsrc's -2 = timed event, per REMOTE.H:12's own comment"
        );

        // Not the same slot, and not `errcod` (placed between them) either --
        // a mutation that collapsed the three into one address would still
        // pass a test that checked only one name back.
        assert_eq!(f.host.globals().word(&f.machine, "errcod").expect("errcod"), 0);
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
        // Both ABIs: `input` and `margv` are `char[]` and `char*[]`, neither
        // of which changes width, but everything placed before them would
        // move the pair together if it did.
        for placed in [
            layout::<crate::abi::Wg16>(),
            layout::<crate::abi::Wg32>(),
        ] {
            let input = placed.iter().find(|p| p.0 == "input").expect("input");
            let margv = placed.iter().find(|p| p.0 == "margv").expect("margv");
            assert_eq!(input.1 + input.2, margv.1, "margv must follow input");
            assert!(margv.1 >= 2, "margv[-1] must be inside the segment");
        }
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
