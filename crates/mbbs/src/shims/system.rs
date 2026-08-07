//! The clock, the audit trail, and registering a module.
//!
//! Everything here that reads the world reads it through [`Host`], so a test
//! can point it at a directory of its own.

use mbbs16::{FarPtr, Machine, Ret};

use crate::{DateBuffers, Host};
use crate::fmt::{Args, format};
use crate::random::Random;
use crate::shims::{NO, ShimError};
use crate::shims::text::write_cstr;

/// `MAJORBBS.H:37` -- maximum size for module names, terminator included.
const MNMSIZ: u16 = 25;

/// `GCSP.H:19` -- application id size, terminator included.
const AIDSIZ: u16 = 9;

/// Bytes of `struct agent`: the appid, then four far vectors.
///
/// 25, and the binary agrees: `register_agent` multiplies every index by
/// `0x19`.
const AGENT_SIZE: u16 = AIDSIZ + 4 * 4;

/// Bytes of the buffer `gmdnam` returns a pointer into.
///
/// `static char tmpbuf[40]` in the real one
/// (`mbbs625sdk/MBBS_SDK/INSTALLA/MAJORBBS.C:1141`), and it holds a whole line
/// of the `.MDF` before the name is picked out of it.
const MDF_LINE: u16 = 40;

/// `int now(void)` -- the time of day, packed as DOS packs it.
///
/// `DOSFACE.H:73`. Hours in bits 15..11, minutes in 10..5, and *two-second*
/// units in 4..0, because five bits will not hold sixty.
///
/// # Errors
///
/// If the host's clock cannot say what time it is.
pub fn now(_: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let t = host.clock().civil().map_err(ShimError::Failed)?;
    Ok(Ret::U16(t.dos_time()))
}

/// `int today(void)` -- the date, packed as DOS packs it.
///
/// Years since 1980 in bits 15..9, month in 8..5, day in 4..0.
///
/// # Errors
///
/// If the host's clock cannot say what day it is, or the year is one those
/// seven bits will not hold. The old shim clamped with `.max(0)`, which turned
/// 1970 into 1980 -- a date that is wrong rather than absent, and the one
/// outcome this crate exists to avoid.
pub fn today(_: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let t = host.clock().civil().map_err(ShimError::Failed)?;
    let packed = t
        .dos_date()
        .map_err(|why| ShimError::Failed(format!("today: {why}")))?;
    Ok(Ret::U16(packed))
}

/// `long time(long *tloc)` -- seconds since 1970, and stored if asked.
///
/// # Errors
///
/// If the host's clock cannot say, or `tloc` names memory the module does not
/// own.
pub fn time(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let seconds = host.clock().epoch().map_err(ShimError::Failed)?;

    // A null pointer is how C spells "do not store it", and is the ordinary
    // case rather than an error.
    let tloc = machine.arg_far(0);
    if tloc.selector != 0 {
        machine.write(tloc, &seconds.to_le_bytes())?;
    }
    Ok(Ret::U32(seconds))
}

/// Bytes of the three date statics, measured from their spacing in
/// `MAJORBBS-wg101.EXE`'s `DGROUP`: `0x40`, `0x49`, `0x52`.
///
/// `GALFIL.C:1210` corroborates the first two independently --
/// `stzcpy(answer, nctime(dctime(nts)), 9)`.
const DATE_LEN: u16 = 9;
const TIME_LEN: u16 = 9;
const EDAT_LEN: u16 = 10;

/// The buffers the date routines format into, allocated the first time one of
/// them runs.
///
/// See [`DateBuffers`] for why they are allocated once rather than per call.
///
/// # Errors
///
/// If the module's heap cannot give up four small blocks.
fn buffers(machine: &mut Machine, host: &mut Host) -> Result<DateBuffers, ShimError> {
    if let Some(already) = host.datebuf {
        return Ok(already);
    }

    // Not a closure over both: `alloc` needs the machine mutably and so does
    // the `write_cstr` below it.
    let date = host.heap.alloc(machine, DATE_LEN).map_err(ShimError::Failed)?;
    let time = host.heap.alloc(machine, TIME_LEN).map_err(ShimError::Failed)?;
    let edat = host.heap.alloc(machine, EDAT_LEN).map_err(ShimError::Failed)?;
    let empty = host.heap.alloc(machine, 1).map_err(ShimError::Failed)?;
    // Written explicitly rather than trusted to the heap's zero-fill -- see
    // `Host::empty` (`lib.rs:212`) for the sibling that gets the same
    // treatment eagerly, in `Host::new`, because it has to exist before this
    // one would ever be allocated.
    write_cstr(machine, empty, b"", 1)?;

    let all = DateBuffers {
        date,
        time,
        edat,
        empty,
    };
    host.datebuf = Some(all);
    Ok(all)
}

/// `char *nctime(int time)` -- a DOS-packed time as `HH:MM:SS`.
///
/// No C source survives for this one. Transcribed from
/// `MAJORBBS-wg101.EXE seg 33:0x0c56`, which is
/// `sprintf(buf, "%02d:%02d:%02d", (t>>11)&0x1f, (t>>5)&0x3f, (t<<1)&0x3e)`
/// and hands back the buffer. Declared at `DOSFACE.H:75`.
///
/// **The low five bits are two-second units and are doubled, not masked** --
/// five bits will not hold 59, so an odd second cannot be represented at all
/// and the routine never prints one. That is the field a reader gets wrong by
/// working from the name instead of the instructions.
///
/// There is no null case: unlike [`ncdate`], `nctime(0)` formats `00:00:00`.
///
/// # Errors
///
/// If the module's heap cannot give the buffer its first time through.
pub fn nctime(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let packed = machine.arg_u16(0);
    let at = buffers(machine, host)?.time;
    let text = format!(
        "{:02}:{:02}:{:02}",
        (packed >> 11) & 0x1f,
        (packed >> 5) & 0x3f,
        (packed << 1) & 0x3e,
    );
    write_cstr(machine, at, text.as_bytes(), TIME_LEN)?;
    Ok(Ret::Far(at))
}

/// `char *ncdate(int date)` -- a DOS-packed date as `MM/DD/YY`.
///
/// No C source survives. Transcribed from `MAJORBBS-wg101.EXE seg 33:0x0c02`;
/// declared at `DOSFACE.H:74`.
///
/// **Date zero is not a date, and the original says so** by returning a
/// separate empty string at `DS:0x82` *without touching its buffer* -- so a
/// result taken earlier is still standing after a null date goes through.
/// Reproduced here, because the alternative reading, formatting `00/00/00`, is
/// a date that is wrong rather than one that is absent.
///
/// The year is `% 100`, so nothing downstream can tell 2007 from 2107. That
/// limitation is the original's, not this host's -- `seg 33:0x0c26` divides by
/// `0x64` and keeps the remainder.
///
/// # Errors
///
/// If the module's heap cannot give the buffer its first time through.
pub fn ncdate(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let packed = machine.arg_u16(0);
    let all = buffers(machine, host)?;

    // `or cx,cx / jnz` at `seg 33:0x0c10`, and the branch it does not take
    // writes nothing at all.
    if packed == 0 {
        return Ok(Ret::Far(all.empty));
    }

    let text = format!(
        "{:02}/{:02}/{:02}",
        (packed >> 5) & 0xf,
        packed & 0x1f,
        (((packed >> 9) & 0x7f) + 1980) % 100,
    );
    write_cstr(machine, all.date, text.as_bytes(), DATE_LEN)?;
    Ok(Ret::Far(all.date))
}

/// `void srand(unsigned seed)`.
///
/// MajorMUD calls this once, six calls into initialisation, with the low word
/// of `time()` -- so the seed is the wall clock and no two runs of the real host
/// agreed either. See [`mbbs::random`](crate::random).
pub fn srand(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    host.random = Random::new(machine.arg_u16(0));
    Ok(Ret::Void)
}

/// `int genrdn(int min, int max)` -- a random number in `[min, max)`.
///
/// The upper bound is exclusive and the routine's own comment says so. See
/// [`between`](crate::random::between), which is the ported algorithm; this is
/// only the two arguments and the draw.
///
/// # Errors
///
/// If the generator stops generating. See
/// [`Runaway`](crate::random::Runaway).
pub fn genrdn(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let (min, max) = (machine.arg_u16(0) as i16, machine.arg_u16(1) as i16);
    host.random
        .genrdn(min, max)
        .map(|n| Ret::U16(n as u16))
        .map_err(|e| ShimError::Failed(e.to_string()))
}

/// `int access(char *path, int amode)` -- is this file there, and may I use it?
///
/// Borland's, re-exported by `MAJORBBS.DLL` as ordinal 850. `amode` is a mask:
/// 0 asks only whether the file exists, 2 whether it can be written, 4 whether
/// it can be read, 6 both. Zero means yes and -1 means no.
///
/// **-1 is an answer, not a refusal.** This is the one routine in the host so
/// far whose whole purpose is to report an absence, so returning "no" for a
/// file that is not there is exactly right where everywhere else it would be
/// the lie this crate is built to avoid.
///
/// It is here rather than with the Btrieve routines it arrived among because it
/// is not one -- but answering it is what lets initialisation finish opening its
/// data files. MajorMUD builds a sixteenth filename, asks
/// `access(".\WCCVACN.DAT", 0)`, is told -1, and **does not open it**. There is
/// no `WCCVACN.VIR` to install one from and no working board has the file, so
/// -1 is both the true answer and the one that lets the module continue.
pub fn access(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let named = String::from_utf8_lossy(machine.read_cstr(machine.arg_far(0))?).into_owned();
    let mode = machine.arg_u16(2);

    // A path this host will not look in is not a file that is missing -- it is
    // a question it cannot answer, and answering "no" would tell the module the
    // file is absent when nobody looked.
    let name = Host::dos_name(&named).map_err(ShimError::Failed)?;
    let Some(path) = host.find(name) else {
        return Ok(Ret::U16(NO));
    };
    let Ok(metadata) = std::fs::metadata(&path) else {
        return Ok(Ret::U16(NO));
    };

    // Bit 1 is write and bit 2 is read. Nothing else is defined, and a mode
    // with anything else in it is a call this host has misread rather than a
    // question about a file.
    if mode & !0b110 != 0 {
        return Err(ShimError::Failed(format!(
            "access({named}, {mode}), and only 0, 2, 4 and 6 are modes"
        )));
    }
    if mode & 2 != 0 && metadata.permissions().readonly() {
        return Ok(Ret::U16(NO));
    }
    Ok(Ret::U16(0))
}

/// `char *gmdnam(char *mdfnam)` -- a module's name, out of its `.MDF`.
///
/// The real one (`MAJORBBS.C:1137`) opens the file, finds the line beginning
/// `Module Name:`, unpads it and returns a pointer past the label into its own
/// static buffer. This does the same into a buffer the host owns, so the
/// pointer the module keeps stays valid.
///
/// A file it cannot open is `catastro` in the original. Here it stops the
/// module with the path, which is the same outcome and says more.
pub fn gmdnam(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let name = machine.read_cstr(machine.arg_far(0))?.to_vec();
    let name = String::from_utf8_lossy(&name).into_owned();

    let path = host
        .find(&name)
        .ok_or_else(|| ShimError::Failed(format!("gmdnam: no {name} under {:?}", host.root)))?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| ShimError::Failed(format!("gmdnam: {}: {e}", path.display())))?;

    const LABEL: &str = "Module Name:";
    let module = text
        .lines()
        .find_map(|line| line.strip_prefix(LABEL))
        .map(str::trim)
        .ok_or_else(|| ShimError::Failed(format!("gmdnam: no module name in {name}")))?;

    let at = host.mdf_buffer();
    write_cstr(machine, at, module.as_bytes(), MDF_LINE)?;
    Ok(Ret::Far(at))
}

/// `void shocst(char *tex1, char *tex2, ...)` -- one line of audit trail.
///
/// Two strings then printf arguments, as every call site has it:
/// `shocst("C/S FILE PAGE FILE MISSING","%s %s",mnutmp2.pagnam,fpath)`
/// (`BBSMAINM.C:498`). The real host writes it to the audit-trail Btrieve file
/// and the console; this keeps it, and [`Host::audit`] is where it can be read.
pub fn shocst(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let headline = machine.read_cstr(machine.arg_far(0))?.to_vec();
    let (detail, _) = format(machine, machine.arg_far(2), Args::Call { first: 4 })?;
    host.audit.push(format!(
        "{}: {}",
        String::from_utf8_lossy(&headline),
        String::from_utf8_lossy(&detail)
    ));
    Ok(Ret::Void)
}

/// `void rtkick(int delay, void (*dstrou)())` -- run this later.
///
/// The host remembers it and **nothing runs it**, because running it needs a
/// main loop and a clock that this host does not have. That is a debt rather
/// than a lie: `rtkick` returns `void`, so it promises the caller nothing at
/// call time, and a module cannot observe a second that never passes. See
/// [`Host::kicks`] for what the main loop will read when there is one.
///
/// # Errors
///
/// If `delay` is negative, which no caller can mean and a misread argument
/// list would produce.
pub fn rtkick(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let delay = machine.arg_u16(0);
    if delay & 0x8000 != 0 {
        return Err(ShimError::Failed(format!(
            "rtkick: a negative delay ({} seconds)",
            delay as i16
        )));
    }
    let dstrou = machine.arg_far(1);
    host.kicks.push(Kick { delay, dstrou });
    Ok(Ret::Void)
}

/// `void dclvda(int size)` -- declare how much volatile data area this module
/// needs.
///
/// `MAJORBBS.C:1157`, in full: `if (size > vdasiz) vdasiz=size`. The largest
/// declaration wins, because every module shares one area per channel.
pub fn dclvda(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let size = machine.arg_u16(0) as i16;
    let current = host
        .globals()
        .word(machine, "vdasiz")
        .map_err(|e| ShimError::Failed(e.to_string()))? as i16;
    if size > current {
        host.globals()
            .write(machine, "vdasiz", &size.to_le_bytes())
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    Ok(Ret::Void)
}

/// `int register_module(struct module *mod)` -- take a module online.
///
/// `MAJORBBS.H:241`: 25 bytes of description, then nine far pointers, which are
/// every entry point the host will ever call back into. **The pointer is kept,
/// not the contents.** The real host stores `mod` itself
/// (`MAJORBBS.C:1327`, `module[nmods]=mod`) and the module is free to change
/// its own block afterwards, so a snapshot would go stale.
///
/// Two things the real one does that this does not, both deliberate. It
/// allocates a `mdstats` record out of Btrieve, which is a subsystem that does
/// not exist yet. And it fills a null `stsrou` with the host's own `dfsthn` --
/// pointless here, because a null `stsrou` simply means the host has no status
/// routine to call, which is what it would mean either way.
pub fn register_module(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let block = machine.arg_far(0);

    // `descrp` is a fixed-width field, so the string inside it is read bounded
    // rather than scanned: a module whose description fills all 25 bytes has no
    // terminator, and scanning would run into `lonrou`.
    let bytes = machine.resolve(block, usize::from(MNMSIZ))?;
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let description = String::from_utf8_lossy(&bytes[..end]).into_owned();

    // The same two refusals the real one makes, and for the same reason: this
    // name is the key a module's records are stored under.
    if description.len() < 3 {
        return Err(ShimError::Failed(format!(
            "register_module: the name {description:?} is too short"
        )));
    }
    if description.len() > usize::from(MNMSIZ) - 1 {
        return Err(ShimError::Failed(format!(
            "register_module: the name {description:?} is too long"
        )));
    }

    Ok(Ret::U16(host.register(description, block)))
}

/// `void register_agent(struct agent *agdptr)` -- take a client/server agent
/// online.
///
/// An *agent* is a module's server-side handler for a Worldgroup client, and
/// its `appid` is the name a client addresses it by (`GCSPSRV.H:21`). MajorMUD
/// registers exactly one, `WCCMMUD`.
///
/// **The record is copied, not pointed at**, and that is the one way this
/// differs from [`register_module`]. The real routine ends in
/// `movmem(agdptr, &agents[nagents], 25)` (seg 30:0x0121 of
/// `MAJORBBS-wg200.EXE`) -- so the caller's block is free to go out of scope
/// afterwards, and a host that kept the pointer would be reading whatever
/// replaced it.
///
/// **Nothing dispatches to these vectors**, because dispatching needs a client
/// and this host has none. A debt rather than a lie, on the same terms as
/// [`Host::kicks`](crate::Host::kicks): the routine returns `void`, so it
/// promises the module nothing.
///
/// Two things the real one does that this does not. It grows the table twenty
/// slots at a time out of the *host's* heap, which the module never sees and
/// cannot observe. And it fills a null vector with a host default -- see
/// [`Agent`] for what those defaults are and why filling one in here would say
/// less than leaving it `None`.
///
/// # Errors
///
/// If the block does not name 25 readable bytes, or the `appid` is empty. The
/// second is this host's own refusal and not the original's: an agent with no
/// name can never be addressed by a client, so no caller can mean it, and a
/// misread argument list is what would produce one.
pub fn register_agent(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let block = machine.arg_far(0);
    let bytes = machine.resolve(block, usize::from(AGENT_SIZE))?;

    // `appid` is a fixed-width field, so the name inside it is read bounded
    // rather than scanned -- an agent whose name fills all nine bytes has no
    // terminator, and scanning would run into the `read` vector.
    let field = &bytes[..usize::from(AIDSIZ)];
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    let appid = String::from_utf8_lossy(&field[..end]).into_owned();
    if appid.is_empty() {
        return Err(ShimError::Failed(
            "register_agent: an agent with no appid can never be addressed".to_owned(),
        ));
    }

    // A vector is null when **both** its words are zero. The real routine tests
    // it as `mov ax,[es:bx+9]; or ax,[es:bx+0xb]`, and the difference matters:
    // offset zero is a perfectly good address, and `seg 26:0x0000` of
    // `WCCMMUD.DLL` is the very routine that makes this call.
    let vector = |n: usize| {
        let at = usize::from(AIDSIZ) + n * 4;
        let ptr = FarPtr {
            offset: u16::from_le_bytes([bytes[at], bytes[at + 1]]),
            selector: u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]),
        };
        (ptr.offset != 0 || ptr.selector != 0).then_some(ptr)
    };
    let agent = Agent {
        appid,
        read: vector(0),
        write: vector(1),
        xferdone: vector(2),
        abort: vector(3),
    };

    host.agents.push(agent);
    Ok(Ret::Void)
}

/// `int register_textvar(char *name, char *(*varrou)())` -- register a text
/// variable.
///
/// `MAJORBBS.C:1279`, and this one has surviving source -- unlike
/// [`register_agent`], which had to be transcribed. It is checked against the
/// wg200 binary anyway (`seg 4:0x21b0`, ordinal 494) because the source is
/// Worldgroup 1's and the module is built against Worldgroup 2. They agree.
///
/// A *text variable* is a substitution: the module hands over a name and a
/// routine, and the routine's return value replaces that name wherever a
/// message mentions it. MajorMUD registers exactly one, `MUDCHARINFO`.
///
/// **The table is module memory, not a `Vec`**, and that is the difference from
/// [`register_agent`]. `WCCMMUD.DLL` addresses `txtvars` at ten sites and walks
/// the table through it -- see [`TextVars`](crate::TextVars) for the access
/// pattern that settles it.
///
/// **It returns the index**, which `register_agent` did not: the original ends
/// `return(ntvars++)`, and the binary's `mov ax,[0x44]` before its `inc` is
/// that.
///
/// Two things the real one does that this does not. It keeps a `ntvars` global
/// (ordinal 861) which `WCCMMUD.DLL` never addresses, so the count stays on the
/// Rust side and `Host::load` is the guard if that changes. And it leaves the
/// bytes past a short name's terminator as whatever the heap last held; this
/// zeroes the record first, which no correct reader can tell apart.
///
/// # Errors
///
/// If the name is empty, if the pointers do not name readable memory, or if the
/// heap has no room. The empty name is this host's own refusal and not the
/// original's -- weaker than the agent's, since `findtvar("")` could genuinely
/// match one, and carried instead by the realistic cause being a misread
/// argument list.
pub fn register_textvar(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let name = String::from_utf8_lossy(machine.read_cstr(machine.arg_far(0))?).into_owned();
    let varrou = machine.arg_far(2);

    let mut table = std::mem::take(&mut host.textvars);
    let pushed = table.push(machine, &mut host.heap, &name, varrou);
    host.textvars = table;
    let n = pushed?;

    // The module reaches the table only through this. A host that filled the
    // table and left the global null would have registered nothing.
    let at = host.textvars.at().expect("a row was just added");
    host.globals()
        .write(machine, "txtvars", &at.to_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(Ret::U16(n))
}

/// `void catastro(char *fmat, ...)` -- the module has given up.
///
/// Stops it, deliberately. `catastro` is a module saying it cannot continue,
/// and a host that formatted the message and returned would be resuming code
/// that has already decided it is in an impossible state.
pub fn catastro(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let (text, _) = format(machine, machine.arg_far(0), Args::Call { first: 2 })?;
    Err(ShimError::Failed(format!(
        "catastro: {}",
        String::from_utf8_lossy(&text)
    )))
}

/// A module routine the host has been asked to run later.
///
/// `rtkick(delay, dstrou)` is a **one-shot** timer: `dstrou` runs once, `delay`
/// seconds from the call, and a callback that wants to keep going re-arms
/// itself. `GALMJD.C:180` registers `mjdrtk` with `rtkick(1,mjdrtk)` and
/// `GALMJD.C:1106` is that same call *inside* `mjdrtk` -- which is only
/// necessary, and only correct, if a kick fires once.
///
/// `delay` is kept as it was given rather than converted to a deadline. This
/// host has no clock to measure one against, and inventing an epoch here would
/// commit the future main loop to whichever one this file guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kick {
    /// Seconds from registration until it is due. `0` means the next tick.
    pub delay: u16,

    /// The module routine to call. Far, and into the module's own code -- the
    /// one MajorMUD registers is an `INTERNALREF` to its NE segment 6.
    pub dstrou: FarPtr,
}

/// A module that has been taken online.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The name from `descrp`, which is the key its records are kept under.
    pub description: String,

    /// The module's own `struct module`, in its own memory. Every entry point
    /// the host will ever call is read back through here rather than copied,
    /// because the module may change them.
    pub block: FarPtr,
}

/// A client/server agent that has been taken online.
///
/// A **snapshot**, unlike [`Registration`]: `register_agent` copies the
/// caller's 25 bytes into the host's own table, so these vectors are what the
/// module registered and not what its memory says now.
///
/// A `None` vector is one the module left null, and the real host would fill it
/// with its own default at registration time -- `rejectreq` for `read` and
/// `write` (seg 30:0x251e and 0x252f, both of which call seg 31:0x5f6), and a
/// bare `retf` for `xferdone` and `abort`. That substitution is *not* made
/// here, because this host has nothing to dispatch and a `None` says which
/// vector the module actually supplied. Whoever builds the dispatcher owes
/// those four defaults, and the table above is what they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    /// The name a client addresses this agent by. MajorMUD's is `WCCMMUD`.
    pub appid: String,

    /// Deliver a dynapak to the agent, or `None` -- which rejects the request.
    pub read: Option<FarPtr>,

    /// Take a dynapak from the agent, or `None` -- which rejects the request.
    pub write: Option<FarPtr>,

    /// A transfer finished, or `None` -- which does nothing.
    pub xferdone: Option<FarPtr>,

    /// A transfer was abandoned, or `None` -- which does nothing.
    pub abort: Option<FarPtr>,
}

impl Registration {
    /// Where one of the nine entry points is, or `None` if the module left it
    /// null.
    ///
    /// `n` is its position in `struct module` after `descrp`: 0 is `lonrou`,
    /// 1 `sttrou`, 2 `stsrou`, and so on to 8 for `finrou`.
    ///
    /// Read every time. That is the whole reason the pointer is kept.
    ///
    /// # Errors
    ///
    /// If the block no longer names memory the module owns.
    pub fn entry(&self, machine: &Machine, n: usize) -> Result<Option<FarPtr>, ShimError> {
        let at = FarPtr {
            offset: self.block.offset + MNMSIZ + (n as u16) * 4,
            selector: self.block.selector,
        };
        let bytes = machine.resolve(at, 4)?;
        let ptr = FarPtr {
            offset: u16::from_le_bytes([bytes[0], bytes[1]]),
            selector: u16::from_le_bytes([bytes[2], bytes[3]]),
        };
        Ok((ptr.selector != 0).then_some(ptr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    /// A `struct module` in module memory: 25 bytes of name, then nine far
    /// pointers.
    fn module_block(f: &mut Fixture, name: &str, entries: &[FarPtr]) -> FarPtr {
        let mut bytes = vec![0u8; usize::from(MNMSIZ)];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        for entry in entries {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        bytes.resize(usize::from(MNMSIZ) + 9 * 4, 0);
        f.bytes(&bytes, false)
    }

    /// A `struct agent` in module memory: nine bytes of appid, then four far
    /// vectors.
    fn agent_block(f: &mut Fixture, appid: &str, vectors: &[FarPtr]) -> FarPtr {
        let mut bytes = vec![0u8; usize::from(AIDSIZ)];
        bytes[..appid.len()].copy_from_slice(appid.as_bytes());
        for vector in vectors {
            bytes.extend_from_slice(&vector.to_bytes());
        }
        bytes.resize(usize::from(AGENT_SIZE), 0);
        f.bytes(&bytes, false)
    }

    #[test]
    fn now_and_today_are_packed_the_way_dos_packs_them() {
        let mut f = Fixture::new();

        let Ret::U16(time) = f.invoke(now, &[]).expect("now") else {
            panic!("now returns an int");
        };
        let (hour, minute, second) = (time >> 11, (time >> 5) & 0x3f, (time & 0x1f) * 2);
        assert!(hour < 24, "{hour}");
        assert!(minute < 60, "{minute}");
        assert!(second < 60, "{second}");

        let Ret::U16(date) = f.invoke(today, &[]).expect("today") else {
            panic!("today returns an int");
        };
        let (year, month, day) = (1980 + (date >> 9), (date >> 5) & 0x0f, date & 0x1f);
        assert!((1..=12).contains(&month), "{month}");
        assert!((1..=31).contains(&day), "{day}");
        assert!(year >= 2020, "{year}");
    }

    /// MajorMUD 1.11p's build stamp: `Dec 30 2005 14:20:05` UTC.
    const BUILD: u32 = 1_135_952_405;

    #[test]
    fn a_pinned_clock_packs_the_instant_it_was_pinned_to() {
        // Both numbers are derived rather than observed:
        //   today = (2005-1980)<<9 | 12<<5 | 30 = 13214
        //   now   = 14<<11 | 20<<5 | 5/2        = 29314
        // and the seconds field is *two-second units*, so 5 packs as 2.
        let mut f = Fixture::new();
        f.host.set_clock(crate::Clock::pinned(BUILD));

        assert_eq!(f.invoke(today, &[]).expect("today"), Ret::U16(13214));
        assert_eq!(f.invoke(now, &[]).expect("now"), Ret::U16(29314));
        assert_eq!(f.invoke(time, &[0, 0]).expect("time"), Ret::U32(BUILD));
    }

    #[test]
    fn all_three_describe_one_instant() {
        // The bug this rules out: three independent `SystemTime::now()` calls,
        // which is what these shims used to be. Under a pin they cannot drift,
        // and `time` is the one that has to agree with the other two rather
        // than merely be plausible.
        let mut f = Fixture::new();
        f.host.set_clock(crate::Clock::pinned(BUILD));

        let Ret::U32(seconds) = f.invoke(time, &[0, 0]).expect("time") else {
            panic!("time returns a long");
        };
        let civil = crate::Clock::pinned(seconds).civil().expect("in range");

        let Ret::U16(date) = f.invoke(today, &[]).expect("today") else {
            panic!("today returns an int");
        };
        assert_eq!(u32::from(date >> 9) + 1980, civil.year as u32);
        assert_eq!(u32::from((date >> 5) & 0x0f), civil.month);
        assert_eq!(u32::from(date & 0x1f), civil.day);
    }

    #[test]
    fn a_year_dos_cannot_pack_is_refused_rather_than_clamped() {
        // `today` has seven bits for `year - 1980`. The old shim wrote
        // `.max(0)`, which turned 1970 into 1980 and handed the module a date
        // that was wrong rather than absent -- the one outcome this crate is
        // built to avoid.
        //
        // Only the lower bound can be reached. A `u32` of epoch seconds runs
        // out on 2106-02-07, so the 2107 ceiling those seven bits impose is
        // unreachable while the clock is a `u32` -- the check is there because
        // the format has the limit, not because a test can provoke it.
        let mut f = Fixture::new();

        f.host.set_clock(crate::Clock::pinned(0));
        let e = f.invoke(today, &[]).expect_err("1970 is not a DOS year");
        assert!(format!("{e}").contains("1970"), "{e}");

        // The last second a `u32` can hold is still inside the range, so the
        // ceiling stays a refusal nothing trips over.
        f.host.set_clock(crate::Clock::pinned(u32::MAX));
        assert!(f.invoke(today, &[]).is_ok(), "2106 is a DOS year");
    }

    #[test]
    fn time_stores_through_a_pointer_and_ignores_a_null_one() {
        let mut f = Fixture::new();
        let tloc = f.buffer(4);

        let Ret::U32(seconds) = f.invoke(time, &Fixture::far(tloc)).expect("time") else {
            panic!("time returns a long");
        };
        let stored = f.machine.resolve(tloc, 4).expect("in bounds");
        assert_eq!(u32::from_le_bytes(stored.try_into().unwrap()), seconds);

        // A null pointer means "do not store it", which is the ordinary call.
        assert!(f.invoke(time, &[0, 0]).is_ok());
    }

    #[test]
    fn dclvda_keeps_the_largest_declaration() {
        let mut f = Fixture::new();
        let vdasiz = |f: &Fixture| f.host.globals().word(&f.machine, "vdasiz").expect("vdasiz");

        f.invoke(dclvda, &[512]).expect("declared");
        assert_eq!(vdasiz(&f), 512);

        // Every module shares one volatile data area per channel, so a smaller
        // declaration must not shrink it.
        f.invoke(dclvda, &[128]).expect("declared");
        assert_eq!(vdasiz(&f), 512);

        f.invoke(dclvda, &[1024]).expect("declared");
        assert_eq!(vdasiz(&f), 1024);
    }

    #[test]
    fn gmdnam_returns_the_name_after_the_label() {
        let mut f = Fixture::new();
        let name = f.text("SAMPLE.MDF");
        let Ret::Far(at) = f.invoke(gmdnam, &Fixture::far(name)).expect("read") else {
            panic!("gmdnam returns a pointer");
        };
        assert_eq!(f.read(at), "Sample Module");
    }

    #[test]
    fn gmdnam_finds_a_file_whatever_case_it_was_named_in() {
        // A DOS module names its own files in whatever case it likes, and the
        // filesystem underneath is not as forgiving as DOS was.
        let mut f = Fixture::new();
        let name = f.text("sample.mdf");
        assert!(f.invoke(gmdnam, &Fixture::far(name)).is_ok());
    }

    #[test]
    fn gmdnam_stops_the_module_rather_than_inventing_a_name() {
        let mut f = Fixture::new();
        let name = f.text("NOSUCH.MDF");
        assert!(f.invoke(gmdnam, &Fixture::far(name)).is_err());
    }

    #[test]
    fn shocst_keeps_the_headline_and_the_formatted_detail() {
        let mut f = Fixture::new();
        let headline = f.text("MODULE ONLINE");
        let detail = f.text("%s on channel %d");
        let who = f.text("rangerdan");
        let args = [
            headline.offset,
            headline.selector,
            detail.offset,
            detail.selector,
            who.offset,
            who.selector,
            3,
        ];
        f.invoke(shocst, &args).expect("recorded");
        assert_eq!(f.host.audit(), ["MODULE ONLINE: rangerdan on channel 3"]);
    }

    #[test]
    fn register_module_keeps_the_pointer_and_hands_back_a_number() {
        let mut f = Fixture::new();
        let entries: Vec<FarPtr> = (0..9)
            .map(|n| FarPtr {
                offset: 0x100 + n * 0x10,
                selector: f.machine.code_selector(),
            })
            .collect();
        let block = module_block(&mut f, "MajorMUD", &entries);

        assert_eq!(
            f.invoke(register_module, &Fixture::far(block)).expect("ok"),
            Ret::U16(0),
            "the first module is module zero"
        );
        let registered = &f.host.modules()[0];
        assert_eq!(registered.description, "MajorMUD");

        for (n, expect) in entries.iter().enumerate() {
            assert_eq!(
                registered.entry(&f.machine, n).expect("readable"),
                Some(*expect)
            );
        }
    }

    #[test]
    fn a_registered_module_may_change_its_own_entry_points() {
        // The real host stores the module's own block rather than a copy
        // (`MAJORBBS.C:1327`), and the module is free to rewrite it. A snapshot
        // would go stale and the host would call the wrong address.
        let mut f = Fixture::new();
        let block = module_block(&mut f, "MajorMUD", &[]);
        f.invoke(register_module, &Fixture::far(block)).expect("ok");

        assert_eq!(
            f.host.modules()[0].entry(&f.machine, 1).expect("readable"),
            None,
            "a null entry point is no entry point"
        );

        let sttrou = FarPtr {
            offset: 0x0200,
            selector: f.machine.code_selector(),
        };
        let at = FarPtr {
            offset: block.offset + MNMSIZ + 4,
            selector: block.selector,
        };
        f.machine.write(at, &sttrou.to_bytes()).expect("in bounds");

        assert_eq!(
            f.host.modules()[0].entry(&f.machine, 1).expect("readable"),
            Some(sttrou),
            "read back, not remembered"
        );
    }

    #[test]
    fn register_module_refuses_a_name_the_real_host_would_refuse() {
        // Both are `catastro` in the original: the name is the key a module's
        // records are stored under, so a bad one is not something to carry on
        // from.
        let mut f = Fixture::new();
        let short = module_block(&mut f, "AB", &[]);
        assert!(f.invoke(register_module, &Fixture::far(short)).is_err());

        let mut f = Fixture::new();
        let full = module_block(&mut f, "0123456789012345678901234", &[]);
        assert!(f.invoke(register_module, &Fixture::far(full)).is_err());
    }

    #[test]
    fn catastro_stops_the_module_with_its_own_message() {
        let mut f = Fixture::new();
        let template = f.text("BAD LIBRARY FILE DATA POINTER (%d)");
        let failed = f
            .invoke(catastro, &[template.offset, template.selector, 7])
            .expect_err("catastro never returns");
        assert!(
            failed
                .to_string()
                .contains("BAD LIBRARY FILE DATA POINTER (7)"),
            "{failed}"
        );
    }

    #[test]
    fn srand_starts_the_generator_over() {
        // What `srand` is *for*. The seed was stored and unused from step 7
        // until now; this is the first test that can see it do anything.
        let mut f = Fixture::new();
        f.invoke(srand, &[0x1234]).expect("seeded");
        let first: Vec<u16> = (0..8).map(|_| f.host.random.rand()).collect();

        f.invoke(srand, &[0x1234]).expect("seeded again");
        let again: Vec<u16> = (0..8).map(|_| f.host.random.rand()).collect();
        assert_eq!(first, again);

        f.invoke(srand, &[0x1235]).expect("a different seed");
        let other: Vec<u16> = (0..8).map(|_| f.host.random.rand()).collect();
        assert_ne!(first, other);
    }

    #[test]
    fn genrdn_answers_inside_the_range_the_module_asked_for() {
        // Measured: the two calls initialisation makes are both
        // `genrdn(0, 343)`, so this is that call, a thousand times over.
        let mut f = Fixture::new();
        f.invoke(srand, &[40615]).expect("seeded");
        for _ in 0..1000 {
            let Ret::U16(n) = f.invoke(genrdn, &[0, 343]).expect("a number") else {
                panic!("genrdn returns an int");
            };
            assert!(n < 343, "{n} is outside 0..343");
        }
    }

    #[test]
    fn genrdn_draws_rather_than_repeating() {
        // A shim that read its arguments and returned one of them would pass
        // the bounds check above.
        let mut f = Fixture::new();
        f.invoke(srand, &[40615]).expect("seeded");
        let drawn: std::collections::HashSet<u16> = (0..100)
            .map(|_| match f.invoke(genrdn, &[0, 343]).expect("a number") {
                Ret::U16(n) => n,
                other => panic!("genrdn returns an int, not {other:?}"),
            })
            .collect();
        assert!(drawn.len() > 50, "100 draws gave {} values", drawn.len());
    }

    #[test]
    fn rtkick_remembers_the_callback_and_when_it_is_due() {
        let mut f = Fixture::new();
        let dstrou = FarPtr {
            offset: 0x0a21,
            selector: 0x0067,
        };

        let args = [1, dstrou.offset, dstrou.selector];
        assert!(matches!(f.invoke(rtkick, &args), Ok(Ret::Void)));

        assert_eq!(f.host.kicks(), [Kick { delay: 1, dstrou }]);
    }

    #[test]
    fn kicks_are_kept_in_the_order_they_were_registered() {
        // `prcrtk` runs them in list order, and the real host's list is a
        // queue appended at the tail, so two kicks due in the same second run
        // in the order they were asked for. Nothing depends on that yet; it is
        // cheaper to be right now than to discover it from a bug later.
        let mut f = Fixture::new();
        let first = FarPtr {
            offset: 0x1111,
            selector: 0x0067,
        };
        let second = FarPtr {
            offset: 0x2222,
            selector: 0x0067,
        };

        f.invoke(rtkick, &[5, first.offset, first.selector])
            .expect("first");
        f.invoke(rtkick, &[5, second.offset, second.selector])
            .expect("second");

        assert_eq!(
            f.host.kicks(),
            [
                Kick {
                    delay: 5,
                    dstrou: first
                },
                Kick {
                    delay: 5,
                    dstrou: second
                },
            ]
        );
    }

    #[test]
    fn a_negative_delay_is_refused_rather_than_stored() {
        // `int delay` is signed and "call this 32,769 seconds ago" is not a
        // thing a caller can mean. The realistic cause is the host reading the
        // arguments in the wrong order, which this catches at the call rather
        // than as a stored pointer nobody looks at until there is a main loop.
        let mut f = Fixture::new();

        let e = f
            .invoke(rtkick, &[0xffff, 0x0a21, 0x0067])
            .expect_err("refused");
        assert!(format!("{e}").contains("negative delay"), "{e}");
        assert!(f.host.kicks().is_empty());
    }

    #[test]
    fn register_agent_keeps_the_appid_and_the_four_vectors() {
        // Measured: MajorMUD's own record, at `seg 67:0x0000` of
        // `WCCMMUD.DLL`, is `WCCMMUD` and four vectors into its segment 26.
        let mut f = Fixture::new();
        let vectors: Vec<FarPtr> = [0x0069, 0x016b, 0x029c, 0x02a1]
            .into_iter()
            .map(|offset| FarPtr {
                offset,
                selector: f.machine.code_selector(),
            })
            .collect();
        let block = agent_block(&mut f, "WCCMMUD", &vectors);

        assert_eq!(
            f.invoke(register_agent, &Fixture::far(block))
                .expect("registered"),
            Ret::Void,
            "register_agent returns nothing"
        );

        let agent = &f.host.agents()[0];
        assert_eq!(agent.appid, "WCCMMUD");
        assert_eq!(agent.read, Some(vectors[0]));
        assert_eq!(agent.write, Some(vectors[1]));
        assert_eq!(agent.xferdone, Some(vectors[2]));
        assert_eq!(agent.abort, Some(vectors[3]));
    }

    #[test]
    fn an_agent_is_copied_rather_than_pointed_at() {
        // The opposite of `register_module`, and measured: `register_agent`
        // ends in `movmem(agdptr, &agents[nagents], 25)`, so the caller's block
        // is the host's to forget. A host that kept the pointer would report
        // whatever the module later put there.
        let mut f = Fixture::new();
        let read = FarPtr {
            offset: 0x0069,
            selector: f.machine.code_selector(),
        };
        let block = agent_block(&mut f, "WCCMMUD", &[read]);
        f.invoke(register_agent, &Fixture::far(block))
            .expect("registered");

        let at = FarPtr {
            offset: block.offset,
            selector: block.selector,
        };
        f.machine.write(at, b"OVERWRIT\0").expect("in bounds");

        assert_eq!(
            f.host.agents()[0].appid,
            "WCCMMUD",
            "the copy is the host's, and the module cannot change it"
        );
        assert_eq!(f.host.agents()[0].read, Some(read));
    }

    #[test]
    fn a_null_vector_is_no_vector() {
        // What the real host does here is substitute its own default --
        // `rejectreq` for read and write, nothing for the other two. This host
        // has nothing to dispatch, so it records the absence instead. See
        // `Agent`.
        let mut f = Fixture::new();
        let block = agent_block(&mut f, "SILENT", &[]);
        f.invoke(register_agent, &Fixture::far(block))
            .expect("registered");

        let agent = &f.host.agents()[0];
        assert_eq!(agent.read, None);
        assert_eq!(agent.write, None);
        assert_eq!(agent.xferdone, None);
        assert_eq!(agent.abort, None);
    }

    #[test]
    fn a_vector_at_offset_zero_is_still_a_vector() {
        // The real routine tests both words -- `mov ax,[es:bx+9]` then
        // `or ax,[es:bx+0xb]` -- and this is why that is not pedantry. Offset
        // zero is a real address: `seg 26:0x0000` of `WCCMMUD.DLL` is the
        // routine that calls `register_agent` in the first place.
        let mut f = Fixture::new();
        let start = FarPtr {
            offset: 0,
            selector: f.machine.code_selector(),
        };
        let block = agent_block(&mut f, "WCCMMUD", &[start]);
        f.invoke(register_agent, &Fixture::far(block))
            .expect("registered");

        assert_eq!(f.host.agents()[0].read, Some(start));
    }

    #[test]
    fn an_appid_filling_its_field_is_read_bounded() {
        // `char appid[AIDSIZ]` is nine bytes and a name that uses all nine has
        // no terminator. Scanning for one would run into the `read` vector and
        // return a name with a pointer stuck to the end of it.
        let mut f = Fixture::new();
        let read = FarPtr {
            offset: 0x0069,
            selector: f.machine.code_selector(),
        };
        let block = agent_block(&mut f, "ABCDEFGHI", &[read]);
        f.invoke(register_agent, &Fixture::far(block))
            .expect("registered");

        assert_eq!(f.host.agents()[0].appid, "ABCDEFGHI");
        assert_eq!(f.host.agents()[0].read, Some(read));
    }

    #[test]
    fn register_textvar_publishes_the_table_through_the_global() {
        // Measured: MajorMUD registers one text variable, `MUDCHARINFO`, whose
        // routine is at `seg 3:0x001e` of `WCCMMUD.DLL`. And the *global* is
        // the point -- the module reaches the table only through `txtvars`, so
        // a host that filled a table and left the pointer null would have
        // registered nothing.
        let mut f = Fixture::new();
        let name = f.text("MUDCHARINFO");
        let varrou = FarPtr {
            offset: 0x001e,
            selector: f.machine.code_selector(),
        };

        let args = [name.offset, name.selector, varrou.offset, varrou.selector];
        assert_eq!(
            f.invoke(register_textvar, &args).expect("registered"),
            Ret::U16(0),
            "the first text variable is number zero"
        );

        let published = f
            .host
            .globals()
            .pointer(&f.machine, "txtvars")
            .expect("txtvars");
        assert_ne!(published, mbbs16::FarPtr::NULL, "the global was filled in");
        assert_eq!(published, f.host.textvars().at().expect("a table"));

        let row = f
            .host
            .textvars()
            .get(&f.machine, 0)
            .expect("readable")
            .expect("a row");
        assert_eq!(row.name, "MUDCHARINFO");
        assert_eq!(row.varrou, Some(varrou));
    }

    #[test]
    fn a_second_text_variable_moves_the_table_and_the_first_survives() {
        // The table grows one record at a time, so registering a second one
        // reallocates. Two things have to hold: the first row's bytes come with
        // it, and the global points at where they went. An implementation that
        // allocated and forgot to copy would pass every test in Task 5.
        let mut f = Fixture::new();
        let first = f.text("MUDCHARINFO");
        let second = f.text("USERID");
        let a = FarPtr {
            offset: 0x001e,
            selector: f.machine.code_selector(),
        };
        let b = FarPtr {
            offset: 0x0200,
            selector: f.machine.code_selector(),
        };

        assert_eq!(
            f.invoke(
                register_textvar,
                &[first.offset, first.selector, a.offset, a.selector]
            )
            .expect("registered"),
            Ret::U16(0)
        );
        assert_eq!(
            f.invoke(
                register_textvar,
                &[second.offset, second.selector, b.offset, b.selector]
            )
            .expect("registered"),
            Ret::U16(1),
            "the index counts up"
        );

        assert_eq!(f.host.textvars().len(), 2);
        let published = f
            .host
            .globals()
            .pointer(&f.machine, "txtvars")
            .expect("txtvars");
        assert_eq!(published, f.host.textvars().at().expect("a table"));

        let row0 = f
            .host
            .textvars()
            .get(&f.machine, 0)
            .expect("readable")
            .expect("a row");
        assert_eq!(row0.name, "MUDCHARINFO", "the first row came along");
        assert_eq!(row0.varrou, Some(a));

        let row1 = f
            .host
            .textvars()
            .get(&f.machine, 1)
            .expect("readable")
            .expect("a row");
        assert_eq!(row1.name, "USERID");
        assert_eq!(row1.varrou, Some(b));

        assert_eq!(
            f.host.textvars().get(&f.machine, 2).expect("readable"),
            None,
            "and there is no third"
        );
    }

    #[test]
    fn a_name_too_long_for_the_field_is_truncated_rather_than_refused() {
        // `stzcpy(name, name, TVRSIZ)` and not `strncpy`: at most fifteen
        // characters, always terminated. The sixteenth would leave the field
        // unterminated and running into `varrou`, which is the bug `stzcpy`
        // exists to avoid -- so the original truncates, and so does this.
        let mut f = Fixture::new();
        let name = f.text("ABCDEFGHIJKLMNOPQRST");
        let varrou = FarPtr {
            offset: 0x001e,
            selector: f.machine.code_selector(),
        };

        f.invoke(
            register_textvar,
            &[name.offset, name.selector, varrou.offset, varrou.selector],
        )
        .expect("registered");

        let row = f
            .host
            .textvars()
            .get(&f.machine, 0)
            .expect("readable")
            .expect("a row");
        assert_eq!(row.name, "ABCDEFGHIJKLMNO", "fifteen and a terminator");
        assert_eq!(row.varrou, Some(varrou), "and varrou was not written over");
    }

    #[test]
    fn a_null_routine_is_stored_rather_than_refused() {
        // The opposite of `register_agent`'s null vectors, and measured: the
        // module tests `varrou` before calling it -- `mov ax,[es:bx+0x10]` then
        // `or ax,[es:bx+0x12]` at `seg 23:0x22f5` -- so a null one is a row
        // that produces nothing, not a row that is wrong.
        let mut f = Fixture::new();
        let name = f.text("MUDCHARINFO");

        f.invoke(register_textvar, &[name.offset, name.selector, 0, 0])
            .expect("registered");

        let row = f
            .host
            .textvars()
            .get(&f.machine, 0)
            .expect("readable")
            .expect("a row");
        assert_eq!(row.name, "MUDCHARINFO");
        assert_eq!(row.varrou, None);
        assert_eq!(f.host.textvars().len(), 1, "it is still a row");
    }

    #[test]
    fn a_text_variable_with_no_name_is_refused() {
        // This host's own refusal, and a weaker one than the agent's empty
        // `appid`: `findtvar("")` could genuinely match this. What carries it
        // is that a name arriving empty is a misread argument list, and a
        // nameless row in a table nobody prints is expensive to find later.
        let mut f = Fixture::new();
        let name = f.text("");

        let e = f
            .invoke(register_textvar, &[name.offset, name.selector, 0x1e, 0x67])
            .expect_err("refused");
        assert!(format!("{e}").contains("no name"), "{e}");
        assert!(f.host.textvars().is_empty());
        assert_eq!(
            f.host
                .globals()
                .pointer(&f.machine, "txtvars")
                .expect("txtvars"),
            mbbs16::FarPtr::NULL,
            "and nothing was published"
        );
    }

    #[test]
    fn an_agent_with_no_appid_is_refused() {
        // This host's own refusal and not the original's. A client addresses an
        // agent by its appid, so an empty one is an agent nobody can reach --
        // no caller can mean it, and a misread argument list is what produces
        // one. Same grounds as `rtkick`'s negative delay.
        let mut f = Fixture::new();
        let block = agent_block(&mut f, "", &[]);

        let e = f
            .invoke(register_agent, &Fixture::far(block))
            .expect_err("refused");
        assert!(format!("{e}").contains("no appid"), "{e}");
        assert!(f.host.agents().is_empty());
    }

    #[test]
    fn nctime_unpacks_the_three_fields_dos_packed() {
        // 13:45:30, packed the way `now` packs it -- seconds are two-second
        // units, so 30 seconds is 15. The unpacking is read off
        // `MAJORBBS-wg101.EXE seg 33:0x0c56`: `sar 0xb / and 0x1f`,
        // `sar 0x5 / and 0x3f`, and `add ax,ax / and 0x3e`.
        let packed = (13 << 11) | (45 << 5) | 15;
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(nctime, &[packed]).expect("nctime") else {
            panic!("nctime returns a far pointer");
        };
        assert_eq!(f.read(at), "13:45:30");
    }

    #[test]
    fn nctime_doubles_the_seconds_rather_than_masking_them() {
        // The one field a reader gets wrong by reading the name instead of the
        // instructions. Five bits will not hold 59, so what is stored is half
        // the seconds and an odd second cannot be represented at all.
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(nctime, &[(23 << 11) | (59 << 5) | 29]).expect("nctime")
        else {
            panic!("far pointer");
        };
        assert_eq!(f.read(at), "23:59:58", "29 units is 58 seconds, not 29");
    }

    #[test]
    fn nctime_writes_over_what_the_last_call_left() {
        // The original formats into one static at `DGROUP:0x49`. A module
        // holding the first pointer sees the second call's answer, and this
        // host must not be quietly kinder about it than the thing it
        // reproduces.
        let mut f = Fixture::new();
        let Ret::Far(first) = f.invoke(nctime, &[(1 << 11) | (2 << 5) | 1]).expect("nctime")
        else {
            panic!("far pointer");
        };
        assert_eq!(f.read(first), "01:02:02");

        let Ret::Far(second) = f.invoke(nctime, &[0]).expect("nctime") else {
            panic!("far pointer");
        };
        assert_eq!(first, second, "one buffer, not two");
        assert_eq!(f.read(first), "00:00:00", "and no null case, unlike ncdate");
    }

    #[test]
    fn ncdate_is_month_day_and_a_two_digit_year() {
        // 2026-08-05, packed the way `today` packs it.
        let packed = ((2026 - 1980) << 9) | (8 << 5) | 5;
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(ncdate, &[packed]).expect("ncdate") else {
            panic!("far pointer");
        };
        assert_eq!(f.read(at), "08/05/26");
    }

    #[test]
    fn ncdate_of_zero_is_empty_and_leaves_the_buffer_alone() {
        // `seg 33:0x0c14` returns `DS:0x82` -- a different address from the
        // buffer at `DS:0x40` -- and it never writes. So a result taken earlier
        // is still standing afterwards, which a shim formatting "00/00/00"
        // would have destroyed.
        let mut f = Fixture::new();
        let Ret::Far(real) = f.invoke(ncdate, &[(46 << 9) | (8 << 5) | 5]).expect("ncdate")
        else {
            panic!("far pointer");
        };
        let Ret::Far(none) = f.invoke(ncdate, &[0]).expect("ncdate") else {
            panic!("far pointer");
        };
        assert_ne!(none, real, "the empty string is not the buffer");
        assert_eq!(f.read(none), "");
        assert_eq!(f.read(real), "08/05/26", "a null date did not overwrite it");
    }

    #[test]
    fn ncdate_wraps_the_year_at_a_century() {
        // 2107 is the last year seven bits reach: 127 + 1980. `idiv 100` leaves
        // 7, so the string is a bare "07" and a caller cannot tell it from
        // 2007. That is the original's limitation, reproduced.
        let packed = (127 << 9) | (12 << 5) | 31;
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(ncdate, &[packed]).expect("ncdate") else {
            panic!("far pointer");
        };
        assert_eq!(f.read(at), "12/31/07");
    }

    #[test]
    fn the_date_and_time_buffers_are_not_the_same_block() {
        // Three statics in the original, at DGROUP 0x40, 0x49 and 0x52. A
        // module may hold an ncdate result across an nctime call, so sharing
        // one block here would corrupt it in a way nothing else would catch.
        let mut f = Fixture::new();
        let Ret::Far(date) = f.invoke(ncdate, &[(46 << 9) | (8 << 5) | 5]).expect("ncdate")
        else {
            panic!("far pointer");
        };
        let Ret::Far(time) = f.invoke(nctime, &[(13 << 11) | (45 << 5) | 15]).expect("nctime")
        else {
            panic!("far pointer");
        };
        assert_ne!(date, time);
        assert_eq!(f.read(date), "08/05/26", "the date survived the time");
        assert_eq!(f.read(time), "13:45:30");
    }
}
