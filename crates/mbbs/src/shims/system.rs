//! The clock, the audit trail, and registering a module.
//!
//! Everything here that reads the world reads it through [`Host`], so a test
//! can point it at a directory of its own.

use mbbs16::{FarPtr, Machine, Ret};

use crate::Host;
use crate::fmt::format;
use crate::random::Random;
use crate::shims::{NO, ShimError};
use crate::shims::text::write_cstr;

/// `MAJORBBS.H:37` -- maximum size for module names, terminator included.
const MNMSIZ: u16 = 25;

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
pub fn now(_: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let t = local_time()?;
    Ok(Ret::U16(
        ((t.tm_hour as u16) << 11) | ((t.tm_min as u16) << 5) | (t.tm_sec as u16 / 2),
    ))
}

/// `int today(void)` -- the date, packed as DOS packs it.
///
/// Years since 1980 in bits 15..9, month in 8..5, day in 4..0.
pub fn today(_: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let t = local_time()?;
    let year = (t.tm_year + 1900 - 1980).max(0) as u16;
    Ok(Ret::U16(
        (year << 9) | ((t.tm_mon as u16 + 1) << 5) | (t.tm_mday as u16),
    ))
}

/// `long time(long *tloc)` -- seconds since 1970, and stored if asked.
pub fn time(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .as_secs() as u32;

    // A null pointer is how C spells "do not store it", and is the ordinary
    // case rather than an error.
    let tloc = machine.arg_far(0);
    if tloc.selector != 0 {
        machine.write(tloc, &seconds.to_le_bytes())?;
    }
    Ok(Ret::U32(seconds))
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
    let (detail, _) = format(machine, machine.arg_far(2), 4)?;
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

/// `void catastro(char *fmat, ...)` -- the module has given up.
///
/// Stops it, deliberately. `catastro` is a module saying it cannot continue,
/// and a host that formatted the message and returned would be resuming code
/// that has already decided it is in an impossible state.
pub fn catastro(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let (text, _) = format(machine, machine.arg_far(0), 2)?;
    Err(ShimError::Failed(format!(
        "catastro: {}",
        String::from_utf8_lossy(&text)
    )))
}

/// Now, in the local timezone, as the C library breaks it down.
fn local_time() -> Result<libc::tm, ShimError> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .as_secs() as libc::time_t;

    // SAFETY: `localtime_r` fills the caller's `tm` and touches nothing else.
    // The zeroed struct is a valid `tm` for it to overwrite.
    let mut out: libc::tm = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::localtime_r(&seconds, &mut out) };
    if ok.is_null() {
        return Err(ShimError::Failed("the local time is unknown".to_owned()));
    }
    Ok(out)
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
}
