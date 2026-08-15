//! The volatile data area address routine, and the three GALGSBL routines
//! the corpus's outstanding-symbol census flags heaviest after it: `_VDAOFF`
//! (7 modules, 1,228 call sites -- the single heaviest outstanding symbol in
//! the corpus), `_BTUPMT` (13 modules), `_BTUOBA` (10), and `_BTUINP`
//! (imported on the 32-bit/PE side only).
//!
//! `lngopt` (`GCOMM.H:289`) also lived here once -- it is [`crate::shims::msg`]'s
//! registered `_LNGOPT` now, and this file's copy was the dead twin
//! (`docs/2026-08-15-dead-twin-shims.md`), deleted rather than kept because
//! the two bodies agreed observably and `msg.rs`'s own tests already covered
//! more (a ceiling too wide for `numopt`'s `i16`).
//!
//! Two more names on the same census, `_OUTBSZ` and `_NMODS`, turn out to be
//! **data**, not routines -- `MAJORBBS.H` declares both `extern int`, with no
//! prototype anywhere in `GCOMM.H`/`BRKTHU.H`/`MAJORBBS.H`. There is
//! deliberately no shim for either here; see "Two names that are not
//! routines" below for the `globals.rs` rows they need instead, and what
//! this crate is missing that keeps them from being wired up today.
//!
//! # `_VDAOFF` and the machinery it already has to stand on
//!
//! This host already models the volatile data area end to end and
//! `vdaoff` adds nothing new to that model -- it is a read of state
//! [`Users`](crate::Users) has kept since [`Host::alcvda`] ran:
//!
//! | Vendor (`MAJORBBS.C`) | This host |
//! |---|---|
//! | `int vdasiz` (`:209`) | the `vdasiz` global, grown by [`crate::shims::system::dclvda`] |
//! | `alcvda()` (`:1370`) | [`Host::alcvda`], called once from [`Host::finish_init`] |
//! | `vdahdl=alcblok(nterms,vdasiz)` | [`crate::users::Users::alcvda_mem`] |
//! | `vdaoff(unum)` == `ptrblok(vdahdl,unum)` (`:1379-1384`) | [`crate::users::Users::vda`] |
//!
//! [`vdaoff`] below is therefore a thin read of [`Users::vda`], exactly the
//! shape [`crate::shims::user::uacoff`] already is for the account block --
//! bound the channel number against [`crate::Terms::chan`], then hand back
//! whatever the table holds for it. It is not a second implementation of the
//! volatile data area; it is the one call site that was missing to reach the
//! one this crate already has.

use mbbs_machine::ptr::ModulePtr;

use super::ShimError;
use super::gsbl::OUT_OF_RANGE;
use crate::Host;
use crate::abi::{self, Abi, Call};

/// `char *vdaoff(int unum)` -- the volatile data area calculation routine.
///
/// `MAJORBBS.C:1379-1384`:
///
///
/// `MAJORBBS.H:665` is the prototype.
///
/// # The channel bound, and why it refuses rather than computes
///
/// Real `ptrblok` (`GCOMM.H:486`) has no bound at all -- it is `bigptr +
/// index*size` and nothing stops `unum` from walking off the end of the
/// block `vdahdl` names. [`crate::shims::user::uacoff`]'s own doc comment
/// found the same shape for the account table and refused it for the same
/// reason: an out-of-range `unum` handed back the bytes after the last
/// record, and `WCCMMUD.DLL` would go on to read a `struct` out of whatever
/// memory happens to follow the block. [`Terms::chan`](crate::Terms::chan)
/// is where every other routine in this crate stops that, and `vdaoff` is
/// no different -- a channel this host does not have is
/// `ShimError::Failed`, not a wild pointer.
///
/// # The allocation bound, and why it does not refuse
///
/// [`Users::vda`](crate::users::Users::vda) answers `None` for a channel
/// that *is* in range when [`Host::alcvda`] has not run yet -- `vdahdl`
/// itself is still null, which is exactly what real `vdaoff` would compute
/// against too (`ptrblok(NULL, unum)`). [`Host::point_curusr_mem`] already
/// treats that `None` as a null pointer to write into `vdaptr` rather than a
/// failure; this answers the same way for the same reason, so a module that
/// calls `vdaoff` for itself during its own init sees what `curusr` would
/// have shown it.
pub fn vdaoff<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let unum = Into::<u32>::into(call.int()) as i16;
    let chan = host
        .users()
        .terms()
        .chan(unum)
        .ok_or_else(|| ShimError::Failed(format!("vdaoff({unum}): there is no such channel")))?;
    let ptr = host.users().vda(chan).unwrap_or_else(A::null_ptr);
    Ok(abi::Ret::Ptr(ptr))
}

/// `int btuoba(int chan)` -- `BRKTHU.H:164` -- free bytes remaining in the
/// channel's output buffer.
///
/// Not called anywhere in the surviving `GALDSRC/SRC` -- GALGSBL is a closed,
/// compiled library in this archive, and `BRKTHU.H` is only its header -- so
/// the semantics come from *callers*, not from `btuoba` itself. Two are
/// unambiguous once read together. `AUTSNS.C:104`:
/// `alldone=alldone && btuoba(usrnum) == OUTSIZ-1;` -- a transfer is "all
/// done" exactly when the buffer holds its maximum free space, i.e. is
/// empty. `GALFILU.C:3949`: `while (btuoba(usrnum) > (outbsz-1024)) { ...
/// prfmsg... }` -- a fill loop that keeps queuing list entries only while
/// there is still room. Both read `btuoba` as **free space**, matching
/// MBBSEmu's independent reimplementation of the same ordinal
/// (`docs/mirrors/github-mbbsemu-MBBSEmu/MBBSEmu/HostProcess/ExportedModules/Galgsbl.cs:262`,
/// "amount of space available").
///
/// # What this host measures free space against, and why it is not
/// `crate::gsbl`'s own `OUTSIZ`
///
/// [`crate::gsbl::Channel::output`] is the actual queue -- `pub(crate)`,
/// readable from here -- and [`crate::gsbl`] already enforces a cap on it
/// (`transmit`/`transmit_raw`'s overflow check, `crate::gsbl.rs:617`,
/// `:889`), but that cap is a private `const OUTSIZ: usize = 8192` with no
/// visibility past `crate::gsbl` itself. Reaching it from here would need
/// either duplicating the number (a second, silently-driftable copy of a
/// value this crate's own `globals.rs` doc comment on `OUTBSZ` already
/// warns against) or a one-line visibility bump this file is not the place
/// to make -- see the module doc comment's constraint on what this commit
/// touches.
///
/// [`crate::globals::OUTBSZ`] is used instead, and it is not a lesser
/// stand-in: it is this crate's existing, already-public value for the
/// vendor's own `outbsz` -- the *one* variable real `btusiz`/`btulsz`
/// (`BRKTHU.H:113-114`) size the genuine per-channel output buffer from
/// (`MAJORBBS.C:572`), and the same denominator a module's own `outbsz-256`
/// comparisons (`REMSYS.C:1674`, `GALQWK.C:560`, ...) are written against.
/// Measuring `btuoba` against anything else would make those comparisons
/// mean nothing. The cost is real and is recorded rather than hidden:
/// `crate::gsbl::Channel::output` is *allowed* to grow past `OUTBSZ` (up to
/// the real, enforced `OUTSIZ`=8192) before `transmit`/`transmit_raw`
/// refuses another byte, and `saturating_sub` below reports "no room left"
/// throughout that whole stretch rather than a number that would go
/// negative. A module reading `_OUTBSZ` as a datum (see this file's own doc
/// comment) and a module calling `btuoba` would therefore agree with each
/// other, just not with the larger number this host is actually willing to
/// queue.
///
/// An out-of-range `chan` answers `-11`
/// ([`OUT_OF_RANGE`](super::gsbl::OUT_OF_RANGE)), the same sentinel every
/// converted `GALGSBL` routine in [`crate::shims::gsbl`] answers with --
/// unreachable via `-10` for the reason that module's own doc comment gives:
/// [`Host::new`](crate::Host::new) allocates every channel and there is no
/// `btudef`.
pub fn btuoba<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan_num = Into::<u32>::into(call.int()) as i16;
    let Some(chan) = host.gsbl().terms().chan(chan_num) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    let used = host.gsbl().channel(chan).output.len();
    let capacity = usize::from(crate::globals::OUTBSZ);
    // `capacity` is `OUTBSZ`, so `free <= capacity` always -- the `as u16`
    // below is lossless because `OUTBSZ` itself is a `u16`.
    let free = capacity.saturating_sub(used) as u16;
    Ok(abi::Ret::Int(A::Int::from(free)))
}

/// `int btuinp(int chan, char *rdbptr)` -- `BRKTHU.H:139` -- take the
/// channel's oldest completed input line into `rdbptr`, NUL-terminated, and
/// return its length.
///
/// This is exactly [`Host::get_input_mem`]'s own `paccin` step
/// (`crate::lib::Host::get_input`'s doc comment, quoting
/// `MAJORBBS.C:2247`/`:3317`'s `inplen=btuinp(usrnum,input)`), which that
/// function's doc comment already says outright: **`btuinp` is not itself a
/// shim there -- `WCCMMUD.DLL` imports it only on the 32-bit side** -- so it
/// has no argument stack to read there, and its behaviour is folded directly
/// into `get_input_mem` for the 16-bit dispatch path instead. This is the
/// missing other half: a real, callable shim for modules that import
/// `_BTUINP` themselves rather than going through `getin`/`paccin`.
///
/// Built on the same one piece of state
/// [`Host::get_input_mem`] already uses --
/// [`Gsbl::take_line`](crate::gsbl::Gsbl::take_line), "completed lines,
/// oldest first" (`crate::gsbl.rs:103`) -- rather than a second queue. An
/// empty line (nothing ready) is not refused: it is exactly the byte string
/// an empty line already is, matching `Host::get_input_mem`'s own comment on
/// the point, and real `btuinp` never had a "nothing ready" error code to
/// give either (`inplen` is simply `0`).
///
/// Unlike `Host::get_input_mem`, the destination here is **not** truncated
/// to any fixed-size global -- `rdbptr` is the module's own pointer with no
/// size this host knows, matching real `btuinp`'s signature (`char
/// *rdbptr`, no length argument) and the module's responsibility to size
/// its own buffer, the same trust every raw-pointer GSBL write already
/// extends.
///
/// An out-of-range `chan` answers `-11`
/// ([`OUT_OF_RANGE`](super::gsbl::OUT_OF_RANGE)), before `rdbptr` is ever
/// written to -- the same "resolve everything that can fail first" ordering
/// `Host::get_input_mem`'s own doc comment cites R16 for.
///
/// # Errors
///
/// If the write to `rdbptr` runs off a segment, or the line is somehow
/// longer than an `int` can report (`crate::gsbl::Gsbl::push_input` bounds
/// every line to `maxinl`/`INPSIZ` long before this reads it, so this is not
/// reachable in practice -- refused rather than silently truncated all the
/// same).
pub fn btuinp<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan_num = Into::<u32>::into(call.int()) as i16;
    let rdbptr = call.ptr();
    let Some(chan) = host.gsbl().terms().chan(chan_num) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };

    let line = host.gsbl_mut().take_line(chan).unwrap_or_default();
    let len = u16::try_from(line.len())
        .map_err(|_| ShimError::Failed(format!("btuinp: a {}-byte line does not fit an int", line.len())))?;

    let mut bytes = line;
    bytes.push(0);
    rdbptr
        .write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Int(A::Int::from(len)))
}

/// `int btupmt(int chan, char pmchar)` -- `BRKTHU.H:141` -- set the
/// channel's "prompt character".
///
/// GALGSBL is a closed, compiled library in this archive: `BRKTHU.H`
/// declares the prototype and nothing in the recovered sources describes
/// what transmitting `pmchar` then does. `crate::shims::gsbl::btupbc`'s own
/// doc comment already names the sibling case one line away in the same
/// header (`:142`, the screen-pause character) -- and MBBSEmu's independent
/// reimplementation
/// (`docs/mirrors/github-mbbsemu-MBBSEmu/MBBSEmu/HostProcess/ExportedModules/Galgsbl.cs:827`)
/// only stores the byte too, with nothing reading it back either. "Record
/// it, do not act on it" is this crate's own established answer for exactly
/// this shape of GSBL sentinel-character setter --
/// [`crate::gsbl::Channel::pause_char`] and `::clear_pause_char`
/// (`crate::gsbl.rs:215-231`) are stored and explicitly documented as
/// **not acted on**, for the same reason: the behaviour they would drive
/// (screen-pause mode) is not implemented, so nothing this host has would
/// consume the value even once it is kept.
///
/// # Why this does not follow that pattern all the way through
///
/// It cannot -- `Channel` has no field for a prompt character to land in.
/// Adding one is a one-line change of exactly the shape `pause_char` already
/// is, but it is a change to `crate::gsbl`, and this file is confined to
/// [`shims::vda`](self) -- see the module doc comment. Rather than invent a
/// side table here (a second, `crate::gsbl`-shaped copy of per-channel state
/// living somewhere `crate::gsbl` cannot see, which is the exact bug
/// `crate::globals`'s own module doc comment warns against for module
/// memory) or silently discard `pmchar` and answer success, this refuses
/// loudly for a channel that **is** valid, naming the fix: add
///
/// ```text
/// pub(crate) prompt_char: u8,
/// ```
///
/// to `Channel` next to `clear_pause_char`, `0` in `Channel::default()`,
/// and change this function's body to `g.channel_mut(chan).prompt_char =
/// pmchar; Ok(0)` -- `crate::shims::gsbl::btupbc`, verbatim, with the field
/// renamed.
///
/// The channel bound check itself needs none of that and is complete: an
/// out-of-range `chan` answers `-11`
/// ([`OUT_OF_RANGE`](super::gsbl::OUT_OF_RANGE)), exactly as
/// `crate::shims::gsbl::btupbc` answers for its own `pausch`.
///
/// # Errors
///
/// Always, for a channel in range -- see above. Never a fabricated `0`.
pub fn btupmt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan_num = Into::<u32>::into(call.int()) as i16;
    let pmchar = Into::<u32>::into(call.int()) as u8;
    let Some(_chan) = host.gsbl().terms().chan(chan_num) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    Err(ShimError::Failed(format!(
        "btupmt({chan_num}, {pmchar:#04x}): channel is valid, but this host's \
         Channel has no field to hold a prompt character in -- see this \
         function's doc comment for the one-field fix this needs"
    )))
}

// # Two names that are not routines
//
// `_OUTBSZ` and `_NMODS` are both `extern int`s in `MAJORBBS.H`
// (`archive/galacticomm/extract/wg1/GALDSRC/SRC/MAJORBBS.H`), never
// prototyped as functions anywhere in `GCOMM.H`, `BRKTHU.H` or `MAJORBBS.H`
// itself. Per this file's own instructions, a datum gets no shim -- what
// follows is the `globals.rs` row each needs, reported rather than added,
// since this commit is confined to this one new file.
//
// ## `outbsz` -- `gi("outbsz")`
//
// `MAJORBBS.H:516-517`: `extern int outbsz, /* output buffer size per
// channel */ ...;`. `MAJORBBS.C:572` sets it once, at startup, from the
// board's own configuration: `outbsz=numopt(OUTBSZ,4096,16384)`.
//
// This host has no path from a `.MSG` config read to host-global
// initialisation -- `numopt` exists (`crate::shims::msg::numopt`) but only as
// a *module-callable* shim, never invoked by the host's own bring-up the way
// `MAJORBBS.C:572` invokes it on itself. Until that path exists, the row
// should be written with `crate::globals::OUTBSZ` (`4096`, the low end of
// the real `numopt` bound and already this crate's chosen value -- see
// `crate::shims::fsd`'s own sizing off the same constant), at the same point
// `globals.rs`'s `Globals::new` writes `nterms`/`hichp1` before any module
// runs (`globals.rs:613-634`), so a module reading `outbsz` during its own
// init sees a real number and not the zero an unwritten global is born
// with.
//
// `btuoba` above already reads `crate::globals::OUTBSZ` directly rather than
// waiting on this row -- see its own doc comment for why a *module* reading
// `outbsz` and *this host* computing `btuoba` need to agree on the same
// number, and for the gap between that number and the larger amount
// `crate::gsbl::Channel::output` is actually allowed to hold.
//
// ## `nmods` -- `gi("nmods")`
//
// `MAJORBBS.H:254`: `extern int nmods; /* number of modules currently
// online */`. `MAJORBBS.C:48` starts it at `0`; `MAJORBBS.C:1343`'s
// `return(nmods++);` is the only increment, inside `register_module`.
//
// **Adding the row alone would make this worse, not better.**
// `crate::shims::system::register_module` already exists and already
// computes the count `nmods` needs -- `host.register(description, block)`
// (`lib.rs:1870-1873`) pushes onto `Host::modules` and returns
// `self.modules.len() - 1`, the same value `nmods++` hands back in the real
// host -- but it never writes that count into module memory. A `gi("nmods")`
// row with nothing writing to it would sit at the zero it is born with
// forever: a datum that reads as "no modules online" no matter how many
// registered, which is a silently wrong answer of exactly the kind this
// crate's own `globals.rs` module doc comment refuses to leave module memory
// holding.
//
// `register_module` needs the write added alongside the row -- and one more
// thing to get right when it is: `Host::modules` is one `Vec` holding both
// `Registration::Module` and `Registration::Native` entries (`lib.rs:1870`,
// `:1882-1885` -- the FSD registers a native slot through the same table).
// Real `nmods` counts modules only; `self.modules.len()` after this crate's
// own native registrations would overcount. The write belongs keyed off how
// many `Registration::Module` entries exist, not the whole vector's length.

#[cfg(test)]
mod tests {
    use mbbs_machine::m16::{FarPtr, Ret};

    use super::*;
    use crate::testing::Fixture;

    // -- vdaoff --

    #[test]
    fn vdaoff_refuses_a_channel_that_does_not_exist() {
        let mut f = Fixture::new();
        let e = f.invoke(vdaoff, &[1]).expect_err("only channel 0 exists");
        assert!(e.to_string().contains('1'), "{e}");
    }

    #[test]
    fn vdaoff_is_null_before_alcvda_has_run() {
        let mut f = Fixture::new();
        assert_eq!(f.invoke(vdaoff, &[0]).expect("in range"), Ret::Far(FarPtr::NULL));
    }

    #[test]
    fn vdaoff_matches_users_vda_once_allocated() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(crate::shims::system::dclvda, &[512]).expect("declared");
        f.host.alcvda(&mut f.machine).expect("allocated");

        let Ret::Far(ptr) = f.invoke(vdaoff, &[0]).expect("in range") else {
            panic!("vdaoff returns a pointer");
        };
        assert_eq!(ptr, f.host.users().vda(console).expect("allocated"));
        assert_ne!(ptr, FarPtr::NULL);
    }

    /// `Users::vda`'s own stride check, driven through the shim rather than
    /// the accessor directly. Moved from `shims::user`'s dead twin of this
    /// routine (`docs/2026-08-15-dead-twin-shims.md`) because it is the only
    /// test in either copy that exercised more than channel 0.
    #[test]
    fn vdaoff_addresses_each_channel_at_its_own_area() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        f.invoke(crate::shims::system::dclvda, &[512]).expect("declared");
        f.host.alcvda(&mut f.machine).expect("allocated");

        let Ret::Far(at0) = f.invoke(vdaoff, &[0]).expect("channel 0") else {
            panic!("vdaoff returns a pointer");
        };
        let Ret::Far(at1) = f.invoke(vdaoff, &[1]).expect("channel 1") else {
            panic!("vdaoff returns a pointer");
        };
        assert_ne!(at0, at1, "two channels must not share a volatile data area");
    }

    // -- btuoba --

    #[test]
    fn btuoba_reports_the_full_buffer_free_on_an_idle_channel() {
        let mut f = Fixture::new();
        assert_eq!(
            f.invoke(btuoba, &[0]).expect("in range"),
            Ret::U16(crate::globals::OUTBSZ)
        );
    }

    #[test]
    fn btuoba_shrinks_as_the_channel_queues_output() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().transmit_raw(console, &[b'x'; 100]);
        assert_eq!(
            f.invoke(btuoba, &[0]).expect("in range"),
            Ret::U16(crate::globals::OUTBSZ - 100)
        );
    }

    #[test]
    fn btuoba_refuses_a_channel_that_does_not_exist() {
        let mut f = Fixture::new();
        assert_eq!(f.invoke(btuoba, &[1]).expect("still answers"), Ret::U16(OUT_OF_RANGE));
    }

    // -- btuinp --

    #[test]
    fn btuinp_takes_the_oldest_completed_line() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().push_input(console, b"look\r");
        let dest = f.buffer(16);

        let mut args = vec![0u16];
        args.extend(Fixture::far(dest));
        assert_eq!(f.invoke(btuinp, &args).expect("in range"), Ret::U16(4));
        assert_eq!(f.read(dest), "look");
    }

    #[test]
    fn btuinp_answers_zero_and_an_empty_string_when_nothing_is_ready() {
        let mut f = Fixture::new();
        let dest = f.buffer(4);

        let mut args = vec![0u16];
        args.extend(Fixture::far(dest));
        assert_eq!(f.invoke(btuinp, &args).expect("in range"), Ret::U16(0));
        assert_eq!(f.read(dest), "");
    }

    #[test]
    fn btuinp_refuses_a_channel_that_does_not_exist() {
        let mut f = Fixture::new();
        let dest = f.buffer(4);

        let mut args = vec![1u16];
        args.extend(Fixture::far(dest));
        assert_eq!(f.invoke(btuinp, &args).expect("still answers"), Ret::U16(OUT_OF_RANGE));
    }

    // -- btupmt --

    #[test]
    fn btupmt_refuses_a_channel_that_does_not_exist() {
        let mut f = Fixture::new();
        assert_eq!(
            f.invoke(btupmt, &[1, u16::from(b'>')]).expect("still answers"),
            Ret::U16(OUT_OF_RANGE)
        );
    }

    #[test]
    fn btupmt_refuses_a_valid_channel_too_for_now() {
        let mut f = Fixture::new();
        let e = f
            .invoke(btupmt, &[0, u16::from(b'>')])
            .expect_err("no field to store a prompt character in yet");
        assert!(e.to_string().contains("prompt character"), "{e}");
    }
}
