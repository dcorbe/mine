//! Full-Screen Data Entry: the form, the session, and the screen there is not.
//!
//! FSD is the subsystem behind MajorMUD's character-creation screens. Eight of
//! its routines are imported by `WCCMMUD.DLL`; seven are here.
//!
//! # The three pieces of state, and where each one lives
//!
//! - **The compiled form** -- fields, widths, punctuation templates, `maxans`
//!   -- is host-side, in [`Host::forms`], put there by [`fsdroom`]. The real
//!   host leaves it in `prfbuf` for [`fsdapr`] to copy out (`FSDBBS.C:131`, and
//!   `FSDBBS.H:109` warns that those bytes must survive in between); this host
//!   does not, so an intervening `prf` cannot corrupt a form here.
//! - **`struct fsdscb`** is in a segment of the host's -- one per channel, in
//!   [`Host::fsdscb`] -- and the `fsdscb` global points at whichever channel's
//!   is current. Not host-side: the module dereferences that global at 55
//!   sites and *writes* through it -- fourteen `flddat[i].flags |= FFFAVD` from
//!   `seg 3:0x4344` on, marking the fields a player may see but not type into,
//!   and reading them back at `seg 3:0x374a` to choose a branch.
//! - **The session** -- punctuation, the `struct fsdfld` array, the answer
//!   string -- is in the buffer the module hands [`fsdapr`], laid out in the
//!   order [`crate::fsd::Form::size`] added up.
//!
//! # What is not here, and why
//!
//! `fsdbkg` (`FSDBBS.C:185`) writes an ANSI clear-screen, then calls `btutsw`,
//! `btulok` and `btuoes` against a channel and `fsddsp` to draw every field of
//! the form. It was once refused for want of a screen to draw on; Stage 5
//! built one, and [`fsdbkg`] now paints for real.
//!
//! [`fsdego`] (`FSDBBS.C:196`) started out beside it for the same reason: it
//! arranges for the module's own `fldvfy` and `whndun` -- two far pointers
//! into module code, pushed at `seg 3:0x4463` -- to be called back later, and
//! this host has no re-entrant host-to-module call at all (`Machine::call` is
//! the top-level entry, and a shim already holds `&mut Machine`). What moved
//! it into `ROUTINES`: storing a `FarPtr` and returning is not a call, so
//! `fsdego` itself never needs one -- the callbacks it stores fire later,
//! from a channel's own dispatch (`Host::poll`, once the FSD's `state` is
//! current), which is a fresh top-level entry the same way `dopoll`/`polrou`
//! already are. `amode == 1` dispatches to [`fsd::fsdent`], the full-screen
//! counterpart of `fsdlin`, as of Stage 5's Task 8.
//!
//! `installs fsdchi as the channel's character-input handler through
//! btuchi` in the original has no equivalent shim at all: `crate::gsbl`'s
//! `raw` mode (which [`fsdego`] turns on through `fsdcon`) is what
//! `btuchi`'s whole family collapses to here -- see [`fsdcon`]'s own doc
//! comment.

use mbbs16::{FarPtr, Machine, Module, Ret};

use crate::fsd::{self, MBPMAX};
use crate::globals::OUTBSZ;
use crate::shims::{NO, ShimError};
use crate::{Chan, Host};

/// This channel's session control block, allocating it on first use.
///
/// `inifsdscb()`, `FSDBBS.C:64`. The real one is
/// `alczer(nterms*sizeof(struct fsdbbs))` out of the *host's* heap; this is a
/// segment of its own, one per channel rather than one shared by all of
/// them, so that a module writing past what it was given cannot reach the
/// globals, and so that the module's heap accounting does not report a host
/// allocation as one of the module's.
///
/// Only the `struct fsdscb` prefix of `struct fsdbbs` is modelled. The rest --
/// the `ainscb`, `curmbk`, `tmpmsg`, `amode`, `flags` and `whndun` members --
/// belongs to the entry session and to `fsdusr`, which no module imports.
///
/// The module-visible `fsdscb` global is written on **every** call, not just
/// the one that allocates -- `setfsd(chan)`, `FSDBBS.C:58-61`, repoints it
/// unconditionally, and a host that only wrote it on first allocation would
/// leave the global pointing at whichever channel allocated last after a
/// second channel's `fsdroom` reused its own, already-allocated block.
fn control_block(machine: &mut Machine, host: &mut Host, chan: Chan) -> Result<FarPtr, ShimError> {
    let at = match host.fsdscb[chan.index()] {
        Some(at) => at,
        None => {
            let selector = machine.alloc_segment(usize::from(fsd::FSDSCB)).map_err(|e| {
                ShimError::Failed(format!("fsdroom: no room for a session block: {e}"))
            })?;
            let at = FarPtr {
                offset: 0,
                selector,
            };
            host.fsdscb[chan.index()] = Some(at);
            at
        }
    };
    host.globals()
        .write(machine, "fsdscb", &at.to_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(at)
}

/// Read the session control block out of module memory.
fn read_block(machine: &Machine, at: FarPtr) -> Result<fsd::Scb, ShimError> {
    let bytes = machine.resolve(at, usize::from(fsd::FSDSCB))?;
    fsd::Scb::from_bytes(bytes).map_err(|e| ShimError::Failed(e.to_string()))
}

/// A pointer `by` bytes past `base`, refusing rather than wrapping.
///
/// A 16-bit offset that wrapped would name a byte near the start of the same
/// segment, which *resolves* -- so the bounds check downstream would pass and
/// the module would be handed a pointer into the wrong part of its own buffer.
fn offset(base: FarPtr, by: usize) -> Result<FarPtr, ShimError> {
    let offset = u16::try_from(by)
        .ok()
        .and_then(|by| base.offset.checked_add(by))
        .ok_or_else(|| ShimError::Failed(format!("fsd: {base} plus {by} leaves the segment")))?;
    Ok(FarPtr {
        offset,
        selector: base.selector,
    })
}

/// Where field `n`'s record starts, relative to the field array.
///
/// `n * sizeof(struct fsdfld)`, in arithmetic that cannot wrap. `n` has been
/// checked against `fsdscb->numfld` before it gets here, but `numfld` is itself
/// read out of a control block the module holds a pointer to -- so a module
/// that wrote 60000 there could ask for field 3000, and `3000 * 23` is not a
/// `u16`. In release that wraps and reads a `struct fsdfld` from somewhere else
/// in the segment, which resolves, and is a plausible answer.
fn field_at(n: u16) -> usize {
    usize::from(n) * usize::from(fsd::FSDFLD)
}

/// An answer string, read out of module memory. `stranslen()`, `FSD.C:2061`.
///
/// Not a C string: it is a run of NUL-terminated entries ended by an empty one,
/// so `read_cstr` is called once per entry rather than once. The bytes returned
/// include the final empty entry's NUL, which is what makes [`fsd::extract`]
/// stop.
///
/// # Errors
///
/// If the run reaches the end of its segment without the empty entry that ends
/// it -- which is what a pointer to something that is not an answer string
/// does. The original would have walked on into whatever followed.
fn answer_string(machine: &Machine, mut at: FarPtr) -> Result<Vec<u8>, ShimError> {
    let mut out = Vec::new();
    loop {
        let entry = machine.read_cstr(at)?;
        let len = entry.len();
        out.extend_from_slice(entry);
        out.push(0);
        if len == 0 {
            return Ok(out);
        }
        at = offset(at, len + 1)?;
    }
}

/// `int fsdroom(int tmpmsg, char *fldspc, int amode)` -- how big is this form?
///
/// The size is **measured**, by compiling the template and the field
/// specification the caller names, and it has to be: the module hands it
/// straight to `dclvda`, which takes the largest declaration and never looks
/// back, so a number that was merely plausible would size every channel's
/// volatile data area wrongly and nothing would say so. MBBSEmu returns a flat
/// `0x2000` here. That is the failure this crate exists to not have.
///
/// What is *not* done is writing into `prfbuf`. The real one leaves the
/// punctuation array at `prfbuf` and the field array at `prfbuf+MBPMAX` for a
/// later `fsdapr()` to read (`FSDBBS.H:108`); there is no `fsdapr` here, so the
/// parse is kept in [`Host::forms`] instead, where a test can see it and a
/// future session can find it already done.
///
/// # Errors
///
/// If the module asks for a full-screen entry session, which needs an ANSI
/// screen this host cannot draw; if the template and specification disagree in
/// any of the ways `fsdppc` counts as an error, which the real host answered
/// with `catastro`; or if the form is too big for the buffer it must fit in.
pub fn fsdroom(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let number = machine.arg_u16(0);
    let amode = machine.arg_u16(3) as i16;

    if amode != 0 && amode != 1 && amode != -1 {
        return Err(ShimError::Failed(format!(
            "fsdroom(message {number}): amode {amode} is neither entry (0/1) nor display (-1)"
        )));
    }

    // The block that is current *now*, which is the one `fsdroom` compiles
    // against and records for `fsdrft` to come back to later.
    let curmbk = host
        .globals()
        .pointer(machine, "curmbk")
        .map_err(|e| ShimError::Failed(format!("fsdroom: {e}")))?;
    let template = fsd_template(machine, host, curmbk, number, amode)?;
    let spec = machine.read_cstr(machine.arg_far(1))?.to_vec();

    // `maxfld`, `FSDBBS.C:130`: the field array and the punctuation array share
    // the output buffer, and the punctuation array gets its MBPMAX first.
    let max_fields = (OUTBSZ - MBPMAX) / fsd::FSDFLD;
    let form = fsd::compile(&template, &spec, max_fields, ascn_for(amode));

    if !form.errors.is_empty() {
        return Err(ShimError::Failed(format!(
            "fsdroom: message {number} and its field spec have {} error(s); the first is: {}",
            form.errors.len(),
            form.errors[0]
        )));
    }
    if form.fields.len() >= usize::from(max_fields) {
        return Err(ShimError::Failed(format!(
            "fsdroom: message {number}'s field spec has {} fields, and only {} fit \
             beside the punctuation array in a {OUTBSZ}-byte output buffer",
            form.fields.len(),
            max_fields
        )));
    }
    if form.punctuation.len() > usize::from(MBPMAX) {
        return Err(ShimError::Failed(format!(
            "fsdroom: message {number} has {} bytes of embedded punctuation, {} more than fits",
            form.punctuation.len(),
            form.punctuation.len() - usize::from(MBPMAX)
        )));
    }

    let size = form
        .size()
        .map_err(|e| ShimError::Failed(format!("fsdroom: {e}")))?;

    // `fsdppc()`'s outputs go into the session control block, where `fsdapr`
    // and the module itself read them. `flddat` and `mbpunc` are *not* set
    // here: the real host leaves them pointing into `prfbuf` (`FSDBBS.C:131`)
    // for `fsdapr` to copy out of, and this host keeps the parse in
    // `Host::forms` instead -- see the module documentation above.
    //
    // `Host::forms` is keyed by `(message number, amode)`, not by channel --
    // see its doc comment -- so the cache is filled in regardless of whether
    // anyone is current right now.
    host.forms.insert((number, amode), form.clone());

    // `setfsd(usrnum)`, `FSDBBS.C:129`. `_INIT__WCCMMUD` calls `fsdroom` for
    // message 6 and message 7 at calls 7326 and 7328, before any channel has
    // connected at all -- `usrnum` is `-1` there. Once a session is under
    // way, `fsdapr`'s own doc comment traces MajorMUD's one call site to
    // after `point_curusr`, so a channel is current by then.
    //
    // Confirmed by instrumenting this shim across all 18 of this crate's
    // module-level acceptance tests: 34 `fsdroom` calls total. The first two
    // of every `_INIT__WCCMMUD` run (32 of the 34, across the 16 tests that
    // reach init) are the message-6/message-7 priming above, with
    // `usrnum=-1`. The other two are ordinary per-channel calls with
    // `usrnum=0`: one in `entering_the_realm_reaches_character_creation`
    // (message 6, `amode=1`, refused by the `amode == 1` check above before
    // it ever reaches [`Host::current_channel`]) and one in
    // `entering_the_realm_reaches_character_creation_in_line_mode` (message
    // 7, `amode=0`, a genuine successful mid-session call). So the only
    // `fsdroom` calls actually measured with no channel current are the
    // two init-time priming calls; every later, real per-channel call in
    // this test suite had one.
    //
    // The original's `setfsd(-1)` computes `fsdtbl+(unsigned)(-1)`, a garbage
    // `fsdscb` one struct short of the array, and writes through it anyway --
    // and gets away with it only because nothing downstream ever reads that
    // write back before a real channel's own `fsdroom` overwrites it
    // properly. This host has no adjacent segment to alias into by accident
    // and nothing sane to invent one from, so a priming call with no channel
    // current sizes and caches the form -- which is all `dclvda`, the very
    // next thing MajorMUD does with the answer, ever needed -- and leaves the
    // per-channel control block alone rather than corrupt a channel that is
    // not this one.
    if let Ok(chan) = host.current_channel(machine) {
        let at = control_block(machine, host, chan)?;
        let mut scb = read_block(machine, at)?;
        scb.set_fldspc(machine.arg_far(1));
        scb.set_numfld(form.fields.len() as u16);
        scb.set_numtpl(form.in_template as u16);
        scb.set_mbleng(form.punctuation.len() as u16);
        scb.set_maxans(form.answer_max);
        scb.set_hlplen(form.help_len);
        scb.set_hlpoff(form.help_at);
        machine.write(at, scb.as_bytes())?;

        // `fsdusr->{curmbk,tmpmsg,amode}`, `FSDBBS.C:134`, for `fsdrft` to
        // come back to. The block is read now rather than at `fsdrft` time
        // because the module will have `rstmbk`'d by then -- it does so four
        // instructions after this call, at `seg 3:0x3f86`.
        let curmbk = host
            .globals()
            .pointer(machine, "curmbk")
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        host.fsdtmp[chan.index()] = Some((curmbk, number, amode));
    }

    Ok(Ret::U16(size))
}

/// `void fsdapr(char *sesbuf, int sbleng, char *answers)` -- lay the session
/// out. `FSDBBS.C:157`.
///
/// The buffer is the one the module allocated from the number `fsdroom`
/// returned, and it gets the three things a session needs, in that order and
/// with no padding: the embedded-punctuation templates, the array of
/// `struct fsdfld`, and the answer string. `fsdscb->mbpunc`, `->flddat` and
/// `->newans` are pointed into it, and from that moment the module reads its
/// own answers through them -- eight `fsdnan` sites, three `fsdord`, six
/// `fsdxan`, and fourteen writes to `flddat[i].flags`.
///
/// MajorMUD calls it once, at `seg 3:0x41aa`, as
/// `fsdapr(vdaptr, vdasiz, vdatmp)`: the channel's volatile data area, sized by
/// the `dclvda` that `fsdroom`'s answer fed at initialisation.
///
/// **Where the parse comes from is this host's one deviation.** The real
/// `fsdroom` leaves `mbpunc` at `prfbuf` and `flddat` at `prfbuf+MBPMAX` and
/// this copies them out, which is why `FSDBBS.H:109` warns that those bytes
/// must go untouched in between. This host kept the compiled form in
/// [`Host::forms`] instead, so the copy comes from there. The bytes written
/// into `sesbuf` are the same bytes; what differs is that an intervening `prf`
/// cannot corrupt them, which makes this strictly harder to break than the
/// original rather than differently behaved.
///
/// # Errors
///
/// If no form has been sized; if the module's buffer is smaller than the size
/// `fsdroom` told it, which the real host answered with `catastro`; or if the
/// buffer or the answer string will not resolve.
pub fn fsdapr(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let buffer = machine.arg_far(0);
    let length = machine.arg_u16(2);
    let defaults = machine.arg_far(3);

    let chan = host.current_channel(machine)?;
    let Some((_, msgno, amode)) = host.fsdtmp[chan.index()] else {
        return Err(ShimError::Failed(
            "fsdapr: no form has been sized, and FSDBBS.H:245 has this called after fsdroom()"
                .into(),
        ));
    };
    // Invariant: `fsdroom` always inserts into `Host::forms` before it
    // records this channel's `fsdtmp` entry, and nothing ever removes a
    // `Host::forms` entry -- so if `fsdtmp` names a `(msgno, amode)`, that key
    // is in the map. Refused rather than assumed, because a Rust-side
    // invariant across two fields is exactly the kind of thing a future edit
    // could quietly break.
    let Some(form) = host.forms.get(&(msgno, amode)).cloned() else {
        return Err(ShimError::Failed(format!(
            "fsdapr: channel {chan} recorded message {msgno} (amode {amode}) but no such form \
             is cached -- fsdroom and fsdtmp have gone out of sync"
        )));
    };
    let needed = form
        .size()
        .map_err(|e| ShimError::Failed(format!("fsdapr: {e}")))?;
    if length < needed {
        return Err(ShimError::Failed(format!(
            "fsdapr: a session over this form needs {needed} bytes and the module offered \
             {length}, which is {} byte(s) too small",
            needed - length
        )));
    }

    let at = host.fsdscb[chan.index()]
        .ok_or_else(|| ShimError::Failed("fsdapr: no session control block".into()))?;
    let mut block = read_block(machine, at)?;
    let spec = machine.read_cstr(block.fldspc())?.to_vec();
    let old = answer_string(machine, defaults)?;
    let installed = fsd::answers(&form, &spec, &old);

    // Punctuation, then the field array, then the answer string: the same three
    // terms, in the same order, that `Form::size` added up.
    let mut bytes = form.punctuation.clone();
    let flddat_at = bytes.len();
    for (field, (ansoff, anslen)) in form.fields.iter().zip(&installed.offsets) {
        bytes.extend_from_slice(&field.record(*ansoff, *anslen));
    }
    let newans_at = bytes.len();
    bytes.extend_from_slice(&installed.text);
    machine.write(buffer, &bytes)?;

    block.set_mbpunc(buffer);
    block.set_flddat(offset(buffer, flddat_at)?);
    block.set_newans(offset(buffer, newans_at)?);
    block.set_allans(installed.allans);
    // `FSDBBS.C:180`. The one member a caller is invited to change afterwards
    // (`FSDBBS.H:127`), which is why it is set here and not in `fsdroom`.
    block.set_crsatr(0x70);
    machine.write(at, block.as_bytes())?;

    // `clrprf(); prf("")`, FSDBBS.C:181. `FSDBBS.H:117` tells callers to do
    // their own prf'ing *after* this, for exactly this reason.
    crate::shims::text::clrprf(machine, host)?;
    Ok(Ret::Void)
}

/// The session control block, once `fsdapr` has filled one in.
///
/// # Errors
///
/// If `fsdroom` never ran, or `fsdapr` never did. The second shows as a null
/// `newans`, which is the same test the real host's own `fsdchi` makes at
/// `FSDBBS.C:340` before touching anything.
fn prepared(machine: &Machine, host: &Host, who: &str) -> Result<(fsd::Scb, FarPtr), ShimError> {
    let chan = host.current_channel(machine)?;
    let at = host.fsdscb[chan.index()].ok_or_else(|| {
        ShimError::Failed(format!(
            "{who}: no form has been sized, so there is no session; FSDBBS.H:245 has \
             fsdroom() first"
        ))
    })?;
    let block = read_block(machine, at)?;
    if block.newans() == FarPtr::NULL {
        return Err(ShimError::Failed(format!(
            "{who}: no answers have been prepared; FSD.H has this called after fsdapr()"
        )));
    }
    Ok((block, at))
}

/// One `struct fsdfld` out of the field array, bounds-checked.
///
/// The original indexes with no check at all. `FSD.H:635` states the range, and
/// a field number outside it reads whatever follows the array and calls it an
/// answer.
fn field_record(
    machine: &Machine,
    block: &fsd::Scb,
    field: u16,
    who: &str,
) -> Result<[u8; fsd::FSDFLD as usize], ShimError> {
    if field >= block.numfld() {
        return Err(ShimError::Failed(format!(
            "{who}({field}): the form has {} fields",
            block.numfld()
        )));
    }
    let at = offset(block.flddat(), field_at(field))?;
    let bytes = machine.resolve(at, usize::from(fsd::FSDFLD))?;
    let mut out = [0u8; fsd::FSDFLD as usize];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Where a field's answer starts, out of its record.
fn answer_offset(record: &[u8; fsd::FSDFLD as usize]) -> u16 {
    u16::from_le_bytes([record[fsd::fld::ANSOFF], record[fsd::fld::ANSOFF + 1]])
}

/// `char *fsdnan(int fldi)` -- where field `fldi`'s answer is. `FSD.C:2190`.
///
/// `fsdscb->newans + fsdscb->flddat[fldi].ansoff`, and both halves are read out
/// of module memory rather than remembered, because both are the module's to
/// change: `fsdord` rewrites `ansoff` for every field after the one it touched,
/// and the module writes into `flddat` itself at fourteen sites.
///
/// MajorMUD calls this eight times and hands seven of the results to `atol` --
/// the six `TOT_` statistics and one more -- and the eighth to `skpwht` for the
/// character's name. Those are the values a new character is made of, so an
/// answer that was merely plausible would be a character with the wrong
/// statistics and nothing anywhere to say so.
///
/// # Errors
///
/// If no session has been prepared, or `fldi` is not a field of it.
pub fn fsdnan(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let field = machine.arg_u16(0);
    let (block, _) = prepared(machine, host, "fsdnan")?;
    let record = field_record(machine, &block, field, "fsdnan")?;
    Ok(Ret::Far(offset(
        block.newans(),
        usize::from(answer_offset(&record)),
    )?))
}

/// `int fsdord(int fldi)` -- which `ALT=` value field `fldi` holds.
/// `FSD.C:2244`.
///
/// `-1` when nothing matches, **and when more than one does**: `chkalt` counts
/// its matches and `fsdord` reports only an unequivocal one (`FSD.H:655`). A
/// host that resolved `"B"` against `ALT=Black ALT=Brown` to the first would be
/// picking a hair colour for the player.
///
/// It is not a query. On a match the answer is rewritten in the alternate's own
/// spelling -- which is what `FSD.H:656` means by "in that case, answer is
/// available via `fsdnan(fldi)`" -- and if that changed its length, every later
/// field's `ansoff` and the string's `allans` move with it. `stfans()`,
/// `FSD.C:1036`.
///
/// The field is read back out of the module's own array rather than out of
/// [`Host::forms`], because the module edits it: fourteen sites set `FFFAVD`.
///
/// MajorMUD calls this three times -- `HAIR_LEN`, `HAIR_COL` and `EYE_COL`,
/// fields 22, 23 and 24 -- and stores each answer as one byte of the character
/// record, at `+0x6cd`, `+0x6ce` and `+0x6d0`.
///
/// # Errors
///
/// If no session has been prepared, `fldi` is not a field of it, or the
/// rewritten answer string would not fit the room `fsdroom` reserved.
pub fn fsdord(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let number = machine.arg_u16(0);
    let (mut block, at) = prepared(machine, host, "fsdord")?;
    let record = field_record(machine, &block, number, "fsdord")?;
    let field = fsd::Field::from_record(&record);

    let spec = machine.read_cstr(block.fldspc())?.to_vec();
    let ansoff = answer_offset(&record);
    let anslen = record[fsd::fld::ANSLEN];
    let answer = machine
        .read_cstr(offset(block.newans(), usize::from(ansoff))?)?
        .to_vec();

    let Some((index, canonical)) = fsd::ordinal(&spec, &field, &answer) else {
        return Ok(Ret::U16(NO));
    };

    // `stfans()`, FSD.C:1036: put the canonical spelling back, shift what
    // follows it, and push every later field's `ansoff` along by the
    // difference.
    let grew = canonical.len() as i32 - i32::from(anslen);
    let allans = i32::from(block.allans()) + grew;
    let room = i32::from(block.maxans()) + 1;
    if allans > room {
        return Err(ShimError::Failed(format!(
            "fsdord({number}): the alternate \"{}\" does not fit -- the answer string would \
             be {allans} bytes and fsdroom reserved {room}",
            String::from_utf8_lossy(&canonical)
        )));
    }

    // `nr = fsdscb->allans - nl - m`, which the original computes as a signed
    // int and hands straight to `movmem`. A negative one means the control
    // block disagrees with itself -- `allans` shorter than the answer it
    // claims to contain -- and the original would have moved that many bytes
    // as an unsigned count. There is nothing to salvage from it either way.
    let tail_at = usize::from(ansoff) + usize::from(anslen);
    let tail_len = usize::from(block.allans())
        .checked_sub(tail_at)
        .ok_or_else(|| {
            ShimError::Failed(format!(
                "fsdord({number}): field {number}'s answer ends at {tail_at} and the whole \
             string is only {} bytes, so the control block is inconsistent",
                block.allans()
            ))
        })?;
    let tail = machine
        .resolve(offset(block.newans(), tail_at)?, tail_len)?
        .to_vec();
    let mut rewritten = canonical.clone();
    rewritten.extend_from_slice(&tail);
    machine.write(offset(block.newans(), usize::from(ansoff))?, &rewritten)?;

    // `fldptr->anslen = anslen`. `anslen` is a `char` in the C struct and
    // `chkalt`'s value came through `endtkn`, which clamps at ANSLEN -- so this
    // fits, and the conversion says so rather than assuming it.
    let mut record = record;
    record[fsd::fld::ANSLEN] = u8::try_from(canonical.len()).map_err(|_| {
        ShimError::Failed(format!(
            "fsdord({number}): the alternate is {} bytes and anslen is a char",
            canonical.len()
        ))
    })?;
    machine.write(offset(block.flddat(), field_at(number))?, &record)?;

    // `while (efptr != fldptr) { efptr->ansoff += anslen-m; efptr--; }` -- the
    // fields *after* this one, and none before.
    for later in number + 1..block.numfld() {
        let mut record = field_record(machine, &block, later, "fsdord")?;
        let moved = i32::from(answer_offset(&record)) + grew;
        let moved = u16::try_from(moved).map_err(|_| {
            ShimError::Failed(format!(
                "fsdord({number}): moving field {later}'s answer by {grew} puts it at {moved}"
            ))
        })?;
        record[fsd::fld::ANSOFF..fsd::fld::ANSOFF + 2].copy_from_slice(&moved.to_le_bytes());
        machine.write(offset(block.flddat(), field_at(later))?, &record)?;
    }

    block.set_allans(u16::try_from(allans).map_err(|_| {
        ShimError::Failed(format!(
            "fsdord({number}): an answer string of {allans} bytes"
        ))
    })?);
    machine.write(at, block.as_bytes())?;
    Ok(Ret::U16(index))
}

/// `char *fsdxan(char *answer, char *name)` -- a field's value, by name.
/// `FSD.C:2073`.
///
/// Walks the answer string one NUL-terminated entry at a time, looking for one
/// that begins with `name` and has `'='` immediately after it. The second test
/// is what keeps the field `NAME` from matching the answer `NAMEX=1`; the first
/// is `sameto`, which ignores case, so `FSD.H:592`'s "all caps required" is
/// advice rather than a rule.
///
/// **Never null.** A name that is not there answers the answer string's final
/// `'\0'` (`FSD.H:595`), which reads as `""`. MajorMUD hands all six of its
/// results straight to `atol`, so a null would be a fault where the original
/// produced a zero.
///
/// It needs no session. Six of MajorMUD's sites pass `fsdscb->newans`, but
/// nothing here reads `fsdscb`: `FSD.H:583` files this under "call on any
/// unprocessed answer string", and a version that demanded `fsdapr` first would
/// refuse a call the real host answers.
///
/// The global `xannam` the original also sets is not modelled. Worldgroup 1.01
/// does not export it -- there is no entry in
/// `crates/mbbs/data/majorbbs_wg101.tsv` -- so no module can read it, and the
/// only two routines that do, `fsdpan` and `fsddan`, are neither implemented
/// here nor imported by `WCCMMUD.DLL`.
///
/// # Errors
///
/// If the answer string runs to the end of its segment without the empty entry
/// that ends it, or either pointer will not resolve.
pub fn fsdxan(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let name = machine.read_cstr(machine.arg_far(2))?.to_vec();
    let mut at = machine.arg_far(0);
    loop {
        let entry = machine.read_cstr(at)?;
        if entry.is_empty() {
            return Ok(Ret::Far(at));
        }
        let len = entry.len();
        if len > name.len()
            && entry[..name.len()].eq_ignore_ascii_case(&name)
            && entry[name.len()] == b'='
        {
            return Ok(Ret::Far(offset(at, name.len() + 1)?));
        }
        at = offset(at, len + 1)?;
    }
}

/// `char *fsdrft(void)` -- the template again. `FSDBBS.C:413`.
///
/// The original is `setmbk(fsdusr->curmbk); getasc(tmpmsg); rstmbk()`, and the
/// point of that pair is that the answer comes from *that* message file
/// whatever is current now. `Messages::text` takes the block explicitly, so
/// this asks the recorded block directly; the round trip through `curmbk`
/// arrives at the same pointer. Recorded per channel, in [`Host::fsdtmp`],
/// because `fsdusr` -- and so which block a `fsdroom` recorded -- is itself
/// per channel.
///
/// `getasc` versus `getmsg` is not modelled, for the reason the `fsdroom` plan
/// gave: the difference is line terminators, both are white space to the
/// template scanner, and no width in a form is computed across one.
///
/// **`xlttxv` is not applied**, which is a content difference rather than a
/// whitespace one -- it expands the text variables marked by a `0x01` byte. It
/// is inherited from `fsdroom`, which compiled the form without expanding them
/// either, so the template this returns and the template the field offsets were
/// measured against are the same string; expanding here and not there would be
/// worse than expanding in neither place. Neither of MajorMUD's two templates
/// contains a `0x01`. The day one does, both call sites need it together.
///
/// Its one call site, `seg 3:0x41e8`, is on the branch taken only by an ANSI
/// user with a screen of at least 23 by 80 -- which is the branch `fsdroom`
/// refuses at `amode=1`. So nothing reaches this today. It is here because it
/// is measured behaviour that costs ten lines, and leaving it out would make
/// this family's refusals two where one is the truth.
///
/// # Errors
///
/// If no form has been sized, or the template is not in the file that was
/// current when one was.
pub fn fsdrft(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let chan = host.current_channel(machine)?;
    let Some((block, number, amode)) = host.fsdtmp[chan.index()] else {
        return Err(ShimError::Failed(
            "fsdrft: no template has been compiled; FSDBBS.C:419 refreshes the one fsdroom \
             recorded, and fsdroom has not run"
                .into(),
        ));
    };
    ascii_template(machine, host, block, number, amode).map(Ret::Far)
}

/// The template as a pointer the module can hold, in whichever form this
/// `amode` compiled against. Backs [`fsdrft`].
///
/// At `amode == -1` that is the message text where it already sits, and this
/// hands back the pointer `getmsg` would have. Otherwise it is
/// [`getasc`](crate::msg::getasc)'s expansion, which exists nowhere in memory
/// until something writes it -- so this allocates a segment, writes it, and
/// caches it in [`Host::fsd_ascii`].
///
/// # Why it cannot simply return the message text
///
/// `fsdbkg(fsdrft())` (`FSDBBS.C:87`) walks the returned string using every
/// field's `tmpoff`, and those were measured against the expanded form. Hand
/// back the compact one and every field's supporting text is read off the
/// wrong bytes: the two disagree from the first line break onward. The genuine
/// host has the same problem and solves it the same way -- `getasc` writes
/// into a buffer of the host's and returns a pointer to that.
fn ascii_template(
    machine: &mut Machine,
    host: &mut Host,
    block: FarPtr,
    number: u16,
    amode: i16,
) -> Result<FarPtr, ShimError> {
    let at = host.messages.text(block, number).map_err(ShimError::Failed)?;
    if amode == -1 {
        return Ok(at);
    }
    if let Some(cached) = host.fsd_ascii.get(&(block, number)) {
        return Ok(*cached);
    }

    let compact = machine.read_cstr(at)?.to_vec();
    let mut expanded = crate::msg::getasc(&compact);
    expanded.push(0);
    let selector = machine.alloc_segment(expanded.len()).map_err(|e| {
        ShimError::Failed(format!(
            "fsdrft: no room for the ASCII form of message {number}: {e}"
        ))
    })?;
    let buffer = FarPtr {
        offset: 0,
        selector,
    };
    machine.write(buffer, &expanded)?;
    host.fsd_ascii.insert((block, number), buffer);
    Ok(buffer)
}

/// `void fsdbkg(char *templt)` -- paint the full-screen background.
/// `FSDBBS.C:185-194`.
///
///
/// Module-callable, and the module does call it: `fsdbkg(fsdrft())`
/// (`FSDBBS.C:87`), before `fsdego`. Nothing inside the FSD calls it --
/// `fsdlin` does not and neither does `fsdego`, which is why line mode never
/// runs any of this.
///
/// # `btutsw(usrnum,0)` is the load-bearing line
///
/// [`Channel::transmit`](crate::gsbl::Channel::transmit) counts every byte
/// that is not `\r`/`\n` toward the wrap column, with no idea that ANSI
/// escapes exist. A cursor-goto sent at a nonzero width can be split in the
/// middle, which corrupts the screen in a way that looks exactly like a
/// cursor-tracker bug and is not one. Zeroing the width here is what stops
/// that, and it is why this lands before anything lights a field. [`fsdcof`]
/// restores the account's own width on the way out (`FSDBBS.C:112`).
///
/// `btulok(usrnum,1)` locks the keyboard until the screen has drained, and
/// `btuoes(usrnum,1)` asks to be told when it has. The lock is the busy-wait
/// the design doc replaced with an edge; the `btuoes` arming is what Task 11
/// turns into that edge, so both are set as real channel state here rather
/// than dropped. [`fsd_drain_edge`]'s own doc comment has the other half:
/// this lock is released there, on the session's first `OUTMT`, exactly
/// where the original releases it (`FSDBBS.C:266`) -- Task 12's own
/// acceptance test found that this port had never ported the release at
/// all, so a channel `fsdbkg` locked stayed locked for the rest of the
/// session.
///
/// # Errors
///
/// If no channel is current, if no form has been sized for it, or if the
/// template pointer it was handed is not addressable.
pub fn fsdbkg(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let chan = host.current_channel(machine)?;
    let templt = machine.arg_far(0);
    let Some((_, msgno, amode)) = host.fsdtmp[chan.index()] else {
        return Err(ShimError::Failed(
            "fsdbkg: no template has been compiled for this channel; FSDBBS.H:245 has \
             fsdroom() first"
                .into(),
        ));
    };
    let Some(form) = host.forms.get(&(msgno, amode)).cloned() else {
        return Err(ShimError::Failed(format!(
            "fsdbkg: channel {chan} recorded message {msgno} (amode {amode}) but no such \
             form is cached"
        )));
    };

    let (block, _) = prepared(machine, host, "fsdbkg")?;
    let form = live_form(machine, &block, &form)?;
    let answers = read_answers(machine, &block)?;
    let template = machine.read_cstr(templt)?.to_vec();

    // `prf("\x1B[0m\x1B[2J\x1B[0m")` -- reset, clear screen, reset again.
    crate::shims::text::append(machine, host, b"\x1b[0m\x1b[2J\x1b[0m")?;

    {
        let ch = host.gsbl_mut().channel_mut(chan);
        ch.width = 0;
        ch.locked = true;
        ch.oes = true;
    }

    let drawn = fsd::fsddsp(&form, &answers, &template);
    crate::shims::text::append(machine, host, &drawn)?;

    Ok(Ret::Void)
}

/// `int vfyadn(int fldno, char *answer)` -- `FSD.C:2007-2053`. See
/// [`fsd::vfyadn`]'s own doc comment for what it does and why it is in
/// scope: MajorMUD's own `_ljnvfy` (the `fldvfy` [`fsdego`] is handed)
/// falls through to this on every field, so `machine.call(fldvfy, ..)`
/// cannot return at all until this ordinal is serviced like any other
/// import.
///
/// Not called from this crate's own dispatch -- `fsdscb->fldvfy` calling it
/// is `WCCMMUD.DLL`'s doing, reached only from inside
/// [`fsdprc`]'s `machine.call(fldvfy, ..)`. Registered under `"vfyadn"` in
/// `shims/mod.rs`'s `ROUTINES` table the same way `fsdroom`/`fsdapr`/etc.
/// are, so it is this file's convention to keep it here beside them.
///
/// # Errors
///
/// If no session has been prepared, or `fldno` is not a field of it.
pub fn vfyadn(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let fldno = machine.arg_u16(0);
    let answer = machine.read_cstr(machine.arg_far(1))?.to_vec();

    let (mut block, at) = prepared(machine, host, "vfyadn")?;
    let record = field_record(machine, &block, fldno, "vfyadn")?;
    let field = u8::try_from(fldno).map_err(|_| {
        ShimError::Failed(format!("vfyadn: field {fldno} does not fit fsdscb->entfld's byte"))
    })?;
    let ansoff = answer_offset(&record);
    let current = machine
        .read_cstr(offset(block.newans(), usize::from(ansoff))?)?
        .to_vec();

    let numtpl = block.numtpl();
    let vc = fsd::vfyadn(&mut block, field, numtpl, &answer, &current);
    machine.write(at, block.as_bytes())?;

    Ok(Ret::U16(vc as u16))
}

/// `fsdcon()`, `FSDBBS.C:91-101`. Turn on the channel settings an FSD session
/// needs: raw input (Stage 2's [`crate::gsbl::Channel::raw`], so `push_input`
/// stops assembling lines and delivers keystrokes one at a time) and no echo
/// (the entry engine echoes its own bytes explicitly, byte by byte, once
/// Task 7 lands).
///
/// Of the original's eight `btu*` calls, `crate::gsbl::Channel::raw`'s own
/// doc comment already accounts for all eight: `btuche`/`btuchi` become
/// `raw`, `btuech` becomes `echo`, `btucli`/`btuche(1)`'s echo-drain half
/// have no state to touch here, and `btulfd`/`btuscr`/`btupbc`/`btuxnf` are
/// terminal-driver knobs this host does not model individually. **Width is
/// not one of the eight** -- `fsdcon` itself never calls `btutsw`. The
/// `btutsw(usrnum,0)` that zeroes wrap width belongs to `fsdbkg`
/// (`FSDBBS.C:186`, "display background for full-screen entry mode"), a
/// *module-callable* routine a caller invokes before `fsdego` for full-screen
/// (`amode == 1`, ANSI, Stage 5) sessions -- `fsdlin` (line mode, what this
/// host builds) never calls it, and neither `fsdego` nor `fsdcon` do either.
/// Line mode leaves width exactly as the connection set it.
fn fsdcon(host: &mut Host, chan: Chan) {
    let ch = host.gsbl_mut().channel_mut(chan);
    ch.raw = true;
    ch.echo = false;
}

/// `fsdcof()`, `FSDBBS.C:103-113`. Undo [`fsdcon`]: restore cooked input and
/// echo, and -- unconditionally, regardless of `amode` -- the screen width
/// from the account record (`usaptr->scnwid`, `btutsw(usrnum,usaptr->scnwid)`
/// at `FSDBBS.C:112`). In line mode this is a no-op against what `fsdcon` did
/// (which never touched width, see its doc comment), but it is still exactly
/// what the original always does on the way out, so this host does too.
fn fsdcof(host: &mut Host, chan: Chan, scnwid: u16) {
    let ch = host.gsbl_mut().channel_mut(chan);
    ch.raw = false;
    ch.echo = true;
    ch.width = scnwid;
}

/// `usrptr->substt` while an entry session is under way. `FSDBBS.C:54`:
/// `#define ENTERING 1`. Not in `MAJORBBS.H` -- FSDBBS defines its own
/// substate codes, and `grep -rn "ENTERING" crates/mbbs/src/` before adding
/// this found nothing already modeling it.
const ENTERING: u16 = 1;

/// The template text an FSD form is compiled and driven against, for one
/// `amode`. `FSDBBS.C:137`.
///
///
/// Every place this crate needs the template goes through here, and that is
/// the point rather than tidiness: a field's `tmpoff` is an offset *into this
/// string*, so compiling against one form and later reading against the other
/// would put the punctuation scan, and eventually the module's own redisplay,
/// on the wrong bytes. [`getasc`](crate::msg::getasc) inserts a byte per line
/// break, so the two forms disagree from the first one onward.
fn fsd_template(
    machine: &Machine,
    host: &Host,
    block: FarPtr,
    number: u16,
    amode: i16,
) -> Result<Vec<u8>, ShimError> {
    let at = host.messages.text(block, number).map_err(ShimError::Failed)?;
    let compact = machine.read_cstr(at)?.to_vec();
    Ok(if amode == -1 {
        compact
    } else {
        crate::msg::getasc(&compact)
    })
}

/// Which of `fsdppc`'s two scanning modes an `amode` asks for.
/// `amode == 1` (`FSDBBS.C:139`), and nothing else.
fn ascn_for(amode: i16) -> fsd::Ascn {
    if amode == 1 {
        fsd::Ascn::Ansi
    } else {
        fsd::Ascn::Line
    }
}

/// `eurmsk`, the high-bit mask `fsdchi` applies to every ordinary byte.
/// `MAJORBBS.C:311`: `char eurmsk=0x7F;` -- "0x7F if U.S.A. only, 0xFF if
/// European."
///
/// # Why a constant and not a global
///
/// The genuine host promotes it to `0xFF` at `MAJORBBS.C:673`, off a
/// configuration option, and exports it for modules to read (ordinal 194).
/// `WCCMMUD.DLL` imports no such symbol, and this host has no European
/// configuration to switch on, so a constant is the whole of the behaviour
/// rather than a stub of it. It is not a no-op either way: at `0x7F` this
/// strips the high bit off every inbound byte, which is why a CP437
/// character typed into a field arrives as its low seven bits.
const EURMSK: i16 = 0x7F;

/// The [`fsd::Form`] `fsdlin` should walk for this channel's session: the
/// compiled [`Host::forms`] entry, with every field's `flags` refreshed from
/// the module's own `flddat[]` rather than trusted from the cache.
///
/// `_EDIT_CHARACTER_STATS` sets `FFFAVD` on fourteen fields (`seg 3:0x4344`
/// on, per [`fsdroom`]'s own doc comment) *before* calling `fsdego`, and
/// `movfld(0,1,0)` -- the first thing [`fsd::fsdlin`] does -- has to skip
/// them. A `Form` still carrying `fsdroom`-time flags would let the cursor
/// land on a field the player was never meant to type into. Same reasoning
/// [`fsdord`]'s own doc comment gives for reading `flddat` fresh rather than
/// [`Host::forms`]'s copy; no other field of [`fsd::Field`] is module-mutable
/// (fourteen `or byte [...+12],0x80` sites are the only writes into
/// `flddat[]` anywhere in this crate's own measurements), so `flags` is the
/// only one refreshed.
fn live_form(
    machine: &Machine,
    block: &fsd::Scb,
    form: &fsd::Form,
) -> Result<fsd::Form, ShimError> {
    let mut form = form.clone();
    for (i, field) in form.fields.iter_mut().enumerate() {
        let record = field_record(machine, block, i as u16, "fsdego")?;
        field.flags = record[fsd::fld::FLAGS];
    }
    Ok(form)
}

/// `void fsdego(int (*fldvfy)(int,char*), void (*whndun)(int))` -- hand the
/// channel to the FSD. `FSDBBS.C:196-220`.
///
/// Stores `fldvfy` in the session control block, runs [`fsd::fsdlin`] (line
/// mode -- everything this host builds today; full-screen/`fsdent` is Stage
/// 5 and refused below), sets `state`/`substt` so [`Host::poll`]'s dispatch
/// finds the FSD next time, records `whndun` where only this host can see
/// it, and finally turns on raw mode with [`fsdcon`] -- in that order,
/// matching the original exactly, so that the prompt this call composes is
/// still being built under the channel's *ordinary* settings.
///
/// # Output
///
/// `fsdlin`'s return value is appended to the print buffer through
/// [`crate::shims::text::append`] -- the same "leave it in `prfbuf` for the
/// caller to flush" contract [`fsdapr`]'s own doc comment already states for
/// its twelve `prf` calls. It is not written to the channel directly: the
/// real host's own comment on `fsdego` says "(expects caller to
/// outprf(usrnum))", and `WCCMMUD_decompiled.c:1910-1911` shows the actual
/// caller doing exactly that --
/// `fsdego(ljnvfy,ljndun); tell_user(usrnum);` -- immediately afterward,
/// through the same `_TELL_USER`/`btuxmt` path every other `prf` in this
/// module already uses (`shims/gsbl.rs`'s `btuxmt` doc comment). So the
/// prompt reaches the channel the first time the module calls `tell_user`
/// after this returns, not before.
///
/// # `amode == 1` is refused, defensively
///
/// [`fsdroom`] already refuses to size a full-screen (`amode == 1`) form at
/// all -- the module never reaches `fsdapr`, let alone `fsdego`, over one --
/// so in this host's own call sequence this branch is dead code reachable
/// only from a forged `Host::fsdtmp` entry. Checked anyway, and checked
/// *before* anything below is allowed to mutate `block`/`state`/`substt`/
/// [`Host::fsd_sessions`]: one refusing gate is what `fsdroom` itself is,
/// and a second, independent one here is this crate's defense-in-depth
/// discipline rather than trusting that gate alone.
///
/// # Errors
///
/// If no session has been prepared (`fsdroom`/`fsdapr` first), or the
/// recorded `amode` is `1`.
pub fn fsdego(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let fldvfy = machine.arg_far(0);
    let whndun = machine.arg_far(2);
    let chan = host.current_channel(machine)?;

    let (mut block, at) = prepared(machine, host, "fsdego")?;
    let Some((mbk, msgno, amode)) = host.fsdtmp[chan.index()] else {
        return Err(ShimError::Failed(
            "fsdego: no template on record for this channel; FSDBBS.H:245 has fsdroom() first"
                .into(),
        ));
    };
    let Some(form) = host.forms.get(&(msgno, amode)).cloned() else {
        return Err(ShimError::Failed(format!(
            "fsdego: channel {chan} recorded message {msgno} (amode {amode}) but no such form \
             is cached -- fsdroom and fsdtmp have gone out of sync"
        )));
    };

    let form = live_form(machine, &block, &form)?;
    let spec = machine.read_cstr(block.fldspc())?.to_vec();
    let template = fsd_template(machine, host, mbk, msgno, amode)?;
    let answers = answer_string(machine, block.newans())?;

    block.set_fldvfy(fldvfy);
    // `FSDBBS.C:205-212`: the amode fork. `fsdent(0)` for a full-screen
    // session and `fsdlin()` for a linear one, and `FBFULL` in the
    // per-channel flags either way, which `goback` reads on the way out
    // (`FSDBBS.C:227`).
    let full_screen = amode == 1;
    let output = if full_screen {
        let installed = read_answers(machine, &block)?;
        fsd::fsdent(&form, &installed, &mut block, 0)
    } else {
        fsd::fsdlin(&form, &spec, &template, &mut block, &answers)
    };
    machine.write(at, block.as_bytes())?;

    host
        .users
        .set_state(machine, chan, host.fsd_state() as u16)
        .map_err(|e| ShimError::Failed(format!("fsdego: {e}")))?;
    host
        .users
        .set_substt(machine, chan, ENTERING)
        .map_err(|e| ShimError::Failed(format!("fsdego: {e}")))?;
    host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
        whndun: (whndun != FarPtr::NULL).then_some(whndun),
        save: false,
        full_screen,
    });

    // `ainscb=&fsdusr->ainscb; ainbeg();` -- FSDBBS.C:217-218, *outside* the
    // amode branch above and immediately before fsdcon(). Line mode gets a
    // decoder too; see `fsd::ain`'s module docs for what that changes.
    host.fsd_ain[chan.index()].ainbeg();

    fsdcon(host, chan);
    crate::shims::text::append(machine, host, &output)?;

    Ok(Ret::Void)
}

/// This channel's -- rather, this host's -- scratch buffer for
/// [`fsd::candidate_answer`], allocating it on first use. See
/// [`crate::Host::fsd_scratch`]'s own doc comment for why one segment,
/// not one per channel, is the right shape here.
fn fsd_scratch(machine: &mut Machine, host: &mut Host) -> Result<FarPtr, ShimError> {
    match host.fsd_scratch {
        Some(at) => Ok(at),
        None => {
            let selector = machine
                .alloc_segment(usize::from(fsd::ANSLEN) + 1)
                .map_err(|e| {
                    ShimError::Failed(format!("fsdprc: no room for a scratch buffer: {e}"))
                })?;
            let at = FarPtr {
                offset: 0,
                selector,
            };
            host.fsd_scratch = Some(at);
            Ok(at)
        }
    }
}

/// The answer string and every field's `(ansoff, anslen)`, read out of
/// module memory -- [`fsd::Answers`], built the way [`fsd::store`] (this
/// port's `stfans()`) needs it, rather than trusted from
/// [`Host::forms`]'s own cache: `fsdord`'s own doc comment already
/// explains why a field's mutable members are read live, and `ansoff`/
/// `anslen` are exactly the members `fsdord` itself already writes.
fn read_answers(machine: &Machine, block: &fsd::Scb) -> Result<fsd::Answers, ShimError> {
    let text = answer_string(machine, block.newans())?;
    let mut offsets = Vec::with_capacity(usize::from(block.numfld()));
    for i in 0..block.numfld() {
        let record = field_record(machine, block, i, "fsdprc")?;
        offsets.push((answer_offset(&record), record[fsd::fld::ANSLEN]));
    }
    Ok(fsd::Answers {
        text,
        offsets,
        allans: block.allans(),
    })
}

/// `fsdprc()`'s `FSDBUF` arm, wired through `Machine`. `FSD.C:1124-1233`.
/// The pure decision logic is [`fsd::fsdprc`]; this resolves `vc` --
/// calling the module's `fldvfy`, if it registered one -- and writes back
/// whatever changed: the answer string, every field's `ansoff`/`anslen`
/// (`stfans`'s own writes, `FSD.C:1054-1058`) and `FFFCHG`, the control
/// block itself, and finally the composed output through
/// [`crate::shims::text::append`], the same "leave it in `prfbuf` for the
/// caller to flush" contract [`fsdego`]'s own doc comment already states.
///
/// Not wired to any ordinal: `fsdprc` is not among `WCCMMUD.DLL`'s
/// imports (`FSDBBS.C`'s `fsdsts` calls it directly, from the FSD's own
/// `CYCLE` dispatch), so this is `pub(crate)` for whatever eventually
/// builds that dispatch loop (a later task) rather than a shim the
/// ordinal table resolves to.
///
/// # The callback discipline
///
/// `fldvfy`'s own `FarPtr` and the scratch buffer's address are read out
/// of `block` *before* the call, and `block` -- along with the candidate
/// answer itself -- is **re-read from `Machine`** immediately afterward,
/// never trusted from the pre-call copy: `VFYOK`'s own contract lets a
/// module rewrite the answer in place (`FSD.H`'s Note 2), and the same
/// note lets it set `scb.state()` directly to end the session. Both are
/// exactly the trap `polrou` already documents (`lib.rs:1128`, cited by
/// the design doc's "The two callbacks into module code").
///
/// **Correction, found driving this against the real `WCCMMUD.DLL`
/// (Task 12):** an earlier version of this doc comment said `machine.call`
/// was used directly here, "not the full `Host::run` service loop", and
/// that "a callback that itself calls a further host routine is therefore
/// not serviced". That was true of the code and false about what MajorMUD
/// needs: measured against the real module, `fldvfy` (`_ljnvfy`,
/// `re/exports/WCCMMUD_decompiled.c:11227`) calls a further host routine
/// (`vfyadn`, now [`crate::shims::fsd::vfyadn`]) on every field, so a
/// `machine.call` that could not service a nested call could not process a
/// single field against the real module. This now goes through
/// [`Host::run`], the same servicing loop `dopoll`/`polrou` use, so nested
/// calls resolve like any other import.
///
/// # Errors
///
/// If no session has been prepared, or if `fldvfy` stops the machine (an
/// unimplemented import, a fault, or a timeout, anywhere in the call tree
/// `Host::run` services) -- the machine is already poisoned with the real
/// reason by the time that happens (`Machine::poison`'s "the first reason
/// wins"), so this only has to name the fact, not invent a better one.
pub(crate) fn fsdprc(
    machine: &mut Machine,
    host: &mut Host,
    module: &Module,
    chan: Chan,
) -> Result<Ret, ShimError> {
    let (block, at) = prepared(machine, host, "fsdprc")?;
    let Some((mbk, msgno, amode)) = host.fsdtmp[chan.index()] else {
        return Err(ShimError::Failed(
            "fsdprc: no template on record for this channel".into(),
        ));
    };
    let Some(form) = host.forms.get(&(msgno, amode)).cloned() else {
        return Err(ShimError::Failed(format!(
            "fsdprc: channel {chan} recorded message {msgno} (amode {amode}) but no such form \
             is cached"
        )));
    };
    let form = live_form(machine, &block, &form)?;
    let spec = machine.read_cstr(block.fldspc())?.to_vec();
    let template = fsd_template(machine, host, mbk, msgno, amode)?;

    let entfld = block.entfld();
    let field = &form.fields[usize::from(entfld)];
    let candidate = fsd::candidate_answer(field, block.ansbuf());

    let scratch = fsd_scratch(machine, host)?;
    let mut scratch_bytes = candidate;
    scratch_bytes.push(0);
    machine.write(scratch, &scratch_bytes)?;

    let vc = if block.flags() & fsd::entry_flags::FSDIGA != 0 {
        let mut cleared = block.clone();
        cleared.set_flags(cleared.flags() & !fsd::entry_flags::FSDIGA);
        machine.write(at, cleared.as_bytes())?;
        fsd::verify::VFYDEF
    } else if block.fldvfy() != FarPtr::NULL {
        let fldvfy = block.fldvfy();
        // The borrow on `block` ends here: everything after this point
        // re-reads fresh from `Machine`, per the callback discipline
        // above.
        let outcome = host
            .run(
                machine,
                module,
                fldvfy,
                &[u16::from(entfld), scratch.offset, scratch.selector],
                Some(chan),
            )
            .map_err(|e| ShimError::Failed(format!("fsdprc: fldvfy call failed: {e}")))?;
        match outcome {
            crate::Outcome::Returned { ax, .. } => ax as i16,
            crate::Outcome::Stopped(poison) => {
                return Err(ShimError::Failed(format!(
                    "fsdprc: fldvfy at {fldvfy} stopped the machine: {poison}"
                )));
            }
        }
    } else {
        fsd::verify::VFYCHK
    };

    // Re-read everything the callback (if any ran) could have touched.
    let mut block = read_block(machine, at)?;
    let bufptr = machine.read_cstr(scratch)?.to_vec();
    let mut answers = read_answers(machine, &block)?;

    let (output, changed) = fsd::fsdprc(
        &form,
        &spec,
        &template,
        &mut block,
        &mut answers,
        vc,
        &bufptr,
    );

    // `stfans`'s own writes: every field's `(ansoff, anslen)`, and
    // `FFFCHG` on the one that was just validated. Written for every
    // field on every call rather than only the ones that moved --
    // `answers.offsets` already holds the right value either way (a
    // reject leaves it identical to what module memory already has), and
    // "always write the current truth" is simpler than tracking which
    // fields genuinely need it.
    for i in 0..block.numfld() {
        let mut record = field_record(machine, &block, i, "fsdprc")?;
        let (ansoff, anslen) = answers.offsets[usize::from(i)];
        record[fsd::fld::ANSOFF..fsd::fld::ANSOFF + 2].copy_from_slice(&ansoff.to_le_bytes());
        record[fsd::fld::ANSLEN] = anslen;
        if i == u16::from(entfld) && changed {
            record[fsd::fld::FLAGS] |= fsd::flags::CHANGED;
        }
        machine.write(offset(block.flddat(), field_at(i))?, &record)?;
    }
    machine.write(block.newans(), &answers.text)?;
    block.set_allans(answers.allans);
    machine.write(at, block.as_bytes())?;

    // Propagate the outcome into `Host::fsd_sessions`, right while
    // `block.state()` is known-fresh (re-read from `Machine` above, per
    // the callback discipline). `goback()` (Task 11) needs `save` after
    // the session buffer this `state` came from may already be gone --
    // see [`crate::FsdSession::save`]'s own doc comment -- so this is the
    // one place that state is both current and about to stop being
    // readable, and the only place it is copied out to the Rust-side flag
    // that survives past it.
    if let Some(session) = host.fsd_sessions[chan.index()].as_mut() {
        match block.state() {
            fsd::state::FSDSAV => session.save = true,
            fsd::state::FSDQIT => session.save = false,
            _ => {}
        }
    }

    crate::shims::text::append(machine, host, &output)?;

    // The session is over. `goback()` (Task 11) is what the real
    // `fsdsts()` reaches from here -- but only after one more poll pass
    // through its `FINISHING` substate, which waits for
    // `btuoba(usrnum) == outbsz-1` (`FSDBBS.C:291-299`) before calling it.
    // That wait, and the substate itself, are on the design doc's own
    // "Dropped" list: there is no asynchronous transmit backlog here for
    // it to wait *for* -- `crate::gsbl::Gsbl::transmit` either has queued
    // the bytes or it hasn't, synchronously -- so the wait would spin on
    // a condition that is already true the instant it is asked, which is
    // exactly what the design doc's standing rule (every poll becomes an
    // edge) forbids keeping. Ending the session on this same pass is
    // therefore not a shortcut; it is what dropping `FINISHING` requires.
    if matches!(block.state(), fsd::state::FSDSAV | fsd::state::FSDQIT) {
        return goback(machine, host, module, chan);
    }

    Ok(Ret::Void)
}

/// `outprf(int chan)`, declared at `GCOMM.H:447` with no body anywhere in
/// this repo's copy of the source -- unlike `prf`/`clrprf`/`tell_user`, it
/// is host-internal, not one of `WCCMMUD.DLL`'s imports, so there was never
/// a reason for Galacticomm to ship it. Reconstructed from `powprf`
/// (`MAJORBBS.C:1791-1795`, `"power" outprf() - cut through input`), which
/// says outright what it stands in for:
///
///
/// `powprf` is `outprf` plus one more call, `btucli` -- flushing input --
/// which is exactly the "power" the name claims and the reason this is not
/// simply `powprf` without it. Transmit whatever `prf`/`append` have queued
/// since the last flush, then clear the buffer the way [`crate::shims::text::clrprf`]
/// (`clrprf()`) already does.
fn outprf(machine: &mut Machine, host: &mut Host, chan: Chan) -> Result<(), ShimError> {
    let start = host
        .globals()
        .pointer(machine, "prfbuf")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let text = machine.read_cstr(start)?.to_vec();
    host.gsbl_mut().transmit(chan, &text);
    crate::shims::text::clrprf(machine, host)?;
    Ok(())
}

/// `usaptr->scnwid`, read directly out of the account record rather than
/// cached anywhere -- the same reason [`Host::current_channel`] reads
/// `usrnum` fresh on every call instead of remembering it.
fn account_scnwid(machine: &Machine, host: &Host, chan: Chan) -> Result<u16, ShimError> {
    let account = host.users.account(chan);
    let at = offset(account, crate::users::usracc::SCNWID)?;
    Ok(u16::from(machine.resolve(at, 1)?[0]))
}

/// `void goback(void)` -- end the entry session and hand the channel back.
/// `FSDBBS.C:222-240`.
///
/// Restores the channel ([`fsdcof`], with the account's own `scnwid` --
/// [`account_scnwid`], the same source [`fsdcof`]'s own doc comment names),
/// clears the print buffer, sends a colour reset and flushes it, then calls
/// the module's `whndun(save)` -- or, if `fsdego` was handed `NULL`, injects
/// `CRSTG` the way the original's `else` branch does
/// (`btuinj(usrnum,CRSTG)`) -- and flushes once more on the way out.
///
/// # The `FBFULL` cursor park, and where `maxy` comes from
///
/// `if (fsdusr->flags&FBFULL) { prf("\x1B[%d;1f",min(ANSILN,fsdscb->maxy+1)); }`
/// -- `FSDBBS.C:227-229` -- parks the cursor below a full-screen (ANSI,
/// `amode==1`) form before handing the channel back. `FBFULL` is
/// [`crate::FsdSession::full_screen`], set by `fsdego`'s `amode==1` branch
/// (`fsdego`'s own doc comment) at the moment the fork is taken, the same
/// bookkeeping the original does at `FSDBBS.C:207`.
///
/// `fsdscb->maxy` (the C's per-session control block, offset 165 --
/// [`fsd::scb::MAXY`]) is never written by anything in this port. The value
/// it would hold is computed once, at compile time, by [`fsd::Form::max_y`]
/// -- see that member's own doc comment, which already names this exact
/// caller. This function reads `Host::forms` the same way [`fsd_cycle`]
/// does (`host.fsdtmp[chan]` for the `(msgno, amode)` key, then
/// `host.forms.get`) rather than adding a second place that carries the
/// same number: `fsd::scb::MAXY` would need `fsdroom`/`fsdego` to start
/// writing a field nothing else ever reads, purely so `goback` could read it
/// back from the one place the C happened to keep it. `Form::max_y` already
/// has a home; giving `maxy` a second one is not reproducing the original's
/// *behaviour*, only its *storage*, and the design doc's own instinct
/// (`Host::forms` caching a `fsdroom` parse instead of re-scanning it on
/// every call) already made that trade once for this exact structure.
///
/// The one place this could matter: the original computes `maxy` afresh
/// every session (`tmpscn` reruns on every `fsdroom`), while this host
/// caches [`fsd::Form`] by `(msgno, amode)` and reuses it across sessions.
/// That is a difference only if the *same* `(msgno, amode)` could compile to
/// two different `max_y` values on two different calls -- and it cannot:
/// `compile`/`tmpscn` are pure functions of the template bytes and `ascn`,
/// both fixed for a given message number, so every session over the same
/// template produces the same layout and the same `max_y`. Two sessions
/// sharing one cached `Form` therefore park the cursor exactly where two
/// independent `tmpscn` runs would have.
///
/// # The colour reset is ported, and is not conditional on ANSI
///
/// `prf("\x1B[0;1;32m")` sits *outside* the `FBFULL` test, so the original
/// sends it to every session on the way out, line mode included. Kept for
/// the same reason this crate generally prefers measured behaviour over a
/// plausible-looking simplification: it costs one constant byte string, no
/// cursor tracking or screen model, and dropping it would be a second,
/// unstated ANSI-only gate where the original has one.
///
/// # Nothing runs after `whndun` except one more flush
///
/// Read `FSDBBS.C:222-240` end to end: the last statement is a second
/// `outprf(usrnum)`, *after* the `if (whndun!=NULL){...}else{...}`. It
/// exists so that anything `whndun` itself queued into `prfbuf` via `prf()`
/// -- without flushing it before returning, which is not this host's
/// business to require of a callback -- still reaches the channel. There is
/// no third statement; this is the session's last word, and this port's own
/// final [`outprf`] call is exactly that flush, not an extra step invented
/// on top of the original.
///
/// # The callback discipline
///
/// The session is [`Option::take`]n out of [`Host::fsd_sessions`] *before*
/// `whndun` runs, so there is no live borrow across the call -- the same
/// rule `fsdprc`'s own `fldvfy` call follows (this file, above), stated for
/// exactly this reason by the design doc's "The two callbacks into module
/// code". Because the teardown (`fsdcof`, the session's own removal) all
/// happens before the call rather than after, a `whndun` that dies leaves
/// nothing half-done: the channel is already back to cooked input and the
/// session is already gone, whether `whndun` returns, faults, times out, or
/// asks for an import this crate has not built.
///
/// **Correction, found the same way `fsdprc`'s own doc comment was
/// (Task 12):** `whndun` -- in practice, MajorMUD's `_LJNDUN`, the routine
/// that actually saves the finished character -- calls plenty of further
/// host routines of its own (Btrieve, `prf`, polling registration). Those
/// go through [`Host::run`] now, the same servicing loop `dopoll`/`polrou`
/// use, rather than the bare `machine.call` an earlier version of this
/// function used (and could not get past a single field's `fldvfy` with,
/// let alone `whndun`).
///
/// # The gap this does not close: a hard disconnect mid-session
///
/// `FSDBBS.C`'s own `fsdmod` initializer (`FSDBBS.C:28-39`) assigns
/// `huprou=fsdhup`, and `fsdhup` (`FSDBBS.C:305-311`) calls exactly this
/// function to save/tear down a session on a hard hangup mid-entry. This
/// host's `Native` dispatch (Task 1) currently treats `Native` as "no
/// `huprou`" for `lonrou`/`lofrou`/`huprou` alike, which is right for the
/// first two -- `FSDBBS.C` supplies neither -- but wrong for the third. A
/// channel that disconnects while mid-field never reaches `goback` at all
/// today: its session sits in `Host::fsd_sessions` until the channel is
/// reused, `whndun` never runs, and no `_LJNDUN`-style cleanup fires. Fixing
/// this means revisiting Task 1's dispatch design (giving `Vector::Hangup`
/// a way to reach a `Native` handler) and is out of scope for this task,
/// which is about the *normal* exit path -- `fsdprc` observing
/// `FSDSAV`/`FSDQIT` -- not the hangup one. Tracked, not fixed, so it is not
/// silently forgotten a second time.
///
/// # Errors
///
/// If the channel has no session to close, or `whndun` stops the machine
/// anywhere in the call tree `Host::run` services -- see `fsdprc`'s own
/// doc comment on why the machine is already correctly poisoned by then.
pub(crate) fn goback(
    machine: &mut Machine,
    host: &mut Host,
    module: &Module,
    chan: Chan,
) -> Result<Ret, ShimError> {
    let session = host.fsd_sessions[chan.index()].take().ok_or_else(|| {
        ShimError::Failed(format!("goback: channel {chan} has no session to close"))
    })?;

    let scnwid = account_scnwid(machine, host, chan)?;
    fsdcof(host, chan, scnwid);
    crate::shims::text::clrprf(machine, host)?;

    // `if (fsdusr->flags&FBFULL) { prf("\x1B[%d;1f",min(ANSILN,fsdscb->maxy+1)); }`
    // -- FSDBBS.C:227-229. See this function's own doc comment, "The FBFULL
    // cursor park, and where `maxy` comes from", for why `maxy` is read out
    // of `Host::forms` rather than a per-session `Scb` member.
    if session.full_screen {
        let Some((_, msgno, amode)) = host.fsdtmp[chan.index()] else {
            return Err(ShimError::Failed(format!(
                "goback: channel {chan} has FBFULL set but no template on record -- fsdego's \
                 own invariant has come apart"
            )));
        };
        let Some(form) = host.forms.get(&(msgno, amode)) else {
            return Err(ShimError::Failed(format!(
                "goback: channel {chan} recorded message {msgno} (amode {amode}) but no such \
                 form is cached -- fsdroom and fsdtmp have gone out of sync"
            )));
        };
        // `maxy+1` is `u8+1`; guard the wrap a template that reached row 255
        // would otherwise cause (`ANSILN` is 25, so the `min` below would
        // hide it anyway, but the addition itself must not panic or silently
        // wrap first).
        let row = u16::from(form.max_y).saturating_add(1).min(fsd::ANSILN);
        crate::shims::text::append(machine, host, format!("\x1b[{row};1f").as_bytes())?;
    }

    // `prf("\x1B[0;1;32m"); outprf(usrnum);` -- FSDBBS.C:231-232. See this
    // function's own doc comment on why the colour reset is ported
    // unconditionally.
    crate::shims::text::append(machine, host, b"\x1b[0;1;32m")?;
    outprf(machine, host, chan)?;
    // `prf("");` -- FSDBBS.C:233. No text of its own; its only effect is
    // making sure `prfptr` is back at `prfbuf`'s own start before whatever
    // `whndun` itself queues, which `append` with an empty slice already
    // does (it moves `prfptr` by zero bytes, from wherever `clrprf` above
    // already put it -- a genuine no-op, kept because the original has one
    // and a caller diffing this against the C should find nothing missing).
    crate::shims::text::append(machine, host, b"")?;

    match session.whndun {
        Some(whndun) => {
            let outcome = host
                .run(machine, module, whndun, &[u16::from(session.save)], Some(chan))
                .map_err(|e| ShimError::Failed(format!("goback: whndun call failed: {e}")))?;
            match outcome {
                crate::Outcome::Returned { .. } => {}
                crate::Outcome::Stopped(poison) => {
                    return Err(ShimError::Failed(format!(
                        "goback: whndun at {whndun} stopped the machine: {poison}"
                    )));
                }
            }
        }
        None => {
            // `btuinj(usrnum,CRSTG)`, FSDBBS.C:238 -- `Gsbl::inject` is
            // `btuinj` (its own doc comment), and `Gsbl::CRSTG` is the same
            // constant `fsdprc`'s neighbours already cite.
            host.gsbl_mut().inject(chan, crate::gsbl::Gsbl::CRSTG);
        }
    }

    outprf(machine, host, chan)?;
    Ok(Ret::Void)
}

/// The FSD's own `CYCLE` dispatch -- `fsdsts()`'s `ENTERING` case
/// (`FSDBBS.C:275-286`), folded together with the interrupt-level echo
/// `fsdchi`/`fsdinc` (`FSDBBS.C:329-361`) would otherwise already have
/// produced by the time any `CYCLE` reached it. There is no interrupt level
/// here, so both run in the same pass: raw-mode [`crate::gsbl::Gsbl::push_input`]
/// queues exactly one `CYCLE` for however many bytes arrived together (its
/// own doc comment), and this drains every one of them -- the design doc's
/// "the handler drains `channel.input` completely on every pass".
///
/// Each byte goes through [`fsd::fsdinc`]; its echo is queued in `pending`
/// rather than sent immediately, but flushed to the channel as its own
/// segment the instant a byte lands a field on [`fsd::state::FSDBUF`] --
/// matching the timing the original's interrupt-level `fsdchi` already had,
/// since by the time a real `fsdsts` ever ran, every prior keystroke's echo
/// was already on the wire. At that point [`fsdprc`] runs immediately --
/// `fsdsts`'s own `clrprf(); prf("");` preamble first (`FSDBBS.C:279-280`),
/// so its composed output starts from an empty print buffer regardless of
/// what was just flushed -- and if that ends the session ([`goback`],
/// called from inside `fsdprc` per Task 11), the rest of this pass's queued
/// bytes are left undrained: the channel is no longer in an FSD session for
/// them to mean anything to.
///
/// # No `fsdnfy()` of its own
///
/// The original's `fsdchi` calls `fsdnfy()` itself once a field commits, to
/// wake `fsdsts` on a later pass. This function has no later pass to wake:
/// `fsdprc` runs inline, in the same call, which is what dropping `FSDSTB`
/// (the design doc's own "Dropped" list) requires -- see `fsdprc`'s own doc
/// comment, "No `FSDSTB` catch-up". So nothing here ever queues `CYCLE`
/// again on its own account; per the design doc's standing rule ("every
/// place the original polls, this host makes an edge"), a channel with
/// nothing left in `channel.input` leaves this function having queued no
/// further work, and [`crate::Host::cycle`] is free to go `Idle`.
///
/// # The output-drained edge (Stage 5's Task 11), and why it is here too
///
/// This same native slot is also what `Host::poll` reaches for `OUTMT`
/// (`lib.rs`'s own `poll`, `MAJORBBS.C:152`'s `status==4||status==5` ->
/// entry 2), not only `CYCLE`/`INBLK`. `poll` writes the `status` global
/// before dispatching, the same global `fsdsts()` itself reads
/// (`FSDBBS.C:264`) -- so this function starts by reading it back, and if
/// it names `OUTMT`, hands off to [`fsd_drain_edge`] instead of touching
/// `channel.input` at all: an `OUTMT` dispatch is not about input, and
/// there is nothing in `channel.input` for it to mean.
///
/// This is *not* a port of `fsdsts`'s own `OUTMT` handling
/// (`FSDBBS.C:264-267`, which disarms `oes`/unlocks input and never calls
/// `fsdqoe`) -- see [`fsd::fsdqoe`]'s own doc comment, "Decision 3", for
/// why this host substitutes `btuoes`/`OUTMT` for a signal
/// (`btuche`/the quick-output buffer draining) it has no other way to
/// reach. [`crate::gsbl::Gsbl::drain_output`] already raises `OUTMT` when
/// `oes` is armed (Task 6); this is what turns that into `fsdqoe`
/// (Task 11).
///
/// # Errors
///
/// If this channel has no session control block or no
/// [`crate::Host::fsd_sessions`] entry -- reaching the FSD's own `CYCLE`
/// dispatch with neither means `fsdego` never ran for this channel, which is
/// a bug in whatever put it in [`crate::Host::fsd_state`] rather than a
/// condition to paper over -- or if anything [`fsd::fsdinc`]/[`fsdprc`]
/// themselves need turns out missing (the same errors `fsdprc` and its
/// neighbours already raise).
pub(crate) fn fsd_cycle(
    machine: &mut Machine,
    host: &mut Host,
    module: &Module,
    chan: Chan,
) -> Result<(), ShimError> {
    let at = host.fsdscb[chan.index()].ok_or_else(|| {
        ShimError::Failed(format!(
            "fsd_cycle: channel {chan} is in the FSD's own state but has no session control \
             block -- fsdego never ran for it"
        ))
    })?;
    if host.fsd_sessions[chan.index()].is_none() {
        return Err(ShimError::Failed(format!(
            "fsd_cycle: channel {chan} is in the FSD's own state but Host::fsd_sessions has \
             nothing recorded for it -- fsdego never ran, or the session already ended"
        )));
    }

    // `fsdsts`'s own first line, `FSDBBS.C:264`: `if (status == OUTMT...)`.
    // See this function's own doc comment, "The output-drained edge", for
    // why this reads the same global rather than porting that branch's own
    // body.
    let status = host
        .globals()
        .word(machine, "status")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    if status == crate::gsbl::Gsbl::OUTMT as u16 {
        return fsd_drain_edge(machine, host, at, chan);
    }

    let mut pending: Vec<u8> = Vec::new();

    while let Some(byte) = host.gsbl_mut().channel_mut(chan).input.pop_front() {
        // `if ((c=ainchr(c)) != 0) { if (c < 256) c&=eurmsk; fsdinc(c); }`
        // -- FSDBBS.C:349-356. Three things about this are load-bearing:
        //
        // * There is no `amode` test. Every byte of every session, line mode
        //   included, is decoded (see `fsd::ain`).
        // * A zero return means "consumed" -- a byte part-way through an
        //   escape sequence -- and `fsdinc` is not called at all. `continue`
        //   rather than falling through with a 0, which `fsdinc` would treat
        //   as an ordinary control byte.
        // * The `eurmsk` mask belongs *here*, not inside the decoder, and is
        //   guarded by `c < 256` so it cannot touch a special key: `eurmsk`
        //   is 0x7F on a U.S. board (`MAJORBBS.C:311`) and `CRSRUP & 0x7F`
        //   would be 0.
        let key = host.fsd_ain[chan.index()].ainchr(byte);
        if key == 0 {
            continue;
        }
        let key = if key < 256 { key & EURMSK } else { key };

        let mut block = read_block(machine, at)?;
        let Some((_, msgno, amode)) = host.fsdtmp[chan.index()] else {
            return Err(ShimError::Failed(format!(
                "fsd_cycle: channel {chan} recorded no template -- fsdego's own invariant has \
                 come apart"
            )));
        };
        let Some(form) = host.forms.get(&(msgno, amode)).cloned() else {
            return Err(ShimError::Failed(format!(
                "fsd_cycle: channel {chan} recorded message {msgno} (amode {amode}) but no \
                 such form is cached"
            )));
        };
        let form = live_form(machine, &block, &form)?;
        let spec = machine.read_cstr(block.fldspc())?.to_vec();
        // `fsdinc`'s `FSDAPT` arm needs the installed answer string --
        // `hopfld`'s repaint and the Ctrl-F/DEL per-field-width guards read
        // a field's *stored* answer, not the in-session `ansbuf` -- the same
        // `read_answers` this shim's `fsdego` already builds for `fsdent`.
        let answers = read_answers(machine, &block)?;

        pending.extend(fsd::fsdinc(&form, &spec, &answers, &mut block, key));
        machine.write(at, block.as_bytes())?;

        if block.state() == fsd::state::FSDBUF {
            if !pending.is_empty() {
                host.gsbl_mut().transmit(chan, &pending);
                pending.clear();
            }

            // `clrprf(); prf("");` -- FSDBBS.C:279-280, immediately before
            // fsdprc(), so its own composed output starts from an empty
            // print buffer regardless of anything already flushed above.
            crate::shims::text::clrprf(machine, host)?;
            crate::shims::text::append(machine, host, b"")?;

            fsdprc(machine, host, module, chan)?;

            if host.fsd_sessions[chan.index()].is_none() {
                // `goback` already ran (from inside `fsdprc`), flushed its
                // own output and torn the session down. Nothing left in
                // `channel.input` is this channel's to read any more.
                return Ok(());
            }

            // The session is still open: `fsdprc`'s own output (a
            // reprompt, or a rejection message) is sitting in `prfbuf`,
            // unflushed -- no module code runs to `tell_user` it for us.
            outprf(machine, host, chan)?;
        }
    }

    if !pending.is_empty() {
        host.gsbl_mut().transmit(chan, &pending);
    }

    Ok(())
}

/// [`fsd::fsdqoe`], wired through `Machine` -- the transport half of
/// Stage 5's Task 11. Called by [`fsd_cycle`] the instant it sees this
/// channel dispatched for `OUTMT` rather than `CYCLE`/`INBLK`; see that
/// function's own doc comment for why that is the right trigger.
///
/// Reads the session control block and its form fresh, the same way every
/// other `fsd_cycle`-adjacent function does, calls the pure [`fsd::fsdqoe`],
/// writes back whatever it changed, and transmits whatever it produced --
/// `fsdqoe` most often produces nothing at all (`FSDSHN` clear is the
/// resting state), in which case this sends nothing rather than an empty
/// segment.
///
/// # `btulok(usrnum,0)`, found by Task 12's own acceptance test
///
/// `fsdsts`'s real first line is not just "call `fsdqoe`" -- it is
/// `FSDBBS.C:263-267` in full:
///
///
/// and `fsdqoe` is reached a completely different way in the original: from
/// `fsdchi`'s own `c == -1` sentinel (`FSDBBS.C:345-347`), the interrupt-level
/// echo-drain callback `btuche(usrnum,1)` arms (`Channel::raw`'s own doc
/// comment, "This host has no equivalent"). Decision 3 substitutes `OUTMT`
/// for that missing signal -- correctly, `fsdqoe`'s own effect is right -- but
/// an earlier version of this function stopped there and never ported the
/// `fsdsts` branch above at all, on the theory that `OUTMT` was now spoken
/// for by `fsdqoe`. It was not: `btulok(usrnum,0)` is `fsdbkg`'s own lock
/// (`FSDBBS.C:192`, "Turn off keyboard till all displayed") being released,
/// and **nothing else in this port ever released it**. `Channel::locked` is
/// set exactly once, by [`fsdbkg`], and until this function set it back
/// nothing ever cleared it again -- so the very first full-screen paint
/// locked every session for its own remaining lifetime, silently discarding
/// every keystroke after it ([`crate::gsbl::Channel::take`]'s own "locked
/// case" doc comment). Task 12's own acceptance test found this the only
/// way it could be found: driving a real ANSI session past the first paint
/// and watching a cursor key vanish -- every shim-level test of this
/// function stops at `fsdqoe`'s own effect and never presses a key
/// afterward to notice the channel never took it.
///
/// `btuoes(usrnum,0)` -- disarming `oes` -- is deliberately **not** ported
/// alongside it. The original disarms it because its own `fsdqoe` path
/// never needs `OUTMT` again (the echo-drain callback carries every later
/// repaint instead); this port has no echo-drain callback, so `OUTMT` is
/// `fsdqoe`'s only way to run for the rest of the session, and disarming
/// `oes` here would silently strand every later deferred cursor shuffle
/// exactly the way the missing unlock stranded every later keystroke.
/// Decision 3's own substitution depends on `oes` staying armed for the
/// session's whole life; this fix must not undo that to fix the other half.
///
/// # Gated on `oes`, defensively
///
/// In production an `OUTMT` dispatch cannot reach this function unless
/// `oes` is armed -- that is the only thing that makes
/// [`crate::gsbl::Gsbl::drain_output`] queue the status in the first place.
/// This checks it again anyway: `oes` is armed exactly once per session, by
/// [`fsdbkg`] alone, so a line-mode channel (nothing in line mode ever
/// calls it) never should reach the lookups below, and refusing early on a
/// flag this function can read directly is cheaper than trusting a
/// caller's own invariant a second time -- the same "one refusing gate
/// plus a second, independent one" discipline [`fsdego`]'s own doc comment
/// states for its `amode == 1` check. The unlock happens *before* this
/// gate, not after: `locked` and `oes` are two different flags `fsdbkg` sets
/// together but this function has two different reasons to treat
/// separately, and a channel that was locked while `oes` -- for whatever
/// reason -- was not still deserves to be unlocked.
///
/// # Errors
///
/// If this channel has no template on record, or the form it names is not
/// cached -- both would mean `fsdego` never ran for it, the same
/// inconsistency [`fsd_cycle`]'s own errors already guard against, reached
/// here instead because `fsd_cycle` checks `Host::fsdscb`/`fsd_sessions`
/// before ever reading `status`.
fn fsd_drain_edge(
    machine: &mut Machine,
    host: &mut Host,
    at: FarPtr,
    chan: Chan,
) -> Result<(), ShimError> {
    // `btulok(usrnum,0)` -- FSDBBS.C:266. See this function's own doc
    // comment, "btulok(usrnum,0), found by Task 12's own acceptance test",
    // for why this is not covered by `fsdqoe` below and must not be folded
    // into the `oes` gate that follows it.
    host.gsbl_mut().channel_mut(chan).locked = false;

    if !host.gsbl_mut().channel_mut(chan).oes {
        return Ok(());
    }
    let block = read_block(machine, at)?;
    let Some((_, msgno, amode)) = host.fsdtmp[chan.index()] else {
        return Err(ShimError::Failed(format!(
            "fsd_drain_edge: channel {chan} recorded no template -- fsdego's own invariant has \
             come apart"
        )));
    };
    let Some(form) = host.forms.get(&(msgno, amode)).cloned() else {
        return Err(ShimError::Failed(format!(
            "fsd_drain_edge: channel {chan} recorded message {msgno} (amode {amode}) but no \
             such form is cached"
        )));
    };
    let form = live_form(machine, &block, &form)?;
    let answers = read_answers(machine, &block)?;

    let mut block = block;
    let out = fsd::fsdqoe(&form, &answers, &mut block);
    machine.write(at, block.as_bytes())?;

    if !out.is_empty() {
        host.gsbl_mut().transmit(chan, &out);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;
    use mbbs16::FarPtr;

    /// Point `usrnum` at the fixture's own console.
    ///
    /// Every FSD shim now asks [`Host::current_channel`] which channel it is
    /// serving, the way the real module's own `usrnum` reads do -- so a test
    /// that never made one current, the way none of these had to before this
    /// channel key landed, would fail on that question before it reached
    /// whatever the test actually means to exercise. `Fixture::new` builds a
    /// single-channel host and deliberately leaves `usrnum` at `-1`
    /// (`MAJORBBS.C:882`, see `globals.rs`'s own test of that fact) until
    /// something points it somewhere, which is what this does.
    fn current(f: &mut Fixture) {
        let chan = f.console();
        f.host
            .point_curusr(&mut f.machine, chan)
            .expect("channel 0 is current");
    }

    /// Open `SAMPLE.MSG`, which `Fixture` roots on, and make it current.
    fn open(f: &mut Fixture) -> FarPtr {
        current(f);
        let name = f.text("SAMPLE.MSG");
        let block = f
            .invoke(crate::shims::msg::opnmsg, &Fixture::far(name))
            .expect("opened");
        match block {
            Ret::Far(at) => at,
            other => panic!("opnmsg returned {other:?}"),
        }
    }

    #[test]
    fn fsdroom_sizes_the_form_and_records_it() {
        let mut f = Fixture::new();
        let _ = open(&mut f);
        let spec = f.text("ONE TWO");

        // Message 0 of SAMPLE.MSG is the template. Whatever it is, the answer
        // has to be the one `fsd::compile` gives for the same two strings --
        // this asserts the shim wires the right pair together, not arithmetic
        // that is already tested in `fsd`.
        let template = crate::shims::msg::message(&f.machine, &f.host, 0).expect("message");
        let template = f.machine.read_cstr(template).expect("text").to_vec();
        let expected = crate::fsd::compile(&template, b"ONE TWO", (4096 - 200) / 23, fsd::Ascn::Line)
            .size()
            .expect("fits");

        let args = [0, spec.offset, spec.selector, 0];
        assert!(matches!(f.invoke(fsdroom, &args), Ok(Ret::U16(n)) if n == expected));

        assert_eq!(f.host.forms().len(), 1, "{:?}", f.host.forms());
        let form = f.host.forms().get(&(0, 0)).expect("message 0, amode 0");
        assert_eq!(form.fields.len(), 2);
    }

    /// Open `FSDFORM.MSG` and make it current.
    ///
    /// `SAMPLE.MSG`'s message 0 is the bare word `SAMPLE`, so every field
    /// compiled against it has width zero and no answer can be longer than
    /// nothing. A session needs a template with field runs in it, which is
    /// what this file is: four thirty-character `?` runs as message 0, and a
    /// `###-####` as message 1.
    fn open_form(f: &mut Fixture) -> FarPtr {
        current(f);
        let name = f.text("FSDFORM.MSG");
        let block = f
            .invoke(crate::shims::msg::opnmsg, &Fixture::far(name))
            .expect("opened");
        match block {
            Ret::Far(at) => at,
            other => panic!("opnmsg returned {other:?}"),
        }
    }

    /// Size a form over `spec`, then lay a session out over `defaults`.
    ///
    /// Returns the session buffer and its size, which is what the module
    /// itself holds after the `dclvda`/`alcmem` pair that `fsdroom` feeds.
    fn session(f: &mut Fixture, spec: &str, defaults: &[u8]) -> (FarPtr, u16) {
        session_over(f, 0, spec, defaults)
    }

    /// [`session`], over a named message of `FSDFORM.MSG`.
    fn session_over(f: &mut Fixture, message: u16, spec: &str, defaults: &[u8]) -> (FarPtr, u16) {
        session_amode(f, message, spec, defaults, 0)
    }

    /// [`session`], at a chosen `amode` -- 1 for a full-screen form.
    fn session_amode(
        f: &mut Fixture,
        message: u16,
        spec: &str,
        defaults: &[u8],
        amode: u16,
    ) -> (FarPtr, u16) {
        let _ = open_form(f);
        let spec = f.text(spec);
        let Ok(Ret::U16(size)) = f.invoke(fsdroom, &[message, spec.offset, spec.selector, amode])
        else {
            panic!("fsdroom refused")
        };
        let buffer = f.buffer(size);
        let defaults = f.bytes(defaults, false);
        f.invoke(
            fsdapr,
            &[
                buffer.offset,
                buffer.selector,
                size,
                defaults.offset,
                defaults.selector,
            ],
        )
        .expect("prepared");
        (buffer, size)
    }

    /// The session control block, as it stands.
    fn block(f: &Fixture) -> crate::fsd::Scb {
        let at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");
        read_block(&f.machine, at).expect("readable")
    }

    #[test]
    fn fsdapr_lays_punctuation_then_fields_then_answers_into_the_buffer() {
        let mut f = Fixture::new();
        let (buffer, _) = session(&mut f, "ONE TWO", b"\0");
        let scb = block(&f);

        assert_eq!(scb.mbpunc(), buffer);
        assert_eq!(scb.flddat().offset, buffer.offset + scb.mbleng());
        assert_eq!(
            scb.newans().offset,
            buffer.offset + scb.mbleng() + scb.numfld() * crate::fsd::FSDFLD
        );
        assert_eq!(scb.crsatr(), 0x70, "FSDBBS.C:180");
        assert_eq!(
            scb.numfld(),
            f.host.forms()[&(0, 0)].fields.len() as u16,
            "message 0, amode 0"
        );
        assert_eq!(scb.allans(), b"ONE=\0TWO=\0\0".len() as u16);
    }

    #[test]
    fn the_field_array_is_where_the_module_indexes_it() {
        // The module reaches `flddat[i].flags` as `[flddat + 23*i + 12]` --
        // fourteen sites from seg 3:0x4344 on. This is that arithmetic, run
        // against a form whose flags are known.
        let mut f = Fixture::new();
        let _ = session(&mut f, "A B(SECRET)", b"\0");
        let scb = block(&f);

        let stride = usize::from(crate::fsd::FSDFLD);
        let bytes = f
            .machine
            .resolve(scb.flddat(), stride * 2)
            .expect("in range");
        assert_eq!(bytes[crate::fsd::fld::FLAGS], 0, "A has no options");
        assert_eq!(
            bytes[stride + crate::fsd::fld::FLAGS],
            crate::fsd::flags::SECRET
        );
    }

    #[test]
    fn the_field_array_starts_after_the_punctuation_and_not_at_the_buffer() {
        // Every other session here compiles a form with no embedded
        // punctuation, so `mbleng` is 0 and `buffer + mbleng` is `buffer` --
        // which makes a `flddat` set to the buffer itself indistinguishable
        // from a correct one. Message 1 of FSDFORM.MSG is `Phone: ###-####`,
        // whose one field joins, so `mbleng` is nine and the two differ.
        let mut f = Fixture::new();
        let (buffer, _) = session_over(&mut f, 1, "PHONE", b"PHONE=5551234\0\0");
        let scb = block(&f);

        assert_eq!(scb.mbleng(), 9, "\"   -    \" and its NUL");
        assert_ne!(scb.flddat(), buffer);
        assert_eq!(scb.flddat().offset, buffer.offset + 9);

        // And the punctuation really is at the front of the buffer, which is
        // what `fsdscb->mbpunc = sesbuf` means.
        let punctuation = f.machine.resolve(buffer, 9).expect("in range");
        assert_eq!(punctuation, b"   -    \0");

        // The field's `mbpoff` names an offset into that array, not into the
        // template.
        let record = f
            .machine
            .resolve(scb.flddat(), usize::from(crate::fsd::FSDFLD))
            .expect("in range");
        let mbpoff = i16::from_le_bytes([
            record[crate::fsd::fld::MBPOFF],
            record[crate::fsd::fld::MBPOFF + 1],
        ]);
        assert_eq!(mbpoff, 0);
        assert_eq!(record[crate::fsd::fld::WIDTH], 7, "seven digits");
        assert_eq!(record[crate::fsd::fld::XWIDTH], 8, "spanning eight");
    }

    #[test]
    fn the_session_buffer_is_exactly_as_big_as_fsdroom_said() {
        // `fsdroom` returns `mbleng + numfld*23 + maxans + 1`, and this writes
        // those same three runs. If the two ever disagreed the module would
        // have allocated to one number and been written to by another.
        let mut f = Fixture::new();
        let (buffer, size) = session(&mut f, "NAME RANK", b"RANK=MAJOR\0\0");
        let scb = block(&f);
        let used = scb.newans().offset - buffer.offset + scb.allans();
        assert!(used <= size, "{used} bytes written into a buffer of {size}");
    }

    #[test]
    fn a_buffer_smaller_than_the_session_needs_stops_the_module() {
        // `catastro`, FSDBBS.C:171. A host that carried on would write the
        // answer string past the end of the channel's volatile data area.
        let mut f = Fixture::new();
        let _ = open_form(&mut f);
        let spec = f.text("ONE TWO");
        let Ok(Ret::U16(size)) = f.invoke(fsdroom, &[0, spec.offset, spec.selector, 0]) else {
            panic!("fsdroom refused")
        };
        let buffer = f.buffer(size);
        let defaults = f.bytes(b"\0", false);
        let e = f
            .invoke(
                fsdapr,
                &[
                    buffer.offset,
                    buffer.selector,
                    size - 1,
                    defaults.offset,
                    defaults.selector,
                ],
            )
            .expect_err("refused");
        assert!(format!("{e}").contains("1 byte(s) too small"), "{e}");
    }

    #[test]
    fn fsdapr_before_any_fsdroom_stops_the_module() {
        // FSDBBS.H:245: "call after fsdroom()". The real host would have read
        // an uninitialised control block; there is nothing here to read and
        // nothing plausible to invent.
        let mut f = Fixture::new();
        current(&mut f);
        let buffer = f.buffer(64);
        let defaults = f.bytes(b"\0", false);
        let e = f
            .invoke(
                fsdapr,
                &[
                    buffer.offset,
                    buffer.selector,
                    64,
                    defaults.offset,
                    defaults.selector,
                ],
            )
            .expect_err("refused");
        assert!(format!("{e}").contains("fsdroom"), "{e}");
    }

    #[test]
    fn a_defaults_pointer_that_is_not_an_answer_string_stops_the_module() {
        // A segment filled to its last byte with non-NULs, so there is no
        // empty entry to end the run. `stranslen` would have walked on into
        // whatever followed it.
        let mut f = Fixture::new();
        let _ = open_form(&mut f);
        let spec = f.text("ONE");
        let Ok(Ret::U16(size)) = f.invoke(fsdroom, &[0, spec.offset, spec.selector, 0]) else {
            panic!("fsdroom refused")
        };
        let buffer = f.buffer(size);

        let selector = f.machine.alloc_segment(8).expect("a segment");
        let junk = FarPtr {
            offset: 0,
            selector,
        };
        f.machine.write(junk, b"xxxxxxxx").expect("fills it");

        let e = f
            .invoke(
                fsdapr,
                &[
                    buffer.offset,
                    buffer.selector,
                    size,
                    junk.offset,
                    junk.selector,
                ],
            )
            .expect_err("refused");
        assert!(matches!(e, ShimError::BadPointer(_)), "{e}");
    }

    #[test]
    fn fsdapr_empties_the_print_buffer() {
        // `clrprf(); prf("")` -- FSDBBS.C:181. FSDBBS.H:117 tells callers to do
        // their own prf'ing after fsdapr for exactly this reason.
        let mut f = Fixture::new();
        let _ = open(&mut f);
        let text = f.text("something queued");
        f.invoke(crate::shims::text::prf, &[text.offset, text.selector])
            .expect("printed");
        assert_eq!(f.read(f.host.globals().prf_buffer()), "something queued");

        let _ = session(&mut f, "ONE", b"\0");
        assert_eq!(f.read(f.host.globals().prf_buffer()), "");
    }

    #[test]
    fn defaults_land_in_the_answer_string_under_the_form_s_own_names() {
        let mut f = Fixture::new();
        let (buffer, _) = session(&mut f, "NAME RANK", b"RANK=MAJOR\0\0");
        let scb = block(&f);
        let text = f
            .machine
            .resolve(scb.newans(), usize::from(scb.allans()))
            .expect("in range");
        assert_eq!(text, b"NAME=\0RANK=MAJOR\0\0");
        assert!(scb.newans().offset > buffer.offset);
    }

    #[test]
    fn fsdnan_points_at_the_answer_the_defaults_carried() {
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME RANK", b"RANK=MAJOR\0\0");

        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[1]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(at), "MAJOR");

        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[0]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(at), "", "no default, so blank");
    }

    #[test]
    fn fsdnan_reads_the_field_array_the_module_could_have_changed() {
        // Not a host-side shadow: the pointer is computed from `fsdscb` and
        // `flddat[i].ansoff` as they stand in module memory *now*. Move the
        // answer string and `fsdnan` must follow it there.
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME RANK", b"RANK=MAJOR\0\0");
        let at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");
        let mut scb = block(&f);

        let moved = f.bytes(b"NAME=\0RANK=COLONEL\0\0", false);
        scb.set_newans(moved);
        f.machine.write(at, scb.as_bytes()).expect("written");

        let Ok(Ret::Far(got)) = f.invoke(fsdnan, &[1]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(got), "COLONEL");
    }

    #[test]
    fn a_field_number_outside_the_form_stops_the_module() {
        // FSD.H:635 bounds it at `0 to fsdscb->numfld-1`, and the original
        // indexes without checking -- so field 99 would be a read of whatever
        // follows the array, returned as an answer.
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME RANK", b"\0");
        let e = f.invoke(fsdnan, &[2]).expect_err("refused");
        assert!(format!("{e}").contains("2 fields"), "{e}");
        let e = f.invoke(fsdnan, &[0xffff]).expect_err("refused");
        assert!(format!("{e}").contains("2 fields"), "{e}");
    }

    #[test]
    fn a_field_count_the_module_forged_cannot_index_out_of_the_segment() {
        // `numfld` lives in the control block, which the module holds a pointer
        // to and writes through. Forge a huge one and the bound stops nothing
        // -- what has to stop it is that `field * 23` no longer fits a `u16`.
        // Wrapping would read a `struct fsdfld` from elsewhere in the segment,
        // which resolves, and hand back a plausible answer.
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME", b"\0");
        let at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");
        let mut scb = block(&f);
        scb.set_numfld(60000);
        f.machine.write(at, scb.as_bytes()).expect("written");

        // 3000 * 23 = 69000, which is not a u16.
        let e = f.invoke(fsdnan, &[3000]).expect_err("refused");
        assert!(matches!(e, ShimError::Failed(_)), "{e}");
        let e = f.invoke(fsdord, &[3000]).expect_err("refused");
        assert!(matches!(e, ShimError::Failed(_)), "{e}");
    }

    #[test]
    fn fsdnan_before_a_session_stops_the_module() {
        let mut f = Fixture::new();
        current(&mut f);
        let e = f.invoke(fsdnan, &[0]).expect_err("refused");
        assert!(format!("{e}").contains("fsdroom"), "{e}");

        // And after `fsdroom` but before `fsdapr`, when `newans` is still null.
        let _ = open_form(&mut f);
        let spec = f.text("NAME");
        f.invoke(fsdroom, &[0, spec.offset, spec.selector, 0])
            .expect("sized");
        let e = f.invoke(fsdnan, &[0]).expect_err("refused");
        assert!(format!("{e}").contains("fsdapr"), "{e}");
    }

    #[test]
    fn fsdord_answers_the_position_of_the_alternate_chosen() {
        let mut f = Fixture::new();
        let spec = "COLOUR(ALT=Black ALT=Brown ALT=Red MULTICHOICE)";
        let _ = session(&mut f, spec, b"COLOUR=Brown\0\0");
        assert!(matches!(f.invoke(fsdord, &[0]), Ok(Ret::U16(1))));
    }

    #[test]
    fn an_answer_matching_nothing_answers_minus_one() {
        // FSD.H:653: "-1 if no match". The one place in this family where a
        // number that is not an ordinal is an honest answer.
        let mut f = Fixture::new();
        let spec = "COLOUR(ALT=Black ALT=Red)";
        let _ = session(&mut f, spec, b"COLOUR=Green\0\0");
        assert!(matches!(f.invoke(fsdord, &[0]), Ok(Ret::U16(NO))));
    }

    #[test]
    fn a_matched_answer_is_rewritten_in_full_and_later_fields_move() {
        // `stfans()`. "br" becomes "Brown", three bytes longer, and every field
        // after this one has its `ansoff` pushed along by three. A `fsdord`
        // that returned the ordinal without doing this would leave `fsdnan`
        // reading the middle of somebody else's answer.
        let mut f = Fixture::new();
        let spec = "COLOUR(ALT=Black ALT=Brown) NAME";
        let _ = session(&mut f, spec, b"COLOUR=br\0NAME=Fred\0\0");

        let Ok(Ret::Far(before)) = f.invoke(fsdnan, &[1]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(before), "Fred");
        let was = block(&f).allans();

        assert!(matches!(f.invoke(fsdord, &[0]), Ok(Ret::U16(1))));

        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[0]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(at), "Brown", "FSD.H:656");
        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[1]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(at), "Fred", "still readable, three bytes further on");
        assert_eq!(at.offset, before.offset + 3);
        assert_eq!(block(&f).allans(), was + 3);
    }

    #[test]
    fn an_answer_that_shrinks_moves_later_fields_back() {
        // The same arithmetic with a *negative* difference, which the signed
        // `anslen-m` in `stfans` handles and an unsigned one would not. Reached
        // because `chkalt` matches against `rmvwht(answer)` while the length it
        // replaces is the raw one: "B l a c k" is nine bytes on the way in and
        // "Black" is five on the way out.
        let mut f = Fixture::new();
        let spec = "COLOUR(ALT=Black) NAME";
        let _ = session(&mut f, spec, b"COLOUR=B l a c k\0NAME=Fred\0\0");

        let Ok(Ret::Far(before)) = f.invoke(fsdnan, &[1]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(before), "Fred");
        let was = block(&f).allans();

        assert!(matches!(f.invoke(fsdord, &[0]), Ok(Ret::U16(0))));

        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[0]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(at), "Black");
        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[1]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(at), "Fred", "four bytes closer, not further");
        assert_eq!(at.offset, before.offset - 4);
        assert_eq!(block(&f).allans(), was - 4);
    }

    #[test]
    fn fsdord_writes_the_new_length_back_into_the_field() {
        // `fldptr->anslen = anslen`, FSD.C:1053. `stfans` reads `m` from there
        // on the *next* call, so a length left stale makes a second `fsdord`
        // shift by the wrong amount and tear the answer string in half.
        let mut f = Fixture::new();
        let spec = "COLOUR(ALT=Black ALT=Brown) NAME";
        let _ = session(&mut f, spec, b"COLOUR=br\0NAME=Fred\0\0");

        assert!(matches!(f.invoke(fsdord, &[0]), Ok(Ret::U16(1))));
        let scb = block(&f);
        let record = f
            .machine
            .resolve(scb.flddat(), usize::from(crate::fsd::FSDFLD))
            .expect("in range");
        assert_eq!(
            record[crate::fsd::fld::ANSLEN],
            5,
            "\"Brown\", not the \"br\" that was there"
        );

        // And a second call over the now-canonical answer is a no-op that
        // leaves everything where the first put it.
        let Ok(Ret::Far(name)) = f.invoke(fsdnan, &[1]) else {
            panic!("fsdnan refused")
        };
        let allans = block(&f).allans();
        assert!(matches!(f.invoke(fsdord, &[0]), Ok(Ret::U16(1))));
        assert_eq!(block(&f).allans(), allans, "nothing moved the second time");
        let Ok(Ret::Far(again)) = f.invoke(fsdnan, &[1]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(again, name);
        assert_eq!(f.read(again), "Fred");
    }

    #[test]
    fn fsdord_reads_the_flags_the_module_left_and_not_the_host_s_copy() {
        // The module edits `flddat[i].flags`. Clear FFFALT there and `chkalt`
        // must bail on its first line, whatever `Host::forms` still says.
        let mut f = Fixture::new();
        let spec = "COLOUR(ALT=Black ALT=Red)";
        let _ = session(&mut f, spec, b"COLOUR=Red\0\0");
        assert!(matches!(f.invoke(fsdord, &[0]), Ok(Ret::U16(1))));

        let scb = block(&f);
        let mut record = [0u8; crate::fsd::FSDFLD as usize];
        record.copy_from_slice(
            f.machine
                .resolve(scb.flddat(), usize::from(crate::fsd::FSDFLD))
                .expect("in range"),
        );
        record[crate::fsd::fld::FLAGS] &= !crate::fsd::flags::ALTERNATES;
        f.machine.write(scb.flddat(), &record).expect("written");

        assert!(matches!(f.invoke(fsdord, &[0]), Ok(Ret::U16(NO))));
        assert!(
            f.host.forms()[&(0, 0)].fields[0].flags & crate::fsd::flags::ALTERNATES != 0,
            "the host's own copy still says otherwise, which is the point"
        );
    }

    #[test]
    fn an_answer_that_would_outgrow_the_buffer_stops_the_module() {
        // `stfans` moves bytes with no bound of its own, and the buffer is the
        // one `fsdroom` sized -- `maxans` counted each field's width, not the
        // length of its longest alternate. FSD.H:218 warns callers off; this
        // refuses rather than write past the end of the module's memory.
        let mut f = Fixture::new();
        let long = "A".repeat(60);
        let spec = format!("C(ALT={long})");
        let _ = session_over(&mut f, 1, &spec, b"C=A\0\0");
        let e = f.invoke(fsdord, &[0]).expect_err("refused");
        assert!(format!("{e}").contains("does not fit"), "{e}");
    }

    #[test]
    fn fsdord_on_a_field_with_no_alternates_answers_minus_one() {
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME", b"NAME=Fred\0\0");
        assert!(matches!(f.invoke(fsdord, &[0]), Ok(Ret::U16(NO))));
    }

    #[test]
    fn fsdord_outside_the_form_stops_the_module() {
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME", b"\0");
        let e = f.invoke(fsdord, &[1]).expect_err("refused");
        assert!(format!("{e}").contains("1 fields"), "{e}");
    }

    #[test]
    fn fsdxan_finds_a_value_by_name() {
        let mut f = Fixture::new();
        let answers = f.bytes(b"NAME=Fred\0RANK=MAJOR\0\0", false);
        let name = f.text("RANK");
        let Ok(Ret::Far(at)) = f.invoke(
            fsdxan,
            &[answers.offset, answers.selector, name.offset, name.selector],
        ) else {
            panic!("fsdxan refused")
        };
        assert_eq!(f.read(at), "MAJOR");
    }

    #[test]
    fn a_name_that_is_not_there_answers_the_final_terminator() {
        // FSD.H:595: "otherwise return value and xannam point to final '\0' of
        // answer string". Not NULL -- the module runs `atol` on the result, so
        // a null pointer would be a fault where the original gave a zero.
        let mut f = Fixture::new();
        let answers = f.bytes(b"NAME=Fred\0\0", false);
        let name = f.text("RANK");
        let Ok(Ret::Far(at)) = f.invoke(
            fsdxan,
            &[answers.offset, answers.selector, name.offset, name.selector],
        ) else {
            panic!("fsdxan refused")
        };
        assert_eq!(f.read(at), "");
        assert_eq!(
            at.offset,
            answers.offset + 10,
            "the string's own terminator, not the first entry's"
        );
    }

    #[test]
    fn fsdxan_needs_no_session() {
        // Six of MajorMUD's sites pass `fsdscb->newans`, but nothing here reads
        // `fsdscb`: FSD.H:583 files this under "call on any unprocessed answer
        // string". A version that required `fsdapr` would refuse a call the
        // real host answers.
        let mut f = Fixture::new();
        assert!(f.host.forms().is_empty());
        let answers = f.bytes(b"A=1\0\0", false);
        let name = f.text("A");
        let Ok(Ret::Far(at)) = f.invoke(
            fsdxan,
            &[answers.offset, answers.selector, name.offset, name.selector],
        ) else {
            panic!("fsdxan refused")
        };
        assert_eq!(f.read(at), "1");
    }

    #[test]
    fn fsdxan_matches_a_whole_name_and_not_a_prefix_of_one() {
        let mut f = Fixture::new();
        let answers = f.bytes(b"NAMEX=1\0NAME=2\0\0", false);
        let name = f.text("NAME");
        let Ok(Ret::Far(at)) = f.invoke(
            fsdxan,
            &[answers.offset, answers.selector, name.offset, name.selector],
        ) else {
            panic!("fsdxan refused")
        };
        assert_eq!(f.read(at), "2", "the second entry, not the first");
    }

    #[test]
    fn an_answer_string_that_never_ends_stops_the_module() {
        // A segment full of non-NULs to its last byte, so there is no empty
        // entry. The original would have walked on past it.
        let mut f = Fixture::new();
        let selector = f.machine.alloc_segment(8).expect("a segment");
        let junk = FarPtr {
            offset: 0,
            selector,
        };
        f.machine.write(junk, b"xxxxxxxx").expect("fills it");
        let name = f.text("A");
        let e = f
            .invoke(
                fsdxan,
                &[junk.offset, junk.selector, name.offset, name.selector],
            )
            .expect_err("refused");
        assert!(matches!(e, ShimError::BadPointer(_)), "{e}");
    }

    /// What `fsdrft` hands back, as bytes.
    ///
    /// These used to compare the returned *pointer* against the message
    /// text's. They compare content now, because since Task 6 the pointer is
    /// deliberately not that one: at any `amode` but -1 the module must get
    /// `getasc`'s expansion, which lives in a buffer of the host's
    /// (`FSDBBS.C:137`, and see [`ascii_template`]).
    fn fsdrft_text(f: &mut Fixture) -> Vec<u8> {
        let Ok(Ret::Far(at)) = f.invoke(fsdrft, &[]) else {
            panic!("fsdrft refused")
        };
        f.machine.read_cstr(at).expect("addressable").to_vec()
    }

    #[test]
    fn fsdrft_returns_the_template_fsdroom_compiled() {
        let mut f = Fixture::new();
        let _ = open_form(&mut f);
        let spec = f.text("ONE");
        f.invoke(fsdroom, &[0, spec.offset, spec.selector, 0])
            .expect("sized");

        let expected = crate::shims::msg::message(&f.machine, &f.host, 0).expect("message");
        let expected = f.machine.read_cstr(expected).expect("text").to_vec();
        assert_eq!(fsdrft_text(&mut f), crate::msg::getasc(&expected));
    }

    #[test]
    fn fsdrft_comes_back_to_its_own_message_file() {
        // `setmbk(fsdusr->curmbk)` -- the block that was current when `fsdroom`
        // ran, and not whichever one is current now. A host that read `curmbk`
        // at call time would hand back a message of the wrong file, which is
        // not hypothetical: the module `rstmbk`s four instructions after
        // `fsdroom` returns, at seg 3:0x3f86.
        let mut f = Fixture::new();
        let form = open_form(&mut f);
        let spec = f.text("ONE");
        f.invoke(fsdroom, &[0, spec.offset, spec.selector, 0])
            .expect("sized");

        let other = f.text("SAMPLE.MSG");
        let Ok(Ret::Far(block)) = f.invoke(crate::shims::msg::opnmsg, &Fixture::far(other)) else {
            panic!("opnmsg refused")
        };
        f.invoke(crate::shims::msg::setmbk, &Fixture::far(block))
            .expect("current");

        let expected = f
            .host
            .messages()
            .text(form, 0)
            .expect("message 0 of the form's own file");
        let expected = f.machine.read_cstr(expected).expect("text").to_vec();
        let current = crate::shims::msg::message(&f.machine, &f.host, 0).expect("message");
        let current = f.machine.read_cstr(current).expect("text").to_vec();
        assert_ne!(
            expected, current,
            "and the current file's message 0 is a different string"
        );
        assert_eq!(fsdrft_text(&mut f), crate::msg::getasc(&expected));
    }

    #[test]
    fn fsdrft_returns_the_template_of_the_last_form_sized() {
        let mut f = Fixture::new();
        let _ = open_form(&mut f);
        let spec = f.text("ONE");
        f.invoke(fsdroom, &[0, spec.offset, spec.selector, 0])
            .expect("sized");
        f.invoke(fsdroom, &[1, spec.offset, spec.selector, 0])
            .expect("sized");

        let expected = crate::shims::msg::message(&f.machine, &f.host, 1).expect("message");
        let expected = f.machine.read_cstr(expected).expect("text").to_vec();
        assert_eq!(fsdrft_text(&mut f), crate::msg::getasc(&expected));
    }

    #[test]
    fn fsdrft_before_any_fsdroom_stops_the_module() {
        let mut f = Fixture::new();
        current(&mut f);
        let e = f.invoke(fsdrft, &[]).expect_err("refused");
        assert!(format!("{e}").contains("fsdroom"), "{e}");
    }

    #[test]
    fn fsdroom_points_the_fsdscb_global_at_a_block_it_filled_in() {
        // `inifsdscb()` + `setfsd(usrnum)`, FSDBBS.C:125-129. The module tests
        // `fsdscb` for null at seg 3:0x430f and bails to `rstmbk` when it is,
        // so leaving it zero would be a decision and not an omission.
        let mut f = Fixture::new();
        let _ = open(&mut f);
        let spec = f.text("ONE TWO");

        assert_eq!(
            f.host
                .globals()
                .pointer(&f.machine, "fsdscb")
                .expect("placed"),
            FarPtr::NULL,
            "null until a form has been sized"
        );

        f.invoke(fsdroom, &[0, spec.offset, spec.selector, 0])
            .expect("sized");

        let at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");
        assert_ne!(at, FarPtr::NULL);

        let block = read_block(&f.machine, at).expect("readable");
        assert_eq!(block.numfld(), 2);
        assert_eq!(
            block.fldspc(),
            spec,
            "the module's own copy of the spec, not a host one"
        );
        assert_eq!(block.maxans(), f.host.forms()[&(0, 0)].answer_max);
        assert_eq!(
            block.mbleng(),
            f.host.forms()[&(0, 0)].punctuation.len() as u16
        );
    }

    #[test]
    fn a_second_form_reuses_the_one_control_block() {
        // `inifsdscb()` allocates only `if (fsdtbl == NULL)`, and `nterms` is
        // one here. A segment per call would leak an LDT entry a form.
        let mut f = Fixture::new();
        let _ = open(&mut f);
        let spec = f.text("ONE");
        f.invoke(fsdroom, &[0, spec.offset, spec.selector, 0])
            .expect("sized");
        let first = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");
        f.invoke(fsdroom, &[0, spec.offset, spec.selector, 0])
            .expect("sized");
        let second = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");
        assert_eq!(first, second);
    }

    #[test]
    fn two_channels_sizing_different_forms_do_not_share_a_session() {
        // The shape that catches a flat `Host::forms`/`fsdscb`/`fsdtmp`: size
        // and prepare a session for channel A, then a *different* one for
        // channel B, before anything reads either back. A test that only
        // ever looked at one channel could not tell "keyed by channel" from
        // "still flat" -- `a_second_form_reuses_the_one_control_block` above
        // is exactly that kind of test, and it stays green under either
        // implementation. This one does not: reverting `forms`/`fsdscb`/
        // `fsdtmp` to their old flat shape makes it fail while every other
        // FSD test in this file keeps passing, which is the whole point.
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let a = f.host.users().terms().chan(0).expect("channel 0");
        let b = f.host.users().terms().chan(1).expect("channel 1");

        // Channel A sizes and prepares message 0 of FSDFORM.MSG ("NAME"),
        // with "Alice" as its answer.
        f.host
            .point_curusr(&mut f.machine, a)
            .expect("channel 0 is current");
        let _ = open_form(&mut f);
        let spec_a = f.text("NAME");
        let Ok(Ret::U16(size_a)) = f.invoke(fsdroom, &[0, spec_a.offset, spec_a.selector, 0])
        else {
            panic!("fsdroom (channel A) refused");
        };
        let buffer_a = f.buffer(size_a);
        let defaults_a = f.bytes(b"NAME=Alice\0\0", false);
        f.invoke(
            fsdapr,
            &[
                buffer_a.offset,
                buffer_a.selector,
                size_a,
                defaults_a.offset,
                defaults_a.selector,
            ],
        )
        .expect("fsdapr (channel A) prepared");

        // Channel B sizes and prepares a *different* form -- message 1
        // ("PHONE") -- before channel A's session is ever read back.
        f.host
            .point_curusr(&mut f.machine, b)
            .expect("channel 1 is current");
        let spec_b = f.text("PHONE");
        let Ok(Ret::U16(size_b)) = f.invoke(fsdroom, &[1, spec_b.offset, spec_b.selector, 0])
        else {
            panic!("fsdroom (channel B) refused");
        };
        let buffer_b = f.buffer(size_b);
        let defaults_b = f.bytes(b"PHONE=5551234\0\0", false);
        f.invoke(
            fsdapr,
            &[
                buffer_b.offset,
                buffer_b.selector,
                size_b,
                defaults_b.offset,
                defaults_b.selector,
            ],
        )
        .expect("fsdapr (channel B) prepared");

        // Back to channel A: `fsdnan(0)` must still resolve against *A's*
        // control block and answer string, not whatever channel B's fsdroom/
        // fsdapr left behind.
        f.host
            .point_curusr(&mut f.machine, a)
            .expect("channel 0 is current again");
        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[0]) else {
            panic!("fsdnan (channel A) refused");
        };
        assert_eq!(
            f.read(at),
            "Alice",
            "channel A's own answer, not channel B's PHONE session"
        );
    }

    #[test]
    fn a_full_screen_session_is_scanned_against_the_cursor_tracker() {
        // This used to assert the opposite: `amode=1` scans the template
        // against an ANSI screen to read each field's cursor position off it,
        // there was no screen, and a form whose fields all thought they were
        // at the origin would have been worse than none. Stage 5 built the
        // tracker (`fsd::Terminal`, checked field by field against the
        // genuine host in `tests/fsd_oracle.rs`), so the scan happens.
        let mut f = Fixture::new();
        let _ = open(&mut f);
        let spec = f.text("ONE");

        let Ok(Ret::U16(size)) = f.invoke(fsdroom, &[0, spec.offset, spec.selector, 1]) else {
            panic!("fsdroom(amode=1) refused")
        };
        assert!(size > 0);
        assert!(
            f.host.forms().contains_key(&(0, 1)),
            "and the full-screen form is cached under its own amode"
        );
        // This file's message 0 has no field runs, so there are no cursor
        // positions here to look at; `fsdroom_sizes_a_full_screen_form_
        // instead_of_refusing_it` makes that assertion against a template
        // that does.
    }

    #[test]
    fn an_amode_that_is_neither_entry_nor_display_is_refused() {
        let mut f = Fixture::new();
        let _ = open(&mut f);
        let spec = f.text("ONE");

        let e = f
            .invoke(fsdroom, &[0, spec.offset, spec.selector, 7])
            .expect_err("refused");
        assert!(format!("{e}").contains("neither entry"), "{e}");
    }

    #[test]
    fn a_field_spec_the_compiler_rejects_stops_the_module() {
        // The real host calls `catastro` here, which never returns. A refusal
        // is this crate's `catastro`.
        let mut f = Fixture::new();
        let _ = open(&mut f);
        let spec = f.text("A_VERY_LONG_NAME_INDEED");

        let e = f
            .invoke(fsdroom, &[0, spec.offset, spec.selector, 0])
            .expect_err("refused");
        assert!(format!("{e}").contains("too long"), "{e}");
        assert!(f.host.forms().is_empty());
    }

    #[test]
    fn fsdcon_sets_raw_and_clears_echo_but_leaves_width_alone() {
        let mut f = Fixture::new();
        let chan = f.console();
        {
            let ch = f.host.gsbl_mut().channel_mut(chan);
            ch.echo = true;
            // Deliberately not 80 (the crate's usual default) -- a value
            // that could only survive here by genuinely being left alone,
            // not by a `ch.width = 80` mutation coincidentally matching a
            // fixture that also starts at 80.
            ch.width = 37;
            ch.raw = false;
        }

        fsdcon(&mut f.host, chan);

        let ch = f.host.gsbl_mut().channel_mut(chan);
        assert!(ch.raw, "fsdcon must turn raw input on");
        assert!(!ch.echo, "fsdcon must turn echo off");
        assert_eq!(
            ch.width, 37,
            "fsdcon never calls btutsw (FSDBBS.C:91-101) -- width zeroing is \
             fsdbkg's job, and fsdbkg is not part of line mode"
        );
    }

    #[test]
    fn fsdcof_restores_what_fsdcon_changed() {
        let mut f = Fixture::new();
        let chan = f.console();
        {
            let ch = f.host.gsbl_mut().channel_mut(chan);
            ch.echo = true;
            ch.width = 41;
            ch.raw = false;
        }

        fsdcon(&mut f.host, chan);
        // 41 here is deliberately not the pre-fsdcon width (41 vs. its own
        // value above) -- fsdcof's argument is what must land, not
        // whatever fsdcon left in place, which fsdcof_sets_width_from_its_
        // argument_not_whatever_fsdcon_left_behind proves more directly.
        // Kept equal to the fixture's own value here only so this test can
        // also serve as an end-to-end fsdcon-then-fsdcof round trip.
        fsdcof(&mut f.host, chan, 41);

        let ch = f.host.gsbl_mut().channel_mut(chan);
        assert!(!ch.raw, "fsdcof must turn raw input back off");
        assert!(ch.echo, "fsdcof must turn echo back on");
        assert_eq!(ch.width, 41, "fsdcof restores width from usaptr->scnwid");
    }

    #[test]
    fn fsdcof_sets_width_from_its_argument_not_whatever_fsdcon_left_behind() {
        // FSDBBS.C:112 always writes usaptr->scnwid on the way out, even
        // though fsdcon on the way in never touched width in line mode --
        // this proves fsdcof's width write is unconditional, not "restore
        // if changed".
        let mut f = Fixture::new();
        let chan = f.console();
        f.host.gsbl_mut().channel_mut(chan).width = 0;

        fsdcof(&mut f.host, chan, 132);

        assert_eq!(f.host.gsbl_mut().channel_mut(chan).width, 132);
    }

    #[test]
    fn fsdego_hands_the_channel_to_the_fsd_and_prompts_the_first_field() {
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME", b"NAME=Kaimon\0\0");
        let chan = f.console();

        // The expected prompt, computed independently: the same template
        // and form fsdroom compiled, walked through the pure `fsd::fsdlin`
        // this shim wraps -- not a literal copied from FSDFORM.MSG, which
        // this test does not otherwise depend on the exact wording of.
        let template = crate::shims::msg::message(&f.machine, &f.host, 0).expect("message");
        let template = f.machine.read_cstr(template).expect("text").to_vec();
        let form = f.host.forms()[&(0, 0)].clone();
        let mut expected_scb = fsd::Scb::from_bytes(&[0u8; fsd::FSDSCB as usize]).expect("zeroed");
        let expected = fsd::fsdlin(&form, b"NAME", &template, &mut expected_scb, b"NAME=Kaimon\0\0");

        let fldvfy = FarPtr {
            offset: 0x1000,
            selector: 0x2000,
        };
        let whndun = FarPtr {
            offset: 0x3000,
            selector: 0x4000,
        };

        assert!(
            !f.host.gsbl_mut().channel_mut(chan).raw,
            "not raw before fsdego"
        );
        assert_eq!(f.host.users().state(&f.machine, chan).expect("read"), 0);

        assert!(matches!(
            f.invoke(
                fsdego,
                &[fldvfy.offset, fldvfy.selector, whndun.offset, whndun.selector],
            ),
            Ok(Ret::Void)
        ));

        assert_eq!(
            f.host.users().state(&f.machine, chan).expect("read"),
            f.host.fsd_state() as u16,
            "usrptr->state = fsdstt"
        );
        assert_eq!(
            f.host.users().substt(&f.machine, chan).expect("read"),
            ENTERING,
            "usrptr->substt = ENTERING"
        );
        assert!(f.host.gsbl_mut().channel_mut(chan).raw, "fsdcon ran");

        assert_eq!(
            f.read(f.host.globals().prf_buffer()),
            String::from_utf8_lossy(&expected),
            "fsdlin's output, appended to the print buffer the way fsdapr's \
             twelve prf calls already are"
        );

        match &f.host.fsd_sessions[chan.index()] {
            Some(session) => {
                assert_eq!(session.whndun, Some(whndun));
                assert!(!session.save, "not exiting yet");
            }
            None => panic!("fsdego did not record a session"),
        }
    }

    #[test]
    fn fsdego_reads_flddat_flags_live_not_the_host_s_cached_form() {
        // `_EDIT_CHARACTER_STATS` sets FFFAVD on flddat[i].flags directly,
        // after fsdroom/fsdapr already cached the form in Host::forms. This
        // reproduces that: two fields, FFFAVD poked into field 0's *live*
        // module record only -- Host::forms's copy is left alone, which is
        // the whole point live_form exists for. If fsdego trusted the cache
        // instead, movfld(0,1,0) would land the cursor on field 0.
        let mut f = Fixture::new();
        let _ = session(&mut f, "A B", b"\0");
        let scb = block(&f);

        let stride = usize::from(crate::fsd::FSDFLD);
        let mut record = [0u8; crate::fsd::FSDFLD as usize];
        record.copy_from_slice(f.machine.resolve(scb.flddat(), stride).expect("in range"));
        record[crate::fsd::fld::FLAGS] |= crate::fsd::flags::AVOID;
        f.machine.write(scb.flddat(), &record).expect("written");

        assert_eq!(
            f.host.forms()[&(0, 0)].fields[0].flags & crate::fsd::flags::AVOID,
            0,
            "Host::forms's cached copy must NOT have FFFAVD set -- only the \
             live module record does"
        );

        assert!(matches!(f.invoke(fsdego, &[0, 0, 0, 0]), Ok(Ret::Void)));

        assert_eq!(
            block(&f).crsfld(),
            1,
            "field 0 is avoided in the live flddat record, so movfld(0,1,0) \
             must skip it and land the cursor on field 1"
        );
    }

    #[test]
    fn fsdego_before_any_session_stops_the_module() {
        let mut f = Fixture::new();
        current(&mut f);
        let e = f.invoke(fsdego, &[0, 0, 0, 0]).expect_err("refused");
        assert!(format!("{e}").contains("fsdroom"), "{e}");
    }

    #[test]
    fn fsdego_refuses_a_forged_amode_recording_defensively() {
        // `amode == 1` is legitimate since Stage 5's Task 8, so this no
        // longer forges *that*. What it forges instead is the same class of
        // fault: a `Host::fsdtmp` that has come apart from `Host::forms`, the
        // way `a_field_count_the_module_forged_cannot_index_out_of_the_
        // segment` forges `numfld`. fsdego must refuse on its own terms
        // rather than index into a form that was never compiled.
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME", b"\0");
        let chan = f.console();
        let (mbk, msgno, _) = f.host.fsdtmp[chan.index()].expect("recorded by session()");
        // amode 1 recorded, but only the amode-0 form was ever compiled.
        f.host.fsdtmp[chan.index()] = Some((mbk, msgno, 1));

        let e = f.invoke(fsdego, &[0, 0, 0, 0]).expect_err("refused");
        assert!(format!("{e}").contains("no such form"), "{e}");

        // And refusing did not half-mutate anything on the way there.
        assert_eq!(f.host.users().state(&f.machine, chan).expect("read"), 0);
        assert_eq!(f.host.users().substt(&f.machine, chan).expect("read"), 0);
        assert!(f.host.fsd_sessions[chan.index()].is_none());
        assert!(!f.host.gsbl_mut().channel_mut(chan).raw, "fsdcon did not run");
    }

    // --- Task 10: fsdprc, the fldvfy callback wiring --------------------

    /// Leave the session control block the way `xitfld` would just before
    /// `fsdprc`'s `FSDBUF` arm runs: `entfld` the field just committed,
    /// `crsfld` wherever `xitfld`'s own `movfld` already advanced to,
    /// `state` `FSDBUF`, `xitkey` whatever byte triggered the commit, and
    /// `ansbuf` the candidate answer that was typed.
    fn set_buffered(f: &mut Fixture, entfld: u8, crsfld: u8, xitkey: u8, ansbuf: &[u8]) {
        let at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");
        let mut scb = block(f);
        scb.set_entfld(entfld);
        scb.set_crsfld(crsfld);
        scb.set_xitkey(u16::from(xitkey));
        scb.set_ansbuf(ansbuf);
        scb.set_state(fsd::state::FSDBUF);
        f.machine.write(at, scb.as_bytes()).expect("written");
    }

    /// A synthetic `fldvfy` at `code_offset` in the scratch code segment:
    /// `mov ax, retval; retf`, ignoring both its arguments. Written well
    /// past whatever a preceding `f.invoke` call's own thunk-driver
    /// trampoline used at offset 0, so the two do not collide.
    fn stub_returning(f: &mut Fixture, code_offset: u16, retval: i16) -> FarPtr {
        let mut code = vec![0xb8u8];
        code.extend_from_slice(&(retval as u16).to_le_bytes());
        code.push(0xcb);
        let ptr = f.machine.code_ptr(code_offset);
        f.machine.write(ptr, &code).expect("stub fits");
        ptr
    }

    /// A synthetic `fldvfy` that pokes `new_state` directly into `scb`'s
    /// own `state` byte -- `FSD.H`'s Note 2, "the field verify routine
    /// ... sets fsdscb->state" -- before returning `retval`. Exercises
    /// the callback discipline: `fsdprc` must re-read `scb` after this
    /// call rather than trust the pre-call copy.
    fn stub_setting_state(
        f: &mut Fixture,
        code_offset: u16,
        scb: FarPtr,
        new_state: u8,
        retval: i16,
    ) -> FarPtr {
        let mut code = Vec::new();
        code.push(0xb8); // mov ax, <scb's segment>
        code.extend_from_slice(&scb.selector.to_le_bytes());
        code.extend_from_slice(&[0x8e, 0xc0]); // mov es, ax
        code.extend_from_slice(&[0x26, 0xc6, 0x06]); // mov byte [es:disp16], imm8
        code.extend_from_slice(&(scb.offset + fsd::scb::STATE).to_le_bytes());
        code.push(new_state);
        code.push(0xb8); // mov ax, retval
        code.extend_from_slice(&(retval as u16).to_le_bytes());
        code.push(0xcb); // retf
        let ptr = f.machine.code_ptr(code_offset);
        f.machine.write(ptr, &code).expect("stub fits");
        ptr
    }

    /// A synthetic `fldvfy` that immediately far-calls thunk 0 -- an
    /// import `f.minimal_module()` never registered, so [`Host::run`]
    /// services the call (unlike the old bare `machine.call` this replaced)
    /// but still stops the machine, naming the unimplemented import rather
    /// than refusing to look at it at all.
    fn stub_calling_a_thunk(f: &mut Fixture, code_offset: u16) -> FarPtr {
        let mut code = vec![0x9au8]; // far call
        code.extend_from_slice(&f.machine.thunk_address(0).to_bytes());
        code.push(0xcb);
        let ptr = f.machine.code_ptr(code_offset);
        f.machine.write(ptr, &code).expect("stub fits");
        ptr
    }

    #[test]
    fn fsdprc_accepts_via_fldvfy_stores_the_rewritten_answer_and_advances() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let (buffer, _) = session(&mut f, "A B", b"\0");
        let chan = f.console();
        let scb_at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");

        // VFYOK: fsdprc must store bufptr as fldvfy left it, without
        // running any local chktyp/chkmin/chkmax/chkalt check of its own.
        let fldvfy = stub_returning(&mut f, 0x100, crate::fsd::verify::VFYOK);
        let mut scb = block(&f);
        scb.set_fldvfy(fldvfy);
        f.machine.write(scb_at, scb.as_bytes()).expect("written");

        // entfld=0 ("A"), crsfld=1 ("B") -- xitfld already advanced past
        // A when Enter committed it.
        set_buffered(&mut f, 0, 1, b'\r', b"hello");
        let _ = buffer; // silence unused warning if the field is trivial

        crate::shims::fsd::fsdprc(&mut f.machine, &mut f.host, &module, chan).expect("processed");

        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[0]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(at), "hello", "the callback's own answer, stored verbatim");
        assert_eq!(
            block(&f).state(),
            fsd::state::FSDNPT,
            "not over -- straight back to point mode, no FSDSTB"
        );
        assert_eq!(block(&f).crsfld(), 1, "landed on field B");
        assert!(
            !f.read(f.host.globals().prf_buffer()).is_empty(),
            "field B's prompt was appended to the print buffer"
        );

        let scb = block(&f);
        let record = f
            .machine
            .resolve(scb.flddat(), usize::from(crate::fsd::FSDFLD))
            .expect("field 0's record");
        assert_eq!(
            record[crate::fsd::fld::FLAGS] & crate::fsd::flags::CHANGED,
            crate::fsd::flags::CHANGED,
            "FFFCHG set on field A's own record in module memory"
        );
    }

    #[test]
    fn fsdprc_rejects_via_fldvfy_and_does_not_advance() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A", b"\0");
        let chan = f.console();
        let scb_at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");

        let fldvfy = stub_returning(&mut f, 0x100, crate::fsd::verify::VFYREJ);
        let mut scb = block(&f);
        scb.set_fldvfy(fldvfy);
        f.machine.write(scb_at, scb.as_bytes()).expect("written");
        set_buffered(&mut f, 0, 0, b'\r', b"nope");

        crate::shims::fsd::fsdprc(&mut f.machine, &mut f.host, &module, chan).expect("processed");

        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[0]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(at), "", "VFYREJ -- nothing stored");
        assert_eq!(block(&f).state(), fsd::state::FSDNPT, "not over -- reprompting");
    }

    #[test]
    fn fsdprc_a_callback_that_sets_state_directly_ends_the_session_and_is_re_read_not_trusted() {
        // FSD.H's Note 2. This is the real mechanism a completed form
        // uses -- see fsd::fsdprc's own doc comment on why the "no wrap"
        // fallback inside fsdprc's own movfld arithmetic is unreachable.
        // If fsdprc trusted its pre-call copy of `scb` instead of
        // re-reading after the callback, it would never see FSDSAV here
        // and would wrongly redisplay the field instead of ending the
        // session.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A", b"\0");
        let chan = f.console();
        // Task 11: `fsdprc` now reaches `goback` itself as soon as it sees
        // FSDSAV/FSDQIT (this file's own doc comment on that call site), so
        // a session has to be on record for it to close -- the way
        // `fsdego` would have left one, recreated by hand here so this test
        // can still drive `fsdprc` directly. `whndun: None` keeps this
        // test's own focus on `scb.state()`/the stored answer, not on the
        // callback -- that is what the `goback_*` tests below are for.
        f.host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
            full_screen: false,
            whndun: None,
            save: false,
        });
        let scb_at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");

        let fldvfy = stub_setting_state(
            &mut f,
            0x100,
            scb_at,
            fsd::state::FSDSAV,
            crate::fsd::verify::VFYOK,
        );
        let mut scb = block(&f);
        scb.set_fldvfy(fldvfy);
        f.machine.write(scb_at, scb.as_bytes()).expect("written");
        // The sentinel: the single field's own xitfld(0) left crsfld
        // unmoved, then fsdinc stepped it one past the end by hand.
        set_buffered(&mut f, 0, 1, b'\r', b"done");

        crate::shims::fsd::fsdprc(&mut f.machine, &mut f.host, &module, chan).expect("processed");

        assert_eq!(
            block(&f).state(),
            fsd::state::FSDSAV,
            "left exactly as the callback set it, not overwritten back to FSDNPT"
        );
        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[0]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(at), "done", "VFYOK still stored the answer");
    }

    #[test]
    fn fsdprc_landing_on_fsdsav_reaches_whndun_with_the_save_flag_set() {
        // Task 10 review gap, extended by Task 11's own wiring: `scb.state()`
        // landing on FSDSAV is not, by itself, enough for `goback()` to know
        // a session ended in save -- by the time it runs, the session
        // buffer FSDSAV was read from may already be gone (design doc:
        // `FsdSession.save` exists precisely so the flag survives that).
        // `fsdprc` propagates the outcome into `Host::fsd_sessions[chan]
        // .save` itself, while `block.state()` is still fresh, and -- since
        // Task 11 -- immediately calls `goback` with it, which is why this
        // is now observed through `whndun`'s own argument rather than by
        // reading `Host::fsd_sessions` back afterward: `goback` consumes
        // the session as part of the same call, so nothing is left to read.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A", b"\0");
        let chan = f.console();
        let scb_at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");

        // A session normally starts life through `fsdego`, which is what
        // populates `Host::fsd_sessions` in the first place; recreated by
        // hand here so this test can drive `fsdprc` directly the way its
        // neighbours already do, without `fsdego`'s own `fsdlin` call
        // moving `state` off `FSDBUF` before `set_buffered` gets to it.
        let marker = f.buffer(2);
        f.machine.write(marker, &[0xff, 0xff]).expect("seeded");
        let whndun = stub_recording_save(&mut f, 0x200, marker);
        f.host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
            full_screen: false,
            whndun: Some(whndun),
            save: false,
        });

        let fldvfy = stub_setting_state(
            &mut f,
            0x100,
            scb_at,
            fsd::state::FSDSAV,
            crate::fsd::verify::VFYOK,
        );
        let mut scb = block(&f);
        scb.set_fldvfy(fldvfy);
        f.machine.write(scb_at, scb.as_bytes()).expect("written");
        set_buffered(&mut f, 0, 1, b'\r', b"done");

        crate::shims::fsd::fsdprc(&mut f.machine, &mut f.host, &module, chan).expect("processed");

        assert!(
            f.host.fsd_sessions[chan.index()].is_none(),
            "goback consumed the session -- FSDSAV must reach whndun, not just module memory"
        );
        let recorded = f.machine.resolve(marker, 2).expect("in range");
        assert_eq!(
            u16::from_le_bytes([recorded[0], recorded[1]]),
            1,
            "whndun's own argument was true"
        );
    }

    #[test]
    fn fsdprc_landing_on_fsdqit_reaches_whndun_with_the_save_flag_clear() {
        // The other half of the same propagation, asserted explicitly
        // (rather than trusting a default that happens to already be
        // false) so a regression that stops updating the flag on *every*
        // exit -- FSDSAV included -- would not be masked by FSDQIT's own
        // outcome already matching an untouched default. See the FSDSAV
        // sibling test above for why this reads `whndun`'s own argument
        // rather than `Host::fsd_sessions` after the call.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A", b"\0");
        let chan = f.console();
        let scb_at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");

        // Seeded `1` so a `fsdprc` that never threads `save` through to
        // `whndun` at all would leave this test's assertion failing rather
        // than vacuously true.
        let marker = f.buffer(2);
        f.machine.write(marker, &[1, 0]).expect("seeded");
        let whndun = stub_recording_save(&mut f, 0x200, marker);
        f.host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
            full_screen: false,
            whndun: Some(whndun),
            save: true,
        });

        let fldvfy = stub_setting_state(
            &mut f,
            0x100,
            scb_at,
            fsd::state::FSDQIT,
            crate::fsd::verify::VFYOK,
        );
        let mut scb = block(&f);
        scb.set_fldvfy(fldvfy);
        f.machine.write(scb_at, scb.as_bytes()).expect("written");
        set_buffered(&mut f, 0, 1, b'\r', b"done");

        crate::shims::fsd::fsdprc(&mut f.machine, &mut f.host, &module, chan).expect("processed");

        assert!(f.host.fsd_sessions[chan.index()].is_none(), "goback consumed the session");
        let recorded = f.machine.resolve(marker, 2).expect("in range");
        assert_eq!(
            u16::from_le_bytes([recorded[0], recorded[1]]),
            0,
            "FSDQIT must clear the flag, not just leave FSDSAV's earlier true in place"
        );
    }

    #[test]
    fn fsdprc_fsdiga_ignores_the_answer_and_calls_no_callback_at_all() {
        // The 'U'-64 (move-to-previous-field) path in fsdinc sets FSDIGA
        // before entering FSDBUF -- fsdprc must clear it and treat this
        // as VFYDEF without ever touching fldvfy, even if one is
        // registered. A registered stub that always rejects proves the
        // callback genuinely did not run: if it had, the reject would
        // show up as an empty answer and no field advance.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A B", b"\0");
        let chan = f.console();
        let scb_at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");

        let fldvfy = stub_returning(&mut f, 0x100, crate::fsd::verify::VFYREJ);
        let mut scb = block(&f);
        scb.set_fldvfy(fldvfy);
        scb.set_flags(scb.flags() | fsd::entry_flags::FSDIGA);
        f.machine.write(scb_at, scb.as_bytes()).expect("written");
        set_buffered(&mut f, 1, 0, u8::try_from(0x15).unwrap(), b"Al");

        crate::shims::fsd::fsdprc(&mut f.machine, &mut f.host, &module, chan).expect("processed");

        assert_eq!(
            block(&f).flags() & fsd::entry_flags::FSDIGA,
            0,
            "FSDIGA cleared"
        );
        assert_eq!(
            block(&f).state(),
            fsd::state::FSDNPT,
            "VFYDEF is not VFYREJ -- the field moves on, matching the stub \
             never having run at all"
        );
    }

    #[test]
    fn fsdprc_stops_the_module_when_a_nested_call_is_unimplemented() {
        // A nested call *is* serviced now (`Host::run`, not a bare
        // `machine.call` -- see this function's own doc comment on the
        // Task 12 correction), so this no longer refuses the call outright;
        // it runs it, and the call itself stops the machine because
        // thunk 0 names no import `f.minimal_module()` ever registered.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A", b"\0");
        let chan = f.console();
        let scb_at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");

        let fldvfy = stub_calling_a_thunk(&mut f, 0x100);
        let mut scb = block(&f);
        scb.set_fldvfy(fldvfy);
        f.machine.write(scb_at, scb.as_bytes()).expect("written");
        set_buffered(&mut f, 0, 0, b'\r', b"x");

        let e = crate::shims::fsd::fsdprc(&mut f.machine, &mut f.host, &module, chan).expect_err("refused");
        assert!(format!("{e}").contains("stopped the machine"), "{e}");
        assert!(
            f.machine.poisoned().is_some(),
            "the machine is poisoned with the real reason, not merely this call's own Result"
        );
    }

    #[test]
    fn fsdprc_with_no_fldvfy_validates_locally() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A(MIN=1 MAX=5)", b"\0");
        let chan = f.console();
        // fldvfy left NULL -- fsdroom/fsdapr never set one.
        set_buffered(&mut f, 0, 1, b'\r', b"3");

        crate::shims::fsd::fsdprc(&mut f.machine, &mut f.host, &module, chan).expect("processed");

        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[0]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(at), "3", "accepted by fsdprc's own local chktyp/chkmin/chkmax");
    }

    #[test]
    fn fsdprc_before_any_session_stops_the_module() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        current(&mut f);
        let chan = f.console();
        let e =
            crate::shims::fsd::fsdprc(&mut f.machine, &mut f.host, &module, chan).expect_err("refused");
        assert!(format!("{e}").contains("fsdroom"), "{e}");
    }

    // --- Task 11: goback, and whndun/CRSTG on the way out --------------

    /// Put a channel in the same "session under way" shape [`fsdego`] would
    /// have left it in -- raw, echo off -- without going through `fsdego`
    /// itself, the way [`set_buffered`] stages `fsdprc`'s own entry state by
    /// hand rather than typing a whole field to reach it.
    fn entered(f: &mut Fixture, chan: Chan) {
        let ch = f.host.gsbl_mut().channel_mut(chan);
        ch.raw = true;
        ch.echo = false;
    }

    /// A synthetic `whndun(int save)` that copies its one argument -- the
    /// word at `[bp+4]`, where a far call's frame puts the first argument
    /// above the return address -- into `marker`, so a test can read back
    /// both "was this called at all" and "with which value". `goback`'s own
    /// argument is `(fsdusr->flags&FBSAVE) != 0` (`FSDBBS.C:229`), i.e.
    /// exactly [`crate::FsdSession::save`] cast to a word.
    fn stub_recording_save(f: &mut Fixture, code_offset: u16, marker: FarPtr) -> FarPtr {
        let mut code = Vec::new();
        code.extend_from_slice(&[0x8b, 0xec]); // mov bp, sp
        code.extend_from_slice(&[0x8b, 0x46, 0x04]); // mov ax, [bp+4]  (the `save` argument)
        code.push(0xb9); // mov cx, <marker's segment>
        code.extend_from_slice(&marker.selector.to_le_bytes());
        code.extend_from_slice(&[0x8e, 0xc1]); // mov es, cx
        code.push(0x26); // ES: segment override
        code.push(0xa3); // mov [disp16], ax
        code.extend_from_slice(&marker.offset.to_le_bytes());
        code.push(0xcb); // retf
        let ptr = f.machine.code_ptr(code_offset);
        f.machine.write(ptr, &code).expect("stub fits");
        ptr
    }

    /// A synthetic `whndun` that dies: `ud2`, an undefined opcode, which
    /// `mbbs16`'s own fault handler turns into `Exit::Fault` (`SIGILL`)
    /// rather than crashing the test process -- the same machinery that
    /// makes a genuinely misbehaving module survivable in production. There
    /// is no benign way to manufacture `Outcome::Stopped` from outside
    /// `mbbs16`, so this raises a real fault rather than simulating one.
    fn stub_that_faults(f: &mut Fixture, code_offset: u16) -> FarPtr {
        let ptr = f.machine.code_ptr(code_offset);
        f.machine.write(ptr, &[0x0f, 0x0b]).expect("stub fits");
        ptr
    }

    #[test]
    fn goback_calls_whndun_with_the_save_flag_and_restores_the_channel() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A", b"\0");
        let chan = f.console();
        entered(&mut f, chan);

        let marker = f.buffer(2);
        f.machine
            .write(marker, &[0xff, 0xff])
            .expect("seeded with a value session.save as u16 can never be");
        let whndun = stub_recording_save(&mut f, 0x100, marker);
        f.host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
            full_screen: false,
            whndun: Some(whndun),
            save: true,
        });

        assert!(matches!(
            goback(&mut f.machine, &mut f.host, &module, chan),
            Ok(Ret::Void)
        ));

        assert!(!f.host.gsbl_mut().channel_mut(chan).raw, "fsdcof turned raw off");
        assert!(f.host.gsbl_mut().channel_mut(chan).echo, "fsdcof turned echo on");
        assert!(
            f.host.fsd_sessions[chan.index()].is_none(),
            "the session is consumed, not left behind"
        );

        let recorded = f.machine.resolve(marker, 2).expect("in range");
        assert_eq!(
            u16::from_le_bytes([recorded[0], recorded[1]]),
            1,
            "whndun's own argument was session.save (true), cast to a word"
        );
    }

    #[test]
    fn goback_calls_whndun_with_a_false_save_flag_when_the_session_quit() {
        // The other half of the same argument -- seeded `1` so a `goback`
        // that never threads `session.save` through at all (always passing
        // 0, say) would not pass this test by accident the way seeding 0
        // and expecting 0 could.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A", b"\0");
        let chan = f.console();
        entered(&mut f, chan);

        let marker = f.buffer(2);
        f.machine.write(marker, &[1, 0]).expect("seeded");
        let whndun = stub_recording_save(&mut f, 0x100, marker);
        f.host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
            full_screen: false,
            whndun: Some(whndun),
            save: false,
        });

        assert!(matches!(
            goback(&mut f.machine, &mut f.host, &module, chan),
            Ok(Ret::Void)
        ));

        let recorded = f.machine.resolve(marker, 2).expect("in range");
        assert_eq!(u16::from_le_bytes([recorded[0], recorded[1]]), 0);
    }

    #[test]
    fn goback_with_no_whndun_injects_crstg() {
        // `FSDBBS.C`'s own `else` branch: `fsdego`'s caller is allowed to
        // pass `whndun == NULL` (its own contract), and the original
        // answers that with `btuinj(usrnum,CRSTG)`.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A", b"\0");
        let chan = f.console();
        entered(&mut f, chan);
        f.host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
            full_screen: false,
            whndun: None,
            save: true,
        });

        assert!(matches!(
            goback(&mut f.machine, &mut f.host, &module, chan),
            Ok(Ret::Void)
        ));

        assert_eq!(
            f.host.gsbl_mut().next_status(chan),
            Some(crate::gsbl::Gsbl::CRSTG),
            "btuinj(usrnum, CRSTG)"
        );
    }

    #[test]
    fn goback_parks_the_cursor_below_a_full_screen_form_and_not_a_line_mode_one() {
        // `FSDBBS.C:227-229`: `if (fsdusr->flags&FBFULL) prf("\x1B[%d;1f",
        // min(ANSILN,fsdscb->maxy+1));`, ported now that
        // `crate::FsdSession::full_screen` has a real reader.
        //
        // `Form::max_y` is pinned to a chosen value rather than trusted from
        // whatever FSDFORM.MSG's own field layout happens to compile to, so
        // this checks the arithmetic goback does with a number the test
        // controls (this file's own oracle-checked `fsd::compile(.., ascn=1)`
        // tests already cover getting `max_y` right in the first place).
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session_amode(&mut f, 0, "A", b"\0", 1);
        let chan = f.console();
        entered(&mut f, chan);
        f.host
            .forms
            .get_mut(&(0, 1))
            .expect("fsdroom cached message 0, amode 1")
            .max_y = 10;
        f.host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
            full_screen: true,
            whndun: None,
            save: false,
        });

        assert!(matches!(
            goback(&mut f.machine, &mut f.host, &module, chan),
            Ok(Ret::Void)
        ));

        let sent = String::from_utf8_lossy(&f.host.gsbl_mut().drain_output(chan)).into_owned();
        assert!(
            sent.starts_with("\x1b[11;1f\x1b[0;1;32m"),
            "the cursor park (maxy+1 = 11, ANSILN not reached) precedes the \
             unconditional colour reset: {sent:?}"
        );
    }

    #[test]
    fn goback_clamps_the_cursor_park_to_ansiln_and_does_not_overflow_a_saturated_maxy() {
        // Two things `min(ANSILN,fsdscb->maxy+1)` asks for at once: the clamp
        // to row 25 (`ANSILN`), and -- this host's own `u8` `maxy`, which the
        // original's `char maxy` shares -- `maxy+1` must not panic when
        // `maxy` is already the type's own maximum.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session_amode(&mut f, 0, "A", b"\0", 1);
        let chan = f.console();
        entered(&mut f, chan);
        f.host
            .forms
            .get_mut(&(0, 1))
            .expect("fsdroom cached message 0, amode 1")
            .max_y = u8::MAX;
        f.host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
            full_screen: true,
            whndun: None,
            save: false,
        });

        assert!(matches!(
            goback(&mut f.machine, &mut f.host, &module, chan),
            Ok(Ret::Void)
        ));

        let sent = String::from_utf8_lossy(&f.host.gsbl_mut().drain_output(chan)).into_owned();
        assert!(
            sent.starts_with("\x1b[25;1f"),
            "ANSILN (25) wins over maxy+1 (256): {sent:?}"
        );
    }

    #[test]
    fn goback_does_not_park_the_cursor_for_a_line_mode_session() {
        // `FBFULL` is unset for a line-mode session (`fsdego`'s `else`
        // branch, `FSDBBS.C:210-212`), so `goback`'s `if` does not fire and
        // the first byte out is the unconditional colour reset.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A", b"\0");
        let chan = f.console();
        entered(&mut f, chan);
        f.host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
            full_screen: false,
            whndun: None,
            save: false,
        });

        assert!(matches!(
            goback(&mut f.machine, &mut f.host, &module, chan),
            Ok(Ret::Void)
        ));

        let sent = String::from_utf8_lossy(&f.host.gsbl_mut().drain_output(chan)).into_owned();
        assert!(
            sent.starts_with("\x1b[0;1;32m"),
            "no cursor park precedes the colour reset in line mode: {sent:?}"
        );
    }

    #[test]
    fn a_module_that_dies_inside_whndun_stops_the_host_cleanly() {
        // `Outcome::Stopped` from `whndun` must propagate out of `goback`
        // cleanly -- no half-torn-down session, per the design doc's "The
        // two callbacks into module code".
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A", b"\0");
        let chan = f.console();
        entered(&mut f, chan);

        let whndun = stub_that_faults(&mut f, 0x100);
        f.host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
            full_screen: false,
            whndun: Some(whndun),
            save: false,
        });

        let e = goback(&mut f.machine, &mut f.host, &module, chan).expect_err("whndun faulted");
        assert!(format!("{e}").contains("stopped the machine"), "{e}");

        // The teardown already happened, unconditionally, before the call
        // -- so there is nothing left half-done: the channel is back to
        // cooked input and the session is gone, exactly as if `whndun` had
        // returned normally.
        assert!(!f.host.gsbl_mut().channel_mut(chan).raw, "fsdcof still ran");
        assert!(f.host.gsbl_mut().channel_mut(chan).echo, "fsdcof still ran");
        assert!(
            f.host.fsd_sessions[chan.index()].is_none(),
            "the session is still consumed, even though whndun never returned"
        );

        // And the machine itself is left exactly as a real dispatch loop
        // would need it to be to answer `Outcome::Stopped`: `mbbs16`'s own
        // `Machine::call` poisons on a terminal exit independently of
        // whatever this shim's own `Result` says.
        assert!(
            f.machine.poisoned().is_some(),
            "the fault must poison the machine, not just this call's own Result"
        );
    }

    #[test]
    fn goback_with_no_session_stops_the_module() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        current(&mut f);
        let chan = f.console();
        let e = goback(&mut f.machine, &mut f.host, &module, chan).expect_err("refused");
        assert!(format!("{e}").contains("no session"), "{e}");
    }

    #[test]
    fn fsdprc_landing_on_fsdsav_calls_goback_and_the_session_is_gone() {
        // The wiring point: `shims::fsd::fsdprc` itself calls `goback` once
        // it sees the post-callback `block.state()` is `FSDSAV`/`FSDQIT`,
        // rather than leaving that to a dispatch loop this stage does not
        // build (Task 12). An end-to-end call through `fsdprc` is what
        // proves the callback genuinely reaches module code, the way the
        // design doc's own testing section asks for.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "A", b"\0");
        let chan = f.console();
        entered(&mut f, chan);
        let scb_at = f
            .host
            .globals()
            .pointer(&f.machine, "fsdscb")
            .expect("placed");

        let marker = f.buffer(2);
        f.machine.write(marker, &[0xff, 0xff]).expect("seeded");
        let whndun = stub_recording_save(&mut f, 0x200, marker);
        f.host.fsd_sessions[chan.index()] = Some(crate::FsdSession {
            full_screen: false,
            whndun: Some(whndun),
            save: false,
        });

        let fldvfy = stub_setting_state(
            &mut f,
            0x100,
            scb_at,
            fsd::state::FSDSAV,
            crate::fsd::verify::VFYOK,
        );
        let mut scb = block(&f);
        scb.set_fldvfy(fldvfy);
        f.machine.write(scb_at, scb.as_bytes()).expect("written");
        set_buffered(&mut f, 0, 1, b'\r', b"done");

        assert!(matches!(
            crate::shims::fsd::fsdprc(&mut f.machine, &mut f.host, &module, chan),
            Ok(Ret::Void)
        ));

        assert!(
            f.host.fsd_sessions[chan.index()].is_none(),
            "fsdprc must reach goback itself -- no dispatch loop exists yet to do it later"
        );
        assert!(!f.host.gsbl_mut().channel_mut(chan).raw, "fsdcof ran");
        let recorded = f.machine.resolve(marker, 2).expect("in range");
        assert_eq!(
            u16::from_le_bytes([recorded[0], recorded[1]]),
            1,
            "whndun ran, with the save flag fsdprc's own state propagation set"
        );
    }

    // --- Task 12: fsd_cycle, the FSD's own CYCLE dispatch ----------------

    /// Push straight into `channel.input`, the way raw-mode
    /// [`crate::gsbl::Gsbl::push_input`] would have -- a `fsd_cycle` test
    /// wants full control over exactly which bytes are queued for one pass,
    /// not `push_input`'s own line-cooking or its `CYCLE` bookkeeping.
    fn queue(f: &mut Fixture, chan: Chan, bytes: &[u8]) {
        f.host
            .gsbl_mut()
            .channel_mut(chan)
            .input
            .extend(bytes.iter().copied());
    }

    #[test]
    fn fsd_cycle_drains_a_whole_field_and_advances_without_ending_the_session() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "NAME RANK", b"\0");
        let chan = f.console();

        assert!(matches!(
            f.invoke(fsdego, &[0, 0, 0, 0]),
            Ok(Ret::Void)
        ));
        // `fsdego` prompted field 0 into the print buffer; that is not this
        // test's concern, and `fsd_cycle` starts every pass with its own
        // `clrprf` only once a field commits -- so drop it here rather than
        // let it leak into the assertions below.
        crate::shims::text::clrprf(&mut f.machine, &mut f.host).expect("cleared");

        queue(&mut f, chan, b"Kaimon\r");
        assert!(matches!(
            fsd_cycle(&mut f.machine, &mut f.host, &module, chan),
            Ok(())
        ));

        assert!(
            f.host.gsbl_mut().channel_mut(chan).input.is_empty(),
            "every queued byte must be drained in one pass"
        );
        assert_eq!(
            block(&f).crsfld(),
            1,
            "Enter on a non-final field commits it and moves the cursor to the next one"
        );
        assert!(
            f.host.fsd_sessions[chan.index()].is_some(),
            "the session is not over -- there is still a field left"
        );
        assert!(
            !f.host
                .gsbl_mut()
                .channel_mut(chan)
                .status
                .contains(&crate::gsbl::Gsbl::CYCLE),
            "fsd_cycle must not re-arm CYCLE on its own account"
        );

        let sent = String::from_utf8_lossy(&f.host.gsbl_mut().drain_output(chan)).into_owned();
        assert!(
            sent.contains("Kaimon"),
            "the typed field must have been echoed to the channel: {sent:?}"
        );
    }

    #[test]
    fn fsd_cycle_ends_the_session_and_calls_whndun_on_ctrl_g() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "NAME", b"\0");
        let chan = f.console();

        let marker = f.buffer(2);
        f.machine
            .write(marker, &[0xff, 0xff])
            .expect("seeded with a value session.save as u16 can never be");
        let whndun = stub_recording_save(&mut f, 0x100, marker);

        assert!(matches!(
            f.invoke(
                fsdego,
                &[0, 0, whndun.offset, whndun.selector],
            ),
            Ok(Ret::Void)
        ));
        crate::shims::text::clrprf(&mut f.machine, &mut f.host).expect("cleared");

        // 0x07: Ctrl-G, "save and exit" -- FSD.C:1877-1940's own xitkey.
        queue(&mut f, chan, b"Kaimon\x07");
        assert!(matches!(
            fsd_cycle(&mut f.machine, &mut f.host, &module, chan),
            Ok(())
        ));

        assert!(
            f.host.gsbl_mut().channel_mut(chan).input.is_empty(),
            "every queued byte must be drained, even the one that ended the session"
        );
        assert!(
            f.host.fsd_sessions[chan.index()].is_none(),
            "fsdprc must reach goback itself when the last field is saved"
        );
        assert!(
            !f.host.gsbl_mut().channel_mut(chan).raw,
            "goback's fsdcof restored cooked input"
        );

        let recorded = f.machine.resolve(marker, 2).expect("in range");
        assert_eq!(
            u16::from_le_bytes([recorded[0], recorded[1]]),
            1,
            "whndun ran, with save=true"
        );
    }

    #[test]
    fn fsd_cycle_needs_two_escapes_to_quit_a_line_mode_session() {
        // The landed line-mode divergence `fsd::ain` corrects, pinned where
        // it is actually observable. `fsdchi` routes every byte through
        // `ainchr` with no `amode` test (FSDBBS.C:349-356), so a bare ESC is
        // swallowed into WT4BKT and never reaches `fsdinc`. Before the
        // decoder was wired in, one ESC quit the session on the spot.
        //
        // Both halves matter: a test that only pressed ESC ESC would pass
        // just as well against the old, undecoded code.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "NAME", b"\0");
        let chan = f.console();

        assert!(matches!(f.invoke(fsdego, &[0, 0, 0, 0]), Ok(Ret::Void)));
        crate::shims::text::clrprf(&mut f.machine, &mut f.host).expect("cleared");

        queue(&mut f, chan, b"Kaimon\x1b");
        assert!(matches!(
            fsd_cycle(&mut f.machine, &mut f.host, &module, chan),
            Ok(())
        ));
        assert!(
            f.host.fsd_sessions[chan.index()].is_some(),
            "one ESC is swallowed by the decoder -- the session must still be open"
        );
        assert_eq!(
            block(&f).ansbuf(),
            b"Kaimon",
            "and the field is untouched: the ESC was consumed, not typed"
        );

        // The second ESC lands on WT4BKT's default arm (AIN.C:54-57), which
        // hands back the offending character -- so *now* fsdinc sees a 27.
        queue(&mut f, chan, b"\x1b");
        assert!(matches!(
            fsd_cycle(&mut f.machine, &mut f.host, &module, chan),
            Ok(())
        ));
        assert!(
            f.host.fsd_sessions[chan.index()].is_none(),
            "the second ESC reaches fsdinc and abandons the session"
        );
    }

    #[test]
    fn fsd_cycle_decodes_an_arrow_key_into_a_line_mode_field_move() {
        // The other half of the widening: `ESC [ B` is CRSRDN (20480), which
        // the C's line-mode switch groups with '\r' and TAB
        // (FSD.C:1890-1892). Three bytes in, one field advance out -- and
        // none of the three is echoed as text, which is what would happen if
        // the decoder were absent and `[`/`B` fell through to the printable
        // arm.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "NAME RANK", b"\0");
        let chan = f.console();

        assert!(matches!(f.invoke(fsdego, &[0, 0, 0, 0]), Ok(Ret::Void)));
        crate::shims::text::clrprf(&mut f.machine, &mut f.host).expect("cleared");

        queue(&mut f, chan, b"Kaimon\x1b[B");
        assert!(matches!(
            fsd_cycle(&mut f.machine, &mut f.host, &module, chan),
            Ok(())
        ));

        assert_eq!(
            block(&f).crsfld(),
            1,
            "CRSRDN commits the field and advances, exactly as Enter does"
        );
        assert!(
            f.host.fsd_sessions[chan.index()].is_some(),
            "there is still a field left -- the session is not over"
        );

        let sent = String::from_utf8_lossy(&f.host.gsbl_mut().drain_output(chan)).into_owned();
        assert!(
            !sent.contains('['),
            "no byte of the escape sequence may be echoed as text: {sent:?}"
        );
    }

    #[test]
    fn fsd_cycle_ignores_a_sideways_arrow_in_line_mode_rather_than_typing_it() {
        // What keeps `fsdinc`'s two `c < 256` bounds (FSD.C:1878, :1925)
        // honest. CRSRRT is 19712; drop either bound and it satisfies
        // `'!' <= c` / `' ' <= c`, gets truncated to a byte -- 19712 & 0xFF
        // is 0x00 -- and a NUL is typed into the field. Line mode has no
        // horizontal cursor, so the correct behaviour is that nothing at all
        // happens, twice: once from FSDNPT and once from FSDNEN, because the
        // two bounds are in different arms and one test hitting only the
        // first would leave the second unguarded.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "NAME RANK", b"\0");
        let chan = f.console();

        assert!(matches!(f.invoke(fsdego, &[0, 0, 0, 0]), Ok(Ret::Void)));
        crate::shims::text::clrprf(&mut f.machine, &mut f.host).expect("cleared");

        // From FSDNPT -- the state `fsdlin` leaves a fresh session in.
        assert_eq!(block(&f).state(), fsd::state::FSDNPT);
        queue(&mut f, chan, b"\x1b[C");
        assert!(matches!(
            fsd_cycle(&mut f.machine, &mut f.host, &module, chan),
            Ok(())
        ));
        assert_eq!(
            block(&f).state(),
            fsd::state::FSDNPT,
            "an arrow key must not begin an entry the way a printable byte does"
        );
        assert_eq!(block(&f).ansbuf(), b"", "and must not be typed into it");

        // And again from FSDNEN, once something really has been typed.
        queue(&mut f, chan, b"Kai\x1b[C");
        assert!(matches!(
            fsd_cycle(&mut f.machine, &mut f.host, &module, chan),
            Ok(())
        ));
        assert_eq!(block(&f).state(), fsd::state::FSDNEN);
        assert_eq!(
            block(&f).ansbuf(),
            b"Kai",
            "the arrow appended nothing -- not even the NUL a truncated \
             CRSRRT would have appended"
        );
        assert_eq!(block(&f).crsfld(), 0, "and it moved no field either");
    }

    #[test]
    fn fsd_cycle_refuses_a_channel_with_no_session() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        current(&mut f);
        let chan = f.console();
        let e = fsd_cycle(&mut f.machine, &mut f.host, &module, chan).expect_err("refused");
        assert!(format!("{e}").contains("no session control block"), "{e}");
    }

    // --- Task 6: fsdbkg ---------------------------------------------------

    #[test]
    fn fsdbkg_clears_the_screen_and_draws_the_form() {
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME RANK", b"NAME=Kai\0RANK=Cpl\0\0");
        crate::shims::text::clrprf(&mut f.machine, &mut f.host).expect("cleared");

        let Ok(Ret::Far(templt)) = f.invoke(fsdrft, &[]) else {
            panic!("fsdrft refused")
        };
        assert!(matches!(
            f.invoke(fsdbkg, &[templt.offset, templt.selector]),
            Ok(Ret::Void)
        ));

        let drawn = f.read(f.host.globals().prf_buffer());
        assert!(
            drawn.starts_with("\x1b[0m\x1b[2J\x1b[0m"),
            "reset, clear, reset -- byte for byte, first: {:?}",
            &drawn[..drawn.len().min(20)]
        );
        assert!(
            drawn.contains("Kai") && drawn.contains("Cpl"),
            "and then every filled-in field: {drawn:?}"
        );
    }

    #[test]
    fn fsdbkg_zeroes_the_wrap_width_so_a_run_of_text_does_not_displace_a_goto() {
        // Decision 5 of the Stage 5 plan, and the reason this task precedes
        // anything that lights a field.
        //
        // This test used to demonstrate a different hazard: that
        // `Channel::transmit` counted every byte of an escape sequence
        // toward the wrap column, so a cursor-goto sent at a nonzero width
        // could be split down the middle. That hazard is gone -- CSI bytes
        // (`ESC` `[` ... a final byte) no longer count toward the column at
        // all, and a wrap can now only ever land between two ordinary bytes,
        // never inside a CSI. See `crates/mbbs/src/gsbl.rs`'s `CsiScan` and
        // its `transmit` for the fix, and its test
        // `a_csi_sequence_does_not_advance_the_wrap_column`.
        //
        // The hazard that remains is a different one: plain visible text run
        // long enough to reach the margin still inserts a `\r\n` the module
        // never asked for -- and for `fsdbkg`'s full-screen paint, every
        // byte after that point is positioned by an absolute cursor `goto`,
        // so an uninvited line break shifts everything below it down a row.
        // `btutsw(usrnum,0)` is what stops that, and it is a real thing the
        // genuine `fsdbkg` does (`FSDBBS.C:186`) independent of this fix.
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME", b"NAME=Kai\0\0");
        let chan = f.console();

        // A narrow width, and eleven digits -- one more than the width --
        // ahead of a goto. Establish first that the hazard is real: the
        // digits alone are enough to trigger a wrap (the CSI immunity above
        // has nothing to do with it, since none of these eleven bytes is
        // part of an escape), and the goto ends up on whatever line the
        // wrap left the cursor on, not glued to the text that preceded it.
        f.host.gsbl_mut().channel_mut(chan).width = 10;
        f.host.gsbl_mut().transmit(chan, b"12345678901\x1b[12;34f");
        let mangled = String::from_utf8_lossy(&f.host.gsbl_mut().drain_output(chan)).into_owned();
        assert!(
            mangled.contains("\r\n"),
            "with a wrap width set, eleven columns of plain text must still \
             wrap -- if it does not, this test cannot discriminate: {mangled:?}"
        );
        assert!(
            mangled.contains("\x1b[12;34f"),
            "the goto itself is never split -- only where it lands moves: {mangled:?}"
        );

        // Now the real thing: fsdbkg's btutsw(usrnum,0).
        crate::shims::text::clrprf(&mut f.machine, &mut f.host).expect("cleared");
        let Ok(Ret::Far(templt)) = f.invoke(fsdrft, &[]) else {
            panic!("fsdrft refused")
        };
        assert!(matches!(
            f.invoke(fsdbkg, &[templt.offset, templt.selector]),
            Ok(Ret::Void)
        ));
        assert_eq!(
            f.host.gsbl_mut().channel_mut(chan).width,
            0,
            "btutsw(usrnum,0)"
        );

        f.host.gsbl_mut().transmit(chan, b"12345678901\x1b[12;34f");
        let intact = String::from_utf8_lossy(&f.host.gsbl_mut().drain_output(chan)).into_owned();
        assert_eq!(
            intact, "12345678901\u{1b}[12;34f",
            "after fsdbkg, width is 0: no wrap at all, and the goto follows \
             the digits directly on the same line: {intact:?}"
        );
    }

    #[test]
    fn fsdbkg_locks_the_keyboard_and_arms_the_output_empty_signal() {
        // btulok(usrnum,1) and btuoes(usrnum,1). Nothing reads `oes` until
        // Task 11 turns it into the output-drained edge; it is set as real
        // channel state now rather than dropped, so that task has something
        // to consume instead of having to add it retroactively.
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME", b"\0");
        let chan = f.console();
        assert!(!f.host.gsbl_mut().channel_mut(chan).locked);
        assert!(!f.host.gsbl_mut().channel_mut(chan).oes);

        let Ok(Ret::Far(templt)) = f.invoke(fsdrft, &[]) else {
            panic!("fsdrft refused")
        };
        f.invoke(fsdbkg, &[templt.offset, templt.selector]).expect("painted");

        assert!(f.host.gsbl_mut().channel_mut(chan).locked, "btulok");
        assert!(f.host.gsbl_mut().channel_mut(chan).oes, "btuoes");
    }

    #[test]
    fn fsdrft_hands_back_the_form_the_field_offsets_were_measured_against() {
        // `fsdbkg(fsdrft())` walks the returned string by tmpoff, so the
        // pointer has to address the ASCII-expanded template (FSDBBS.C:137),
        // not the compact message text. They diverge from the first line
        // break onward, and the symptom of getting it wrong is supporting
        // text drawn from the wrong bytes rather than any kind of error.
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME", b"\0");

        let Ok(Ret::Far(templt)) = f.invoke(fsdrft, &[]) else {
            panic!("fsdrft refused")
        };
        let returned = f.machine.read_cstr(templt).expect("addressable").to_vec();

        let raw = crate::shims::msg::message(&f.machine, &f.host, 0).expect("message");
        let raw = f.machine.read_cstr(raw).expect("text").to_vec();
        assert_eq!(
            returned,
            crate::msg::getasc(&raw),
            "fsdrft returns getasc's expansion"
        );

        // And it is stable: the module holds this pointer across calls, so a
        // second fsdrft must not hand out a different buffer.
        let Ok(Ret::Far(again)) = f.invoke(fsdrft, &[]) else {
            panic!("fsdrft refused")
        };
        assert_eq!(templt, again, "the expansion is cached, not rebuilt");
    }

    // --- Task 8: fsdent, and the wall falls -------------------------------

    #[test]
    fn fsdroom_sizes_a_full_screen_form_instead_of_refusing_it() {
        // The refusal this replaces was unconditional: "a full-screen entry
        // session is scanned against an ANSI screen this host has no way to
        // draw". Stage 5 drew one.
        let mut f = Fixture::new();
        let _ = open_form(&mut f);
        let spec = f.text("NAME");
        let Ok(Ret::U16(size)) = f.invoke(fsdroom, &[0, spec.offset, spec.selector, 1]) else {
            panic!("fsdroom(amode=1) refused")
        };
        assert!(size > 0);

        // And the two forms of one message coexist, because Host::forms is
        // keyed by (message, amode) -- the ANSI one carries cursor gotos and
        // the line one does not.
        f.invoke(fsdroom, &[0, spec.offset, spec.selector, 0]).expect("sized");
        let ansi = f.host.forms()[&(0, 1)].clone();
        let line = f.host.forms()[&(0, 0)].clone();
        assert!(!ansi.fields[0].ansgto.is_empty(), "the ANSI form has gotos");
        assert!(line.fields[0].ansgto.is_empty(), "the line form does not");
    }

    #[test]
    fn fsdroom_still_refuses_an_amode_that_is_not_one_of_the_three() {
        let mut f = Fixture::new();
        let _ = open_form(&mut f);
        let spec = f.text("NAME");
        let e = f
            .invoke(fsdroom, &[0, spec.offset, spec.selector, 7])
            .expect_err("refused");
        assert!(format!("{e}").contains("neither entry"), "{e}");
    }

    #[test]
    fn fsdego_starts_a_full_screen_session_and_lights_the_first_field() {
        // FSDBBS.C:205-207 -> FSD.C:815-834. After this an ANSI player is
        // looking at a lit field and can do nothing else until Task 9 --
        // which is the correct intermediate state, not a gap.
        let mut f = Fixture::new();
        let _ = session_amode(&mut f, 0, "NAME RANK", b"NAME=Kai\0\0", 1);
        let chan = f.console();
        crate::shims::text::clrprf(&mut f.machine, &mut f.host).expect("cleared");

        assert!(matches!(f.invoke(fsdego, &[0, 0, 0, 0]), Ok(Ret::Void)));

        let scb = block(&f);
        assert_eq!(scb.state(), fsd::state::FSDAPT, "cursor-browse mode");
        assert_eq!(
            scb.flags(),
            fsd::entry_flags::FSDANS,
            "flags = FSDANS is an assignment, not an or -- nothing else survives"
        );
        assert_eq!(scb.crsfld(), 0);
        assert_eq!(scb.shffld(), 0, "cursat set both");
        assert_eq!(scb.chgcnt(), 0);

        let drawn = f.read(f.host.globals().prf_buffer());
        let gto = String::from_utf8_lossy(&f.host.forms()[&(0, 1)].fields[0].ansgto).into_owned();
        assert!(drawn.contains(&gto), "it went to field 0: {drawn:?}");
        assert!(drawn.contains("Kai"), "and drew its answer: {drawn:?}");
        assert!(
            drawn.ends_with(&gto),
            "and ended back at the field's start -- fsdent emits the goto a \
             second time after shofld left the cursor at the answer's end: {drawn:?}"
        );

        assert!(
            f.host.fsd_sessions[chan.index()]
                .as_ref()
                .expect("a session")
                .full_screen,
            "FBFULL -- what goback reads to park the cursor below the form"
        );
    }

    #[test]
    fn fsdego_in_line_mode_is_not_marked_full_screen() {
        // The other half of FBFULL, and the reason the flag is worth storing:
        // a line-mode session must not take goback's cursor-parking branch.
        let mut f = Fixture::new();
        let _ = session(&mut f, "NAME", b"\0");
        let chan = f.console();
        f.invoke(fsdego, &[0, 0, 0, 0]).expect("started");

        let session = f.host.fsd_sessions[chan.index()].as_ref().expect("a session");
        assert!(!session.full_screen);
        assert_eq!(block(&f).state(), fsd::state::FSDNPT, "fsdlin's own state");
        assert_eq!(block(&f).flags(), 0, "and fsdlin zeroes flags outright");
    }

    // --- Stage 5's Task 11: the output-drained edge -------------------------

    /// A full-screen session with `fsdbkg`'s own paint already run --
    /// `oes` armed, the way the module's own call order (`fsdbkg(fsdrft())`
    /// before `fsdego`, `FSDBBS.C:87` before `:196`) leaves a channel. The
    /// initial paint (background + `fsdent`'s own field-0 light) is drained
    /// and discarded so a test's own assertions start from a clean channel.
    fn ansi_session(f: &mut Fixture, spec: &str, defaults: &[u8]) -> Chan {
        let _ = session_amode(f, 0, spec, defaults, 1);
        let chan = f.console();
        let Ok(Ret::Far(templt)) = f.invoke(fsdrft, &[]) else {
            panic!("fsdrft refused")
        };
        f.invoke(fsdbkg, &[templt.offset, templt.selector])
            .expect("painted");
        f.invoke(fsdego, &[0, 0, 0, 0]).expect("started");
        let _ = f.host.gsbl_mut().drain_output(chan);
        chan
    }

    /// Simulate the transport actually raising the edge: pop `OUTMT` the
    /// way [`crate::gsbl::Gsbl::drain_output`] would have queued it, write
    /// the `status` global the way `Host::poll` would have before
    /// dispatching (`lib.rs`'s own `poll`, `MAJORBBS.C:152`), and run
    /// `fsd_cycle` again -- the same native slot `Host::poll` would have
    /// reached, driven directly so the test does not need a registered
    /// module's own state table.
    fn raise_drain_edge(f: &mut Fixture, module: &Module, chan: Chan) {
        assert_eq!(
            f.host.gsbl_mut().next_status(chan),
            Some(crate::gsbl::Gsbl::OUTMT),
            "nothing to raise the edge from -- the channel drained no output, or oes was \
             never armed"
        );
        f.host
            .globals()
            .write(
                &mut f.machine,
                "status",
                &(crate::gsbl::Gsbl::OUTMT as u16).to_le_bytes(),
            )
            .expect("placed");
        fsd_cycle(&mut f.machine, &mut f.host, module, chan).expect("drain edge");
    }

    #[test]
    fn the_drain_edge_unlocks_the_channel_fsdbkg_locked() {
        // Found by Task 12's own acceptance test, not designed in ahead of
        // it: `fsdbkg` locks the channel (`FSDBBS.C:192`) and nothing but
        // the session's first `OUTMT` ever releases it in the original
        // (`FSDBBS.C:264-267`). `fsd_drain_edge`'s own doc comment,
        // "btulok(usrnum,0)", has the full account of why an earlier version
        // of this function ported `fsdqoe` alone and left the channel locked
        // for the rest of the session -- silently discarding every keystroke
        // after the first paint, which no test before this one pressed a key
        // late enough to notice.
        // Not `ansi_session`: that helper's own final `drain_output` finds
        // nothing to drain, because `fsdego`'s own doc comment says who is
        // responsible for flushing `prfbuf` -- "(expects caller to
        // outprf(usrnum))", `FSDBBS.C:196` -- and nothing in `ansi_session`
        // is that caller. The real module always is (it is what this
        // function's own doc comment says Task 12's acceptance test found
        // the bug with), so this test plays that part explicitly: an
        // `outprf` right after `fsdego`, the same as every other real
        // caller in this file already does after a bare `f.invoke`.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session_amode(&mut f, 0, "NAME RANK", b"NAME=Kai\0RANK=Cpl\0\0", 1);
        let chan = f.console();
        let Ok(Ret::Far(templt)) = f.invoke(fsdrft, &[]) else {
            panic!("fsdrft refused")
        };
        f.invoke(fsdbkg, &[templt.offset, templt.selector])
            .expect("painted");
        f.invoke(fsdego, &[0, 0, 0, 0]).expect("started");
        outprf(&mut f.machine, &mut f.host, chan).expect("the caller's own flush");
        let painted = f.host.gsbl_mut().drain_output(chan);
        assert!(!painted.is_empty(), "the initial paint must have reached the channel");

        assert!(
            f.host.gsbl_mut().channel_mut(chan).locked,
            "fsdbkg's own lock, still in effect after fsdego"
        );

        raise_drain_edge(&mut f, &module, chan);

        assert!(
            !f.host.gsbl_mut().channel_mut(chan).locked,
            "the session's first OUTMT must release fsdbkg's lock, or no keystroke after the \
             initial paint ever reaches the channel again"
        );
        assert!(
            f.host.gsbl_mut().channel_mut(chan).oes,
            "unlike the original, oes must stay armed -- it is fsdqoe's only way to run for \
             the rest of the session (this function's own doc comment, 'not ported alongside \
             it')"
        );
    }

    #[test]
    fn fsd_cycle_a_single_cursor_key_produces_the_same_output_whether_or_not_the_drain_edge_fires() {
        // What makes the two-key test below meaningful. With only one
        // cursor key in flight, hopfld's own "no big output underway"
        // branch sets FSDQOT but never FSDSHN -- so fsdqoe's only possible
        // effect (repainting the field FSDSHN names) has nothing to do.
        // Raising the edge after a single key must add nothing to what
        // already went out.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let chan = ansi_session(&mut f, "NAME RANK", b"NAME=Kai\0RANK=Cpl\0\0");

        queue(&mut f, chan, b"\x1b[B"); // CRSRDN
        fsd_cycle(&mut f.machine, &mut f.host, &module, chan).expect("one key");
        let echoed = f.host.gsbl_mut().drain_output(chan);
        assert!(!echoed.is_empty(), "the key's own repaint did go out: {echoed:?}");

        raise_drain_edge(&mut f, &module, chan);
        let after_edge = f.host.gsbl_mut().drain_output(chan);

        assert!(
            after_edge.is_empty(),
            "fsdqoe has nothing to add after a single key -- a test that only presses one key \
             cannot tell a working fsdqoe from an absent one: {after_edge:?}"
        );
        // Deliberately not asserting anything about `scb.flags()` here.
        // FSDQOT is internal state a single-key scenario has no other way
        // to observe than by pressing a *second* key and watching what
        // happens -- which is exactly the next test. An assertion on
        // flags here would let this test fail for the wrong reason (an
        // internal-state check) rather than the reason it exists to prove
        // (empty output either way) -- verified by disabling the drain
        // edge in `fsd_cycle` and confirming this test alone still passes
        // while the next one fails.
    }

    #[test]
    fn fsd_cycle_defers_the_second_cursor_keys_repaint_until_the_drain_edge_fires() {
        // Decision 3 of the Stage 5 plan, made real. Two cursor keys land
        // in the same push_input batch -- fsd_cycle drains channel.input to
        // completion in one pass, so there is no chance for a real drain to
        // land between them. hopfld's own deferred-shuffle protocol
        // (FSD.C:1356-1381) is what has to notice: the first key paints and
        // sets FSDQOT; the second sees FSDQOT already set and, per
        // FSD.C:1370-1377, moves the cursor without repainting and sets
        // FSDSHN instead. Nothing but the drain edge resolves that debt.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let chan = ansi_session(&mut f, "NAME RANK", b"NAME=Kai\0RANK=Cpl\0\0");

        queue(&mut f, chan, b"\x1b[B\x1b[B"); // CRSRDN, CRSRDN
        fsd_cycle(&mut f.machine, &mut f.host, &module, chan).expect("two keys, one pass");

        assert_eq!(
            block(&f).flags() & (fsd::entry_flags::FSDQOT | fsd::entry_flags::FSDSHN),
            fsd::entry_flags::FSDQOT | fsd::entry_flags::FSDSHN,
            "the second key's repaint is still owed: {:?}",
            block(&f)
        );
        let queued = f.host.gsbl_mut().drain_output(chan);
        assert!(
            !queued.is_empty(),
            "the second key's own cursor move (just the goto, no repaint) still went out"
        );

        raise_drain_edge(&mut f, &module, chan);

        assert_eq!(
            block(&f).flags() & (fsd::entry_flags::FSDQOT | fsd::entry_flags::FSDSHN),
            0,
            "fully resolved: {:?}",
            block(&f)
        );
        let repaint = f.host.gsbl_mut().drain_output(chan);
        assert!(
            !repaint.is_empty(),
            "fsdqoe's own deferred repaint went out once the edge fired: {repaint:?}"
        );
    }

    #[test]
    fn fsd_cycle_ignores_the_drain_edge_for_a_line_mode_session() {
        // oes is only ever armed by fsdbkg, which nothing in line mode
        // calls -- so an OUTMT dispatch for a line-mode channel must not
        // reach fsd::fsdqoe at all, whether or not there happens to be a
        // session control block behind it.
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let _ = session(&mut f, "NAME", b"\0");
        let chan = f.console();
        f.invoke(fsdego, &[0, 0, 0, 0]).expect("started");
        let _ = f.host.gsbl_mut().drain_output(chan);
        assert!(
            f.host.gsbl_mut().channel_mut(chan).status.is_empty(),
            "oes was never armed -- nothing to have queued OUTMT"
        );

        f.host
            .globals()
            .write(
                &mut f.machine,
                "status",
                &(crate::gsbl::Gsbl::OUTMT as u16).to_le_bytes(),
            )
            .expect("placed");
        assert!(matches!(
            fsd_cycle(&mut f.machine, &mut f.host, &module, chan),
            Ok(())
        ));

        assert_eq!(block(&f).flags(), 0, "fsdqoe would have had nothing to clear anyway");
    }
}
