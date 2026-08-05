//! Full-Screen Data Entry: sizing a form the host cannot yet run.

use mbbs16::{FarPtr, Machine, Ret};

use crate::Host;
use crate::fsd::{self, MBPMAX};
use crate::globals::OUTBSZ;
use crate::shims::{NO, ShimError};

/// This channel's session control block, allocating it on first use.
///
/// `inifsdscb()`, `FSDBBS.C:64`. The real one is
/// `alczer(nterms*sizeof(struct fsdbbs))` out of the *host's* heap; this is a
/// segment of its own, so that a module writing past what it was given cannot
/// reach the globals, and so that the module's heap accounting does not report
/// a host allocation as one of the module's.
///
/// Only the `struct fsdscb` prefix of `struct fsdbbs` is modelled. The rest --
/// the `ainscb`, `curmbk`, `tmpmsg`, `amode`, `flags` and `whndun` members --
/// belongs to the entry session and to `fsdusr`, which no module imports.
fn control_block(machine: &mut Machine, host: &mut Host) -> Result<FarPtr, ShimError> {
    if let Some(at) = host.fsdscb {
        return Ok(at);
    }
    let selector = machine
        .alloc_segment(usize::from(fsd::FSDSCB))
        .map_err(|e| ShimError::Failed(format!("fsdroom: no room for a session block: {e}")))?;
    let at = FarPtr {
        offset: 0,
        selector,
    };
    host.globals()
        .write(machine, "fsdscb", &at.to_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    host.fsdscb = Some(at);
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
fn offset(base: FarPtr, by: u16) -> Result<FarPtr, ShimError> {
    let offset = base
        .offset
        .checked_add(by)
        .ok_or_else(|| ShimError::Failed(format!("fsd: {base} plus {by} leaves the segment")))?;
    Ok(FarPtr {
        offset,
        selector: base.selector,
    })
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
        at = offset(at, len as u16 + 1)?;
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

    if amode == 1 {
        return Err(ShimError::Failed(format!(
            "fsdroom(message {number}, amode=1): a full-screen entry session is \
             scanned against an ANSI screen this host has no way to draw"
        )));
    }
    if amode != 0 && amode != -1 {
        return Err(ShimError::Failed(format!(
            "fsdroom(message {number}): amode {amode} is neither entry (0/1) nor display (-1)"
        )));
    }

    let template = crate::shims::msg::message(machine, host, number)?;
    let template = machine.read_cstr(template)?.to_vec();
    let spec = machine.read_cstr(machine.arg_far(1))?.to_vec();

    // `maxfld`, `FSDBBS.C:130`: the field array and the punctuation array share
    // the output buffer, and the punctuation array gets its MBPMAX first.
    let max_fields = (OUTBSZ - MBPMAX) / fsd::FSDFLD;
    let form = fsd::compile(&template, &spec, max_fields);

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
    let at = control_block(machine, host)?;
    let mut block = read_block(machine, at)?;
    block.set_fldspc(machine.arg_far(1));
    block.set_numfld(form.fields.len() as u16);
    block.set_numtpl(form.in_template as u16);
    block.set_mbleng(form.punctuation.len() as u16);
    block.set_maxans(form.answer_max);
    block.set_hlplen(form.help_len);
    block.set_hlpoff(form.help_at);
    machine.write(at, block.as_bytes())?;

    // `fsdusr->{curmbk,tmpmsg,amode}`, `FSDBBS.C:134`, for `fsdrft` to come
    // back to. The block is read now rather than at `fsdrft` time because the
    // module will have `rstmbk`'d by then -- it does so four instructions after
    // this call, at `seg 3:0x3f86`.
    let block = host
        .globals()
        .pointer(machine, "curmbk")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    host.fsdtmp = Some((block, number, amode));

    host.forms.push(form);
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

    let Some(form) = host.forms.last().cloned() else {
        return Err(ShimError::Failed(
            "fsdapr: no form has been sized, and FSDBBS.H:245 has this called after fsdroom()"
                .into(),
        ));
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

    let at = host
        .fsdscb
        .ok_or_else(|| ShimError::Failed("fsdapr: no session control block".into()))?;
    let mut block = read_block(machine, at)?;
    let spec = machine.read_cstr(block.fldspc())?.to_vec();
    let old = answer_string(machine, defaults)?;
    let installed = fsd::answers(&form, &spec, &old);

    // Punctuation, then the field array, then the answer string: the same three
    // terms, in the same order, that `Form::size` added up.
    let mut bytes = form.punctuation.clone();
    let flddat_at = bytes.len() as u16;
    for (field, (ansoff, anslen)) in form.fields.iter().zip(&installed.offsets) {
        bytes.extend_from_slice(&field.record(*ansoff, *anslen));
    }
    let newans_at = bytes.len() as u16;
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
    let at = host.fsdscb.ok_or_else(|| {
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
    let at = offset(block.flddat(), field * fsd::FSDFLD)?;
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
    Ok(Ret::Far(offset(block.newans(), answer_offset(&record))?))
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
    let answer = machine.read_cstr(offset(block.newans(), ansoff)?)?.to_vec();

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

    let tail_at = ansoff + u16::from(anslen);
    let tail_len = block.allans().saturating_sub(tail_at);
    let tail = machine
        .resolve(offset(block.newans(), tail_at)?, usize::from(tail_len))?
        .to_vec();
    let mut rewritten = canonical.clone();
    rewritten.extend_from_slice(&tail);
    machine.write(offset(block.newans(), ansoff)?, &rewritten)?;

    let mut record = record;
    record[fsd::fld::ANSLEN] = canonical.len() as u8;
    machine.write(offset(block.flddat(), number * fsd::FSDFLD)?, &record)?;

    // `while (efptr != fldptr) { efptr->ansoff += anslen-m; efptr--; }` -- the
    // fields *after* this one, and none before.
    for later in number + 1..block.numfld() {
        let mut record = field_record(machine, &block, later, "fsdord")?;
        let moved = (i32::from(answer_offset(&record)) + grew) as u16;
        record[fsd::fld::ANSOFF..fsd::fld::ANSOFF + 2].copy_from_slice(&moved.to_le_bytes());
        machine.write(offset(block.flddat(), later * fsd::FSDFLD)?, &record)?;
    }

    block.set_allans(allans as u16);
    machine.write(at, block.as_bytes())?;
    Ok(Ret::U16(index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;
    use mbbs16::FarPtr;

    /// Open `SAMPLE.MSG`, which `Fixture` roots on, and make it current.
    fn open(f: &mut Fixture) -> FarPtr {
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
        let expected = crate::fsd::compile(&template, b"ONE TWO", (4096 - 200) / 23)
            .size()
            .expect("fits");

        let args = [0, spec.offset, spec.selector, 0];
        assert!(matches!(f.invoke(fsdroom, &args), Ok(Ret::U16(n)) if n == expected));

        let [form] = f.host.forms() else {
            panic!("expected one form, got {:?}", f.host.forms())
        };
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
        let _ = open_form(f);
        let spec = f.text(spec);
        let Ok(Ret::U16(size)) = f.invoke(fsdroom, &[message, spec.offset, spec.selector, 0])
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
        assert_eq!(scb.numfld(), f.host.forms()[0].fields.len() as u16);
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
    fn fsdnan_before_a_session_stops_the_module() {
        let mut f = Fixture::new();
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
        // The same arithmetic with a negative difference, which the `int`
        // subtraction in `stfans` handles and an unsigned one would not.
        let mut f = Fixture::new();
        let spec = "COLOUR(ALT=Red) NAME";
        let _ = session(&mut f, spec, b"COLOUR=REDDISH\0NAME=Fred\0\0");

        let Ok(Ret::Far(before)) = f.invoke(fsdnan, &[1]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(before), "Fred");

        // "REDDISH" does not begin "Red", so nothing matches and nothing moves.
        assert!(matches!(f.invoke(fsdord, &[0]), Ok(Ret::U16(NO))));

        // "Redd" does not either; "Re" does, and shrinks by five.
        let _ = session(&mut f, spec, b"COLOUR=Re\0NAME=Fred\0\0");
        let Ok(Ret::Far(before)) = f.invoke(fsdnan, &[1]) else {
            panic!("fsdnan refused")
        };
        assert!(matches!(f.invoke(fsdord, &[0]), Ok(Ret::U16(0))));
        let Ok(Ret::Far(at)) = f.invoke(fsdnan, &[1]) else {
            panic!("fsdnan refused")
        };
        assert_eq!(f.read(at), "Fred");
        assert_eq!(at.offset, before.offset + 1, "\"Re\" grew to \"Red\"");
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
            f.host.forms()[0].fields[0].flags & crate::fsd::flags::ALTERNATES != 0,
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
        assert_eq!(block.maxans(), f.host.forms()[0].answer_max);
        assert_eq!(block.mbleng(), f.host.forms()[0].punctuation.len() as u16);
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
    fn a_full_screen_session_is_refused_rather_than_scanned_blind() {
        // `amode=1` scans the template against an ANSI screen to read each
        // field's cursor position off it. There is no screen, and a form whose
        // fields all thought they were at the origin would be worse than none.
        let mut f = Fixture::new();
        let _ = open(&mut f);
        let spec = f.text("ONE");

        let e = f
            .invoke(fsdroom, &[0, spec.offset, spec.selector, 1])
            .expect_err("refused");
        assert!(format!("{e}").contains("ANSI screen"), "{e}");
        assert!(f.host.forms().is_empty());
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
}
