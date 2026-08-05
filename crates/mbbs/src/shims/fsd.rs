//! Full-Screen Data Entry: sizing a form the host cannot yet run.

use mbbs16::{FarPtr, Machine, Ret};

use crate::Host;
use crate::fsd::{self, MBPMAX};
use crate::globals::OUTBSZ;
use crate::shims::ShimError;

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
