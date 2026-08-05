//! Full-Screen Data Entry: sizing a form the host cannot yet run.

use mbbs16::{Machine, Ret};

use crate::Host;
use crate::fsd::{self, MBPMAX};
use crate::globals::OUTBSZ;
use crate::shims::ShimError;

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
