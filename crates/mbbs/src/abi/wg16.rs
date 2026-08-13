//! `Wg16`: the Borland huge-model 16-bit cdecl ABI Galacticomm's own
//! MajorBBS/Worldgroup modules were compiled for.
//!
//! The first [`Abi`] implementation, split out of `abi.rs` once `abi/wg32.rs`
//! existed beside it and there was no longer a reason for one of the two
//! implementations to live in the same file as the trait it implements. See
//! that file's own module doc comment for the two compile-time collisions
//! building the *second* implementation surfaced -- both were fixed by
//! changing shapes this module already commits to (`Ptr: ModulePtr<Memory =
//! Self::Mem>`, `Abi::mem` as a reborrow rather than a second field), so
//! nothing here changed to accommodate them.

use super::{Abi, Arg, Exit, ModuleMem, Ret};

/// The ABI Galacticomm's 16-bit modules were compiled for: Borland huge
/// model, `seg:off` pointers, cdecl with ten callee-cleaned exceptions (see
/// `Cleans::Callee` in `crates/mbbs/src/shims/mod.rs`).
pub struct Wg16;

impl Abi for Wg16 {
    type Ptr = mbbs_machine::m16::FarPtr;
    type Mem = mbbs_machine::m16::Segments;
    type Cpu = mbbs_machine::m16::Machine;
    type Int = u16;

    const PTR_WIDTH: usize = 4;
    const INT_WIDTH: usize = 2;
    const LONG_WIDTH: usize = 4;

    fn ptr_from_bytes(bytes: &[u8]) -> Self::Ptr {
        mbbs_machine::m16::FarPtr::from_bytes(bytes.try_into().expect("PTR_WIDTH bytes"))
    }

    fn ptr_to_bytes(ptr: Self::Ptr) -> Vec<u8> {
        ptr.to_bytes().to_vec()
    }

    fn int_from_bytes(bytes: &[u8]) -> Self::Int {
        u16::from_le_bytes(bytes.try_into().expect("INT_WIDTH bytes"))
    }

    fn long_from_bytes(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes.try_into().expect("LONG_WIDTH bytes"))
    }

    fn ptr_offset(base: Self::Ptr, delta: u16) -> Self::Ptr {
        mbbs_machine::m16::FarPtr {
            offset: base.offset + delta,
            selector: base.selector,
        }
    }

    fn ptr_checked_add(base: Self::Ptr, by: usize) -> Option<Self::Ptr> {
        let by = u16::try_from(by).ok()?;
        let offset = base.offset.checked_add(by)?;
        Some(mbbs_machine::m16::FarPtr {
            offset,
            selector: base.selector,
        })
    }

    fn null_ptr() -> Self::Ptr {
        mbbs_machine::m16::FarPtr::NULL
    }

    /// `Machine::mem_mut` is the one deliberate exception Task 1's facade
    /// left: every other memory method is a narrow delegation (`resolve`,
    /// `read_cstr`, `write`, ...), but reaching `Segments` generically means
    /// handing back the field itself, not one more method that reads through
    /// it. See `Machine::mem_mut`'s own doc comment.
    fn mem(cpu: &mut Self::Cpu) -> &mut Self::Mem {
        cpu.mem_mut()
    }

    fn data_ptr(cpu: &Self::Cpu) -> Self::Ptr {
        mbbs_machine::m16::FarPtr {
            offset: 0,
            selector: cpu.data_selector(),
        }
    }

    /// The second door, opened: `Wg16` is the one `Abi` with routines behind
    /// it. See [`Abi::native`]'s own doc comment for what the ten are and why
    /// they are here rather than in the shared table; the table itself lives
    /// in `shims::mod`, not this file.
    fn native(dll: &str, symbol: &str) -> Option<(crate::shims::Shim<Self>, crate::shims::Cleans)> {
        crate::shims::wg16_native(dll, symbol)
    }

    type Poison = mbbs_machine::m16::Poison;

    /// Encode `args` into the words `mbbs_machine::m16::Machine::call` takes,
    /// then delegate.
    ///
    /// The order is the load-bearing detail: `Arg::Ptr` becomes offset word
    /// then selector word, matching [`Abi::ptr_to_bytes`] (`FarPtr::to_bytes`)
    /// and `testing::Fixture::far`, and proven here (not merely stated) by
    /// `arg_ptr_lands_offset_then_selector_in_a_genuine_relayed_frame` below,
    /// which round-trips through a real `lcall`, not a byte array agreeing
    /// with itself. `Arg::Long` splits low word first, high word second --
    /// the same order [`Ret::Long`]'s own conversion (below) reads back.
    fn call(cpu: &mut Self::Cpu, entry: Self::Ptr, args: &[Arg<Self>]) -> std::io::Result<Exit<Self>> {
        let mut words = Vec::with_capacity(args.len() * 2);
        for arg in args {
            match arg {
                Arg::Int(v) => words.push(*v),
                Arg::Long(v) => {
                    words.push(*v as u16);
                    words.push((*v >> 16) as u16);
                }
                Arg::Ptr(p) => {
                    words.push(p.offset);
                    words.push(p.selector);
                }
            }
        }
        let exit = convert_exit(cpu.call(entry, &words)?);
        debug_assert_attributable(&exit, cpu);
        Ok(exit)
    }

    /// `Cleans::Caller` is `Machine::resume`; `Cleans::Callee(bytes)` is
    /// `Machine::resume_cleaning` -- the fold this trait method's own doc
    /// comment describes, with `Wg16` the one `Abi` that actually has
    /// callee-cleaned rows to serve (`shims::runtime`'s `f_*@` family, behind
    /// [`Abi::native`]).
    fn resume(cpu: &mut Self::Cpu, ret: Ret<Self>, cleans: crate::shims::Cleans) -> std::io::Result<Exit<Self>> {
        let ret16: mbbs_machine::m16::Ret = ret.into();
        let raw = match cleans {
            crate::shims::Cleans::Caller => cpu.resume(ret16)?,
            crate::shims::Cleans::Callee(bytes) => cpu.resume_cleaning(ret16, bytes)?,
        };
        let exit = convert_exit(raw);
        debug_assert_attributable(&exit, cpu);
        Ok(exit)
    }

    fn arg_frame(cpu: &Self::Cpu) -> &[u8] {
        cpu.arg_frame()
    }

    fn poison(cpu: &mut Self::Cpu, why: Self::Poison) -> std::io::Result<()> {
        cpu.poison(why)
    }

    fn poisoned(cpu: &Self::Cpu) -> Option<Self::Poison> {
        cpu.poisoned().cloned()
    }

    fn unimplemented(module: String, symbol: String) -> Self::Poison {
        mbbs_machine::m16::Poison::Unimplemented { module, symbol }
    }
}

/// [`mbbs_machine::m16::Exit`] converted to [`Exit<Wg16>`] -- `Fault`/`Timeout`
/// collapse to `Stopped` (see `Exit`'s own doc comment); the machine has
/// already stored the poison behind [`Machine::poisoned`](mbbs_machine::m16::Machine::poisoned)
/// either way.
/// [`Exit::Stopped`] promises the caller can find out *why* by reading
/// [`Abi::poisoned`] -- that is the whole justification for collapsing
/// `Fault` and `Timeout` into one variant (design §2).
///
/// It holds today because `m16::Machine::terminate` sets `poisoned` before
/// returning either terminal `Exit`. But that is a **machine-side
/// convention, not a structural guarantee**: nothing in `Exit`'s type stops
/// a future terminal variant from being added that skips the poisoning
/// step, and if one were, `Stopped` would silently become unattributable
/// and the collapse would start losing information. Prose in the design doc
/// does not prevent that; this does, in debug builds and the whole test
/// suite.
fn debug_assert_attributable(exit: &Exit<Wg16>, cpu: &mbbs_machine::m16::Machine) {
    debug_assert!(
        !matches!(exit, Exit::Stopped) || cpu.poisoned().is_some(),
        "Exit::Stopped with no poison stored: the machine has stopped and \
         cannot say why, so Abi::poisoned cannot recover what the collapse \
         of Fault/Timeout into Stopped discarded"
    );
}

fn convert_exit(exit: mbbs_machine::m16::Exit) -> Exit<Wg16> {
    match exit {
        mbbs_machine::m16::Exit::Call { index } => Exit::Call { index },
        mbbs_machine::m16::Exit::Returned { ax, dx } => Exit::Returned {
            lo: u32::from(ax),
            hi: u32::from(dx),
        },
        mbbs_machine::m16::Exit::Fault { .. } | mbbs_machine::m16::Exit::Timeout { .. } => Exit::Stopped,
    }
}

impl From<Ret<Wg16>> for mbbs_machine::m16::Ret {
    /// The 16-bit boundary conversion this module's doc comment names:
    /// `Machine::resume` still takes `mbbs_machine::m16::Ret`, unchanged, so this is
    /// where a `Ret<Wg16>` a converted shim hands back becomes it.
    ///
    /// `Ptr` maps to `Far` and `Int` maps to `U16` with no repacking --
    /// `Wg16::Ptr` already is `FarPtr` and `Wg16::Int` already is `u16` -- so
    /// there is no width or byte order to get wrong here, only the variant to
    /// pick correctly. `Int`/`Long` both carry a plain integer, which is
    /// exactly the shape a swap between the two would not be caught by the
    /// type checker; the mutation test below is aimed at exactly that.
    fn from(ret: Ret<Wg16>) -> Self {
        match ret {
            Ret::Void => mbbs_machine::m16::Ret::Void,
            Ret::Int(v) => mbbs_machine::m16::Ret::U16(v),
            Ret::Long(v) => mbbs_machine::m16::Ret::U32(v),
            Ret::Ptr(v) => mbbs_machine::m16::Ret::Far(v),
        }
    }
}

impl From<mbbs_machine::m16::Ret> for Ret<Wg16> {
    /// The reverse of the conversion above -- needed once `Wg16::native`
    /// (see this module's `Abi::native`) has to hand a routine that still
    /// answers in `mbbs_machine::m16::Ret` (the ten permanently-16-bit helpers behind
    /// `Wg16`'s door: `runtime.rs`'s `f_*@` family and `memory.rs`'s
    /// `alctile`/`ptrtile`) back to a caller expecting `Ret<Wg16>`, the same
    /// type every other routine behind `entry` answers in. Same variant
    /// mapping as the forward direction, read backwards.
    fn from(ret: mbbs_machine::m16::Ret) -> Self {
        match ret {
            mbbs_machine::m16::Ret::Void => Ret::Void,
            mbbs_machine::m16::Ret::U16(v) => Ret::Int(v),
            mbbs_machine::m16::Ret::U32(v) => Ret::Long(v),
            mbbs_machine::m16::Ret::Far(v) => Ret::Ptr(v),
        }
    }
}

impl ModuleMem for mbbs_machine::m16::Segments {
    type Ptr = mbbs_machine::m16::FarPtr;

    /// One LDT segment, exactly as `Heap::grow` already gets its backing
    /// store today (`crates/mbbs/src/heap.rs:162`) -- this is that call site
    /// named through the trait rather than new behaviour. `alloc_segment`
    /// itself refuses `bytes > 64 KiB`; chaining several regions to serve a
    /// request larger than one segment is `ModuleMem::alloc_region`'s
    /// caller's job, not this one's, per the trait's own doc comment.
    fn alloc_region(&mut self, bytes: usize) -> std::io::Result<Self::Ptr> {
        let selector = self.alloc_segment(bytes)?;
        Ok(mbbs_machine::m16::FarPtr {
            offset: 0,
            selector,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::Call;
    use mbbs_machine::m16::FarPtr;

    /// The proof this type exists for: `Call<Wg16>` built from a *live*
    /// `mbbs_machine::m16::Machine` -- not `abi::tests::FixtureAbi`'s trivial
    /// `Cpu`/`Mem` -- reading a real argument frame `Fixture::call` pushed
    /// with genuine 16-bit code and a genuine `lcall`. See `abi.rs`'s module
    /// doc comment ("`Call` holds one handle, not two") for why this was
    /// previously impossible to write at all: `Call::new` used to take `mem:
    /// &mut A::Mem` as a second field, and `Machine` has no way to hand out
    /// an independent `&mut Segments` alongside `&mut Machine`.
    ///
    /// `CHAR *stzcpy(CHAR *dst, CHAR *src, UINT num)` --
    /// `re/wg33src/INC/GCOMM.H:396-400`, the same prototype `abi.rs`'s own
    /// fixture tests already check, so all three agree on where cdecl leaves
    /// its arguments.
    #[test]
    fn call_reads_a_real_machines_frame_for_stzcpy() {
        let mut f = crate::testing::Fixture::new();
        let dst = f.buffer(16);
        let src = f.text("Newhaven");

        f.call(&[dst.offset, dst.selector, src.offset, src.selector, 5]);

        // Copied out before `Call::new` takes `&mut f.machine` -- `Call`
        // itself does the same copy internally (see abi.rs's "Why `Call`
        // owns its frame"), this just makes the borrow's end visible at the
        // call site too.
        let frame = f.machine.arg_frame().to_vec();

        let mut call = Call::<Wg16>::new(&mut f.machine, &frame);
        assert_eq!(call.ptr(), dst, "byte 0: dst");
        assert_eq!(call.ptr(), src, "byte 4: src");
        assert_eq!(call.int(), 5, "byte 8: num");

        // `Call::mem` is the other half of this task: prove it reborrows the
        // *same* `Segments` the machine actually runs against, not a
        // disconnected copy, by resolving `src` through it and reading back
        // the exact bytes `Fixture::text` wrote before the call.
        let text = call
            .mem()
            .read_cstr(src)
            .expect("src is what Fixture::text wrote")
            .to_vec();
        assert_eq!(text, b"Newhaven");
    }

    /// The four `Ret<Wg16>` variants, converted at the 16-bit boundary. Values
    /// are chosen with a distinct high and low half (`0x1234`, `0x5678`) so a
    /// transposition -- offset and selector swapped, or the `U16`/`U32` halves
    /// swapped -- would be caught rather than accidentally agreeing.
    #[test]
    fn ret_wg16_converts_to_mbbs16_ret_for_all_four_variants() {
        assert_eq!(mbbs_machine::m16::Ret::from(Ret::<Wg16>::Void), mbbs_machine::m16::Ret::Void);
        assert_eq!(
            mbbs_machine::m16::Ret::from(Ret::<Wg16>::Int(0x1234)),
            mbbs_machine::m16::Ret::U16(0x1234)
        );
        assert_eq!(
            mbbs_machine::m16::Ret::from(Ret::<Wg16>::Long(0x1234_5678)),
            mbbs_machine::m16::Ret::U32(0x1234_5678)
        );

        // `Ret::Far`'s own doc comment: "segment in DX, offset in AX" --
        // i.e. `FarPtr::offset` is the low half and `FarPtr::selector` is the
        // high half, the same order a `long`'s `U32` splits. `Ret::Ptr` must
        // carry that pair through unchanged, offset staying offset and
        // selector staying selector, not swapped.
        let ptr = FarPtr {
            offset: 0x5678,
            selector: 0x1234,
        };
        assert_eq!(
            mbbs_machine::m16::Ret::from(Ret::<Wg16>::Ptr(ptr)),
            mbbs_machine::m16::Ret::Far(ptr),
            "offset (AX) and selector (DX) must land unswapped"
        );
    }

    /// The reverse direction: `Ret<A>` has no `PartialEq` (see `abi.rs`'s own
    /// doc comment on why `Debug`/`Clone`/`Copy` are hand-written rather than
    /// derived), so this destructures each variant instead of comparing whole
    /// values -- same discrimination the forward test above uses (distinct
    /// high and low halves), read backwards.
    #[test]
    fn mbbs16_ret_converts_to_ret_wg16_for_all_four_variants() {
        assert!(matches!(Ret::<Wg16>::from(mbbs_machine::m16::Ret::Void), Ret::Void));

        let Ret::Int(v) = Ret::<Wg16>::from(mbbs_machine::m16::Ret::U16(0x1234)) else {
            panic!("U16 must convert to Int");
        };
        assert_eq!(v, 0x1234);

        let Ret::Long(v) = Ret::<Wg16>::from(mbbs_machine::m16::Ret::U32(0x1234_5678)) else {
            panic!("U32 must convert to Long");
        };
        assert_eq!(v, 0x1234_5678);

        let ptr = FarPtr {
            offset: 0x5678,
            selector: 0x1234,
        };
        let Ret::Ptr(v) = Ret::<Wg16>::from(mbbs_machine::m16::Ret::Far(ptr)) else {
            panic!("Far must convert to Ptr");
        };
        assert_eq!(v, ptr, "offset (AX) and selector (DX) must land unswapped");
    }

    /// `Abi::call`'s [`Arg::Ptr`] encode order, proven against a genuine
    /// `lcall` frame rather than a byte array agreeing with itself (design
    /// §6). The entry `Wg16::call` is pointed at does not read its own
    /// arguments and stop there -- it relays them, through real
    /// `push`/`lcall` instructions, into a *second* genuine far call, whose
    /// frame is then read the same way every other test in this crate reads
    /// one: [`mbbs_machine::m16::Machine::arg_frame`].
    ///
    /// Borland's far-function prologue (`push bp; mov bp, sp`) puts the
    /// first argument word at `bp+6` and the second at `bp+8` --
    /// `crates/mbbs-machine/tests/entry.rs`'s own `SUBTRACT_ENTRY` documents
    /// the identical layout. The relay pushes `bp+8` first and `bp+6` last,
    /// mirroring `testing::Fixture::call_with`'s `.rev()` (last-declared-arg-
    /// pushed-first) so the two words land in the new frame in the same
    /// order they arrived in the old one.
    #[test]
    fn arg_ptr_lands_offset_then_selector_in_a_genuine_relayed_frame() {
        fn relay_two_words(thunk: FarPtr) -> Vec<u8> {
            let mut code = vec![
                0x55, // push bp
                0x89, 0xe5, // mov bp, sp
                0x8b, 0x46, 0x08, // mov ax, [bp+8]   (word 1, the 2nd arg)
                0x50, // push ax
                0x8b, 0x46, 0x06, // mov ax, [bp+6]   (word 0, the 1st arg)
                0x50, // push ax
                0x9a, // lcall $cs, $thunk
            ];
            code.extend_from_slice(&thunk.to_bytes());
            code
        }

        let mut machine = mbbs_machine::m16::Machine::new().expect("16-bit machine");
        let thunk = machine.thunk_address(0);
        machine.load_code(&relay_two_words(thunk)).expect("module fits");
        let entry = machine.code_ptr(0);

        let ptr = FarPtr {
            offset: 0x1000,
            selector: 0x0038,
        };
        let exit = Wg16::call(&mut machine, entry, &[Arg::Ptr(ptr)]).expect("called");
        assert!(
            matches!(exit, Exit::Call { index: 0 }),
            "the relay reached thunk 0, got {exit:?}"
        );

        assert_eq!(
            &machine.arg_frame()[0..4],
            ptr.to_bytes().as_slice(),
            "the relayed frame is offset then selector, exactly what Arg::Ptr pushed"
        );
    }

    /// [`Exit::Returned`]'s `lo`/`hi` mapping: `AX` becomes `lo`, `DX`
    /// becomes `hi`. Distinct halves (`0x1234`, `0x5678`), same
    /// discrimination `ret_wg16_converts_to_mbbs16_ret_for_all_four_variants`
    /// above uses, so a swap cannot pass by agreeing with itself.
    #[test]
    fn returned_maps_ax_to_lo_and_dx_to_hi() {
        // `crates/mbbs-machine/tests/entry.rs`'s `LONG_ENTRY`, byte for byte:
        //  0: b8 34 12   mov $0x1234, %ax
        //  3: ba 78 56   mov $0x5678, %dx
        //  6: cb         lret
        let code = vec![0xb8, 0x34, 0x12, 0xba, 0x78, 0x56, 0xcb];
        let mut machine = mbbs_machine::m16::Machine::new().expect("16-bit machine");
        machine.load_code(&code).expect("module fits");
        let entry = machine.code_ptr(0);

        match Wg16::call(&mut machine, entry, &[]).expect("called") {
            Exit::Returned { lo, hi } => {
                assert_eq!(lo, 0x1234, "AX becomes lo");
                assert_eq!(hi, 0x5678, "DX becomes hi");
            }
            other => panic!("expected Exit::Returned, got {other:?}"),
        }
    }

    /// A faulting entry stops as [`Exit::Stopped`], with the reason readable
    /// through [`Abi::poisoned`] afterward -- the collapse `Exit`'s own doc
    /// comment describes ("every caller's next move is identical: read
    /// `Abi::poisoned`").
    #[test]
    fn a_fault_stops_as_exit_stopped_and_poisons_the_machine() {
        // Byte-for-byte `suicidal()` from `crates/mbbs/tests/fault_16_alone.rs`:
        // privileged HLT, so #GP, arriving as SIGSEGV.
        let code = vec![
            0xb8, 0x34, 0x12, // mov $0x1234, %ax
            0xf4, // hlt
        ];
        let mut machine = mbbs_machine::m16::Machine::new().expect("16-bit machine");
        machine.load_code(&code).expect("module fits");
        let entry = machine.code_ptr(0);

        match Wg16::call(&mut machine, entry, &[]).expect("recovered, not fatal") {
            Exit::Stopped => {}
            other => panic!("expected Exit::Stopped, got {other:?}"),
        }

        match Wg16::poisoned(&machine) {
            Some(mbbs_machine::m16::Poison::Fault { .. }) => {}
            other => panic!("expected Some(Fault{{..}}), got {other:?}"),
        }
    }
}
