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

use super::{Abi, ModuleMem, Ret};

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
}
