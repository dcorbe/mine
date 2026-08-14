//! A Win32 Thread Information Block, because `DllMain` reads through `FS:[4]`
//! before it does anything else.
//!
//! This exists because of a disassembly, not a specification. `DllMain` at
//! `0x401000` in `wccmmud.dll` does:
//!
//!
//! -- part of Borland's stack-limit setup. `FS` therefore has to name a real
//! Thread Information Block whose `StackBase` points at genuinely mapped,
//! readable memory: a plausible-looking constant faults on the third
//! instruction, not the first. See `docs/plans/2026-08-08-mbbs32-design.md`,
//! "The module needs a Win32 TIB, and dereferences through it".
//!
//! # One LDT entry, not `arch_prctl`
//!
//! Two ways exist to give a 32-bit excursion an `FS` that names real memory.
//! `arch_prctl(ARCH_SET_FS)` is cheaper but sets the *same* hidden base the
//! host thread's own glibc TLS depends on (see `crate::m32::asm`'s module doc
//! comment for how easy that is to get wrong even when nothing obviously
//! touches it), so using it for the module's `FS` would mean saving and
//! restoring glibc's own pointer around every crossing on top of whatever
//! `crate::m32::asm::enter` already does for the *host's* side of that problem.
//!
//! An LDT descriptor sidesteps it entirely: the module's `FS` gets a real
//! selector naming a real descriptor, `crate::m32::asm::enter` still saves and
//! restores the *host's* `FS_BASE` around the crossing regardless of what the
//! module's `FS` selector is, and the two concerns never touch. One
//! descriptor per [`Tib`] is the entire LDT footprint this module has -- against
//! 3,576 for a single 16-bit MajorMUD instance in `crate::m16`.
//!
//! # The LDT entry number comes from [`crate::ldt`], not a private allocator
//!
//! This module needs neither `crate::m16::seg`'s tiling nor its 82-descriptors-
//! per-load scale -- one [`Tib`] is one entry -- but the entry *number* still
//! has to come from a free list every ABI in the process shares, because the
//! LDT itself is one 8,192-entry kernel table regardless of how many ABIs
//! carve descriptors out of it. An earlier version of this file drew from a
//! bitmap private to this module instead, on the theory that nothing yet ran
//! both ABIs in one process -- and said so, in so many words, right here.
//! That day arrived building `crates/mbbs-fault`: a test that constructed a
//! `crate::m16::Machine` and then a `crate::m32::Machine` found this module's
//! `Tib::new` silently reserve the same entry 0 the 16-bit machine's code
//! segment already owned, overwrite its descriptor, and fault the very first
//! far jump into the module before it ran a single instruction. No amount of
//! fault-handler arbitration could have caught that: the module's memory was
//! gone before anything reached a signal at all. See `crate::ldt`'s module
//! comment for the shared free list this module now draws from instead, and
//! what stayed here: `modify_ldt`'s bitfield encoding and everything about
//! what a *reserved* entry's descriptor contains (`seg_32bit` set, unlike
//! `crate::m16::seg::describe`'s data segments).

use std::io;

use crate::m32::map::Mapping;

/// `modify_ldt(2)` function code for writing an entry.
const LDT_WRITE: i32 = 1;

/// `struct user_desc`, with the kernel's bitfield word spelled out -- the same
/// layout `crates/mbbs-machine/src/m16/seg.rs::UserDesc` documents.
#[repr(C)]
struct UserDesc {
    entry_number: u32,
    base_addr: u32,
    limit: u32,
    flags: u32,
}

/// Segment contents: data, per `struct user_desc`'s encoding. A TIB is data,
/// never code.
const CONTENTS_DATA: u32 = 0;

/// Layout of `UserDesc::flags`: `seg_32bit:1, contents:2, read_exec_only:1,
/// limit_in_pages:1, seg_not_present:1, useable:1`.
const F_SEG_32BIT: u32 = 1;
const CONTENTS_SHIFT: u32 = 1;
const F_SEG_NOT_PRESENT: u32 = 1 << 5;
const F_USEABLE: u32 = 1 << 6;

/// Reserve one free LDT entry, from [`crate::ldt`]'s process-wide free list --
/// see this file's module comment.
fn take_one() -> io::Result<u32> {
    crate::ldt::take_run(1)
}

/// Hand one entry back.
fn give_one(entry: u32) {
    crate::ldt::give_run(entry, 1);
}

/// Write `desc` into the LDT.
fn write_ldt(desc: &UserDesc) -> io::Result<()> {
    // SAFETY: `desc` is a correctly shaped `user_desc` living for the call,
    // which copies it; `size_of::<UserDesc>()` is exactly what the kernel
    // expects to read.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_modify_ldt,
            LDT_WRITE,
            std::ptr::from_ref(desc),
            size_of::<UserDesc>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Make an LDT entry name nothing at all -- the exact shape the kernel's
/// `LDT_empty()` recognises, matching `crate::m16::seg::clear_ldt_entry`.
fn clear_ldt_entry(entry: u32) -> io::Result<()> {
    write_ldt(&UserDesc {
        entry_number: entry,
        base_addr: 0,
        limit: 0,
        flags: (1 << 3) | F_SEG_NOT_PRESENT, // read_exec_only | seg_not_present
    })
}

/// Point LDT `entry` at `len` bytes of memory starting at `base`, as a
/// **32-bit** data segment -- `seg_32bit` set, which is the one bit
/// `crate::m16::seg::describe` deliberately leaves clear.
fn describe(entry: u32, base: *const u8, len: usize) -> io::Result<()> {
    write_ldt(&UserDesc {
        entry_number: entry,
        base_addr: base as usize as u32,
        limit: (len - 1) as u32,
        flags: F_SEG_32BIT | (CONTENTS_DATA << CONTENTS_SHIFT) | F_USEABLE,
    })
}

/// The selector naming `entry`: index in bits 3..15, `TI` set to select the
/// LDT, `RPL` 3 -- the same encoding `crate::m16::seg::Segment::selector` uses.
fn selector_for(entry: u32) -> u16 {
    ((entry as u16) << 3) | 0x7
}

/// Default stack size for a [`Tib`]'s own stack mapping: 1 MiB, the same
/// figure Windows NT used as a default thread stack commit.  There is no
/// measurement behind this number yet -- nothing through Task 15 runs enough
/// of `wccmmud.dll` to know how deep its own stack usage goes -- so treat it
/// as a placeholder a later increment is free to revisit, not a fact.
pub(crate) const DEFAULT_STACK_LEN: usize = 1 << 20;

/// Offsets into the TIB structure this crate actually sets. Named, not
/// literal, at every write site below -- everywhere else in this crate offsets
/// are derived with `offset_of!`, but there is no `#[repr(C)] struct` for a
/// Win32 TIB to hang that off: only four of its fields are ever written, and
/// the rest is left at the zero anonymous `mmap` already provides.
mod tib_offset {
    /// The head of the SEH exception-handler chain. `0xffff_ffff` means empty.
    pub(super) const EXCEPTION_LIST: usize = 0x00;
    /// The high end of the stack -- where it starts, growing down.
    pub(super) const STACK_BASE: usize = 0x04;
    /// The low end of the stack -- the last valid address.
    pub(super) const STACK_LIMIT: usize = 0x08;
    /// The TIB's own linear address, so code that has a pointer into the
    /// middle of it (or wants to hand `FS:[0x18]` to something) can recover
    /// the whole structure.
    pub(super) const SELF: usize = 0x18;
}

/// An empty SEH chain: no handler is registered, which is the truth for
/// anything this crate enters directly.
const EMPTY_SEH_CHAIN: u32 = 0xffff_ffff;

/// A module's stack and Win32 [`Tib`], with one LDT entry describing the TIB
/// as a 32-bit data segment that `FS` can be pointed at.
///
/// Both the stack and the TIB itself are separate [`Mapping`]s below 4 GiB --
/// separate because nothing requires them to be adjacent, and a `DllMain`
/// that walks past the end of one must not find the bytes of the other.
pub(crate) struct Tib {
    // Never read back through Rust: this mapping's bytes are read by the CPU
    // through `FS:`-relative addressing during a crossing, which is invisible
    // to the compiler's dead-code analysis. Held for ownership -- so the
    // mapping stays live for as long as this `Tib` does, and so `Drop`
    // unmaps it -- not for its contents.
    #[allow(dead_code)]
    tib: Mapping,
    /// The module's own stack.
    ///
    /// `Option` because ownership of this mapping *moves*, once, into
    /// `crate::m32::Memory` -- see [`Tib::take_stack`]. The addresses in the
    /// TIB structure above are written at construction and stay correct
    /// across that move: an `mmap` region does not change address when the
    /// Rust value owning it does.
    stack: Option<Mapping>,
    /// The stack's low end, kept as a number so that it survives
    /// [`Tib::take_stack`] -- `Machine::call` needs it to set `ESP` long
    /// after the mapping itself has moved out.
    stack_limit: u32,
    /// The stack's high end, kept for the same reason.
    stack_base: u32,
    entry: u32,
}

impl Tib {
    /// Build a `stack_len`-byte stack and a TIB describing it, and reserve the
    /// one LDT entry `FS` must be loaded with to reach it.
    ///
    /// # Errors
    ///
    /// If either mapping cannot be made, or if this crate's LDT free list (see
    /// the module doc comment) has nothing left.
    pub(crate) fn new(stack_len: usize) -> io::Result<Self> {
        let stack = Mapping::new(stack_len)?;
        let mut tib = Mapping::new(4096)?;

        let stack_base = stack.base() as usize as u32;
        let stack_top = stack_base
            .checked_add(stack.len() as u32)
            .expect("a below-4GiB mapping's own extent must fit in u32");
        let tib_self = tib.base() as usize as u32;

        let dst = tib.as_mut_slice();
        dst[tib_offset::EXCEPTION_LIST..tib_offset::EXCEPTION_LIST + 4]
            .copy_from_slice(&EMPTY_SEH_CHAIN.to_le_bytes());
        dst[tib_offset::STACK_BASE..tib_offset::STACK_BASE + 4]
            .copy_from_slice(&stack_top.to_le_bytes());
        dst[tib_offset::STACK_LIMIT..tib_offset::STACK_LIMIT + 4]
            .copy_from_slice(&stack_base.to_le_bytes());
        dst[tib_offset::SELF..tib_offset::SELF + 4].copy_from_slice(&tib_self.to_le_bytes());
        // Everything else -- including the 592 bytes or so a real Win32 TEB
        // has beyond what this crate ever reads -- is left exactly as a fresh
        // anonymous mapping already made it: zero. See the module doc
        // comment on `crate::m32::pe`'s parsing side for the same principle: code
        // that sets a field nothing here needs is untested pretending to be a
        // feature.

        let entry = take_one()?;
        if let Err(e) = describe(entry, tib.base(), tib.len()) {
            give_one(entry);
            return Err(e);
        }

        Ok(Self {
            tib,
            stack: Some(stack),
            stack_limit: stack_base,
            stack_base: stack_top,
            entry,
        })
    }

    /// The `FS` selector to load before entering 32-bit code that expects
    /// this TIB -- [`crate::m32::asm::Ctx::fs`].
    pub(crate) fn fs_selector(&self) -> u16 {
        selector_for(self.entry)
    }

    /// The stack's high end -- what `+0x04 StackBase` holds.
    pub(crate) fn stack_base(&self) -> u32 {
        self.stack_base
    }

    /// Hand the stack mapping to whoever will own it from now on.
    ///
    /// `crate::m32::Memory` is that owner: a stack address is a linear
    /// address like any other, and a module passing a pointer to one of its
    /// own locals -- `char buf[128]; fgets(buf, sizeof buf, f);` -- expects
    /// the host to be able to read and write it. `Memory` resolves every
    /// linear address the module can name, so the stack has to be one of the
    /// mappings it owns rather than a third one hidden in here.
    ///
    /// Moved rather than shared. Two owners of one mapping would mean two
    /// live `&mut [u8]` into the same bytes, which is exactly the aliasing
    /// this crate must not have; and `Tib` never needed the *contents*, only
    /// the two addresses, which are kept as numbers above.
    ///
    /// `None` on the second call: the mapping is already somewhere else.
    /// Put a stack mapping back after [`Tib::take_stack`] borrowed it out.
    ///
    /// Used by `Machine::call`/`resume`'s self-owned convenience forms,
    /// which take the mapping out for the duration of a crossing so that the
    /// stack slice and `&mut self` are not two borrows of the same object,
    /// then hand it straight back.
    pub(crate) fn put_stack(&mut self, stack: Mapping) {
        self.stack = Some(stack);
    }

    pub(crate) fn take_stack(&mut self) -> Option<Mapping> {
        self.stack.take()
    }

    /// The stack's low end -- what `+0x08 StackLimit` holds.
    pub(crate) fn stack_limit(&self) -> u32 {
        self.stack_limit
    }

    /// The stack's contents, writable -- for planting words below `StackBase`
    /// a test (or, eventually, a real entry) expects to read back.
    pub(crate) fn stack_mut(&mut self) -> &mut [u8] {
        self.stack
            .as_mut()
            .expect("the stack mapping has moved to `Memory`")
            .as_mut_slice()
    }

    /// The stack's contents, read-only -- for [`Machine::arg_u32`] to read a
    /// cdecl argument back off an outstanding call's frame without needing
    /// `&mut self` (`crates/mbbs-machine/src/m32/mod.rs`, near `resume`).
    pub(crate) fn stack(&self) -> &[u8] {
        self.stack
            .as_ref()
            .expect("the stack mapping has moved to `Memory`")
            .as_slice()
    }
}

impl Drop for Tib {
    fn drop(&mut self) {
        // Descriptor first, same reasoning as `crate::m16::seg::Segment::drop`: a
        // live descriptor over a mapping that is about to be unmapped is a
        // selector naming memory that no longer exists, and a failed clear
        // leaks both on purpose rather than dangling either.
        clear_ldt_entry(self.entry)
            .expect("could not clear this Tib's LDT entry; leaking its mappings rather than dangling it");
        give_one(self.entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m32::asm::{Ctx, USER32_CS, current_cs, enter, trampoline};

    /// Assemble literally the three instructions `DllMain` executes at
    /// `0x401000` before anything else -- `mov edx, fs:[4]`; `mov eax,
    /// [edx-8]`; `mov eax, [edx-4]` -- followed by a far jump back, and enter
    /// it against a real [`Tib`]. Design doc: "the module needs a Win32 TIB,
    /// and dereferences through it".
    fn dllmain_prologue_read() -> Vec<u8> {
        vec![
            0x64, 0x8b, 0x15, 0x04, 0x00, 0x00, 0x00, // mov edx, fs:[4]
            0x8b, 0x42, 0xf8, // mov eax, [edx-8]
            0x8b, 0x42, 0xfc, // mov eax, [edx-4]
        ]
    }

    #[test]
    fn a_module_can_read_through_fs_the_way_dllmain_does() {
        let mut tib = Tib::new(DEFAULT_STACK_LEN).expect("a Tib");

        // Plant two distinct, recognisable words below StackBase -- exactly
        // where DllMain's `[edx-8]` and `[edx-4]` land.
        const BELOW_8: u32 = 0xcafe_babe;
        const BELOW_4: u32 = 0xdead_beef;
        let stack_len = tib.stack_mut().len();
        tib.stack_mut()[stack_len - 8..stack_len - 4].copy_from_slice(&BELOW_8.to_le_bytes());
        tib.stack_mut()[stack_len - 4..stack_len].copy_from_slice(&BELOW_4.to_le_bytes());

        let mut mapping = Mapping::new(4096).expect("a low mapping");
        let tramp_addr = mapping.base() as usize as u32;
        let tramp = trampoline();
        let tramp_len = tramp.len();
        let code_off = tramp_len.div_ceil(16) * 16;

        let mut code = dllmain_prologue_read();
        code.push(0xea); // ljmp ptr16:32
        code.extend_from_slice(&tramp_addr.to_le_bytes());
        code.extend_from_slice(&current_cs().to_le_bytes());

        let dst = mapping.as_mut_slice();
        dst[..tramp_len].copy_from_slice(tramp);
        dst[code_off..code_off + code.len()].copy_from_slice(&code);
        let code_addr = tramp_addr + code_off as u32;

        let mut ctx = Ctx {
            target_offset: code_addr,
            target_selector: USER32_CS,
            fs: tib.fs_selector(),
            esp: tib.stack_base() - 0x100, // never touched by this code
            ..Default::default()
        };
        assert_eq!(
            tib.stack_base() - tib.stack_limit(),
            DEFAULT_STACK_LEN as u32,
            "StackBase and StackLimit do not bracket the stack this Tib actually mapped"
        );

        // SAFETY: `code_addr` names the freshly written instructions above,
        // mapped read/write/execute below 4 GiB; `tib.fs_selector()` names a
        // live LDT descriptor over `tib`'s own mapping; both mappings outlive
        // this call.
        unsafe { enter(&mut ctx) };

        assert_eq!(
            ctx.out_edx,
            tib.stack_base(),
            "FS:[4] did not resolve to this Tib's StackBase"
        );
        assert_eq!(
            ctx.out_eax, BELOW_4,
            "the word planted at StackBase-4 did not come back -- not a fault, but not \
             the right answer either"
        );
    }
}
