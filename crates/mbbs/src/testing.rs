//! A machine stopped at a host call, for testing one shim at a time.
//!
//! The arguments are pushed by real 16-bit code rather than planted on the
//! stack, because where cdecl actually leaves them is half of what a shim has
//! to get right. A test that laid them out itself would agree with a shim that
//! read them wrongly.

use std::path::PathBuf;

use mbbs_machine::m16::{Exit, FarPtr, Machine, Ret};

use crate::Host;
use crate::abi::{self, Abi, Call, Wg16, Wg32, Wg32Cpu};
use crate::shims::ShimError;

/// Both of these moved into the `btrieve` crate with the engine, because that
/// crate's own tests are their heaviest users -- `scratch` alone has 86 call
/// sites there against a handful here. Re-exported rather than relocated in
/// this crate's callers, so `crate::testing::scratch` keeps meaning what it
/// always did.
pub use ::btrieve::testing::{make_keys_modifiable, scratch};

/// A machine stopped at a host call, generic over which ABI it stopped
/// under.
///
/// `A` defaults to [`Wg16`], so every one of this crate's existing call
/// sites -- `Fixture::new()`, `let f: Fixture = ...`, `f.machine`, `f.host`
/// -- keeps meaning exactly what it meant before this type gained a
/// parameter: none of them spell a generic argument, so all of them get the
/// default. `impl Fixture<Wg16>` below is the same inherent block this type
/// always had, under a name that says which ABI it is; not one of its
/// methods changed shape.
///
/// `Fixture<Wg32>` is a second, independent inherent block, added once this
/// task needed one. It does not extend the block above -- a real
/// `Wg32Cpu` needs a real `mbbs_machine::m32::Machine`, which arms this
/// thread's fault recovery, and every existing convention in this crate
/// (`crates/mbbs/tests/wg32_abi.rs`'s own module doc comment, `heap.rs`'s
/// test module) keeps that construction out of `cargo test -p mbbs --lib`
/// entirely. `crates/mbbs/src/testing.rs` compiles into that binary, so
/// `Fixture::<Wg32>`'s own constructors are *defined* here (which costs
/// nothing -- a function body does not run until called) but must only ever
/// be *called* from a `crates/mbbs/tests/*.rs` integration binary, never
/// from a `#[cfg(test)]` module inside `src/`. See that new file's own
/// module doc comment for the isolation this preserves.
///
/// Every `Fixture<Wg32>` method carries a `_wg32` suffix -- `new_wg32`,
/// `rooted_wg32`, `bytes_wg32`, `text_wg32`, `invoke_wg32` -- rather than
/// reusing the `Wg16` block's names. See [`Fixture::new_wg32`]'s own doc
/// comment for the measured reason: two concrete inherent impls sharing a
/// method name is an ambiguity Rust's default type parameter does not
/// resolve, and same-named methods on both blocks broke all 1,155 existing
/// bare `Fixture::new()`/`Fixture::rooted()` call sites the first time this
/// task tried it.
pub struct Fixture<A: Abi = Wg16> {
    pub machine: A::Cpu,
    pub host: Host<A>,
    scratch: u16,
    next: u16,
}

/// Where the sample files a shim reads live.
pub fn data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

/// A scratch directory holding copies of `files` from [`data`].
///
/// What an install step needs: the module's own files, somewhere the test may
/// let the host change them.
pub fn scratch_with(name: &str, files: &[&str]) -> PathBuf {
    let at = scratch(name);
    for file in files {
        std::fs::copy(data().join(file), at.join(file)).expect("a sample file to copy");
    }
    at
}

impl Fixture<Wg16> {
    /// A host over the checked-in sample files.
    pub fn new() -> Self {
        Self::rooted(data())
    }

    /// A host over a directory of the test's choosing.
    ///
    /// For the few shims that *write* into a module's directory -- see
    /// [`scratch_with`] -- which must not be the checked-in one.
    pub fn rooted(root: PathBuf) -> Self {
        Self::rooted_with_terms(root, crate::Terms::new(crate::globals::NTERMS))
    }

    /// A host over a directory of the test's choosing, with `terms` channels.
    ///
    /// The multi-channel entry point. Everything [`Fixture::rooted`] documents
    /// applies.
    pub fn rooted_with_terms(root: PathBuf, terms: crate::Terms) -> Self {
        let mut machine = Machine::new().expect("16-bit machine");
        let mut host = Host::new(&mut machine, root, terms).expect("host");
        // A fixture stands for a host that has finished starting up, because
        // that is the only state a channel may connect to -- see
        // `Host::finish_init`. With no module to `dclvda`, `vdasiz` is zero
        // here and this allocates nothing; what it does is set the flag.
        host.finish_init(&mut machine).expect("finished starting up");
        let scratch = machine.alloc_segment(4096).expect("scratch");
        Self {
            machine,
            host,
            scratch,
            next: 0,
        }
    }

    /// This host's local console: channel zero, minted from the host's own
    /// [`Terms`](crate::Terms).
    ///
    /// Tests used to write the literal `0` and rely on it meaning the same
    /// channel to `Users` and to `Gsbl`. It did, but nothing said so -- which is
    /// the convention [`crate::chan`] replaced. Taking the channel from the host
    /// under test means a test cannot name a channel that host does not have.
    pub fn console(&self) -> crate::Chan {
        self.host
            .users()
            .terms()
            .chan(0)
            .expect("every host has a channel zero")
    }

    /// A NUL-terminated string in scratch memory the module can address.
    pub fn text(&mut self, s: &str) -> FarPtr {
        self.bytes(s.as_bytes(), true)
    }

    /// Raw bytes in scratch memory, terminated or not.
    pub fn bytes(&mut self, bytes: &[u8], terminate: bool) -> FarPtr {
        let at = FarPtr {
            offset: self.next,
            selector: self.scratch,
        };
        let mut out = bytes.to_vec();
        if terminate {
            out.push(0);
        }
        self.machine.write(at, &out).expect("fits");
        self.next += out.len() as u16;
        at
    }

    /// Argument words in scratch memory, laid out as a `va_list` finds them.
    ///
    /// The same order and the same widths as [`Fixture::call`] pushes, which is
    /// the point: a test that formats the same words both ways is a test that
    /// the two sources agree.
    pub fn words(&mut self, words: &[u16]) -> FarPtr {
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        self.bytes(&bytes, false)
    }

    /// Somewhere to write, with nothing in it.
    pub fn buffer(&mut self, len: u16) -> FarPtr {
        self.bytes(&vec![0; usize::from(len)], false)
    }

    /// What a buffer holds, up to its terminator.
    pub fn read(&self, at: FarPtr) -> String {
        String::from_utf8_lossy(self.machine.read_cstr(at).expect("terminated")).into_owned()
    }

    /// Stop at a host call whose argument words are `args`, in declaration
    /// order.
    pub fn call(&mut self, args: &[u16]) {
        self.call_with(args, [0; 4]);
    }

    /// Stop at a host call with `args` pushed and `AX`, `BX`, `CX` and `DX` set,
    /// in that order.
    ///
    /// Borland's 32-bit runtime helpers take their operands in registers and put
    /// nothing on the stack at all, so a fixture that could only push could not
    /// reach them. The registers are loaded *after* the pushes, because the
    /// pushes use `AX` as their scratch.
    pub fn call_with(&mut self, args: &[u16], regs: [u16; 4]) {
        let mut code = Vec::new();
        for word in args.iter().rev() {
            code.push(0xb8); // mov $word, %ax
            code.extend_from_slice(&word.to_le_bytes());
            code.push(0x50); // push %ax
        }
        for (opcode, value) in [0xb8u8, 0xbb, 0xb9, 0xba].into_iter().zip(regs) {
            code.push(opcode); // mov $value, %ax / %bx / %cx / %dx
            code.extend_from_slice(&value.to_le_bytes());
        }
        code.extend_from_slice(&[0x9a, 0, 0, 0, 0]); // lcall $CS, $thunk 0
        let at = code.len() - 4;
        code[at..at + 4].copy_from_slice(&self.machine.thunk_address(0).to_bytes());
        code.push(0xcb);

        self.machine.load_code(&code).expect("module fits");
        let entry = self.machine.code_ptr(0);
        assert!(matches!(
            self.machine.call(entry, &[]).expect("called"),
            Exit::Call { index: 0 }
        ));
    }

    /// Push `args` and run `shim` over them.
    ///
    /// Takes a [`Shim<Wg16>`](crate::shims::Shim) -- the shape every routine
    /// in this crate actually has. It used to take `Wg16Shim`, the bare
    /// `fn(&mut Machine, &mut Host)` shape, which meant every shim needed a
    /// `_wg16` bridge written beside it for no reason except to be callable
    /// here. That was 128 bridge functions serving 594 call sites, and it
    /// made adding one routine to the API surface cost two functions instead
    /// of one. The bridges are gone; this builds the `Call` itself.
    ///
    /// Still returns `mbbs_machine::m16::Ret` rather than [`abi::Ret<Wg16>`], via the
    /// `From` conversion between them. That is what let the bridges be
    /// deleted without touching a single assertion in those 594 tests: the
    /// call sites changed by exactly one thing, dropping `_wg16` from the
    /// symbol.
    pub fn invoke(&mut self, shim: crate::shims::Shim<Wg16>, args: &[u16]) -> Result<Ret, ShimError> {
        self.call(args);
        let frame = self.machine.arg_frame().to_vec();
        let mut call = Call::<Wg16>::new(&mut self.machine, &frame);
        shim(&mut call, &mut self.host).map(Into::into)
    }

    /// Push `args`, set the registers, and run `shim` over both.
    ///
    /// See [`Fixture::invoke`] for why this takes a `Shim<Wg16>`.
    pub fn invoke_with(
        &mut self,
        shim: crate::shims::Shim<Wg16>,
        args: &[u16],
        regs: [u16; 4],
    ) -> Result<Ret, ShimError> {
        self.call_with(args, regs);
        let frame = self.machine.arg_frame().to_vec();
        let mut call = Call::<Wg16>::new(&mut self.machine, &frame);
        shim(&mut call, &mut self.host).map(Into::into)
    }

    /// Push `args` and run a shim, answering in [`abi::Ret<Wg16>`] rather
    /// than converting to `mbbs_machine::m16::Ret` the way [`Fixture::invoke`] does.
    ///
    /// The two tests that need it are in `shims::mod` and reach a routine
    /// through [`entry`](crate::shims::entry) by name rather than by calling
    /// it directly, so they are checking the table's own wiring and want the
    /// return value in the type the table deals in.
    pub fn invoke_call(
        &mut self,
        shim: crate::shims::Shim<Wg16>,
        args: &[u16],
    ) -> Result<abi::Ret<Wg16>, ShimError> {
        self.call(args);
        let frame = self.machine.arg_frame().to_vec();
        let mut call = Call::<Wg16>::new(&mut self.machine, &frame);
        shim(&mut call, &mut self.host)
    }

    /// A far pointer, as the two argument words it arrives in.
    pub fn far(at: FarPtr) -> [u16; 2] {
        [at.offset, at.selector]
    }

    /// Run `line` through `ext`'s `command` handler, on this fixture's own
    /// host and channel, against `module`.
    ///
    /// `CommandCtx`'s fields stay `pub(crate)` to the `mbbs` crate -- a Lua
    /// (or any other) extension crate cannot build one itself, only call
    /// [`crate::extension::Extension::command`] on one this crate handed it.
    /// This is that hand-off, so a test in another crate can invoke a real
    /// handler without `mbbs` ever depending back on that crate.
    ///
    /// Takes `module` now that [`crate::extension::CommandCtx::call_export`]
    /// exists: a handler that wants to call a module export needs both the
    /// machine and the module to resolve and run it against, and this is
    /// the only place a `CommandCtx` gets built for a test. Every existing
    /// caller gained one argument -- the "churn" the task that added
    /// `call_export` called out and approved in advance.
    pub fn run_command(
        &mut self,
        ext: &mut dyn crate::extension::Extension<Wg16>,
        chan: crate::Chan,
        line: &str,
        module: &mbbs_machine::m16::Module,
    ) -> crate::extension::Verdict {
        let mut ctx = crate::extension::CommandCtx {
            chan,
            line: line.to_owned(),
            host: &mut self.host,
            machine: &mut self.machine,
            module,
        };
        ext.command(&mut ctx)
    }

    /// Load [`minimal_module_bytes`] into this fixture's host.
    ///
    /// `Host::connect` and `Host::poll` both take a `&mbbs_machine::m16::Module`, whether
    /// or not the branch under test ever reads it, and `Host::load` is the
    /// only way to produce one -- there is no `Default`, no test constructor,
    /// nothing but real NE bytes in. A test of "no module has registered"
    /// still needs a module to *pass*, just not one that has registered.
    pub fn minimal_module(&mut self) -> mbbs_machine::m16::Module {
        self.host
            .load(&mut self.machine, &minimal_module_bytes())
            .expect("a minimal module loads")
    }
}

/// An inert one-section PE32 image, just parseable enough for
/// [`mbbs_machine::m32::Image::load`]/[`mbbs_machine::m32::Memory::new`] to
/// accept it.
///
/// Byte-for-byte the same skeleton `crates/mbbs/tests/wg32_abi.rs`'s
/// `minimal_with_one_section` and `crates/mbbs/tests/wg32_round_trip.rs`'s
/// `skeleton` build -- duplicated rather than shared, per this crate
/// family's own convention for this exact fixture (see `heap.rs`'s test
/// module doc comment, which cites the same two files for the same reason).
/// Nothing a `Fixture<Wg32>` shim test does ever executes this image's code
/// or walks an import directory -- every test calls a shim function
/// directly through [`Fixture::invoke`](Fixture::invoke) rather than
/// entering the module -- so the section holds no bytes at all; it exists
/// only so `PeImage::parse`/`Image::load` have a real header and one real
/// section to walk.
fn wg32_skeleton() -> Vec<u8> {
    const SIZE_OF_IMAGE: u32 = 0x0000_2000;

    let mut v = vec![0u8; 0x200];
    v[0..2].copy_from_slice(b"MZ");
    v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    v[0x80..0x84].copy_from_slice(b"PE\0\0");
    v[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // machine = i386
    v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    v[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
    v[0x96..0x98].copy_from_slice(&0x010eu16.to_le_bytes()); // characteristics
    v[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32 magic

    let opt = 0x98;
    v[opt + 16..opt + 20].copy_from_slice(&0x0000_1000u32.to_le_bytes()); // entry rva
    v[opt + 28..opt + 32].copy_from_slice(&0x2222_0000u32.to_le_bytes()); // image base
    v[opt + 32..opt + 36].copy_from_slice(&0x0000_1000u32.to_le_bytes()); // section align
    v[opt + 36..opt + 40].copy_from_slice(&0x0000_0400u32.to_le_bytes()); // file align
    v[opt + 56..opt + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());

    let sec = opt + 0xe0;
    v.resize(sec + 40 + 0x400, 0);
    v[sec..sec + 8].copy_from_slice(b"CODE\0\0\0\0");
    v[sec + 8..sec + 12].copy_from_slice(&0x400u32.to_le_bytes()); // VirtualSize
    v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    v[sec + 16..sec + 20].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfRawData
    v[sec + 20..sec + 24].copy_from_slice(&((sec + 40) as u32).to_le_bytes());
    v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE|EXEC|READ|WRITE
    v
}

/// Enough arena for [`Host::<Wg32>::new`]'s own placements (measured at
/// 13,216 bytes by `crates/mbbs/tests/wg32_abi.rs`'s own
/// `alcmem_and_alczer_still_pack_ordinary_wg32_sizes`) plus whatever a dfa
/// shim test opens and writes -- `Heap::reserve` maps a full 65,535-byte
/// `SEGMENT` the first time anything asks it for room, regardless of how
/// small that first request is, so even one small `dfaOpen` needs far more
/// arena behind it than the file it opens.
const WG32_ARENA: usize = 512 * 1024;

impl Fixture<Wg32> {
    /// A `Wg32` host over the checked-in sample files.
    ///
    /// Named `new_wg32`, not `new` -- `impl Fixture<Wg16>` already has a
    /// same-named `new()`, and unlike a bare unparameterised type, two
    /// *concrete* inherent impls (`Fixture<Wg16>`, `Fixture<Wg32>`) sharing a
    /// method name is a hard ambiguity error at every call site that writes
    /// bare `Fixture::new()`: Rust's default type parameter (`A: Abi =
    /// Wg16`) is not consulted to break the tie, because inherent method
    /// lookup collects every impl whose `Self` *could* unify before it ever
    /// gets to defaults. Measured, not assumed: giving both blocks `new()`
    /// produced `E0034: multiple applicable items in scope` at all 1,155
    /// existing `Fixture::new()`/`Fixture::rooted()` call sites across this
    /// crate the first time this task tried it. Distinct names for every
    /// `Wg32` method is what keeps every `Wg16` call site compiling
    /// unchanged -- the actual requirement, not the mechanism this task
    /// first reached for.
    ///
    /// **Must only be called from a `crates/mbbs/tests/*.rs` integration
    /// binary** -- see this module's own doc comment on [`Fixture`] for why.
    pub fn new_wg32() -> Self {
        Self::rooted_wg32(data())
    }

    /// A `Wg32` host over a directory of the test's choosing.
    ///
    /// Builds a real `mbbs_machine::m32::Machine` (thunk table, TIB, fault
    /// recovery armed) over an inert placeholder image -- [`wg32_skeleton`]
    /// -- the same construction `crates/mbbs/tests/wg32_abi.rs`'s own `cpu()`
    /// and `crates/mbbs/tests/wg32_round_trip.rs`'s `machine_and_placeholder`
    /// use. No module is ever loaded through it: every
    /// [`Fixture::invoke_wg32`](Fixture::invoke_wg32) call here reaches a
    /// shim directly, through a hand-built [`Call`], never through
    /// `Host::run`'s dispatch -- so the placeholder image is never entered
    /// and never needs to be anything but parseable.
    pub fn rooted_wg32(root: PathBuf) -> Self {
        let file = wg32_skeleton();
        let pe = mbbs_machine::m32::PeImage::parse(&file).expect("fixture PE parses");
        let image = mbbs_machine::m32::Image::load(&file, &pe).expect("fixture PE loads");
        let mem = mbbs_machine::m32::Memory::new(image, WG32_ARENA).expect("arena mapping");
        let machine = mbbs_machine::m32::Machine::new().expect("32-bit machine");
        let mut cpu = Wg32Cpu::new(machine, mem);
        let mut host =
            Host::<Wg32>::new(&mut cpu, root, crate::Terms::new(crate::globals::NTERMS))
                .expect("host");
        host.finish_init(&mut cpu).expect("finished starting up");
        Self {
            machine: cpu,
            host,
            scratch: 0,
            next: 0,
        }
    }

    /// Raw bytes, written into a fresh region of this fixture's arena.
    ///
    /// The `Wg32` sibling of [`Fixture::<Wg16>::bytes`](Fixture::bytes),
    /// under its own name for the same reason [`Fixture::new_wg32`]'s doc
    /// comment gives: there, scratch memory is a hand-picked segment this
    /// type owns outright; here, it is
    /// [`crate::abi::ModuleMem::alloc_region`] against the same flat arena
    /// `Host::new` and every shim already share -- there being no separate
    /// "scratch segment" concept once near and far collapse to one address
    /// space (the same collapse `Abi::data_ptr`'s own doc comment
    /// describes).
    pub fn bytes_wg32(&mut self, bytes: &[u8]) -> mbbs_machine::m32::Flat32Ptr {
        let mem = <Wg32 as Abi>::mem(&mut self.machine);
        let ptr = <mbbs_machine::m32::Memory as abi::ModuleMem>::alloc_region(mem, bytes.len())
            .expect("arena has room");
        mbbs_machine::ptr::ModulePtr::write(&ptr, mem, bytes).expect("just allocated, so writable");
        ptr
    }

    /// A NUL-terminated string, written into this fixture's arena.
    pub fn text_wg32(&mut self, s: &str) -> mbbs_machine::m32::Flat32Ptr {
        let mut out = s.as_bytes().to_vec();
        out.push(0);
        self.bytes_wg32(&out)
    }

    /// Run `shim` directly against a hand-built [`Call<Wg32>`], skipping
    /// real CPU execution entirely.
    ///
    /// `args` is one `u32` per argument, in declaration order -- the `Wg32`
    /// analogue of [`Fixture::<Wg16>::invoke`](Fixture::invoke)'s one `u16`
    /// per argument, and just as symmetric: every argument this ABI's
    /// argument frame holds, pointer or `int` alike, is exactly four bytes
    /// (`Abi::PTR_WIDTH == Abi::INT_WIDTH == 4` for `Wg32`), so one `u32`
    /// always means one argument.
    ///
    /// Not built by assembling and running real x86 the way
    /// [`Fixture::<Wg16>::call`](Fixture::call) does: this crate's own
    /// `crates/mbbs/tests/wg32_abi.rs` (`alcmem_and_alczer_...`,
    /// `alcblok32_...`) already established the precedent that a shim can be
    /// proven directly against a hand-built [`Call`], with the *real* module
    /// round trip (execution, thunk binding, dispatch) covered separately by
    /// `crates/mbbs/tests/wg32_round_trip.rs`. A dfa shim test needs the
    /// former, not the latter: what is missing is coverage of the shim
    /// itself under `Wg32`, not a second proof that `Host::run`'s dispatch
    /// works.
    pub fn invoke_wg32(
        &mut self,
        shim: crate::shims::Shim<Wg32>,
        args: &[u32],
    ) -> Result<abi::Ret<Wg32>, ShimError> {
        let frame: Vec<u8> = args.iter().flat_map(|word| word.to_le_bytes()).collect();
        let mut call = Call::<Wg32>::new(&mut self.machine, &frame);
        shim(&mut call, &mut self.host)
    }
}

/// The smallest NE image [`mbbs_machine::m16::Machine::load_ne`] accepts: one data
/// segment, no imports, no exports beyond its own name. See
/// [`Fixture::minimal_module`].
///
/// Built by hand rather than borrowed from `crates/mbbs-machine/tests/ne.rs`'s builder,
/// which is private to that crate's own test binary and cannot be imported
/// from here. The field offsets are the NE header's, the same ones
/// `NeImage::parse` reads them back from.
pub fn minimal_module_bytes() -> Vec<u8> {
    const ALIGN: u16 = 4;
    const SECTOR: usize = 1 << ALIGN;

    fn pstring(name: &str, ordinal: u16) -> Vec<u8> {
        let mut out = vec![name.len() as u8];
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&ordinal.to_le_bytes());
        out
    }

    // No imports at all, so the table is only its own leading empty string.
    let impnames = vec![0u8];

    // The module's own name, then a terminator -- no exports.
    let mut restab = pstring("TESTMOD", 0);
    restab.push(0);

    // A description, then a terminator.
    let mut nrtab = pstring("a test module", 0);
    nrtab.push(0);

    // No entries at all: a bundle count of zero ends the table immediately.
    let entrytab = vec![0u8];

    let mut out = vec![0u8; 0x80];
    out[0..2].copy_from_slice(b"MZ");
    out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    out[0x40..0x42].copy_from_slice(b"NE");

    // One segment row, filled in once its data is placed.
    let segtab = 0x80;
    out.resize(segtab + 8, 0);

    let modtab = out.len(); // no imported modules, so nothing follows here
    let imptab = out.len();
    out.extend_from_slice(&impnames);
    let restab_at = out.len();
    out.extend_from_slice(&restab);
    let entrytab_at = out.len();
    out.extend_from_slice(&entrytab);
    let nrtab_at = out.len();
    out.extend_from_slice(&nrtab);

    // The one segment's data, on a sector boundary, with no relocations.
    while !out.len().is_multiple_of(SECTOR) {
        out.push(0);
    }
    let sector = (out.len() / SECTOR) as u16;
    let data = [0u8; 4];
    out.extend_from_slice(&data);

    out[segtab..segtab + 2].copy_from_slice(&sector.to_le_bytes());
    out[segtab + 2..segtab + 4].copy_from_slice(&(data.len() as u16).to_le_bytes());
    out[segtab + 4..segtab + 6].copy_from_slice(&0x0001u16.to_le_bytes()); // a data segment
    out[segtab + 6..segtab + 8].copy_from_slice(&(data.len() as u16).to_le_bytes());

    let w = |out: &mut Vec<u8>, at: usize, v: u16| {
        out[0x40 + at..0x40 + at + 2].copy_from_slice(&v.to_le_bytes());
    };
    w(&mut out, 0x04, (entrytab_at - 0x40) as u16);
    w(&mut out, 0x06, entrytab.len() as u16);
    w(&mut out, 0x0c, 0x8001); // a single-data library
    w(&mut out, 0x0e, 1); // autodata: the one segment
    w(&mut out, 0x1c, 1); // segment count
    w(&mut out, 0x1e, 0); // imported module count
    w(&mut out, 0x20, nrtab.len() as u16);
    w(&mut out, 0x22, (segtab - 0x40) as u16);
    w(&mut out, 0x26, (restab_at - 0x40) as u16);
    w(&mut out, 0x28, (modtab - 0x40) as u16);
    w(&mut out, 0x2a, (imptab - 0x40) as u16);
    w(&mut out, 0x32, ALIGN);
    out[0x40 + 0x2c..0x40 + 0x30].copy_from_slice(&(nrtab_at as u32).to_le_bytes());
    out[0x40 + 0x36] = 0x02;

    out
}

/// [`minimal_module_bytes`], plus one import: `module.symbol`, addressed as
/// data (`OFFSET`, not `FAR_ADDR`) from the one segment's own first two
/// bytes, additively, with `addend` sitting at the site.
///
/// This is what `Resolver::resolve` (`crates/mbbs/src/lib.rs`) needs to be
/// able to record a [`crate::MissingGlobal`] at all: `Host::load` builds
/// its `reach` map (`addressed_as_data`) by walking exactly this shape of
/// relocation, and only a symbol that map has an entry for is ever checked
/// against `shims::entry` for `Why::NotPlaced`/`Why::TooSmall`. A `FAR_ADDR`
/// fixup -- what taking a routine's address looks like -- is invisible to
/// that map on purpose (see `addressed_as_data`'s own doc comment), which is
/// why this builder uses `OFFSET` rather than the wider record.
///
/// `symbol` is written as an **imported name**, not an ordinal: a plain NE
/// pstring (length byte, then bytes, no trailing ordinal word -- that suffix
/// belongs only to the *exported*-name tables, `restab`/`nrtab`) appended to
/// the imported-name table right after `module`'s own. The module reference
/// table then gets its one entry, pointing at `module`'s offset in that same
/// table, and the segment's relocation names it by `TGT_IMPORTNAME`.
///
/// `addend` is written little-endian at the relocation's site (segment
/// offset 0) and is what `addend()` in `lib.rs` reads back to build `Reach`.
/// Pass `0` for a plain "the host does not have this at all"
/// ([`crate::Why::NotPlaced`]) fixture; pass something at or past a real
/// global's placed size to build a [`crate::Why::TooSmall`] one instead (see
/// `missing_globals.rs`'s `refused_when_a_datum_is_addressed_past_its_own_size`
/// for the latter).
pub fn module_bytes_importing(module: &str, symbol: &str, addend: i16) -> Vec<u8> {
    const ALIGN: u16 = 4;
    const SECTOR: usize = 1 << ALIGN;

    // Relocation record constants -- `crates/mbbs-machine/src/m16/ne.rs`'s
    // own, not exported from there, so restated here byte-for-byte against
    // its `parse_relocation`.
    const SRC_OFFSET: u8 = 5;
    const TGT_IMPORTNAME: u8 = 2;
    const TGT_ADDITIVE: u8 = 0x04;

    fn pstring(name: &str, ordinal: u16) -> Vec<u8> {
        let mut out = vec![name.len() as u8];
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&ordinal.to_le_bytes());
        out
    }

    // A plain pstring, with no trailing ordinal -- what the module- and
    // imported-name tables hold, as opposed to the exported-name tables
    // `pstring` above serves.
    fn plain_pstring(name: &str) -> Vec<u8> {
        let mut out = vec![name.len() as u8];
        out.extend_from_slice(name.as_bytes());
        out
    }

    // The imported-name table: a leading empty string at offset 0 (the same
    // convention `minimal_module_bytes`'s `impnames` uses, and the reason
    // module-reference offsets are never 0), then `module`'s own name, then
    // `symbol`'s.
    let mut impnames = vec![0u8];
    let module_at = impnames.len();
    impnames.extend_from_slice(&plain_pstring(module));
    let symbol_at = impnames.len();
    impnames.extend_from_slice(&plain_pstring(symbol));

    // The module's own name, then a terminator -- no exports.
    let mut restab = pstring("TESTMOD", 0);
    restab.push(0);

    // A description, then a terminator.
    let mut nrtab = pstring("a test module", 0);
    nrtab.push(0);

    // No entries at all: a bundle count of zero ends the table immediately.
    let entrytab = vec![0u8];

    let mut out = vec![0u8; 0x80];
    out[0..2].copy_from_slice(b"MZ");
    out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    out[0x40..0x42].copy_from_slice(b"NE");

    // One segment row, filled in once its data is placed.
    let segtab = 0x80;
    out.resize(segtab + 8, 0);

    // One module reference: the offset of its name in the imported-name
    // table, relative to that table's own start.
    let modtab = out.len();
    out.extend_from_slice(&(module_at as u16).to_le_bytes());

    let imptab = out.len();
    out.extend_from_slice(&impnames);
    let restab_at = out.len();
    out.extend_from_slice(&restab);
    let entrytab_at = out.len();
    out.extend_from_slice(&entrytab);
    let nrtab_at = out.len();
    out.extend_from_slice(&nrtab);

    // The one segment's data, on a sector boundary: `addend`, little-endian,
    // at its first two bytes -- the relocation's site -- then padding, since
    // `load_ne` maps the segment at its `minalloc`/file length either way.
    while !out.len().is_multiple_of(SECTOR) {
        out.push(0);
    }
    let sector = (out.len() / SECTOR) as u16;
    let mut data = addend.to_le_bytes().to_vec();
    data.resize(4, 0);
    out.extend_from_slice(&data);

    // The one relocation, immediately after the segment's raw data -- where
    // `parse_segment` looks for it once `SEG_RELOCINFO` is set.
    out.extend_from_slice(&1u16.to_le_bytes()); // relocation count
    out.push(SRC_OFFSET);
    out.push(TGT_IMPORTNAME | TGT_ADDITIVE);
    out.extend_from_slice(&0u16.to_le_bytes()); // site: the segment's first word
    out.extend_from_slice(&1u16.to_le_bytes()); // module reference index, 1-based
    out.extend_from_slice(&(symbol_at as u16).to_le_bytes()); // imported name offset

    out[segtab..segtab + 2].copy_from_slice(&sector.to_le_bytes());
    out[segtab + 2..segtab + 4].copy_from_slice(&(data.len() as u16).to_le_bytes());
    out[segtab + 4..segtab + 6].copy_from_slice(&0x0101u16.to_le_bytes()); // data segment, has relocations
    out[segtab + 6..segtab + 8].copy_from_slice(&(data.len() as u16).to_le_bytes());

    let w = |out: &mut Vec<u8>, at: usize, v: u16| {
        out[0x40 + at..0x40 + at + 2].copy_from_slice(&v.to_le_bytes());
    };
    w(&mut out, 0x04, (entrytab_at - 0x40) as u16);
    w(&mut out, 0x06, entrytab.len() as u16);
    w(&mut out, 0x0c, 0x8001); // a single-data library
    w(&mut out, 0x0e, 1); // autodata: the one segment
    w(&mut out, 0x1c, 1); // segment count
    w(&mut out, 0x1e, 1); // imported module count
    w(&mut out, 0x20, nrtab.len() as u16);
    w(&mut out, 0x22, (segtab - 0x40) as u16);
    w(&mut out, 0x26, (restab_at - 0x40) as u16);
    w(&mut out, 0x28, (modtab - 0x40) as u16);
    w(&mut out, 0x2a, (imptab - 0x40) as u16);
    w(&mut out, 0x32, ALIGN);
    out[0x40 + 0x2c..0x40 + 0x30].copy_from_slice(&(nrtab_at as u32).to_le_bytes());
    out[0x40 + 0x36] = 0x02;

    out
}

/// [`minimal_module_bytes`], plus one named export, `name`, at ordinal 1,
/// pointing at a second segment holding `code` verbatim.
///
/// For [`crate::extension::CommandCtx::call_export`]'s own tests: proving
/// that a name resolves means calling something real, and the only way to
/// get something [`crate::Host::run`] can actually execute is a genuine NE
/// code segment -- the module's memory is mapped executable or not
/// (`mbbs_machine::m16::ne`'s loader: `Segment::new(alloc, !is_data())`)
/// according to exactly this flag, so planting `code` in the existing data
/// segment would fault on the real `PROT_EXEC` mapping rather than produce
/// a clean [`crate::Outcome`]. `minimal_module_bytes`'s own scratch-code
/// trick (`machine.load_code`, used by `Fixture::call`) does not help here
/// either: it writes outside any module's segments, so nothing in `module`
/// would resolve to it by name.
///
/// The entry table gets one **fixed** bundle (`ne.rs`'s `parse_entry_table`
/// -- an indicator byte that is a plain segment number, not `0` or `0xFF`)
/// naming segment 2, offset 0, exported. The resident-name table gets the
/// module's own name (ordinal 0, never resolvable -- see
/// [`mbbs_machine::m16::ne`]'s `collect_names`) followed by `name` at
/// ordinal 1, which is what makes `Module::entry_by_name(name)` answer
/// this entry.
pub fn module_bytes_exporting(name: &str, code: &[u8]) -> Vec<u8> {
    const ALIGN: u16 = 4;
    const SECTOR: usize = 1 << ALIGN;

    fn pstring(name: &str, ordinal: u16) -> Vec<u8> {
        let mut out = vec![name.len() as u8];
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&ordinal.to_le_bytes());
        out
    }

    // No imports at all, so the table is only its own leading empty string.
    let impnames = vec![0u8];

    // The module's own name, then the one export, then a terminator.
    let mut restab = pstring("TESTMOD", 0);
    restab.extend_from_slice(&pstring(name, 1));
    restab.push(0);

    // A description, then a terminator.
    let mut nrtab = pstring("a test module", 0);
    nrtab.push(0);

    // One fixed bundle: count 1, indicator = segment 2 (the code segment
    // below), then that entry's own flags (bit 0 set: exported) and offset
    // (0, the segment's first byte) -- three bytes, per `ne.rs`'s
    // `parse_entry_table` non-moveable arm. A trailing zero count ends the
    // table.
    let entrytab = vec![1u8, 2, 0x01, 0, 0, 0u8];

    let mut out = vec![0u8; 0x80];
    out[0..2].copy_from_slice(b"MZ");
    out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    out[0x40..0x42].copy_from_slice(b"NE");

    // Two segment rows -- data, then code -- filled in once their data is
    // placed.
    let segtab = 0x80;
    out.resize(segtab + 16, 0);

    let modtab = out.len(); // no imported modules, so nothing follows here
    let imptab = out.len();
    out.extend_from_slice(&impnames);
    let restab_at = out.len();
    out.extend_from_slice(&restab);
    let entrytab_at = out.len();
    out.extend_from_slice(&entrytab);
    let nrtab_at = out.len();
    out.extend_from_slice(&nrtab);

    // Segment 1: the autodata segment, four zero bytes, same as
    // `minimal_module_bytes` -- `call_export`'s own tests have no reason to
    // touch DGROUP, only to have one, the way every real module does.
    while !out.len().is_multiple_of(SECTOR) {
        out.push(0);
    }
    let sector1 = (out.len() / SECTOR) as u16;
    let data = [0u8; 4];
    out.extend_from_slice(&data);

    // Segment 2: the code segment, `code` verbatim.
    while !out.len().is_multiple_of(SECTOR) {
        out.push(0);
    }
    let sector2 = (out.len() / SECTOR) as u16;
    out.extend_from_slice(code);

    out[segtab..segtab + 2].copy_from_slice(&sector1.to_le_bytes());
    out[segtab + 2..segtab + 4].copy_from_slice(&(data.len() as u16).to_le_bytes());
    out[segtab + 4..segtab + 6].copy_from_slice(&0x0001u16.to_le_bytes()); // a data segment
    out[segtab + 6..segtab + 8].copy_from_slice(&(data.len() as u16).to_le_bytes());

    out[segtab + 8..segtab + 10].copy_from_slice(&sector2.to_le_bytes());
    out[segtab + 10..segtab + 12].copy_from_slice(&(code.len() as u16).to_le_bytes());
    out[segtab + 12..segtab + 14].copy_from_slice(&0x0000u16.to_le_bytes()); // a code segment
    out[segtab + 14..segtab + 16].copy_from_slice(&(code.len() as u16).to_le_bytes());

    let w = |out: &mut Vec<u8>, at: usize, v: u16| {
        out[0x40 + at..0x40 + at + 2].copy_from_slice(&v.to_le_bytes());
    };
    w(&mut out, 0x04, (entrytab_at - 0x40) as u16);
    w(&mut out, 0x06, entrytab.len() as u16);
    w(&mut out, 0x0c, 0x8001); // a single-data library
    w(&mut out, 0x0e, 1); // autodata: segment 1
    w(&mut out, 0x1c, 2); // segment count
    w(&mut out, 0x1e, 0); // imported module count
    w(&mut out, 0x20, nrtab.len() as u16);
    w(&mut out, 0x22, (segtab - 0x40) as u16);
    w(&mut out, 0x26, (restab_at - 0x40) as u16);
    w(&mut out, 0x28, (modtab - 0x40) as u16);
    w(&mut out, 0x2a, (imptab - 0x40) as u16);
    w(&mut out, 0x32, ALIGN);
    out[0x40 + 0x2c..0x40 + 0x30].copy_from_slice(&(nrtab_at as u32).to_le_bytes());
    out[0x40 + 0x36] = 0x02;

    out
}

/// [`module_bytes_exporting`], generalised to more than one real export.
///
/// A declared-bindings namespace's own tests need several genuine module
/// calls to chain in one run -- `mbbs-lua`'s `wccmmud_test_module` helper,
/// say, needs a real `_GET_PLAYER` far-pointer return alongside five other
/// declared exports -- and `module_bytes_exporting` can only ever build one.
/// Each `(name, code)` pair in `exports` becomes its own fixed
/// entry-table bundle entry, exported at consecutive ordinals starting at
/// 1, with `code` placed at the next free offset in one shared code
/// segment (segment 2) -- so a pointer computed from one export's own code
/// never overlaps another's.
///
/// Everything else -- the autodata segment, the resident-name table's own
/// leading `TESTMOD` entry, no imports -- is identical to
/// `module_bytes_exporting`; see that function's own doc comment for why
/// each piece is shaped the way it is.
pub fn module_bytes_exporting_many(exports: &[(&str, &[u8])]) -> Vec<u8> {
    const ALIGN: u16 = 4;
    const SECTOR: usize = 1 << ALIGN;

    fn pstring(name: &str, ordinal: u16) -> Vec<u8> {
        let mut out = vec![name.len() as u8];
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&ordinal.to_le_bytes());
        out
    }

    // No imports at all, so the table is only its own leading empty string.
    let impnames = vec![0u8];

    // The module's own name, then one export per entry, then a terminator.
    let mut restab = pstring("TESTMOD", 0);
    for (i, (name, _)) in exports.iter().enumerate() {
        restab.extend_from_slice(&pstring(name, (i + 1) as u16));
    }
    restab.push(0);

    // A description, then a terminator.
    let mut nrtab = pstring("a test module", 0);
    nrtab.push(0);

    // One fixed bundle: count = the number of exports, indicator = segment
    // 2 (the shared code segment below), then each entry's own flags (bit 0
    // set: exported) and offset into that segment -- three bytes per entry,
    // per `ne.rs`'s `parse_entry_table` non-moveable arm. A trailing zero
    // count ends the table.
    let mut entrytab = vec![exports.len() as u8, 2];
    let mut offset = 0u16;
    for (_, code) in exports {
        entrytab.push(0x01);
        entrytab.extend_from_slice(&offset.to_le_bytes());
        offset += code.len() as u16;
    }
    entrytab.push(0);

    let mut out = vec![0u8; 0x80];
    out[0..2].copy_from_slice(b"MZ");
    out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    out[0x40..0x42].copy_from_slice(b"NE");

    // Two segment rows -- data, then code -- filled in once their data is
    // placed.
    let segtab = 0x80;
    out.resize(segtab + 16, 0);

    let modtab = out.len(); // no imported modules, so nothing follows here
    let imptab = out.len();
    out.extend_from_slice(&impnames);
    let restab_at = out.len();
    out.extend_from_slice(&restab);
    let entrytab_at = out.len();
    out.extend_from_slice(&entrytab);
    let nrtab_at = out.len();
    out.extend_from_slice(&nrtab);

    // Segment 1: the autodata segment, four zero bytes -- same as
    // `module_bytes_exporting`.
    while !out.len().is_multiple_of(SECTOR) {
        out.push(0);
    }
    let sector1 = (out.len() / SECTOR) as u16;
    let data = [0u8; 4];
    out.extend_from_slice(&data);

    // Segment 2: the code segment, every export's code concatenated in
    // order -- the same order `entrytab`'s offsets above were computed in.
    while !out.len().is_multiple_of(SECTOR) {
        out.push(0);
    }
    let sector2 = (out.len() / SECTOR) as u16;
    let mut code_len = 0u16;
    for (_, code) in exports {
        out.extend_from_slice(code);
        code_len += code.len() as u16;
    }

    out[segtab..segtab + 2].copy_from_slice(&sector1.to_le_bytes());
    out[segtab + 2..segtab + 4].copy_from_slice(&(data.len() as u16).to_le_bytes());
    out[segtab + 4..segtab + 6].copy_from_slice(&0x0001u16.to_le_bytes()); // a data segment
    out[segtab + 6..segtab + 8].copy_from_slice(&(data.len() as u16).to_le_bytes());

    out[segtab + 8..segtab + 10].copy_from_slice(&sector2.to_le_bytes());
    out[segtab + 10..segtab + 12].copy_from_slice(&code_len.to_le_bytes());
    out[segtab + 12..segtab + 14].copy_from_slice(&0x0000u16.to_le_bytes()); // a code segment
    out[segtab + 14..segtab + 16].copy_from_slice(&code_len.to_le_bytes());

    let w = |out: &mut Vec<u8>, at: usize, v: u16| {
        out[0x40 + at..0x40 + at + 2].copy_from_slice(&v.to_le_bytes());
    };
    w(&mut out, 0x04, (entrytab_at - 0x40) as u16);
    w(&mut out, 0x06, entrytab.len() as u16);
    w(&mut out, 0x0c, 0x8001); // a single-data library
    w(&mut out, 0x0e, 1); // autodata: segment 1
    w(&mut out, 0x1c, 2); // segment count
    w(&mut out, 0x1e, 0); // imported module count
    w(&mut out, 0x20, nrtab.len() as u16);
    w(&mut out, 0x22, (segtab - 0x40) as u16);
    w(&mut out, 0x26, (restab_at - 0x40) as u16);
    w(&mut out, 0x28, (modtab - 0x40) as u16);
    w(&mut out, 0x2a, (imptab - 0x40) as u16);
    w(&mut out, 0x32, ALIGN);
    out[0x40 + 0x2c..0x40 + 0x30].copy_from_slice(&(nrtab_at as u32).to_le_bytes());
    out[0x40 + 0x36] = 0x02;

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_minimal_module_loads() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        assert_eq!(module.segment_count(), 1);
    }

    #[test]
    fn the_exporting_module_resolves_its_export_by_name() {
        let mut f = Fixture::new();
        let module = f
            .host
            .load(&mut f.machine, &module_bytes_exporting("SUMMONTEST", &[0xcb]))
            .expect("loads");
        assert_eq!(module.segment_count(), 2);
        assert!(module.entry_by_name("SUMMONTEST").is_some());
    }

    #[test]
    fn the_multi_exporting_module_resolves_every_export_by_name() {
        let mut f = Fixture::new();
        let module = f
            .host
            .load(&mut f.machine, &module_bytes_exporting_many(&[("FIRST", &[0xcb]), ("SECOND", &[0xcb])]))
            .expect("loads");
        assert_eq!(module.segment_count(), 2);
        assert!(module.entry_by_name("FIRST").is_some());
        assert!(module.entry_by_name("SECOND").is_some());
    }
}
