//! A machine stopped at a host call, for testing one shim at a time.
//!
//! The arguments are pushed by real 16-bit code rather than planted on the
//! stack, because where cdecl actually leaves them is half of what a shim has
//! to get right. A test that laid them out itself would agree with a shim that
//! read them wrongly.

use std::path::PathBuf;

use mbbs_machine::m16::{Exit, FarPtr, Machine, Ret};

use crate::Host;
use crate::abi::{self, Call, Wg16};
use crate::shims::ShimError;

pub struct Fixture {
    pub machine: Machine,
    pub host: Host<Wg16>,
    scratch: u16,
    next: u16,
}

/// Where the sample files a shim reads live.
pub fn data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

/// An empty directory a test may write into, under `target/`.
///
/// Some of what the host does is *install* a file rather than read one, and a
/// test of that has to have somewhere to put it that is neither the checked-in
/// sample directory nor the system temporary one. `target/` is both inside the
/// repository and already ignored by git.
///
/// Cleared on each call, so a test never sees what the last run left.
///
/// # Why the thread is part of the path
///
/// `name` alone is not unique. Callers derive it from data rather than from
/// the test -- `btrieve::records`' own helper is
/// `scratch(&format!("btv-rec-{name}"))`, keyed on the `.DAT` filename -- so
/// four tests sharing `FREESLOT.DAT` shared one directory. Under the default
/// parallel harness that is a race against this function's own opening
/// `remove_dir_all`: one test deletes the directory between another's
/// `create_dir_all` and its first `write`, and the write fails `NotFound`, or
/// succeeds into a directory that is then removed and reads back as 0 bytes.
///
/// Both failures were observed, intermittently, in
/// `splicing_matches_a_full_reindex_over_a_long_run_of_writes`, which is not
/// itself one of the colliding tests -- it just shares the helper. That is
/// what made it look like a flaky Btrieve test for weeks rather than a
/// broken test fixture, and every parallel agent working in this crate hit
/// it and was told to ignore it.
///
/// Keying on the thread as well makes collision impossible without changing
/// the contract: a single test still gets one directory, still cleared on
/// each call. Directory names stay readable because
/// [`std::thread::ThreadId`] renders as `ThreadId(N)` and only the digits are
/// kept.
pub fn scratch(name: &str) -> PathBuf {
    let thread = format!("{:?}", std::thread::current().id())
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>();
    let at = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-scratch")
        .join(format!("t{thread}"))
        .join(name);
    let _ = std::fs::remove_dir_all(&at);
    std::fs::create_dir_all(&at).expect("a scratch directory");
    at
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

impl Fixture {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_minimal_module_loads() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        assert_eq!(module.segment_count(), 1);
    }
}
