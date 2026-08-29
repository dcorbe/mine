//! Parse, map, relocate, bind and enter a PE32 executable.

use std::io;

use mbbs_machine::m32::{Exit, ExportAddress, Image, Import32, Machine, Memory, PeImage, Ret};

use mbbs_machine::module::{ImportSite, Symbol};

/// How much guest-addressable scratch the host gets for the things a real
/// process finds already built: the command line, `argv`'s strings and its
/// pointer array.
///
/// **It now also backs the program's own `malloc`**, which is why it is
/// megabytes rather than the 64 KiB a command line and its `argv` needed. Once
/// `cw3220mt.DLL!_malloc` is answered out of here (`crate::win32::crt::malloc`),
/// the arena is the program's heap, and the first thing this program does with
/// it is ask for 8 KiB.
///
/// The arena is a bump allocator with no reclaim (`Memory::alloc`) and nothing
/// here frees, so this size is a hard ceiling on everything a run allocates
/// rather than a working-set figure. That is a deliberate bound: exhaustion is
/// a clean refusal -- `malloc` answers NULL, as C says it may -- rather than a
/// reused block, and raising this number is the first response to hitting it.
const ARENA_LEN: usize = 4 * 1024 * 1024;

/// A loaded executable, ready to be entered.
pub struct Loaded {
    /// The program's memory: its mapped [`Image`], the host's arena, and the
    /// module's own stack.
    ///
    /// Held for its lifetime, not merely as a record of one: the `Image` inside
    /// owns the `mmap` the code was written into, so dropping this unmaps every
    /// byte of the program. A `Loaded` that kept only `entry` would hand out an
    /// address whose page had already been returned to the kernel.
    ///
    /// The stack is moved in here out of the [`Machine`]'s own `Tib`
    /// ([`Memory::adopt_stack`]) so that a pointer to one of the program's own
    /// locals resolves. That is not a nicety: `char buf[128]; GetVersionExA(&osvi)`
    /// is the commonest shape there is in this API, and the address it passes
    /// resolves in neither the image nor the arena. The cost is that every
    /// crossing must go through `call_on`/`resume_on_cleaning` with
    /// `mem.stack_mut()`, because the `Machine` no longer holds its own stack.
    pub mem: Memory,
    pub machine: Machine,
    /// The linear address of `AddressOfEntryPoint`.
    pub entry: u32,
    /// One entry per *distinct* imported `(module, symbol)`, in the order
    /// `Exit::Call`'s index refers to. Not one per import site --
    /// `Image::bind_imports` asks its resolver once per symbol and caches the
    /// answer, so a symbol named at twenty sites appears here once.
    pub imports: Vec<ImportSite>,
    /// This image's own exports, resolved to linear addresses.
    ///
    /// An *executable* with an export table is unusual enough to look like a
    /// mistake, and it is not one: `wccmmutl.exe` has an `.edata` section and
    /// calls `GetProcAddress(GetModuleHandleA(NULL), "_input")` -- it looks
    /// symbols up in itself. That is how a Galacticomm utility reaches the
    /// entry points the server would otherwise have called directly.
    ///
    /// Forwarded exports are dropped rather than represented: following a
    /// forwarder means loading the DLL it names, and this host loads none.
    pub exports: Vec<(String, u32)>,
}

/// One import the program actually called, and how often.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Called {
    pub module: String,
    pub symbol: String,
    pub calls: u32,
}

/// Load `file` with every import deliberately unresolved.
///
/// `ImportResolver::resolve` answering `None` is not a failure mode here, it
/// is the instrument: `crates/mbbs-machine/src/module.rs:142-146` guarantees
/// the loader still installs a thunk "so that calling it is a diagnosable
/// event rather than a call into nothing". A program loaded this way announces
/// which of its imports it reaches, in order, which is what [`trace`] exists
/// to record.
///
/// The order of the steps is not free. [`Machine::new`] comes *before*
/// binding because [`Image::patch_thunk_addresses`] needs
/// [`Machine::thunk_addr`] to answer with, and without that final patch every
/// IAT slot holds a bare thunk *index* (0, 1, 2, ...) rather than an address
/// -- `bind_imports` writes the index and says so, and a program that called
/// through one would jump to address 3. `crates/mbbs/src/abi/wg32.rs:427-487`
/// is the existing host's version of this same sequence.
///
/// # Errors
///
/// If the file is not a PE32 this loader understands, if its relocations
/// cannot be applied, if the mapping cannot be made, or if the machine's
/// thunk table and fault recovery cannot be set up.
pub fn load(file: &[u8]) -> io::Result<Loaded> {
    let parsed = PeImage::parse(file).map_err(io::Error::other)?;

    let mut machine = Machine::new()?;

    let mut image = Image::load(file, &parsed)?;
    image.relocate(&parsed).map_err(io::Error::other)?;

    // Typed explicitly rather than inferred: a closure body of `None` alone
    // fixes neither the `Ptr` of the `Import` it declines to build nor which
    // `ImportResolver` impl is wanted.
    let resolver = |_module: &str, _symbol: &Symbol| -> Option<Import32> { None };
    let imports = image
        .bind_imports(&parsed, &resolver)
        .map_err(io::Error::other)?;

    image.patch_thunk_addresses(&parsed, &imports, |index| {
        machine.thunk_addr(u16::try_from(index).expect("bind_imports never exceeds MAX_THUNKS"))
    });

    let entry = image.base().wrapping_add(parsed.entry_point);
    let base = image.base();
    let exports = parsed
        .exports
        .iter()
        .filter_map(|e| match e.address {
            ExportAddress::Rva(rva) => Some((e.name.clone(), base.wrapping_add(rva))),
            ExportAddress::Forwarded(_) => None,
        })
        .collect();

    let mut mem = Memory::with_image(image, ARENA_LEN)?;
    // After this the machine has no stack of its own, which is why every
    // crossing below uses the `_on` forms. `Machine::call` panics rather than
    // silently making a second stack, so the two cannot be mixed by accident.
    let stack = machine
        .take_stack()
        .expect("a freshly built Machine still owns the stack it made");
    mem.adopt_stack(stack);

    Ok(Loaded {
        mem,
        machine,
        entry,
        imports,
        exports,
    })
}

/// Enter `loaded` at its entry point and record every import it calls, in
/// order, until it returns, faults, or `budget` calls are seen.
///
/// Each [`Exit::Call`] is resumed with a zero return value. That is a lie the
/// program will eventually notice, and noticing is the point: the trace is
/// valid up to the first call whose answer it actually uses.
pub fn trace(loaded: &mut Loaded, budget: usize) -> (Vec<Called>, Stop) {
    let mut seen: Vec<Called> = Vec::new();
    let mut exit = match loaded
        .machine
        .call_on(loaded.mem.stack_mut(), loaded.entry, &[])
    {
        Ok(e) => e,
        Err(e) => return (seen, Stop::Error(e.to_string())),
    };
    for _ in 0..budget {
        let index = match exit {
            Exit::Call { index } => index,
            Exit::Returned { eax, .. } => return (seen, Stop::Returned(eax)),
            Exit::Fault { signo, eip } => return (seen, Stop::Fault { signo, eip }),
            Exit::Timeout { eip } => return (seen, Stop::Timeout { eip }),
        };
        let Some(site) = loaded.imports.get(index as usize) else {
            return (seen, Stop::UnknownThunk(index));
        };
        let name = site.symbol.to_string();
        match seen
            .iter_mut()
            .find(|c| c.module == site.module && c.symbol == name)
        {
            Some(c) => c.calls += 1,
            None => seen.push(Called {
                module: site.module.clone(),
                symbol: name,
                calls: 1,
            }),
        }
        // `Ret::Void` clears both halves, so a program that reads `EDX`
        // anyway sees something deterministic rather than whatever the last
        // call left there. The answer is a lie regardless; a deterministic
        // lie at least makes the trace reproducible.
        exit = match loaded.machine.resume_on(loaded.mem.stack_mut(), Ret::Void) {
            Ok(e) => e,
            Err(e) => return (seen, Stop::Error(e.to_string())),
        };
    }
    (seen, Stop::Budget)
}

/// Why a trace ended. Every arm is a different finding, so they are not
/// collapsed into an `Option`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The entry point returned, with `EAX`.
    Returned(u32),
    /// It took a signal. `eip` is a linear address, directly usable against a
    /// disassembly of the mapped image.
    Fault { signo: i32, eip: u32 },
    /// It used its whole CPU budget without returning.
    Timeout { eip: u32 },
    /// `budget` import calls were seen and the trace was cut short.
    Budget,
    /// A thunk fired whose index names no import. The trampoline should make
    /// this impossible, so it is reported rather than panicked on: it would
    /// mean the thunk table and the bound import list had drifted apart, and
    /// the index is the only evidence of how.
    UnknownThunk(u16),
    /// The machine itself failed.
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture is the NT build the board actually ships, not a synthetic
    /// PE -- a hand-rolled one would prove the parser works and nothing about
    /// whether this program loads.
    fn fixture() -> Vec<u8> {
        let path = std::path::Path::new("/home/daniel/peepeebbs/wccmmutl.exe");
        std::fs::read(path).expect("the PE32 utility")
    }

    #[test]
    fn the_utility_loads_and_names_its_imports() {
        let file = fixture();
        let loaded = load(&file).expect("loads");

        assert_eq!(loaded.imports.len(), 140, "140 imports across six DLLs");
        assert!(
            loaded
                .imports
                .iter()
                .any(|i| i.module.eq_ignore_ascii_case("wbtrv32.dll")),
            "the Btrieve requester is imported"
        );
        assert!(loaded.entry != 0, "an entry point was recorded");
    }

    /// The whole of Task 1's finding, pinned: with nothing implemented, this
    /// program calls exactly two imports and then dies. See
    /// `docs/2026-08-17-win32-import-trace.md` for the disassembly that
    /// explains each line of it.
    ///
    /// This is an assertion about the *program*, not about this host, which is
    /// why it is worth pinning at all: `__startup` being an import rather than
    /// code in the executable is the fact every later task is shaped by, and
    /// if a future change makes this trace longer, that change -- not this
    /// test -- is what should be read first.
    #[test]
    fn the_trace_stops_at_a_c_runtime_startup_it_does_not_contain() {
        let file = fixture();
        let mut loaded = load(&file).expect("loads");
        let (called, stop) = trace(&mut loaded, 400);

        assert_eq!(
            called,
            vec![
                Called {
                    module: "KERNEL32.dll".to_owned(),
                    symbol: "GetModuleHandleA".to_owned(),
                    calls: 1,
                },
                Called {
                    module: "cw3220mt.DLL".to_owned(),
                    symbol: "__startup".to_owned(),
                    calls: 1,
                },
            ],
            "two calls, and the second one is the entire rest of the program"
        );

        // `eip` is zero, not merely "some bad address", and the disassembly
        // says why: the entry stub reaches `__startup` by `jmp`, not `call`,
        // with two cdecl arguments still pushed. Returning from a routine that
        // must never return therefore pops the pushed `0` as a return address.
        // A trace that faulted anywhere *else* would mean something different
        // had gone wrong, so the address is asserted rather than ignored.
        assert_eq!(stop, Stop::Fault { signo: 11, eip: 0 });
    }
}
