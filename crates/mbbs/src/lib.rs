//! The MajorBBS host: the other side of a 16-bit module's imports.
//!
//! [`mbbs16`] puts a module's code on the CPU and tells the host when it wants
//! something. This crate is what answers. It owns the export table, the globals
//! a module addresses directly, and the routines behind the thunks; `mbbs16`
//! stays the execution core and knows nothing about MajorBBS.
//!
//! The design is `docs/plans/2026-08-04-host-shims.md`.
//!
//! # A shim that lies is worse than one that refuses
//!
//! This is the rule the whole crate is shaped around, and it is measured rather
//! than asserted. `crates/mbbs16/tests/trace_init.rs` drives MajorMUD's
//! initialisation with a host that answers zero to everything. It reaches 201
//! calls and then takes SIGSEGV *inside module code*, because `alczer` was told
//! it returned a null pointer at call 183 and the module dereferenced it
//! eighteen calls later. The fault names the module, not the lie.
//!
//! So an import the host cannot service does not return zero and does not
//! return an error the module can interpret. It stops the module, naming the
//! symbol -- see [`Poison::Unimplemented`](mbbs16::Poison::Unimplemented).

mod exports;
mod fmt;
mod globals;
pub mod msg;
mod shims;
#[cfg(test)]
mod testing;

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

pub use exports::Exports;
pub use globals::{GLOBALS, Global, Globals, OUTBSZ};
pub use shims::system::Registration;
pub use shims::{Entry, Shim, ShimError};

use mbbs16::{
    Exit, FarPtr, Import, ImportResolver, Machine, Module, NeImage, Poison, Relocation, Source,
    Symbol, Target,
};

/// How a module entry point ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It returned. `ax` alone for an `int`, `dx:ax` for anything 32 bits wide.
    Returned { ax: u16, dx: u16 },

    /// It was stopped for good, and will not run again.
    Stopped(Poison),
}

/// A global the module addresses that the host cannot place.
///
/// Not a warning. A datum the host does not have would be given a *thunk* --
/// the address of a far call -- and the module would read and write it as a
/// variable, silently. There is no value in loading a module that will do that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingGlobal {
    pub module: String,
    pub symbol: String,
    pub why: Why,
}

/// What is wrong with a global the module addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The host does not place it at all.
    NotPlaced,

    /// The host places it, but the module reaches past the end of it.
    TooSmall { addend: i16, size: u16 },
}

impl std::fmt::Display for MissingGlobal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            module,
            symbol,
            why,
        } = self;
        match why {
            Why::NotPlaced => write!(f, "{module}.{symbol} is a global the host does not have"),
            Why::TooSmall { addend, size } => write!(
                f,
                "{module}.{symbol} is {size} bytes here, and the module reaches {addend} into it"
            ),
        }
    }
}

/// Why a module could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The file is not a module this loader can map. See
    /// [`NeError`](mbbs16::NeError).
    Image(io::Error),

    /// The module addresses host globals the host cannot honestly provide.
    Globals(Vec<MissingGlobal>),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Image(e) => write!(f, "{e}"),
            Self::Globals(missing) => {
                writeln!(f, "{} host globals cannot be provided:", missing.len())?;
                for m in missing {
                    writeln!(f, "    {m}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for LoadError {}

impl From<io::Error> for LoadError {
    fn from(e: io::Error) -> Self {
        Self::Image(e)
    }
}

/// One MajorBBS host.
pub struct Host {
    exports: &'static Exports,
    globals: Globals,

    /// Where the module's own files are: its `.MDF`, its `.MSG` files, and
    /// eventually its Btrieve tables. A DOS module names them without a path
    /// and in whatever case it likes.
    pub root: PathBuf,

    /// `spr`'s rotating buffers, and which one is next.
    spr: FarPtr,
    spr_next: usize,

    /// The line buffer `gmdnam` returns a pointer into.
    mdf: FarPtr,

    /// Where the print buffer ends, so `prf` can refuse to run past it.
    prf_end: u16,

    /// What `srand` was last given. `rand` is not implemented, so nothing
    /// consumes it yet -- but discarding it would make `srand` a lie.
    seed: u16,

    /// Every line `shocst` has been given.
    audit: Vec<String>,

    /// Every module that has come online, in registration order. A module's
    /// number is its index here, which is what `register_module` returns and
    /// what the module passes back.
    modules: Vec<Registration>,

    /// How many host calls have been serviced. The progress meter: with an
    /// unfinished host, how far a module gets before it asks for something
    /// that is not there is a number rather than an impression.
    calls: u64,
}

impl Host {
    /// Build a host over a machine, placing its globals in memory the module
    /// will be able to address.
    ///
    /// `root` is the directory the module's own files live in.
    ///
    /// # Errors
    ///
    /// If the globals or the host's buffers cannot be mapped.
    pub fn new(machine: &mut Machine, root: impl Into<PathBuf>) -> io::Result<Self> {
        let globals = Globals::new(machine)?;
        let prf_end = OUTBSZ;

        // One segment for everything the host hands a module a pointer into and
        // then keeps: `spr`'s four buffers and `gmdnam`'s line. Separate from
        // the globals so that a module overrunning one of these cannot reach
        // `usrnum`.
        let spr_bytes = shims::text::SPR_BYTES as usize * shims::text::SPR_BUFFERS;
        let selector = machine.alloc_segment(spr_bytes + 64)?;

        Ok(Self {
            exports: Exports::wg101(),
            globals,
            root: root.into(),
            spr: FarPtr {
                offset: 0,
                selector,
            },
            spr_next: 0,
            mdf: FarPtr {
                offset: spr_bytes as u16,
                selector,
            },
            prf_end,
            seed: 0,
            audit: Vec::new(),
            modules: Vec::new(),
            calls: 0,
        })
    }

    /// The host's globals.
    pub fn globals(&self) -> &Globals {
        &self.globals
    }

    /// Every line `shocst` has produced, oldest first.
    pub fn audit(&self) -> &[String] {
        &self.audit
    }

    /// Every module that has registered, in the order they did.
    pub fn modules(&self) -> &[Registration] {
        &self.modules
    }

    /// How many host calls this host has serviced.
    pub fn calls(&self) -> u64 {
        self.calls
    }

    /// Find one of the module's files, whatever case it named it in.
    ///
    /// DOS filenames are case-insensitive and a module's are all upper case in
    /// some places and not in others; the filesystem underneath is not. An
    /// exact match first, then one scan of the directory -- so the ordinary
    /// case costs nothing and the awkward one still works.
    pub fn find(&self, name: &str) -> Option<PathBuf> {
        let exact = self.root.join(name);
        if exact.is_file() {
            return Some(exact);
        }
        std::fs::read_dir(&self.root)
            .ok()?
            .filter_map(Result::ok)
            .find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(name))
            .map(|e| e.path())
    }

    /// The next of `spr`'s rotating buffers.
    fn next_spr_buffer(&mut self) -> FarPtr {
        let at = FarPtr {
            offset: self.spr.offset + (self.spr_next as u16) * shims::text::SPR_BYTES,
            selector: self.spr.selector,
        };
        self.spr_next = (self.spr_next + 1) % shims::text::SPR_BUFFERS;
        at
    }

    /// The line buffer `gmdnam` writes into.
    fn mdf_buffer(&self) -> FarPtr {
        self.mdf
    }

    /// One past the last byte `prf` may write.
    fn prf_end(&self) -> u16 {
        self.prf_end
    }

    /// Take a module online, and give it its number.
    fn register(&mut self, description: String, block: FarPtr) -> u16 {
        self.modules.push(Registration { description, block });
        (self.modules.len() - 1) as u16
    }

    /// Load a module, binding its imports to this host.
    ///
    /// The globals the module addresses are checked *before* anything is
    /// mapped, because the failure they would otherwise produce is silent: a
    /// datum the host does not place gets a thunk, and a module reading a
    /// thunk as a variable reads executable bytes and carries on.
    ///
    /// # Errors
    ///
    /// If the file is not a well-formed NE module, or the module addresses a
    /// global the host cannot provide.
    pub fn load(&mut self, machine: &mut Machine, file: &[u8]) -> Result<Module, LoadError> {
        let image = NeImage::parse(file).map_err(io::Error::from)?;

        let missing = self.check_globals(&image, file);
        if !missing.is_empty() {
            return Err(LoadError::Globals(missing));
        }

        let resolver = Resolver {
            exports: self.exports,
            globals: &self.globals,
        };
        Ok(machine.load_ne(file, &resolver)?)
    }

    /// Call a module entry point, servicing its imports until it stops.
    ///
    /// # Errors
    ///
    /// If the module cannot be entered, or the machine malfunctions. A module
    /// that faults, overruns or asks for something unimplemented is not an
    /// error -- it is [`Outcome::Stopped`], which says which.
    pub fn run(
        &mut self,
        machine: &mut Machine,
        module: &Module,
        entry: FarPtr,
        args: &[u16],
    ) -> io::Result<Outcome> {
        let mut exit = machine.call(entry, args)?;
        loop {
            let index = match exit {
                Exit::Returned { ax, dx } => return Ok(Outcome::Returned { ax, dx }),
                Exit::Fault { .. } | Exit::Timeout { .. } => {
                    let poison = machine
                        .poisoned()
                        .expect("a terminal exit poisons the machine")
                        .clone();
                    return Ok(Outcome::Stopped(poison));
                }
                Exit::Call { index } => index,
            };

            // A thunk index the module does not have is not something a module
            // can cause -- it comes from the bridge, and the bridge is the
            // host's. Report it as an unnamed import rather than panicking, so
            // that a loader bug looks like every other refusal.
            let (from, symbol) = match module.import(index) {
                Some(site) => (
                    site.module.clone(),
                    self.symbol_name(&site.module, &site.symbol),
                ),
                None => (String::new(), format!("thunk #{index}")),
            };

            let shim = match shims::entry(&from, &symbol) {
                Entry::Routine(shim) => shim,
                Entry::Datum | Entry::Absolute(_) | Entry::Unimplemented => {
                    return self.stop(
                        machine,
                        Poison::Unimplemented {
                            module: from,
                            symbol,
                        },
                    );
                }
            };

            self.calls += 1;
            match shim(machine, self) {
                Ok(ret) => exit = machine.resume(ret)?,
                Err(e) => {
                    return self.stop(
                        machine,
                        Poison::Unimplemented {
                            module: from,
                            symbol: format!("{symbol} ({e})"),
                        },
                    );
                }
            }
        }
    }

    fn stop(&self, machine: &mut Machine, reason: Poison) -> io::Result<Outcome> {
        machine.poison(reason)?;
        let poison = machine.poisoned().expect("just poisoned").clone();
        Ok(Outcome::Stopped(poison))
    }

    /// The C name of an imported symbol, or something that identifies it when
    /// the host has no name for it.
    fn symbol_name(&self, from: &str, symbol: &Symbol) -> String {
        match symbol {
            Symbol::Name(name) => exports::c_name(name).into_string(),
            Symbol::Ordinal(n) => self
                .exports
                .name(from, *n)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("#{n}")),
        }
    }

    /// Every global the module addresses that the host cannot honestly place.
    fn check_globals(&self, image: &NeImage, file: &[u8]) -> Vec<MissingGlobal> {
        let mut missing = Vec::new();
        for ((from, symbol), reach) in addressed_as_data(image, file) {
            let name = self.symbol_name(&from, &symbol);
            let why = match shims::entry(&from, &name) {
                // A constant has no memory to be too small, and a routine whose
                // address is taken in pieces is a routine -- the thunk's
                // address is the right thing to write.
                Entry::Absolute(_) | Entry::Routine(_) => continue,
                Entry::Unimplemented => Why::NotPlaced,
                Entry::Datum => {
                    let size = self.globals.size(&name).expect("a datum is placed");
                    if reach.max < i32::from(size) {
                        continue;
                    }
                    Why::TooSmall {
                        addend: reach.max as i16,
                        size,
                    }
                }
            };
            missing.push(MissingGlobal {
                module: from,
                symbol: name,
                why,
            });
        }
        missing.sort_by(|a, b| (&a.module, &a.symbol).cmp(&(&b.module, &b.symbol)));
        missing
    }
}

/// How far into a symbol the module's fixups reach.
#[derive(Debug, Clone, Copy)]
struct Reach {
    min: i32,
    max: i32,
}

/// Which imported symbols the module *addresses* rather than calls, and how far
/// into each one it reaches.
///
/// Read out of the relocations rather than from a list of names. A `SEGMENT`,
/// `OFFSET` or `LOBYTE` fixup writes part of an address into the middle of an
/// instruction, which is what taking a variable's address looks like; only
/// `FAR_ADDR` writes the whole thing, which is what a call needs. The
/// classification is one-directional and deliberately so: a routine whose
/// address is taken in pieces would be misread as data, and that is a load
/// error rather than a silent wrong binding.
///
/// The reach is the addend the fixup carries, which for an additive record is
/// the word already sitting at the site. It is **signed**: `WCCMMUD.DLL`
/// reaches `margv` with `0xfffe`, which is -2 and not 65,534.
fn addressed_as_data(image: &NeImage, file: &[u8]) -> HashMap<(String, Symbol), Reach> {
    // Which symbols are data, and how far into each one anything reaches, are
    // two different questions over the same 22,371 records: a datum can also be
    // reached by FAR_ADDR -- `p = margv` and `f()` are the same fixup -- and
    // those addends count too. So classify first, measure second.
    let mut data = std::collections::HashSet::new();
    let mut reach: HashMap<(String, Symbol), Reach> = HashMap::new();

    for pass in 0..2 {
        for segment in &image.segments {
            let bytes = &file[segment.file.clone()];
            for reloc in &segment.relocations {
                let Target::Import { module, symbol } = &reloc.target else {
                    continue;
                };
                let Ok(from) = image.module_name(*module) else {
                    continue;
                };
                let key = (from.to_owned(), symbol.clone());

                if pass == 0 {
                    if reloc.source != Source::FarAddr {
                        data.insert(key);
                    }
                    continue;
                }
                if !data.contains(&key) {
                    continue;
                }

                let at = i32::from(addend(reloc, bytes));
                let seen = reach.entry(key).or_insert(Reach { min: at, max: at });
                seen.min = seen.min.min(at);
                seen.max = seen.max.max(at);
            }
        }
    }

    reach
}

/// The addend a fixup carries.
///
/// Only an additive record has one: a chained record's site holds the offset of
/// the next link, which is not a number to add to anything. Same reading as
/// `apply()` in the loader, and it has to stay the same reading.
fn addend(reloc: &Relocation, segment: &[u8]) -> i16 {
    if !reloc.additive {
        return 0;
    }
    let at = usize::from(reloc.offset);
    match reloc.source {
        Source::LoByte => segment.get(at).map_or(0, |b| i16::from(*b)),
        _ => match segment.get(at..at + 2) {
            Some(word) => i16::from_le_bytes([word[0], word[1]]),
            None => 0,
        },
    }
}

/// Answers "what is `MAJORBBS.474`?" for the loader.
struct Resolver<'a> {
    exports: &'static Exports,
    globals: &'a Globals,
}

impl ImportResolver for Resolver<'_> {
    fn resolve(&self, module: &str, symbol: &Symbol) -> Option<Import> {
        let name = match symbol {
            Symbol::Name(name) => exports::c_name(name).into_string(),
            Symbol::Ordinal(n) => self.exports.name(module, *n)?.to_owned(),
        };

        match shims::entry(module, &name) {
            // A datum is addressed, never called, so the host's own memory goes
            // into the fixup and nothing is ever dispatched for it.
            Entry::Datum => Some(Import::Data(self.globals.address(&name)?)),
            Entry::Absolute(value) => Some(Import::Absolute(value)),
            Entry::Routine(_) => Some(Import::Routine),

            // The loader gives it a thunk anyway. That is what makes calling it
            // an event the host is told about rather than a far call into
            // nothing.
            Entry::Unimplemented => None,
        }
    }
}
