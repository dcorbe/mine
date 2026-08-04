//! What `_INIT__WCCMMUD` asks the host for, in order.
//!
//! Not an assertion about anything -- a measurement, and the road ahead. It
//! drives the module's initialisation entry point with a host that answers zero
//! to every call and prints what was asked, so what a *finished* host will have
//! to answer is a list anyone can produce rather than a thing to reason about.
//!
//! It is no longer the progress meter. `crates/mbbs`'s
//! `init_gets_as_far_as_the_message_files` is, because it runs against a host
//! that tells the truth.
//!
//! ```text
//! cargo test -p mbbs16 --test trace_init -- --ignored --nocapture
//! ```
//!
//! Ignored by default because it is slow, noisy, needs `re/WCCMMUD.DLL`, and
//! passes whatever happens.
//!
//! **Answering zero to everything is a lie, and the trace shows what lying
//! costs.** It reaches 201 calls and then takes SIGSEGV inside module code --
//! because `alczer` was told it returned a null pointer at call 183 and the
//! module dereferenced it eighteen calls later. The fault names the module's
//! code, not the host's lie. That is the argument for shims that refuse loudly
//! rather than return a plausible zero; this tool is the exception that proves
//! it, and it is deliberately not how the host will behave.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use mbbs16::{Exit, FarPtr, Import, Machine, NeImage, Ret, Source, Symbol, Target};

/// Bytes of scratch memory each data import is given. Enough for the largest
/// addend seen in the fixups (452, into `struct sysvbl`) with room over.
const SLOT: u16 = 512;

/// How many host calls to service before giving up on the module finishing.
const MAX_CALLS: usize = 400;

fn repo(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// Ordinal to name, from the host's own export table.
///
/// WG 1.01 rather than 2.0 or MBBS 6.25: WCCMMUD imports up to ordinal 1191,
/// which MBBS 6.25's table does not reach for 15 of them. WG 1.01 and WG 2.0
/// agree on every ordinal this module imports, so either serves.
fn ordinals() -> HashMap<u16, String> {
    std::fs::read_to_string(repo("archive/galacticomm/majorbbs_wg101.tsv"))
        .expect("the ordinal table")
        .lines()
        .filter_map(|line| {
            let (ordinal, name) = line.split_once('\t')?;
            Some((ordinal.parse().ok()?, name.to_owned()))
        })
        .collect()
}

/// Which imported symbols the module *addresses* rather than calls.
///
/// Read out of the relocations rather than from a list of names: a symbol
/// reached by any source other than FAR_ADDR is one the module takes the
/// address of, and there is no call to intercept.
fn data_imports(image: &NeImage) -> HashSet<(String, Symbol)> {
    let mut addressed = HashSet::new();

    for segment in &image.segments {
        for reloc in &segment.relocations {
            let Target::Import { module, symbol } = &reloc.target else {
                continue;
            };
            let Some(name) = image.modules.get(usize::from(*module).wrapping_sub(1)) else {
                continue;
            };
            if reloc.source != Source::FarAddr {
                addressed.insert((name.clone(), symbol.clone()));
            }
        }
    }

    addressed
}

#[test]
#[ignore = "a measurement, not a test; needs re/WCCMMUD.DLL"]
fn what_init_asks_for() {
    let Ok(file) = std::fs::read(repo("re/WCCMMUD.DLL")) else {
        eprintln!("skipped: re/WCCMMUD.DLL is not present in this checkout");
        return;
    };
    let names = ordinals();
    let image = NeImage::parse(&file).expect("parses");
    let data = data_imports(&image);

    let mut machine = Machine::new().expect("machine");
    let scratch = machine.data_selector();

    // Each data import gets its own slot of scratch memory, so a module writing
    // a global writes somewhere harmless. The loader asks once per symbol, so a
    // counter is safe here -- see `a_symbol_is_resolved_once_however_many_fixups_name_it`.
    let next = std::cell::Cell::new(0u16);
    let module = machine
        .load_ne(&file, &|m: &str, s: &Symbol| {
            if !data.contains(&(m.to_owned(), s.clone())) {
                return Some(Import::Routine);
            }
            let at = next.get();
            next.set(at + SLOT);
            Some(Import::Data(FarPtr {
                offset: at,
                selector: scratch,
            }))
        })
        .expect("loads");

    let label = |symbol: &Symbol| match symbol {
        Symbol::Ordinal(n) => names.get(n).cloned().unwrap_or_else(|| n.to_string()),
        Symbol::Name(s) => s.clone(),
    };

    eprintln!(
        "{} data imports placed, {} thunks assigned\n",
        next.get() / SLOT,
        module.imports().len()
    );

    let init = module.entry(1).expect("ordinal 1 is _INIT__WCCMMUD");
    let mut exit = machine.call(init, &[]).expect("entered");
    let mut seen: Vec<String> = Vec::new();

    for step in 0..MAX_CALLS {
        match exit {
            Exit::Call { index } => {
                let site = module.import(index).expect("a thunk that names itself");
                let line = format!("{}.{}", site.module, label(&site.symbol));
                eprintln!("{step:4}  {line}");
                seen.push(line);
                exit = machine.resume(Ret::U16(0)).expect("resumed");
            }
            Exit::Returned { ax, dx } => {
                eprintln!("\nRETURNED ax={ax:#06x} dx={dx:#06x} after {step} host calls");
                break;
            }
            other => {
                eprintln!("\nSTOPPED after {step} host calls: {other:?}");
                break;
            }
        }
    }

    let mut distinct: Vec<&String> = seen.iter().collect();
    distinct.sort_unstable();
    distinct.dedup();
    eprintln!(
        "\n{} calls, {} distinct symbols:",
        seen.len(),
        distinct.len()
    );
    for name in distinct {
        eprintln!("    {name}");
    }
}
