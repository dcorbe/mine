//! What `_init__wccmmud` asks its host for, in order.
//!
//! The 32-bit sibling of `crates/mbbs16/tests/trace_init.rs`, adapted to what
//! is actually different here: every one of the module's 210 imports is by
//! name (`tests/wccmmud.rs`'s `the_import_histogram_is_as_measured`), so there
//! is no data/routine split to derive from relocations first -- **every**
//! import gets [`Import32::Routine`] and therefore a thunk, and reaching one
//! is a diagnosable `Exit::Call` rather than a jump into invented memory.
//!
//! Not an assertion about anything -- a measurement.
//! `docs/plans/2026-08-12-btrieve-finish.md`'s Task 2 is explicit that a
//! trace which dies on call three is as valid a result as one that runs off
//! the end, and that this file must not be steered toward a hoped-for
//! outcome. `docs/wgnt-init-trace.md` is the committed transcript this
//! program's output was turned into.
//!
//! ```sh
//! cargo run -p mbbs32 --example init_trace
//! ```
//!
//! # Every call is answered `Ret::U32(0)`, with no exceptions
//!
//! Unlike `trace_init.rs`'s own warning that "answering zero to everything is
//! a lie, and the trace shows what lying costs" -- this file does not even
//! special-case a pointer-shaped allocator the way that risk would suggest
//! doing. Special-casing a symbol's return value *is* steering the
//! measurement: it is this program deciding, ahead of the module, which lie
//! is survivable. Task 2 asks for the honest number of calls a completely
//! naive host reaches, not the number reachable by a host this program has
//! already started to write. If `_init__wccmmud` stops at an allocator being
//! told it returned null, that stop is exactly as informative as any other --
//! it names the next symbol a real shim has to answer before the trace can
//! see past it, which is what this task exists to produce.

use std::path::Path;

use mbbs32::{Exit, Image, Import32, Machine, PeImage, Ret, Symbol};

/// A generous bound so a trace that never returns or faults -- a genuine
/// infinite loop induced by lying to the module -- still terminates. Nothing
/// measured while writing this file needed more than a few hundred calls;
/// this is headroom, not a number tuned to some run's own length.
const MAX_CALLS: usize = 5000;

/// How many argument words to print per call. cdecl gives no signature to
/// read this trace's own way, so this is "enough to eyeball a filename or a
/// small integer argument list", not a claim about any symbol's real arity --
/// reading past a routine's true argument count only reads harmless stack
/// slack above the frame (`Machine::arg_u32`'s doc comment), never something
/// out of bounds.
const ARGS_SHOWN: usize = 6;

fn repo(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
}

fn symbol_label(symbol: &Symbol) -> String {
    match symbol {
        Symbol::Name(s) => s.clone(),
        // Not exercised by this module (`the_import_histogram_is_as_measured`
        // asserts every import here is `Symbol::Name`), but the trace should
        // not panic on a module that turns out to differ.
        Symbol::Ordinal(n) => format!("#{n}"),
    }
}

fn main() {
    let path = repo("re/wg_nt_ref/WCCNT8PJ/out/wccmmud.dll");
    let file = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    println!(
        "module: {} ({} bytes) -- see docs/wgnt-init-trace.md for the hash this run was \
         measured against",
        path.display(),
        file.len(),
    );

    let pe = PeImage::parse(&file).expect("the module parses as a PE32 image");
    let mut mapped = Image::load(&file, &pe).expect("the module maps");
    mapped.relocate(&pe).expect("the module relocates");

    // Every import gets a thunk -- see this file's own doc comment for why
    // there is no `Import32::Data` arm to compute here, unlike
    // `mbbs16`'s `trace_init.rs`.
    let resolver =
        |_library: &str, _symbol: &Symbol| -> Option<Import32> { Some(Import32::Routine) };
    let thunks = mapped.bind_imports(&pe, &resolver);

    let mut machine = Machine::new().expect("a Machine");
    mapped.patch_thunk_addresses(&pe, &thunks, |index| {
        machine.thunk_addr(u16::try_from(index).expect("well under MAX_THUNKS"))
    });

    println!(
        "{} imports bound, {} distinct thunks assigned\n",
        pe.imports.len(),
        thunks.len()
    );

    let init_rva = pe
        .export_rva("_init__wccmmud")
        .expect("_init__wccmmud is exported -- pinned by tests/wccmmud.rs");
    assert_eq!(init_rva, 0x1aaa, "the RVA this task cites must still hold");
    let entry = mapped.base() + init_rva;

    // `_init__wccmmud` is this module's registration entry point, the exact
    // 32-bit analogue of the 16-bit build's `_INIT__WCCMMUD`
    // (`tests/wccmmud.rs`'s `the_export_table_is_as_measured`). The 16-bit
    // host calls that entry point with no arguments
    // (`crates/mbbs16/tests/wccmmud.rs:280`), and this build exports the
    // identical identifier at the identical registration role, so the same
    // zero-argument call is used here -- not verified against a 32-bit host
    // caller (there is no real 32-bit MAJORBBS/WGSERVER binary in this
    // repo to read the call site from), so this is the one assumption in
    // this file that is carried over rather than measured directly.
    let mut exit = machine
        .call(entry, &[])
        .expect("a fault is recovered as Exit::Fault, never fatal to this process");

    let mut seen: Vec<String> = Vec::new();

    for step in 0..MAX_CALLS {
        exit = match exit {
            Exit::Call { index } => {
                let site = &thunks[usize::from(index)];
                let label = format!("{}:{}", site.library, symbol_label(&site.symbol));

                // How many argument words are actually safe to read above
                // this frame before running off the top of the module's own
                // stack mapping -- `Machine::arg_u32` panics rather than
                // silently reading past it, and a call made while the module
                // has barely used any stack depth (its own `_init__wccmmud`
                // frame, near the very top) can legitimately leave less than
                // `ARGS_SHOWN` words of margin above the frame. This is not a
                // corruption check, only a bound so this recorder itself
                // never panics -- see `docs/wgnt-init-trace.md` for whether
                // any call actually hit this ceiling and what that meant.
                let sp = machine.frame_sp().expect("Exit::Call implies a frame");
                let margin_words = (machine.stack_base() - sp).saturating_sub(4) / 4;
                let shown = ARGS_SHOWN.min(margin_words as usize);
                let args: Vec<u32> = (0..shown).map(|n| machine.arg_u32(n)).collect();
                if shown < ARGS_SHOWN {
                    println!(
                        "{step:4}  {label:<28}  args={args:#010x?}  \
                         (only {shown} of {ARGS_SHOWN} words fit above this frame)"
                    );
                } else {
                    println!("{step:4}  {label:<28}  args={args:#010x?}");
                }
                seen.push(label);
                machine.resume(Ret::U32(0)).expect("resumed")
            }
            Exit::Returned { eax, edx } => {
                println!(
                    "\nRETURNED eax={eax:#010x} edx={edx:#010x} after {step} host calls"
                );
                break;
            }
            Exit::Fault { signo, eip } => {
                let rva = eip.checked_sub(mapped.base());
                let section = rva.and_then(|rva| {
                    pe.sections
                        .iter()
                        .find(|s| rva >= s.rva && rva < s.rva + s.virtual_size)
                        .map(|s| (s.name.clone(), rva - s.rva))
                });
                println!(
                    "\nFAULT signal {signo} at linear eip {eip:#010x} (image base \
                     {:#010x}, rva {rva:?}, section {section:?}) after {step} host calls",
                    mapped.base(),
                );
                break;
            }
        };

        if step == MAX_CALLS - 1 {
            println!("\nSTOPPED: hit the {MAX_CALLS}-call cap without returning or faulting");
        }
    }

    let mut distinct: Vec<&String> = seen.iter().collect();
    distinct.sort_unstable();
    distinct.dedup();
    println!("\n{} calls, {} distinct symbols touched:", seen.len(), distinct.len());
    for name in &distinct {
        println!("    {name}");
    }

    let dfa_calls: Vec<&String> = seen.iter().filter(|s| s.contains(":_dfa")).collect();
    println!(
        "\nreached a dfa* call: {} ({} of them)",
        !dfa_calls.is_empty(),
        dfa_calls.len()
    );
}
