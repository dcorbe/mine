//! Reconnaissance: run the program with every unimplemented import answered
//! zero, and record what it asks for, in order.
//!
//! **The answers are lies, and the list is a hint rather than a contract.** A
//! program told `_time` is zero and `_malloc` is zero takes branches it would
//! never take, so the tail of this list is fiction. What it is good for is
//! bounding the work: it names the symbols that are reached *early*, before the
//! lies compound, and it says which of the 66 linked C runtime symbols are
//! plausibly live at all.
//!
//! This is deliberately a separate instrument from
//! [`crate::win32::process::run`], which stops at the first unimplemented
//! symbol and names it. That strictness is the product; this is the map.

use std::io;

use mbbs_machine::m32::{Exit, Ret};

use crate::win32::load::Loaded;
use crate::win32::process::{self, Outcome, Process};

/// One import the program reached, and how often.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reached {
    pub module: String,
    pub symbol: String,
    pub calls: u32,
    /// How many import calls happened before this symbol was first seen.
    /// Ordering is the useful half of this measurement, so it is recorded
    /// rather than left implicit in the vector's order.
    pub first: usize,
}

/// Run to `budget` import calls, answering anything unimplemented with zero.
///
/// # Errors
///
/// If the machine cannot be entered or resumed.
pub fn survey(
    loaded: &mut Loaded,
    process: &mut Process,
    budget: usize,
) -> io::Result<(Vec<Reached>, Outcome)> {
    let mut seen: Vec<Reached> = Vec::new();
    process.exports.clone_from(&loaded.exports);
    let mut exit = loaded
        .machine
        .call_on(loaded.mem.stack_mut(), loaded.entry, &[])?;

    for n in 0..budget {
        let index = match exit {
            Exit::Call { index } => index,
            Exit::Returned { eax, .. } => return Ok((seen, Outcome::Exited(eax))),
            Exit::Fault { signo, eip } => return Ok((seen, Outcome::Fault { signo, eip })),
            Exit::Timeout { eip } => return Ok((seen, Outcome::Timeout { eip })),
        };
        let Some(site) = loaded.imports.get(index as usize) else {
            return Ok((seen, Outcome::UnknownThunk(index)));
        };
        let symbol = site.symbol.to_string();
        let module = site.module.clone();

        // `__startup` still has to be taken over rather than answered -- it
        // never returns, so a zero would send the program to address zero and
        // the survey would end three calls in. `run` owns that takeover, so the
        // survey defers to it by refusing to handle the symbol itself.
        if module.eq_ignore_ascii_case("cw3220mt.DLL") && symbol == "__startup" {
            let record = loaded.machine.arg_u32(loaded.mem.stack(), 0);
            exit = process::enter_main_for_survey(loaded, process, record)?;
            continue;
        }

        match seen
            .iter_mut()
            .find(|r| r.module == module && r.symbol == symbol)
        {
            Some(r) => r.calls += 1,
            None => seen.push(Reached {
                module: module.clone(),
                symbol: symbol.clone(),
                calls: 1,
                first: n,
            }),
        }

        // Real answers where they exist, zero where they do not. Using the real
        // dispatcher matters: a survey that also faked `GetModuleHandleA` would
        // never get through the process ritual to reach the C runtime at all.
        let site = &loaded.imports[index as usize];
        let answer = process::dispatch(process, &mut loaded.machine, &mut loaded.mem, site);
        if let Some(code) = process.exit_code {
            return Ok((seen, Outcome::Exited(code)));
        }
        let (value, cleans) = match answer {
            Some(a) => (a.value, a.cleans),
            // Zero, cleaning nothing: the C runtime is cdecl, so the caller
            // pops. For an unimplemented *stdcall* symbol this is wrong and
            // will drift the stack -- which is a real limit of this instrument
            // and is recorded in the trace doc rather than hidden.
            None => (0, 0),
        };
        exit =
            loaded
                .machine
                .resume_on_cleaning(loaded.mem.stack_mut(), Ret::U32(value), cleans)?;
    }
    Ok((seen, Outcome::Budget))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32::process::Process;

    /// The reached set is smaller than the linked set, and that gap is the
    /// entire reason this file exists: the executable links 66 C runtime
    /// symbols and Phase 2 measured it calling two imports in total before it
    /// had a process to run in.
    #[test]
    fn the_reached_set_is_smaller_than_the_import_table() {
        let file = std::fs::read("/home/daniel/peepeebbs/wccmmutl.exe").expect("the utility");
        let mut loaded = crate::win32::load::load(&file).expect("loads");
        let mut p = Process::new("C:\\WCCMMUTL.EXE", &[]);

        let (reached, _stop) = survey(&mut loaded, &mut p, 100_000).expect("runs");

        let crt: Vec<&Reached> = reached
            .iter()
            .filter(|r| r.module.eq_ignore_ascii_case("cw3220mt.DLL"))
            .collect();
        assert!(!crt.is_empty(), "it reaches the C runtime at all");
        assert!(
            crt.len() < 66,
            "reached {} of 66 linked CRT symbols; if this ever hits 66 the \
             survey has stopped discriminating",
            crt.len()
        );
        assert_eq!(
            crt.first().map(|r| r.symbol.as_str()),
            Some("_time"),
            "_time is the measured frontier Phase 2 stopped at"
        );

        // The measurement itself, pinned -- see
        // `docs/2026-08-17-win32-crt-trace.md`. Nine of 66, in this order.
        //
        // It was **three** when this test was written, and the six that joined
        // it were not found by looking harder at the import table: they became
        // reachable because the console was implemented. A survey is a function
        // of how much of the host exists, not a fixed property of the program,
        // and this list growing as the host grows is the instrument working
        // rather than the measurement having been wrong.
        let names: Vec<&str> = crt.iter().map(|r| r.symbol.as_str()).collect();
        assert_eq!(
            names,
            [
                "_time",
                "_srand",
                "_memmove",
                "_malloc",
                "_access",
                "_getenv",
                "_memset",
                "_fopen",
                "_vsprintf",
                "_sprintf",
                "_exit",
            ]
        );

        // The survey ends at `_exit` because `_exit` is now *implemented*: the
        // program terminates itself rather than running on into fiction. That
        // is why this list is shorter than it was mid-phase, when the survey
        // ran past the exit and reached `_longjmp` and the whole unwind group.
        //
        // **The headline risk is nonetheless open**, and it is pinned next door
        // rather than here: `process::tests::with_a_filesystem_it_reaches_the_borland_unwind_gate`
        // shows the strict runner stopping at `__Return_unwind` as soon as the
        // host has a filesystem. `_longjmp` and `__Return_unwind` are the same
        // wall -- both restore a register set `m32::Machine` cannot set.
        assert!(
            !crt.iter().any(|r| r.symbol == "_longjmp"),
            "with `_exit` answered the survey stops before the unwind group; \
             if this fires, the exit path changed and the gate moved"
        );
    }

    /// The instrument's own blind spot, stated as a test so it cannot be
    /// forgotten by someone reading only the reached list.
    ///
    /// The survey answers unimplemented symbols with `cleans: 0`, which is
    /// right for the cdecl C runtime and wrong for stdcall Win32 -- so the
    /// ordering after the first *unimplemented stdcall* call is built on a
    /// drifted stack and cannot be trusted.
    ///
    /// **That boundary moved from ordinal 12 to ordinal 1518 when the console
    /// was implemented,** which is the single most useful consequence of this
    /// phase. It used to be `CreateFileA`, twelve calls in, leaving almost the
    /// whole list suspect. It is now `Sleep`, and every C runtime symbol the
    /// program reaches sits *before* it -- so the reached list above is no
    /// longer a hint, it is a measurement.
    ///
    /// Implementing a stdcall symbol is therefore not only progress through the
    /// program; it is a widening of what the survey can honestly see.
    #[test]
    fn implementing_the_console_moved_the_trustworthy_prefix_to_the_whole_list() {
        let file = std::fs::read("/home/daniel/peepeebbs/wccmmutl.exe").expect("the utility");
        let mut loaded = crate::win32::load::load(&file).expect("loads");
        let mut p = Process::new("C:\\WCCMMUTL.EXE", &[]);

        let (reached, _stop) = survey(&mut loaded, &mut p, 100_000).expect("runs");
        let first_of = |s: &str| reached.iter().find(|r| r.symbol == s).map(|r| r.first);

        // `Sleep` marks where the drift boundary *was*. It is answered now, so
        // this is no longer "the first unimplemented stdcall" -- it is a fixed
        // late landmark separating the program's startup from its shutdown.
        //
        // The nine symbols below are the startup set and all precede it.
        // `_sprintf` (ordinal 1690) and `_exit` do not, and that is measured
        // rather than overlooked: they belong to the failure-and-exit path,
        // which runs after the landmark.
        let drift = first_of("Sleep").expect("Sleep is reached");

        for symbol in [
            "_time", "_srand", "_memmove", "_malloc", "_access", "_getenv", "_memset", "_fopen",
            "_vsprintf",
        ] {
            let at = first_of(symbol).unwrap_or_else(|| panic!("{symbol} is reached"));
            assert!(
                at < drift,
                "{symbol} at {at} must sit before the drift at {drift}"
            );
        }

        // And the program gets far enough to draw. Twenty character writes and
        // twenty attribute writes is a screen being painted, not a probe.
        let painted = reached
            .iter()
            .find(|r| r.symbol == "WriteConsoleOutputCharacterA")
            .expect("the program paints");
        assert!(
            painted.calls >= 20,
            "expected a screenful of writes, got {}",
            painted.calls
        );
    }
}

