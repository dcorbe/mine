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
        // Same rule as `process::run`: an import answered is progress, and a
        // program's budget bounds the gap between two of them.
        loaded.machine.rearm_watchdog()?;
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


