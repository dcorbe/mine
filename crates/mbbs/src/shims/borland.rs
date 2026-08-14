//! Borland's own C++ runtime plumbing, and the one KERNEL32 call this host
//! can safely serve alongside it.
//!
//! Ten symbols `LUNATIX.DLL` links against from `cw3220mt.DLL` (Borland C++
//! 5.x's own 32-bit runtime, aliased onto `MAJORBBS` -- `shims::canonical_dll`'s
//! own doc comment) that are not C library routines at all: exception unwinding, a
//! debug-heap lock pair, and the handful of hooks Borland's generated
//! startup code reaches for before the module's own `DllMain` runs. None of
//! them is declared in any header this crate has recovered -- `GCOMM.H`,
//! `BSEDOS.H` and the rest are Galacticomm's own, and this is Borland's
//! internal runtime, one layer further down, with no source or public
//! documentation surviving in this tree for any of them.
//!
//! Landed eagerly rather than survey-driven -- see
//! `docs/plans/2026-08-14-stage3-channel-entry-implementation.md`'s Task 8,
//! "Why eagerly rather than survey-driven": these are boilerplate LunatiX
//! carries because Borland's linker put it there, not module logic, and
//! leaving any of them [`crate::shims::Entry::Unimplemented`] is a source of
//! mid-session poison unrelated to what the module is doing.
//!
//! # What "no-op" means here, and its one hard boundary
//!
//! Every symbol below except [`abort`] is either genuinely a no-op (nothing
//! this host does needs a debug-heap lock or a CRT init hook) or a no-op
//! *conditioned on nothing throwing* -- see [`exception_handler`] and
//! [`catch_cleanup`]'s own doc comments, which say so rather than implying
//! completeness. [`abort`] is the one symbol here that is not boilerplate: a
//! module that calls the C runtime's `abort()` and is allowed to keep
//! running is worse than one this host stops, so it does not return `Ok` at
//! all.
//!
//! # Two KERNEL32 symbols this file deliberately does not implement
//!
//! `GetModuleHandleA` and `GetProcAddress` are measured `stdcall`, not
//! `cdecl`: `LUNATIX.DLL`'s own call sites
//! (`archive/modules/dlls/ISVCWD__LUNWG53F/LUNATIX.DLL`, `0x41d61d` and
//! `0x41d62c`) push 4 and 8 bytes of arguments respectively and neither is
//! followed by an `add esp` -- the callee is expected to pop them, which is
//! exactly what [`crate::shims::Cleans::Callee`] exists to tell the host.
//! But `Wg32::resume` (`crates/mbbs/src/abi/wg32.rs`) panics unconditionally
//! on `Cleans::Callee`, on the stated premise that 32-bit Worldgroup is
//! uniformly `cdecl`. That premise is true for `WGSERVER`'s own game-host
//! API and false for these two genuine Win32 system calls -- a real gap this
//! task's own boilerplate scope runs into, not a guess to paper over.
//! Registering them `Cleans::Caller` would silently leave 4 or 8 bytes on
//! the module's stack after every call -- the exact "quietly wrong" failure
//! mode this crate exists to refuse (see [`crate::shims::Cleans`]'s own doc
//! comment); registering them `Cleans::Callee` would hit `Wg32::resume`'s
//! panic, whose own message blames "a bug in the host's shim table," which
//! is not what this is. Both are worse than leaving these two unresolved,
//! so they stay [`crate::shims::Entry::Unimplemented`] and in
//! `PINNED_MISSES`. [`getversion`] is unaffected -- it takes no arguments at
//! either of its own call sites, so there is nothing for either calling
//! convention to disagree about.

use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::shims::ShimError;

/// `void abort(void)` -- Borland's, and the C standard's: causes abnormal
/// program termination and, absent a caught `SIGABRT`, "does not return to
/// its caller."
///
/// **Never `Ok`.** Every other routine in this file is a no-op that lets the
/// module carry on; this is not one of them. [`ShimError`] is "every variant
/// is terminal" (its own doc comment) -- the module is stopped and the host
/// surfaces why, which is exactly the contract `abort` itself specifies: no
/// return, ever. Registering this as `Ok(Ret::Void)` -- a module that called
/// `abort` and kept running -- is precisely the failure this whole design
/// exists to refuse.
pub fn abort<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Err(ShimError::Failed(
        "abort: the module called the C runtime's abort(), which never returns".to_string(),
    ))
}

/// `__startup` / `__startupd` -- Borland's own per-module C runtime
/// initialiser, and (per the trailing `d`) very likely its debug-build
/// twin, both called from the code Borland's linker generates ahead of a
/// DLL's own entry point -- heap setup, locale, the pieces of the CRT a
/// module's own code assumes already exist by the time it runs.
///
/// This host has none of that internal state to initialise: `crate::heap::Heap`
/// is this host's own allocator for the module's `alcmem`/`galfree` calls,
/// entirely separate from Borland's internal `malloc` arena, and nothing
/// this host runs reads a CRT locale table or an `errno`. A no-op that
/// reports success is what "there is nothing here for this call to do"
/// looks like.
///
/// **Not measured which of the two is which, or what either's real
/// signature is** -- no header or source for Borland's own runtime survives
/// in this tree. That does not matter for correctness here: both are
/// registered `Cleans::Caller`, and 32-bit Worldgroup is uniformly `cdecl`
/// (`Wg32::resume`'s own doc comment, and this file's own module doc on the
/// two KERNEL32 symbols that are *not* cdecl) -- so the module's own
/// compiled call site cleans up whatever it pushed regardless of what this
/// body reads, and it reads nothing.
pub fn startup<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// See [`startup`]. A separate function because it is a separate import, not
/// because anything measured distinguishes the two bodies.
pub fn startupd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    startup(call, host)
}

/// `@_CatchCleanup$qv` -- `_CatchCleanup(void)`, part of Borland's C++
/// exception-handling runtime.
///
/// The `$qv` suffix is Borland's own mangling for "takes nothing" -- the
/// same evidence [`lock_debugger_data`]/[`unlock_debugger_data`] below carry
/// -- and the leading `@` with no `@Class@` ahead of it is Borland's
/// convention for a symbol with file-scope linkage inside the runtime,
/// exported anyway so the runtime's own object files can reach each other.
/// Consistent with all three `$qv` symbols in this file being internal
/// plumbing no Galacticomm header and no public Borland documentation
/// names.
///
/// # No-op only while nothing throws
///
/// This is Borland's own cleanup-after-a-catch-block helper: released
/// temporaries constructed on the exception path, run once a handler has
/// finished. This host's own shims never throw a C++ exception, so a no-op
/// is correct for every call this host itself causes. It says nothing about
/// a C++ exception `LUNATIX.DLL`'s own code might raise and catch entirely
/// within itself -- this host implements no stack unwinding at all, so if
/// that ever happens, whatever `_CatchCleanup` was meant to release is not
/// released. That gap would surface as a leak or a fault somewhere else
/// downstream, not here; this paragraph is where it is written down rather
/// than implied away by calling the stub "done."
pub fn catch_cleanup<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Void)
}

/// `__ExceptionHandler` -- the per-frame handler Borland's SEH setup code
/// registers on the module's own stack (`push offset __ExceptionHandler`,
/// chained through `fs:[0]`), which the OS's structured-exception dispatcher
/// calls when a fault unwinds through a protected frame.
///
/// **Very likely never actually reached as a call at all.** This host's own
/// `m32` loader says outright that it "is not a Windows loader ... no SEH"
/// (`crates/mbbs-machine/src/m32/mod.rs`'s own module doc) -- there is no
/// dispatcher here to invoke a registered handler in the first place. What
/// registering this table entry is really for is giving the module's own
/// SEH-frame setup code a valid, resolvable address to push rather than a
/// fault; the only way this body runs at all is if something calls it
/// directly, as an ordinary routine.
///
/// # If it is ever reached anyway
///
/// A real SEH handler answers an `EXCEPTION_DISPOSITION`, and
/// `ExceptionContinueSearch` (`1`) is the only honest value this host can
/// give: "I did not handle this, keep unwinding" is true here, because this
/// host does no actual exception handling behind this symbol.
/// `ExceptionContinueExecution` (`0`) would assert a repair that never
/// happened, which is exactly the plausible-but-false answer this crate
/// exists to refuse.
pub fn exception_handler<A: Abi>(
    _call: &mut Call<A>,
    _host: &mut Host<A>,
) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Int(A::Int::from(1u16)))
}

/// `__ErrorMessage` -- Borland's own fatal-runtime-error reporting hook (the
/// family behind messages like "Divide by zero" or "Null pointer
/// assignment" before a runtime error terminates a process).
///
/// **The least certain symbol in this file.** No header, no source, and no
/// public Borland documentation for its exact prototype survives in this
/// tree, so neither its argument shape nor whether any caller inspects its
/// return value to decide something is known first-hand the way
/// [`exception_handler`]'s SEH contract or [`catch_cleanup`]'s mangled name
/// pin theirs. This follows the plan's own stated default for this whole
/// family -- "most are no-ops that return zero" -- on the grounds that it
/// sits in the same exception-plumbing neighbourhood as the two symbols
/// above and this host's own shims never generate the fatal runtime error
/// this hook exists to report. That is a boilerplate default, not a
/// measured semantic, and this is the one symbol in this file where Step
/// 1's own escape hatch applies most directly: if a later survey shows this
/// actually gets called with an outcome that depends on what it returns,
/// that is the finding this paragraph predicted rather than a surprise.
pub fn error_message<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `@__lockDebuggerData$qv` -- takes and returns nothing per its `$qv`
/// mangling, one half of a lock/unlock pair guarding Borland's internal
/// debug-heap bookkeeping (the linked lists a debug build's allocator walks
/// to detect leaks).
///
/// A lock with nothing contending for it is correctly a no-op: this
/// module's own memory never goes through Borland's allocator at all --
/// `alcmem`/`galfree` are this host's own [`crate::heap::Heap`], entirely
/// separate state -- and every module on this host runs on one dedicated
/// thread (`docs/`'s "Single-threaded by force"), so there is no second
/// thread this lock could ever have been protecting against here, even if
/// the debug heap it guards existed.
pub fn lock_debugger_data<A: Abi>(
    _call: &mut Call<A>,
    _host: &mut Host<A>,
) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Void)
}

/// `@__unlockDebuggerData$qv` -- the other half of [`lock_debugger_data`].
/// See that routine's own doc comment; nothing distinguishes the two
/// bodies.
pub fn unlock_debugger_data<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
) -> Result<abi::Ret<A>, ShimError> {
    lock_debugger_data(call, host)
}

/// `___debuggerDisableTerminateCallback` -- another debug-heap hook, by
/// name: disables some callback the debug allocator would otherwise fire on
/// thread termination.
///
/// Same reasoning as [`lock_debugger_data`]: this host's module memory
/// never goes through Borland's own allocator, so there is no callback
/// table here to disable anything in. No-op, void -- the name describes an
/// action with no value to report back, the same shape the two `$qv`-mangled
/// lock symbols make explicit.
pub fn debugger_disable_terminate_callback<A: Abi>(
    _call: &mut Call<A>,
    _host: &mut Host<A>,
) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Void)
}

/// `__free_heaps` -- Borland's own CRT shutdown hook: return the internal
/// allocator's arenas to the OS.
///
/// This host's module memory is `mbbs_machine::m32::Memory`'s own mapping,
/// owned by Rust and released by an ordinary `Drop` when the module's
/// `Wg32Cpu` goes away -- nothing routes through this call to make that
/// happen, so there is nothing here for this call to be in a position to
/// free.
pub fn free_heaps<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Void)
}

/// `DWORD GetVersion(VOID)` -- KERNEL32's own OS-version query, one of the
/// three Win32 calls Borland's generated startup code reaches for directly
/// rather than through module logic.
///
/// # Measured, not assumed
///
/// `LUNATIX.DLL`'s own call site (`0x401021` in
/// `archive/modules/dlls/ISVCWD__LUNWG53F/LUNATIX.DLL`) is
///
/// ```text
/// call   GetVersion
/// and    $0x80000000,%eax
/// je     <branch taken when bit 31 is clear>
/// mov    <a different string>,%edx   ; taken when bit 31 is set
/// ```
///
/// -- the standard `GetVersion` idiom, testing bit 31 to choose between
/// Windows NT (clear) and Windows 9x (set), which this host has not traced
/// further than the branch itself. Zero arguments pushed either side of the
/// call, so there is no `cdecl`-vs-`stdcall` question here the way there is
/// for `GetModuleHandleA`/`GetProcAddress` -- see this file's own module
/// doc.
///
/// # The value: Windows NT 4.0, build 1381
///
/// Worldgroup NT and this Borland C++ 5.x runtime (`cw3220mt.DLL`) both date
/// to the mid-to-late 1990s, when NT 4.0 was the current mainstream NT
/// release -- a reasoned, plausible choice, not a measured one: no
/// recovered source pins which NT version `LUNATIX.DLL`'s own startup code
/// was tested against. What the branch above needs is bit 31 clear, which
/// any NT version gives; the exact minor/build only matters if some later,
/// untested path reads them apart.
///
/// `dwVersion = (build << 16) | (minor << 8) | major` -- major 4, minor 0,
/// build `1381` (`0x0565`), whose own top bit is already clear, so the NT/9x
/// bit and the build number agree without masking either one separately.
pub fn getversion<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    const MAJOR: u32 = 4;
    const MINOR: u32 = 0;
    const BUILD: u32 = 1381; // 0x0565 -- top bit clear, so this reports NT.
    Ok(abi::Ret::Long((BUILD << 16) | (MINOR << 8) | MAJOR))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Wg32;
    use crate::shims::{Entry, entry};
    use crate::testing::Fixture;

    #[test]
    fn c_name_strips_exactly_one_leading_underscore_even_from_a_double() {
        // `__ftol`, `__startup` and the rest start with *two* underscores;
        // `crate::exports::c_name` strips exactly one (`str::strip_prefix`
        // removes the pattern once, not repeatedly), so the table has to key
        // on `_startup`, not `startup` -- registering the wrong spelling
        // would silently serve a name nothing imports and leave the one
        // LunatiX actually calls unresolved. Checked directly here rather
        // than assumed, per this task's own instruction.
        assert_eq!(&*crate::exports::c_name("__ftol"), "_ftol");
        assert_eq!(&*crate::exports::c_name("__startup"), "_startup");
        assert_eq!(&*crate::exports::c_name("__startupd"), "_startupd");
        assert_eq!(&*crate::exports::c_name("__ExceptionHandler"), "_exceptionhandler");
        assert_eq!(&*crate::exports::c_name("__ErrorMessage"), "_errormessage");
        assert_eq!(&*crate::exports::c_name("__free_heaps"), "_free_heaps");
        // Three leading underscores: exactly one still comes off, leaving
        // two.
        assert_eq!(
            &*crate::exports::c_name("___debuggerDisableTerminateCallback"),
            "__debuggerdisableterminatecallback"
        );
        // One leading underscore -- the ordinary case, included so the
        // pattern above reads as "one comes off" and not "one is stripped
        // per underscore present until none remain."
        assert_eq!(&*crate::exports::c_name("_abort"), "abort");
        // No leading underscore at all: `strip_prefix` is a no-op, and only
        // the lowercasing applies.
        assert_eq!(&*crate::exports::c_name("GetVersion"), "getversion");
        // The `@`-prefixed ones do not start with `_`, so nothing strips;
        // only the lowercasing touches them.
        assert_eq!(&*crate::exports::c_name("@_CatchCleanup$qv"), "@_catchcleanup$qv");
        assert_eq!(
            &*crate::exports::c_name("@__lockDebuggerData$qv"),
            "@__lockdebuggerdata$qv"
        );
    }

    /// Every Borland runtime symbol LunatiX links against resolves, named
    /// individually rather than counted -- a count passes while one name
    /// silently swaps for another, which is the same reason
    /// `crates/mbbs/tests/lunatix.rs`'s `PINNED_MISSES` is a set equality
    /// and not a length.
    #[test]
    fn the_borland_runtime_family_resolves() {
        for name in [
            "_startup",
            "_startupd",
            "@_catchcleanup$qv",
            "_exceptionhandler",
            "_errormessage",
            "@__lockdebuggerdata$qv",
            "@__unlockdebuggerdata$qv",
            "__debuggerdisableterminatecallback",
            "_free_heaps",
            "abort",
        ] {
            assert!(
                !matches!(entry::<Wg32>("cw3220mt.DLL", name), Entry::Unimplemented),
                "{name} is Borland startup plumbing and must not poison a session"
            );
        }
    }

    #[test]
    fn getversion_resolves_under_kernel32_dll() {
        assert!(matches!(
            entry::<Wg32>("KERNEL32.dll", "getversion"),
            Entry::Routine(..)
        ));
    }

    /// The finding this file's own module doc writes up: measured `stdcall`
    /// at LunatiX's own call sites, and `Wg32::resume` cannot service
    /// `Cleans::Callee` -- so these two stay unresolved rather than either
    /// silently corrupting the module's stack or hitting a panic whose
    /// message names the wrong cause. A future change that "fixes" this by
    /// registering `Cleans::Caller` should fail this test, not silently pass
    /// it.
    #[test]
    fn getmodulehandlea_and_getprocaddress_are_deliberately_left_unresolved() {
        assert!(matches!(
            entry::<Wg32>("KERNEL32.dll", "getmodulehandlea"),
            Entry::Unimplemented
        ));
        assert!(matches!(
            entry::<Wg32>("KERNEL32.dll", "getprocaddress"),
            Entry::Unimplemented
        ));
    }

    #[test]
    fn abort_does_not_return() {
        let mut f = Fixture::new();
        let e = f.invoke(abort, &[]).expect_err("abort must stop the module");
        assert!(e.to_string().contains("abort"), "{e}");
    }

    #[test]
    fn getversion_reports_windows_nt_not_windows_9x() {
        let mut f = Fixture::new();
        let ret = f.invoke(getversion, &[]).expect("getversion");
        let mbbs_machine::m16::Ret::U32(version) = ret else {
            panic!("getversion returns a 32-bit DWORD");
        };
        // Bit 31 clear is the NT branch LUNATIX.DLL's own call site tests
        // for -- see this module's own doc comment on `getversion`.
        assert_eq!(version & 0x8000_0000, 0, "must read as Windows NT, not 9x");
        assert_eq!(version & 0xff, 4, "major version 4");
        assert_eq!((version >> 8) & 0xff, 0, "minor version 0");
    }

    #[test]
    fn exception_handler_answers_continue_search_if_ever_actually_called() {
        let mut f = Fixture::new();
        let ret = f.invoke(exception_handler, &[]).expect("exception_handler");
        assert_eq!(ret, mbbs_machine::m16::Ret::U16(1), "ExceptionContinueSearch");
    }

    #[test]
    fn the_no_op_family_changes_nothing_and_reports_success() {
        let mut f = Fixture::new();
        for shim in [
            startup,
            startupd,
            catch_cleanup,
            lock_debugger_data,
            unlock_debugger_data,
            debugger_disable_terminate_callback,
            free_heaps,
            error_message,
        ] {
            f.invoke(shim, &[]).unwrap_or_else(|e| panic!("expected Ok: {e}"));
        }
    }
}
