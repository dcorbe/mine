//! Task 1's acceptance test: the host thread survives a module stop.
//!
//! `re/WCCMMUD.DLL` is not used here on purpose. Reaching a real wall in it
//! (`l2as` via a monster kill, say) needs a live character and a live
//! monster; this file needs a *deterministic* one, on demand, from a module
//! built byte by byte -- the same technique `crates/mbbs-machine/tests/ne.rs` uses for the
//! NE loader itself, applied one layer up. See `builder` below.
//!
//! ```text
//! cargo test -p mbbs-server --test host_supervisor
//! ```
//!
//! (No `--ignored`: unlike `two_players.rs` and `sleep.rs`, nothing here
//! needs `re/WCCMMUD.DLL` or a live board, so these run by default.)

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Receiver;
use tokio::time::Instant;

use mbbs::abi::Wg16;
use mbbs::{Chan, Connection};
use mbbs_server::conn::{self, default_keys};
use mbbs_server::host::Boot;
use mbbs_server::msg::{In, Out};

/// How long a single read may block before a test declares a hang rather
/// than waiting on CI forever.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Reads from `stream`, appending every chunk to `acc`, until `acc` (decoded
/// lossy as UTF-8, exactly as a real telnet client sees it) contains
/// `needle`. A straight copy of `two_players.rs`'s helper of the same name.
async fn read_until(stream: &mut TcpStream, acc: &mut Vec<u8>, needle: &str) {
    loop {
        if String::from_utf8_lossy(acc).contains(needle) {
            return;
        }
        let mut buf = [0u8; 4096];
        let n = match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => panic!(
                "socket closed before {needle:?} appeared; received so far: {:?}",
                String::from_utf8_lossy(acc)
            ),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("read error waiting for {needle:?}: {e}"),
            Err(_) => panic!(
                "timed out after {READ_TIMEOUT:?} waiting for {needle:?}; received so far: {:?}",
                String::from_utf8_lossy(acc)
            ),
        };
        acc.extend_from_slice(&buf[..n]);
    }
}

/// Reads until the socket closes, or `budget` elapses -- whichever comes
/// first -- and says which. Used to observe `Out::Close` (a clean EOF)
/// without hanging forever if a bug ever left the socket open instead.
async fn read_until_closed(stream: &mut TcpStream, acc: &mut Vec<u8>, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let mut buf = [0u8; 4096];
        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => return true,
            Ok(Ok(n)) => acc.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => return true,
            Err(_) => return false,
        }
    }
}

/// A synthetic NE module, built byte by byte -- deliberately not borrowed
/// from `crates/mbbs-machine/tests/ne.rs`'s own builder, which is private to that crate's
/// test binary and cannot be imported from here (the same situation
/// `mbbs::testing::minimal_module_bytes`'s doc comment already describes).
/// This is a smaller, single-purpose version: just enough NE format to
/// register with the host and, on cue, run `HLT` -- a privileged
/// instruction that raises `SIGSEGV` inside the sandboxed segment
/// (`crates/mbbs-machine/tests/fault.rs` pins the same trick) -- which is what
/// gives every test in this file a *deterministic* module stop instead of
/// one that depends on a live board and a monster kill.
mod builder {
    /// Logical sector alignment, as a shift count. Small, so a two-segment
    /// module is a few hundred bytes rather than a few thousand -- the same
    /// choice `crates/mbbs-machine/tests/ne.rs` makes and for the same reason.
    const ALIGN: u16 = 4;
    const SECTOR: usize = 1 << ALIGN;

    const SRC_SEGMENT: u8 = 2;
    const SRC_FAR_ADDR: u8 = 3;
    const TGT_INTERNALREF: u8 = 0;
    const TGT_IMPORTNAME: u8 = 2;
    const SEG_DATA: u16 = 0x0001;
    const SEG_RELOCINFO: u16 = 0x0100;

    /// One relocation record, as the eight bytes the NE format gives it.
    #[derive(Clone, Copy)]
    struct Reloc {
        source: u8,
        flags: u8,
        offset: u16,
        lo: u16,
        hi: u16,
    }

    fn pstring(name: &str, ordinal: u16) -> Vec<u8> {
        let mut out = vec![name.len() as u8];
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&ordinal.to_le_bytes());
        out
    }

    /// `mov ax, imm16` -- `B8 iw`.
    fn mov_ax_imm(code: &mut Vec<u8>, value: u16) {
        code.push(0xB8);
        code.extend_from_slice(&value.to_le_bytes());
    }

    /// `mov ax, imm16` where `imm16` is this module's own segment
    /// `segment`'s selector -- unknown until load time, so the immediate is
    /// a placeholder and a `Source::Segment`/`Target::Internal` relocation
    /// (`SRC_SEGMENT`/`TGT_INTERNALREF`) patches it in.
    fn mov_ax_own_segment(code: &mut Vec<u8>, relocs: &mut Vec<Reloc>, segment: u8) {
        code.push(0xB8);
        let site = code.len() as u16;
        code.extend_from_slice(&0xFFFFu16.to_le_bytes());
        relocs.push(Reloc {
            source: SRC_SEGMENT,
            flags: TGT_INTERNALREF,
            offset: site,
            lo: u16::from(segment),
            hi: 0,
        });
    }

    /// `push ax` -- `50`.
    fn push_ax(code: &mut Vec<u8>) {
        code.push(0x50);
    }

    /// `mov es, ax`.
    fn mov_es_ax(code: &mut Vec<u8>) {
        code.extend_from_slice(&[0x8E, 0xC0]);
    }

    /// `mov [es:offset], ax`.
    fn store_ax_es(code: &mut Vec<u8>, offset: u16) {
        code.push(0x26);
        code.push(0xA3);
        code.extend_from_slice(&offset.to_le_bytes());
    }

    /// `call far ptr16:16` -- `9A cd`, to a thunk the loader hands out for
    /// `MAJORBBS.<name>` (module reference 1, the only one this module
    /// imports). Every relocation here is `IMPORTNAME`/`FAR_ADDR`, a single
    /// non-additive link (the placeholder `0xFFFF` is `CHAIN_END`) -- the
    /// same shape `crates/mbbs-machine/tests/ne.rs`'s `IMPORTNAME` case pins.
    fn call_far_import(code: &mut Vec<u8>, relocs: &mut Vec<Reloc>, name_offset: u16) {
        code.push(0x9A);
        let site = code.len() as u16;
        code.extend_from_slice(&0xFFFFu16.to_le_bytes());
        code.extend_from_slice(&0x0000u16.to_le_bytes());
        relocs.push(Reloc {
            source: SRC_FAR_ADDR,
            flags: TGT_IMPORTNAME,
            offset: site,
            lo: 1, // module reference 1 == "MAJORBBS"
            hi: name_offset,
        });
    }

    /// `add sp, imm8` -- `83 C4 ib`. cdecl: the module (here, this builder)
    /// cleans up its own arguments after a `Cleans::Caller` routine returns.
    fn add_sp(code: &mut Vec<u8>, bytes: u8) {
        code.extend_from_slice(&[0x83, 0xC4, bytes]);
    }

    /// `retf` -- `CB`.
    fn retf(code: &mut Vec<u8>) {
        code.push(0xCB);
    }

    /// A module whose ordinal 1 (init) immediately executes `HLT`.
    ///
    /// For the boot-failure test: ordinal 1 stopping the machine must not be
    /// treated as a survivable, restartable stop (see `host.rs`'s module
    /// doc). No imports, no data segment beyond the one byte the format
    /// needs -- this is the smallest module that both parses and stops
    /// itself the instant it is entered.
    pub fn faults_on_ordinal_one() -> Vec<u8> {
        finish(Ne {
            code: vec![0xF4], // hlt
            // Every NE module needs a `DGROUP` -- `Machine::load_ne` refuses
            // an autodata segment of 0 ("the automatic data segment is 0,
            // which does not exist") -- even one that addresses nothing in
            // it, so this is one otherwise-unused zeroed byte rather than
            // an empty segment.
            data: vec![0u8],
            entry_offset: 0,
            ..Ne::default()
        })
    }

    /// A module whose ordinal 1 (init) registers with the host (so a
    /// channel may connect without error) and schedules a one-second kick
    /// whose routine is `HLT` -- deterministically faulting the machine from
    /// [`Host::cycle`]'s kick sweep, [`Host::prcrtk`], once real time has
    /// advanced a second. This is the *steady-state*, no-channel path: see
    /// `crates/mbbs/src/lib.rs`'s `Ended::Stopped` doc for why a kick-driven
    /// stop names no channel.
    ///
    /// [`Host::cycle`]: mbbs::Host::cycle
    /// [`Host::prcrtk`]: mbbs::Host
    pub fn faults_one_second_after_boot() -> Vec<u8> {
        let mut code = vec![0xF4u8]; // the fault stub, at offset 0
        let mut relocs = Vec::new();
        let entry_offset = code.len() as u16;

        // register_module(&block) -- block lives at data segment offset 0.
        mov_ax_own_segment(&mut code, &mut relocs, 2); // block.selector
        push_ax(&mut code);
        mov_ax_imm(&mut code, 0); // block.offset
        push_ax(&mut code);
        call_far_import(&mut code, &mut relocs, name_offset("register_module"));
        add_sp(&mut code, 4); // one far-pointer argument

        // rtkick(1, dstrou = code segment : the HLT at offset 0).
        mov_ax_own_segment(&mut code, &mut relocs, 1); // dstrou.selector
        push_ax(&mut code);
        mov_ax_imm(&mut code, 0); // dstrou.offset -- the HLT byte, above
        push_ax(&mut code);
        mov_ax_imm(&mut code, 1); // delay = 1 (the minimum rtkick accepts)
        push_ax(&mut code);
        call_far_import(&mut code, &mut relocs, name_offset("rtkick"));
        add_sp(&mut code, 6); // one word plus one far-pointer argument

        retf(&mut code);

        // `struct module`: 25 bytes of name, then nine null far pointers --
        // MNMSIZ (`crates/mbbs/src/shims/system.rs`) is 25. All nine
        // vectors null means `Registration::dispatch` answers
        // `Dispatch::Module(None)` for every one of them, so `Host::connect`
        // (which reads `lonrou`, vector 0) is a clean no-op: this module
        // exists to demonstrate a *restart*, not to exercise a logon hook.
        let mut block = vec![0u8; 25 + 9 * 4];
        block[..7].copy_from_slice(b"TESTMOD");

        finish(Ne { code, data: block, relocs, entry_offset })
    }

    /// A module whose ordinal 1 (init) registers with the host and then
    /// simply returns -- no kick, no fault, ever. For the same-life double-
    /// free test (Path 1 of the double-free defect this file's
    /// `apply_ignores_a_disconnect_for_a_channel_nobody_is_connected_on`
    /// sibling in `crates/mbbs-server/src/host.rs` also covers): that test
    /// wants one life that keeps running, not a restart, so `flush`'s
    /// send-failure path and a manually-injected duplicate `Disconnect` can
    /// both be aimed at the very same connection within it.
    pub fn boots_and_runs_forever() -> Vec<u8> {
        let mut code = Vec::new();
        let mut relocs = Vec::new();
        let entry_offset = code.len() as u16;

        // register_module(&block) -- block lives at data segment offset 0.
        mov_ax_own_segment(&mut code, &mut relocs, 2); // block.selector
        push_ax(&mut code);
        mov_ax_imm(&mut code, 0); // block.offset
        push_ax(&mut code);
        call_far_import(&mut code, &mut relocs, name_offset("register_module"));
        add_sp(&mut code, 4); // one far-pointer argument

        retf(&mut code);

        // Same all-null-vectors shape as `faults_one_second_after_boot`: a
        // connection's `Host::connect` is a clean no-op, and there is
        // nothing here to exercise a logon hook.
        let mut block = vec![0u8; 25 + 9 * 4];
        block[..7].copy_from_slice(b"TESTMOD");

        finish(Ne { code, data: block, relocs, entry_offset })
    }

    /// A module whose `mcurou` (slot 6 of `struct module`) calls an import
    /// this host does not implement and then returns. In survey mode the
    /// call is fabricated and the symbol lands in the inventory, which is
    /// how a test sees that slot 6 was dispatched at all. Outside survey
    /// mode the call stops the machine, which is how a test sees that a
    /// stop inside `mcurou` is a stop.
    ///
    /// The slot's far pointer is written at init time through `es`, because
    /// this builder's NE writer only relocates the code segment. Slot 6
    /// starts at byte 25 + 6 * 4 = 49 of the block: offset word at 49,
    /// selector word at 51.
    pub fn cleans_up_via_unimplemented_symbol() -> Vec<u8> {
        let mut code = Vec::new();
        let mut relocs = Vec::new();

        // The cleanup routine itself, at offset 0.
        let mcurou_offset: u16 = 0;
        call_far_import(&mut code, &mut relocs, name_offset("definitely_not_a_real_host_routine"));
        retf(&mut code);

        let entry_offset = code.len() as u16;

        // es = data segment.
        mov_ax_own_segment(&mut code, &mut relocs, 2);
        mov_es_ax(&mut code);
        // block.mcurou.offset = mcurou_offset
        mov_ax_imm(&mut code, mcurou_offset);
        store_ax_es(&mut code, 49);
        // block.mcurou.selector = code segment
        mov_ax_own_segment(&mut code, &mut relocs, 1);
        store_ax_es(&mut code, 51);

        // register_module(&block) -- block lives at data segment offset 0.
        mov_ax_own_segment(&mut code, &mut relocs, 2);
        push_ax(&mut code);
        mov_ax_imm(&mut code, 0);
        push_ax(&mut code);
        call_far_import(&mut code, &mut relocs, name_offset("register_module"));
        add_sp(&mut code, 4);

        retf(&mut code);

        let mut block = vec![0u8; 25 + 9 * 4];
        block[..7].copy_from_slice(b"TESTMOD");

        finish(Ne { code, data: block, relocs, entry_offset })
    }

    /// A module whose ordinal 1 (init) registers with the host and schedules
    /// a `delay`-second kick that re-arms *itself* forever -- `retf`, not
    /// `HLT`, at the `dstrou` end, so nothing ever stops this module the way
    /// [`faults_one_second_after_boot`]'s sibling kick does.
    ///
    /// For `host.rs`'s wake-age meter (`Boot::wake_age_ms`): that meter is
    /// only informative against a driver that is *supposed* to keep turning
    /// -- a one-shot kick like `faults_one_second_after_boot`'s goes idle
    /// (`Ended::Idle`, `Wait::Blocked`, no deadline armed at all) the moment
    /// it fires, which would make the meter go stale whether the bell is
    /// alive or dead. A perpetual kick keeps `Wait::Until` (and so the bell)
    /// outstanding for as long as the module runs, which is what makes "the
    /// meter goes stale specifically because the bell died, not because
    /// there was nothing left to wait for" an honest comparison.
    pub fn reschedules_forever(delay: u16) -> Vec<u8> {
        // The dstrou stub goes first, at a known offset, so `entry`'s own
        // `rtkick` call below can name it without a forward reference: it
        // re-arms itself with the identical delay, then returns.
        let mut code = Vec::new();
        let mut relocs = Vec::new();
        let dstrou_offset: u16 = 0;

        mov_ax_own_segment(&mut code, &mut relocs, 1); // dstrou.selector
        push_ax(&mut code);
        mov_ax_imm(&mut code, dstrou_offset); // dstrou.offset -- itself
        push_ax(&mut code);
        mov_ax_imm(&mut code, delay);
        push_ax(&mut code);
        call_far_import(&mut code, &mut relocs, name_offset("rtkick"));
        add_sp(&mut code, 6);
        retf(&mut code);

        let entry_offset = code.len() as u16;

        // register_module(&block) -- block lives at data segment offset 0.
        mov_ax_own_segment(&mut code, &mut relocs, 2); // block.selector
        push_ax(&mut code);
        mov_ax_imm(&mut code, 0); // block.offset
        push_ax(&mut code);
        call_far_import(&mut code, &mut relocs, name_offset("register_module"));
        add_sp(&mut code, 4); // one far-pointer argument

        // rtkick(delay, dstrou = the re-arming stub above).
        mov_ax_own_segment(&mut code, &mut relocs, 1); // dstrou.selector
        push_ax(&mut code);
        mov_ax_imm(&mut code, dstrou_offset); // dstrou.offset
        push_ax(&mut code);
        mov_ax_imm(&mut code, delay);
        push_ax(&mut code);
        call_far_import(&mut code, &mut relocs, name_offset("rtkick"));
        add_sp(&mut code, 6);

        retf(&mut code);

        let mut block = vec![0u8; 25 + 9 * 4];
        block[..7].copy_from_slice(b"TESTMOD");

        finish(Ne { code, data: block, relocs, entry_offset })
    }

    /// The same shape as [`faults_one_second_after_boot`], but the kick's
    /// routine calls a symbol this host has no shim for
    /// (`shims::entry` falls through to `Entry::Unimplemented`) instead of
    /// executing `HLT`.
    ///
    /// Every other test in this file reaches its stop through
    /// `Poison::Fault` -- that is the shape every test up to this one
    /// shares, and `mbbs_machine::m16::Machine::poison` does not care which `Poison`
    /// variant it is handed (see `host.rs`'s module doc: "All three `Poison`
    /// variants poison identically"), so this exists to check that claim
    /// rather than assume it: a real board's actual walls (`l2as`, the
    /// fourth-wall symbol this whole plan was written to survive) are
    /// `Unimplemented`, never `Fault`, and nothing before this function
    /// drove one through the restart path at all.
    pub fn faults_via_unimplemented_symbol_one_second_after_boot() -> Vec<u8> {
        // The fault stub goes *first*, at offset 0, exactly as
        // `faults_one_second_after_boot` places its `HLT` -- so `dstrou`
        // (below) is a known constant rather than a forward reference to
        // code emitted later in this same segment. This one relocation
        // (`IMPORTNAME`/`FAR_ADDR`, non-additive) is the whole stub: the far
        // call itself is what raises `Poison::Unimplemented`, so nothing
        // needs to follow it.
        let mut code = Vec::new();
        let mut relocs = Vec::new();
        call_far_import(&mut code, &mut relocs, name_offset("definitely_not_a_real_host_routine"));
        let dstrou_offset: u16 = 0;

        let entry_offset = code.len() as u16;

        // register_module(&block) -- block lives at data segment offset 0.
        mov_ax_own_segment(&mut code, &mut relocs, 2); // block.selector
        push_ax(&mut code);
        mov_ax_imm(&mut code, 0); // block.offset
        push_ax(&mut code);
        call_far_import(&mut code, &mut relocs, name_offset("register_module"));
        add_sp(&mut code, 4); // one far-pointer argument

        // rtkick(1, dstrou = code segment : the fault stub above).
        mov_ax_own_segment(&mut code, &mut relocs, 1); // dstrou.selector
        push_ax(&mut code);
        mov_ax_imm(&mut code, dstrou_offset); // dstrou.offset
        push_ax(&mut code);
        mov_ax_imm(&mut code, 1); // delay = 1 (the minimum rtkick accepts)
        push_ax(&mut code);
        call_far_import(&mut code, &mut relocs, name_offset("rtkick"));
        add_sp(&mut code, 6); // one word plus one far-pointer argument

        retf(&mut code);

        let mut block = vec![0u8; 25 + 9 * 4];
        block[..7].copy_from_slice(b"TESTMOD");

        finish(Ne { code, data: block, relocs, entry_offset })
    }

    /// The same shape as [`faults_via_unimplemented_symbol_one_second_after_boot`],
    /// except the fault stub does not stop *there*: it calls the
    /// unimplemented symbol and then executes `HLT` right after it, rather
    /// than nothing at all.
    ///
    /// With survey mode off (every other module in this file), this never
    /// reaches the `HLT` -- the call itself stops the machine, exactly like
    /// its sibling above. With survey mode on, it does: the call is
    /// fabricated and recorded instead of stopping anything, execution falls
    /// through to the `HLT` right after it, and *that* is what restarts the
    /// board. Built for Task 2's own acceptance (`docs/plans/2026-08-11-survivability-and-the-reachable-surface.md`):
    /// this fires the identical kick, calling the identical symbol, on every
    /// single life, which is what makes it possible to tell a survey
    /// inventory that really survives a restart from one that was silently
    /// rebuilt empty each time -- the latter could only ever show a count of
    /// one.
    pub fn survey_then_faults_one_second_after_boot() -> Vec<u8> {
        let mut code = Vec::new();
        let mut relocs = Vec::new();
        call_far_import(&mut code, &mut relocs, name_offset("definitely_not_a_real_host_routine"));
        code.push(0xF4); // hlt -- reached only if the call above was continued
        let dstrou_offset: u16 = 0;

        let entry_offset = code.len() as u16;

        // register_module(&block) -- block lives at data segment offset 0.
        mov_ax_own_segment(&mut code, &mut relocs, 2); // block.selector
        push_ax(&mut code);
        mov_ax_imm(&mut code, 0); // block.offset
        push_ax(&mut code);
        call_far_import(&mut code, &mut relocs, name_offset("register_module"));
        add_sp(&mut code, 4); // one far-pointer argument

        // rtkick(1, dstrou = code segment : the stub above).
        mov_ax_own_segment(&mut code, &mut relocs, 1); // dstrou.selector
        push_ax(&mut code);
        mov_ax_imm(&mut code, dstrou_offset); // dstrou.offset
        push_ax(&mut code);
        mov_ax_imm(&mut code, 1); // delay = 1 (the minimum rtkick accepts)
        push_ax(&mut code);
        call_far_import(&mut code, &mut relocs, name_offset("rtkick"));
        add_sp(&mut code, 6); // one word plus one far-pointer argument

        retf(&mut code);

        let mut block = vec![0u8; 25 + 9 * 4];
        block[..7].copy_from_slice(b"TESTMOD");

        finish(Ne { code, data: block, relocs, entry_offset })
    }

    /// Where `name` sits in the imported-names table this builder always
    /// writes: `"register_module"`, `"rtkick"`, then
    /// `"definitely_not_a_real_host_routine"`, in that order, right after
    /// the one imported module name ("MAJORBBS"). A fixed table rather than
    /// a general lookup, because every module this file builds wants some
    /// subset of these three symbols or none at all.
    fn name_offset(name: &str) -> u16 {
        // Offset 0 is conventionally the empty string (`ne.rs`'s same
        // convention), so a relocation can name "no string" without
        // clashing with a real one. Offset 1 is "MAJORBBS"'s own pstring
        // entry, which is itself 1 (its length byte) + 8 (its content)
        // bytes long -- both must be skipped to reach the first by-name
        // symbol, which is where this went wrong the first time: leaving
        // out the length byte pointed one byte short, into the middle of
        // "MAJORBBS"'s own bytes instead of past them.
        let mut at = 1u16 + 1 + "MAJORBBS".len() as u16;
        for candidate in ["register_module", "rtkick", "definitely_not_a_real_host_routine"] {
            if candidate == name {
                return at;
            }
            at += 1 + candidate.len() as u16;
        }
        panic!("name_offset: {name:?} is not one of this builder's fixed imports");
    }

    #[derive(Default)]
    struct Ne {
        code: Vec<u8>,
        data: Vec<u8>,
        relocs: Vec<Reloc>,
        entry_offset: u16,
    }

    /// Assemble `ne` into the bytes [`mbbs_machine::m16::Machine::load_ne`] (through
    /// [`mbbs::Host::load`]) accepts. Modelled on `crates/mbbs-machine/tests/ne.rs`'s
    /// `Ne::finish`; trimmed to this file's one shape -- exactly two
    /// segments (code, then data when non-empty), at most one imported
    /// module ("MAJORBBS"), and exactly one entry point at ordinal 1.
    fn finish(ne: Ne) -> Vec<u8> {
        let has_data = !ne.data.is_empty();
        let imports_majorbbs = !ne.relocs.is_empty();

        // Imported names table: module names first, then by-name symbols --
        // `name_offset` above assumes this exact order and must be kept in
        // sync with it.
        let mut impnames = vec![0u8];
        if imports_majorbbs {
            impnames.push(b"MAJORBBS".len() as u8);
            impnames.extend_from_slice(b"MAJORBBS");
            for name in ["register_module", "rtkick", "definitely_not_a_real_host_routine"] {
                impnames.push(name.len() as u8);
                impnames.extend_from_slice(name.as_bytes());
            }
        }

        // The own name, then the one export by name: a module's init routine
        // is the first export named `_INIT__*` (see `m16::ne::Module::init`),
        // and this builder's single entry point is exactly that.
        let mut restab = pstring("TESTMOD", 0);
        restab.extend_from_slice(&pstring("_INIT__TESTMOD", 1));
        restab.push(0);
        let mut nrtab = pstring("a test module", 0);
        nrtab.push(0);

        // One bundle: ordinal 1, in code segment 1, exported.
        let mut entrytab = vec![1u8, 1u8, 0x01u8];
        entrytab.extend_from_slice(&ne.entry_offset.to_le_bytes());
        entrytab.push(0); // terminator bundle (count 0)

        let mut out = vec![0u8; 0x80];
        out[0..2].copy_from_slice(b"MZ");
        out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        out[0x40..0x42].copy_from_slice(b"NE");

        let segment_count: usize = if has_data { 2 } else { 1 };
        let segtab = 0x80;
        out.resize(segtab + segment_count * 8, 0);

        let modtab = out.len();
        if imports_majorbbs {
            out.extend_from_slice(&1u16.to_le_bytes()); // "MAJORBBS" at impnames[1]
        }
        let imptab = out.len();
        out.extend_from_slice(&impnames);
        let restab_at = out.len();
        out.extend_from_slice(&restab);
        let entrytab_at = out.len();
        out.extend_from_slice(&entrytab);
        let nrtab_at = out.len();
        out.extend_from_slice(&nrtab);

        // Code segment (1), then data segment (2) if there is one -- each on
        // its own sector boundary, relocations (code's only) right after.
        while !out.len().is_multiple_of(SECTOR) {
            out.push(0);
        }
        let code_sector = (out.len() / SECTOR) as u16;
        out.extend_from_slice(&ne.code);
        if !ne.relocs.is_empty() {
            out.extend_from_slice(&(ne.relocs.len() as u16).to_le_bytes());
            for r in &ne.relocs {
                out.push(r.source);
                out.push(r.flags);
                out.extend_from_slice(&r.offset.to_le_bytes());
                out.extend_from_slice(&r.lo.to_le_bytes());
                out.extend_from_slice(&r.hi.to_le_bytes());
            }
        }

        let data_sector = if has_data {
            while !out.len().is_multiple_of(SECTOR) {
                out.push(0);
            }
            let sector = (out.len() / SECTOR) as u16;
            out.extend_from_slice(&ne.data);
            sector
        } else {
            0
        };

        let row = |out: &mut Vec<u8>, at: usize, sector: u16, len: usize, flags: u16| {
            out[at..at + 2].copy_from_slice(&sector.to_le_bytes());
            out[at + 2..at + 4].copy_from_slice(&(len as u16).to_le_bytes());
            out[at + 4..at + 6].copy_from_slice(&flags.to_le_bytes());
            out[at + 6..at + 8].copy_from_slice(&(len as u16).to_le_bytes());
        };
        let code_flags = if ne.relocs.is_empty() { 0 } else { SEG_RELOCINFO };
        row(&mut out, segtab, code_sector, ne.code.len(), code_flags);
        if has_data {
            row(&mut out, segtab + 8, data_sector, ne.data.len(), SEG_DATA);
        }

        let w = |out: &mut Vec<u8>, at: usize, v: u16| {
            out[0x40 + at..0x40 + at + 2].copy_from_slice(&v.to_le_bytes());
        };
        w(&mut out, 0x04, (entrytab_at - 0x40) as u16);
        w(&mut out, 0x06, entrytab.len() as u16);
        w(&mut out, 0x0c, 0x8001); // a single-data library
        w(&mut out, 0x0e, if has_data { 2 } else { 0 }); // autodata
        w(&mut out, 0x1c, segment_count as u16);
        w(&mut out, 0x1e, if imports_majorbbs { 1 } else { 0 }); // module count
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
}

/// Writes `bytes` to a fresh file under `mbbs::testing::scratch(name)` and
/// returns its path -- `Boot::modules` wants paths, not bytes in memory.
fn module_file(name: &str, bytes: &[u8]) -> PathBuf {
    let dir = mbbs::testing::scratch(name);
    let path = dir.join("TESTMOD.DLL");
    std::fs::write(&path, bytes).expect("write the synthetic module");
    path
}

/// One module, the shape every test in this file but the N-module ones
/// below wants -- see [`boot_many`] for a `Boot` with more than one.
fn boot(module: PathBuf, root_name: &str, terms: u16) -> Boot<Wg16> {
    boot_many(vec![module], root_name, terms)
}

/// `Boot::modules` in the order given -- the N-module boot-ordering tests
/// below (`a_second_module_faulting_on_ordinal_one_names_itself_not_the_first`
/// and `a_first_module_faulting_on_ordinal_one_names_itself_and_the_second_is_never_reached`)
/// are what this exists for; every other test in this file still goes
/// through [`boot`], the one-module case.
fn boot_many(modules: Vec<PathBuf>, root_name: &str, terms: u16) -> Boot<Wg16> {
    Boot {
        build: Box::new(mbbs_machine::m16::Machine::new),
        root: mbbs::testing::scratch(root_name),
        modules,
        terms: mbbs::Terms::new(terms),
        bturno: None,
        polls_per_second: 8,
        syscyc_hz: 1,
        clock_reads: None,
        wake_age_ms: None,
        dispatched_total: None,
        calls_total: None,
        survey: None,
        extension: None,
        maintenance_interval: mbbs_server::host::MAINTENANCE_INTERVAL,
    }
}

/// A `watch` channel `host::run` can arm deadlines on, with nothing reading
/// the other end. For the tests below that never need a kick to fire on its
/// own -- every wake is driven by hand over the test's own raw `In` channel,
/// or the module here has no kick at all -- see `host::run`'s own doc for
/// why that degrades cleanly to `Wait::Blocked`'s behaviour (`arm`'s `send`
/// finds no bell listening) rather than needing a real one wired up. A test
/// whose module reschedules a kick and expects it to fire autonomously (this
/// file has several, all built on `faults_one_second_after_boot` or
/// `survey_then_faults_one_second_after_boot`) needs [`real_bell`] instead --
/// without a real bell, `Wait::Until` never resolves and the kick never
/// comes due.
fn no_bell() -> tokio::sync::watch::Sender<Option<Duration>> {
    tokio::sync::watch::channel(None).0
}

/// The real thing: spawns `mbbs_server::alarm`'s bell against `tx`'s own
/// channel, and returns the `watch::Sender` half for `host::run` to arm
/// deadlines on alongside the task's handle.
///
/// **The handle matters for exactly one test.** The bell holds its own clone
/// of `tx`, which keeps the channel alive even after a test drops its own
/// copy -- fine for every test that never checks whether `run` reaches
/// `Woke::Gone` (this file leaves plenty of `host_thread` handles unawaited
/// already), wrong for the one test that explicitly wants "every sender
/// gone" to be reachable
/// (`a_stale_message_from_a_dead_life_does_not_corrupt_the_new_lifes_pool`):
/// that test must `.abort()` this handle -- and `.await` it afterward, so
/// the task's own `tx` clone is actually dropped before the test drops its
/// own -- before it can observe `Woke::Gone`. See that test for the pattern.
fn real_bell(
    tx: &std::sync::mpsc::Sender<In>,
) -> (tokio::sync::watch::Sender<Option<Duration>>, tokio::task::JoinHandle<()>) {
    let (deadline_tx, deadline_rx) = tokio::sync::watch::channel(None);
    let bell = mbbs_server::alarm::spawn(deadline_rx, tx.clone());
    (deadline_tx, bell)
}

/// `In::Connect` over a raw `In`/`Out` channel, bypassing sockets and
/// `conn.rs` entirely -- the same technique
/// `a_module_that_crash_loops_makes_the_supervisor_give_up` and
/// `a_module_that_faults_during_boot_is_not_restarted` above use to drive
/// `host::run` directly. The double-free tests below need this because they
/// inject messages (a duplicate `Disconnect`, a `Disconnect`/`Input` naming a
/// channel from a life that already ended) no real client ever sends.
///
/// The `Receiver<Out>` is returned rather than dropped so the caller decides
/// its lifetime: dropping it closes the connection's `Sender<Out>` from the
/// other end (letting a caller reproduce `flush`'s send-failure path on
/// purpose), keeping it alive does not.
async fn connect_raw(tx: &std::sync::mpsc::Sender<In>, who: &str) -> (Option<Chan>, Receiver<Out>) {
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Out>(32);
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    tx.send(In::Connect {
        who: Connection::ansi(who).with_keys(std::iter::empty::<&str>()),
        out: out_tx,
        reply: reply_tx,
    })
    .expect("host thread is alive");
    let chan = reply_rx.await.expect("host thread answers Connect");
    (chan, out_rx)
}

/// Wait for `Out::Close` on a connection's receiver, or panic after ten
/// seconds naming `what`. Bytes before the close are discarded. A dropped
/// sender counts as closed, the way the connection task treats it.
async fn wait_for_close(out: &mut Receiver<Out>, what: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match out.recv().await {
                Some(Out::Close) | None => break,
                Some(Out::Bytes(_)) => continue,
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}: the channel was not closed inside 10s"));
}

/// Two `In::Connect`s, sent back-to-back with no `.await` between the two
/// `send`s, so they are already both queued before the host thread can have
/// processed either one.
///
/// This is what makes "at most one of these two may succeed" a meaningful,
/// non-flaky assertion for the double-free tests below. `apply`'s loop
/// drains *every* message already queued on one wake before it ever runs a
/// `cycle` (`host.rs`'s `life`, step 2) -- so two `Connect`s queued together
/// are always evaluated against the exact same `Pool` snapshot, in the same
/// life. Calling [`connect_raw`] twice in a row instead -- `.await`ing the
/// first reply before sending the second -- leaves a real-time gap between
/// them, and against a module that keeps re-arming a one-second kick
/// (`faults_one_second_after_boot`), a kick landing in that gap starts a
/// *fresh* life with its own, legitimately-empty `Pool` -- which would also
/// answer the second `Connect` with `Some`, for a completely different and
/// correct reason having nothing to do with a double free. This is not
/// theoretical: it is exactly what made the cross-life test below flaky
/// under load before this helper existed.
async fn connect_two_at_once(
    tx: &std::sync::mpsc::Sender<In>,
    who_a: &str,
    who_b: &str,
) -> ((Option<Chan>, Receiver<Out>), (Option<Chan>, Receiver<Out>)) {
    let (out_tx_a, out_rx_a) = tokio::sync::mpsc::channel::<Out>(32);
    let (reply_tx_a, reply_rx_a) = tokio::sync::oneshot::channel();
    let (out_tx_b, out_rx_b) = tokio::sync::mpsc::channel::<Out>(32);
    let (reply_tx_b, reply_rx_b) = tokio::sync::oneshot::channel();

    tx.send(In::Connect {
        who: Connection::ansi(who_a).with_keys(std::iter::empty::<&str>()),
        out: out_tx_a,
        reply: reply_tx_a,
    })
    .expect("host thread is alive");
    tx.send(In::Connect {
        who: Connection::ansi(who_b).with_keys(std::iter::empty::<&str>()),
        out: out_tx_b,
        reply: reply_tx_b,
    })
    .expect("host thread is alive");

    let a = reply_rx_a.await.expect("host thread answers Connect");
    let b = reply_rx_b.await.expect("host thread answers Connect");
    ((a, out_rx_a), (b, out_rx_b))
}

/// Ordinal 1 (init) faulting is a broken deployment, not a survivable stop:
/// `host::run` must return `Err` immediately, with no restart attempted.
///
/// This is the boot-failure half of `host.rs`'s module doc ("only a stop
/// reached from the steady-state driver loop restarts") -- the half every
/// other test in this file cannot exercise, because they all need boot to
/// succeed before there is a steady state to stop in.
#[tokio::test]
async fn a_module_that_faults_during_boot_is_not_restarted() {
    let module = module_file(
        "mbbs-server-host-supervisor-boot-fault",
        &builder::faults_on_ordinal_one(),
    );
    let boot = boot(module, "mbbs-server-host-supervisor-boot-fault-root", 1);

    // Held for the whole call: `run` never sends anything back over `rx`, so
    // this is purely to keep `tx` from being dropped and turning a real bug
    // (boot "succeeding" on a poisoned machine, then blocking forever on
    // `Wait::Blocked` with nothing ever arriving) into a `Woke::Gone` that
    // would return `Ok(())` and hide it. A wrapping `timeout` below is the
    // actual guard against that: this test caught exactly that bug once --
    // before `life` checked ordinal 1's `Outcome`, this test hung instead of
    // failing.
    let (_tx, rx) = std::sync::mpsc::channel();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx, no_bell())),
    )
    .await
    .expect("boot failing must return promptly, not hang the host thread")
    .expect("the host thread did not panic");

    let err = result.expect_err("a module that faults on ordinal 1 must not boot successfully");
    let text = err.to_string();
    assert!(
        text.contains("ordinal 1") || text.contains("init"),
        "the error should say boot failed at the init routine, not something else: {text:?}"
    );
}

/// `Boot::extension`, when it fails to build, is the same kind of broken
/// deployment a module that cannot load is -- `host::run` must return `Err`
/// immediately, with no restart attempted, and the message must be the
/// builder's own reason, not a generic failure.
///
/// A REAL, successfully-booting module is used here, unlike a version of
/// this test that predates the boot reorder: `life` now builds and installs
/// the extension AFTER `boot.modules` load and initialise, not before (see
/// `host.rs`'s own `ExtensionBuilder`/`Boot::extension` doc comments and the
/// declared-bindings design doc's "Boot-order consequence"), so a builder
/// that fails no longer has to be reached before any module read -- proving
/// the failure is attributable purely to the builder itself, with a module
/// that loaded and ran cleanly.
#[tokio::test]
async fn an_extension_that_fails_to_build_is_a_boot_failure_not_restarted() {
    let module = module_file(
        "mbbs-server-host-supervisor-extension-boot-fault",
        &builder::boots_and_runs_forever(),
    );
    let mut b = boot(module, "mbbs-server-host-supervisor-extension-boot-fault-root", 1);
    b.extension = Some(Box::new(|_modules| {
        Err(std::io::Error::other("stub extension refuses to build, on purpose"))
    }));

    let (_tx, rx) = std::sync::mpsc::channel();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || mbbs_server::host::run(b, rx, no_bell())),
    )
    .await
    .expect("boot failing must return promptly, not hang the host thread")
    .expect("the host thread did not panic");

    let err = result.expect_err("an extension that fails to build must not boot successfully");
    assert!(
        err.to_string().contains("stub extension refuses to build, on purpose"),
        "the error should be the builder's own reason, not a generic failure: {err}"
    );
}

/// The discriminating test for the boot reorder itself: the extension
/// builder receives a module whose export table is ALREADY populated,
/// proving `life` calls it after `Host::load` (not before). Deliberately
/// reuses the "builder fails on purpose" shape
/// (`an_extension_that_fails_to_build_is_a_boot_failure_not_restarted`)
/// rather than driving a live board to a clean shutdown: the builder itself
/// resolves a real, named export against the module it was handed and
/// turns the answer into the boot error's own message, so the assertion
/// below is a direct read of what the builder actually saw -- not an
/// inference from timing or a side channel.
///
/// This test CANNOT pass if `life` still builds the extension before
/// `Host::load` runs (the way it did before this reorder): `PING` would not
/// exist in the module's export table yet, `export_address` would answer
/// `None`, and the builder would report "NOT resolved" instead.
#[tokio::test]
async fn the_extension_builder_receives_modules_whose_export_table_is_already_populated() {
    // Booting runs the module's init routine -- the export named `_INIT__*`
    // -- so the module needs one before the builder is ever reached; `PING`
    // is the export the builder then looks up.
    let module = module_file(
        "mbbs-server-host-supervisor-extension-sees-populated-exports",
        &mbbs::testing::module_bytes_exporting_many(&[("_INIT__TESTMOD", &[0xcb]), ("PING", &[0xcb])]), // retf, retf
    );
    let mut b = boot(
        module,
        "mbbs-server-host-supervisor-extension-sees-populated-exports-root",
        1,
    );
    b.extension = Some(Box::new(|modules: &[(String, <Wg16 as mbbs::abi::Abi>::Module)]| {
        let Some((_, module)) = modules.first() else {
            return Err(std::io::Error::other("proof-of-reorder: the builder received no modules at all"));
        };
        let symbol = mbbs_machine::module::Symbol::Name("PING".to_string());
        match <Wg16 as mbbs::abi::Abi>::export_address(module, &symbol) {
            Some(_) => Err(std::io::Error::other("proof-of-reorder: PING resolved")),
            None => Err(std::io::Error::other("proof-of-reorder: PING NOT resolved -- extension built before module load")),
        }
    }));

    let (_tx, rx) = std::sync::mpsc::channel();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || mbbs_server::host::run(b, rx, no_bell())),
    )
    .await
    .expect("boot failing must return promptly, not hang the host thread")
    .expect("the host thread did not panic");

    let err = result.expect_err("the deliberate builder failure must still fail the boot");
    assert!(
        err.to_string().contains("proof-of-reorder: PING resolved"),
        "the builder must see a module whose export table is already populated, got: {err}"
    );
}

/// Two modules, in order: the first boots cleanly, the second faults on its
/// own ordinal 1. The failure must name the *second* module's own path, not
/// merely say "a module" -- see `Boot::modules`'s own doc on why an N-module
/// boot failure has to be actionable. This also proves the boot is
/// *sequential*: if `life` loaded every file before initialising any of
/// them, or initialised them out of order, this would either fail on the
/// wrong module or (loading `faults_on_ordinal_one` first) never reach the
/// second file's read at all.
///
/// The companion test below swaps the two modules' positions and checks the
/// named path flips with them -- the discriminating half, since a driver that
/// always reported (say) "the last module given" would pass this test alone.
#[tokio::test]
async fn a_second_module_faulting_on_ordinal_one_names_itself_not_the_first() {
    let first = module_file(
        "mbbs-server-host-supervisor-n-module-first-clean",
        &builder::boots_and_runs_forever(),
    );
    let second = module_file(
        "mbbs-server-host-supervisor-n-module-second-faults",
        &builder::faults_on_ordinal_one(),
    );
    let boot = boot_many(
        vec![first.clone(), second.clone()],
        "mbbs-server-host-supervisor-n-module-second-faults-root",
        1,
    );

    let (_tx, rx) = std::sync::mpsc::channel();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx, no_bell())),
    )
    .await
    .expect("boot failing must return promptly, not hang the host thread")
    .expect("the host thread did not panic");

    let err = result.expect_err("the second module's ordinal 1 fault must not boot successfully");
    let text = err.to_string();
    assert!(
        text.contains(&second.display().to_string()),
        "the error should name the module that actually faulted: {text:?}"
    );
    assert!(
        !text.contains(&first.display().to_string()),
        "the error must not blame the first module, which booted cleanly: {text:?}"
    );
    assert!(
        text.contains("ordinal 1") || text.contains("init"),
        "the error should say boot failed at the init routine, not something else: {text:?}"
    );
}

/// The mirror of the test above: the *first* module faults on ordinal 1 and
/// the second (which would otherwise boot cleanly) is never even reached --
/// its own file is never read, because `life` loads and initialises one
/// module fully before starting the next. The error names the first module,
/// proving position in `Boot::modules`, not which builder function was used,
/// is what determines which module's failure is reported.
#[tokio::test]
async fn a_first_module_faulting_on_ordinal_one_names_itself_and_the_second_is_never_reached() {
    let first = module_file(
        "mbbs-server-host-supervisor-n-module-first-faults",
        &builder::faults_on_ordinal_one(),
    );
    let second = module_file(
        "mbbs-server-host-supervisor-n-module-second-clean",
        &builder::boots_and_runs_forever(),
    );
    let boot = boot_many(
        vec![first.clone(), second.clone()],
        "mbbs-server-host-supervisor-n-module-first-faults-root",
        1,
    );

    let (_tx, rx) = std::sync::mpsc::channel();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx, no_bell())),
    )
    .await
    .expect("boot failing must return promptly, not hang the host thread")
    .expect("the host thread did not panic");

    let err = result.expect_err("the first module's ordinal 1 fault must not boot successfully");
    let text = err.to_string();
    assert!(
        text.contains(&first.display().to_string()),
        "the error should name the module that actually faulted: {text:?}"
    );
    assert!(
        !text.contains(&second.display().to_string()),
        "the second module's own file is never read once the first one's init stops the \
         machine, so its path must not appear in the error: {text:?}"
    );
}

/// The heart of Task 1: a module that stops one second after boot, with no
/// channel connected at all, is followed by the board serving again --
/// without an operator touching anything -- because [`host::run`] rebuilds
/// the machine.
///
/// This drives the stop through [`Host::prcrtk`]'s kick sweep, the *other*
/// shape from `two_real_sockets_and_one_sees_the_other`'s eventual sibling
/// below: no channel is open when the module stops, so [`Ended::Stopped`]'s
/// `Option<Chan>` must be `None` here, which this test cannot observe
/// directly (that is `mbbs`'s own unit coverage) but which is exactly the
/// path a mutation deleting the `None` arm in `crates/mbbs-server/src/host.rs`
/// would silently fall through -- reconnecting after the restart is the
/// externally-visible half of that same guarantee.
///
/// [`Host::prcrtk`]: mbbs::Host
/// [`Ended::Stopped`]: mbbs::Ended
#[tokio::test]
async fn the_board_serves_again_after_a_kick_driven_stop_with_no_channel_connected() {
    let module = module_file(
        "mbbs-server-host-supervisor-kick-fault",
        &builder::faults_one_second_after_boot(),
    );
    let boot = boot(module, "mbbs-server-host-supervisor-kick-fault-root", 1);

    let addr = conn::serve(boot, default_keys(), &[("127.0.0.1:0", mbbs_server::termcompat::Stack::modern)])
        .await
        .expect("bind 127.0.0.1:0")[0];

    // Before the kick has had a chance to fire: an ordinary connection
    // succeeds against the first life.
    let mut before = TcpStream::connect(addr).await.expect("connect before the stop");
    let mut before_buf = Vec::new();
    read_until(&mut before, &mut before_buf, "Enter your user ID: ").await;
    drop(before);

    // Wait past the one-second kick, plus slack for the restart itself
    // (a fresh `Machine`, a fresh NE load -- this synthetic module is tiny,
    // so this is generous, not tight).
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // Without any operator action, the board is serving again: a brand new
    // connection against the *second* life succeeds the same way the first
    // one did.
    let mut after = TcpStream::connect(addr).await.expect("connect after the restart");
    let mut after_buf = Vec::new();
    read_until(&mut after, &mut after_buf, "Enter your user ID: ").await;
}

/// A connection open *at the moment of the stop* gets `Out::Close` (its
/// socket is closed, not silently abandoned), and a fresh connection made
/// afterwards reaches a live board again -- the two acceptance halves the
/// plan asks for explicitly, both against the same restart.
#[tokio::test]
async fn a_connected_socket_is_closed_by_the_stop_and_a_new_one_reconnects_after() {
    let module = module_file(
        "mbbs-server-host-supervisor-connected-fault",
        &builder::faults_one_second_after_boot(),
    );
    let boot = boot(module, "mbbs-server-host-supervisor-connected-fault-root", 2);

    let addr = conn::serve(boot, default_keys(), &[("127.0.0.1:0", mbbs_server::termcompat::Stack::modern)])
        .await
        .expect("bind 127.0.0.1:0")[0];

    let mut sock = TcpStream::connect(addr).await.expect("connect");
    let mut buf = Vec::new();
    read_until(&mut sock, &mut buf, "Enter your user ID: ").await;
    // Log in far enough to hold a channel open across the stop -- this
    // module registers no `lonrou`, so `Host::connect` answers with no
    // module call at all and the login prompt above is the last thing this
    // socket will ever see from the module; what matters here is that the
    // channel exists and is connected when the kick fires.
    sock.write_all(b"tester\r").await.expect("write userid");

    // The kick fires the module's `HLT` about a second after boot; give the
    // stop and the flush it triggers (`Out::Close` to every open channel,
    // `host.rs`'s `life`) generous room.
    let closed = read_until_closed(&mut sock, &mut buf, Duration::from_secs(5)).await;
    assert!(closed, "a connection open when the module stops must have its socket closed");

    // And the board is serving again, unattended: a fresh connection after
    // the restart reaches a live login prompt.
    let mut after = TcpStream::connect(addr).await.expect("connect after the restart");
    let mut after_buf = Vec::new();
    read_until(&mut after, &mut after_buf, "Enter your user ID: ").await;
}

/// A module that stops on every single life is a crash loop, and
/// `host::run` must give up rather than rebuild forever -- the other half of
/// `RestartPolicy`'s unit tests in `host.rs`, which pin the counting and
/// windowing logic in isolation but never through `run`'s actual wiring.
/// A mutation that built a fresh, unused `RestartPolicy` per restart (so it
/// never sees more than one stop) would pass every unit test in `host.rs`
/// and only be caught here.
#[tokio::test]
async fn a_module_that_crash_loops_makes_the_supervisor_give_up() {
    let module = module_file(
        "mbbs-server-host-supervisor-crashloop",
        &builder::faults_one_second_after_boot(),
    );
    let boot = boot(module, "mbbs-server-host-supervisor-crashloop-root", 1);

    let (_tx, rx) = std::sync::mpsc::channel();
    let (deadline, _bell) = real_bell(&_tx);
    // MAX_RESTARTS lives at 5 (see `host.rs`), each one about a second (the
    // kick's minimum delay) plus a fast synthetic-module reload: comfortably
    // inside this test's own timeout, and every real restart in between is
    // still exercised -- this is not a mocked policy, it is `run` itself.
    // `real_bell`, not `no_bell`: the whole test depends on this module's
    // kick coming due five times on its own, with nothing ever sent on `_tx`.
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx, deadline)),
    )
    .await
    .expect("the supervisor must give up well inside 30s, not hang")
    .expect("the host thread did not panic");

    let err = result.expect_err("a module that stops every life must exhaust the restart policy");
    let text = err.to_string();
    assert!(
        text.contains("crash-looping") || text.contains("stopped"),
        "the error should say why the supervisor gave up: {text:?}"
    );
}

/// Task 19's headline mutation, re-derived: `crates/mbbs-server/tests/sleep.rs`
/// documents (its own "Mutation 2's honest result") that forcing
/// `Ended::Waiting`'s arm to answer `Wait::Blocked` instead of
/// `Wait::Until(next_kick)` did NOT turn that test red -- with no other wake
/// source in its measurement window, `clock_reads` reads ~0 either way, so a
/// driver that stopped waking for timers looked identical to one sleeping
/// correctly. Catching it, that section says, needs "a different test... one
/// that asserts forward progress on a kick-driven event... within a bounded
/// wall-clock window." This is that test.
///
/// `faults_one_second_after_boot`'s kick makes forward progress cheap to
/// observe from outside without a real DLL: firing it halts the machine,
/// `run` restarts, and five restarts inside sixty seconds is an `Err` this
/// test can wait for -- with `tx` held alive (so a dropped sender can never
/// masquerade as the bug by producing a clean `Woke::Gone`) and NEVER sent
/// to. Under the real driver, the bell alone wakes it once a second and it
/// reaches that `Err` in a handful of seconds. Under the mutation, nothing
/// ever arms a deadline at all (`arm` sees `Wait::Blocked` and sends `None`
/// -- see `arm`'s own doc), so `rx.recv()` blocks forever and `run` never
/// returns; the `timeout` below is what turns that into a clean failure
/// instead of a hang.
///
/// Run by hand with `Ended::wait`'s `Waiting` arm changed to return
/// `Wait::Blocked` (mirroring `sleep.rs`'s own mutation), this test times
/// out -- red, as intended. See this task's own report for the exact output.
#[tokio::test]
async fn a_kick_reaches_five_restarts_with_no_external_wake_ever_sent() {
    let module = module_file(
        "mbbs-server-host-supervisor-kick-only-wake",
        &builder::faults_one_second_after_boot(),
    );
    let boot = boot(module, "mbbs-server-host-supervisor-kick-only-wake-root", 1);

    let (tx, rx) = std::sync::mpsc::channel::<In>();
    let (deadline, _bell) = real_bell(&tx);

    let result = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx, deadline)),
    )
    .await
    .expect(
        "a driver that genuinely wakes for its own timers reaches the five- \
         restart crash-loop ceiling well inside 20s with nothing external \
         ever sent; a driver that stopped waking for timers (the \
         Wait::Blocked mutation sleep.rs documents as otherwise invisible) \
         hangs here forever instead",
    )
    .expect("the host thread did not panic");

    let err = result.expect_err("five restarts inside the window must give up");
    assert!(
        err.to_string().contains("stopped") || err.to_string().contains("crash-looping"),
        "must be the crash-loop message, not some other error: {err}"
    );

    // `tx` is still alive and was never sent to -- explicit, not merely
    // implied by scope, since a premature drop turning into `Woke::Gone`
    // would be exactly the kind of "passes for the wrong reason" this test
    // exists to rule out.
    drop(tx);
}

/// The other half of design doc §7's frozen-world defence: the wake-age
/// meter (`Boot::wake_age_ms`). Where the test above proves the *driver*
/// still reaches a kick with no external wake, this proves the *meter*
/// notices when it stops being able to -- stamped fresh every turn while a
/// live bell keeps `reschedules_forever`'s perpetual kick coming due, and
/// left stale, provably past the kick's own interval, once the bell is
/// killed.
#[tokio::test]
async fn a_dead_bell_leaves_the_wake_age_meter_stale() {
    let module = module_file(
        "mbbs-server-host-supervisor-wake-age",
        &builder::reschedules_forever(1),
    );
    let wake_age = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut boot = boot(module, "mbbs-server-host-supervisor-wake-age-root", 1);
    boot.wake_age_ms = Some(std::sync::Arc::clone(&wake_age));

    let (tx, rx) = std::sync::mpsc::channel::<In>();
    let (deadline, bell) = real_bell(&tx);
    let _host_thread = tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx, deadline));

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_millis() as u64
    }
    fn age_of(wake_age: &std::sync::atomic::AtomicU64) -> u64 {
        now_ms().saturating_sub(wake_age.load(std::sync::atomic::Ordering::Relaxed))
    }

    // Let a couple of live, bell-driven turns happen -- boot itself, plus at
    // least one real kick firing.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let fresh = age_of(&wake_age);
    assert!(
        fresh < 1_500,
        "with a live bell and a one-second kick, the driver must have turned \
         within the last 1.5s; measured {fresh}ms stale"
    );

    // Kill the bell. Nothing else in this test ever sends on `tx`, so the
    // driver's only remaining path back to `rx.recv()` returning was a real
    // Alarm -- which will now never arrive again.
    bell.abort();

    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let stale = age_of(&wake_age);
    assert!(
        stale > 1_000,
        "a dead bell must leave the driver's last turn more than one kick \
         interval (1s) in the past; measured {stale}ms"
    );

    drop(tx);
}

/// The restart path works for `Poison::Unimplemented`, not only
/// `Poison::Fault` -- every test above this one reaches its stop through
/// `HLT`, which is the shape this test exists to break. A real board's
/// actual walls (`l2as`, the fourth-wall symbol this whole plan was written
/// to survive -- see `docs/plans/2026-08-11-survivability-and-the-reachable-
/// surface.md`) are `Unimplemented`, never `Fault`: a mutation that special-
/// cased `Poison::Fault` in `host.rs`'s `life`/`run` (instead of treating
/// every `Poison` identically, as `mbbs_machine::m16::Machine::poison` itself does)
/// would pass every other test in this file and only be caught here.
#[tokio::test]
async fn the_board_serves_again_after_an_unimplemented_symbol_stop() {
    let module = module_file(
        "mbbs-server-host-supervisor-unimplemented-fault",
        &builder::faults_via_unimplemented_symbol_one_second_after_boot(),
    );
    let boot = boot(module, "mbbs-server-host-supervisor-unimplemented-fault-root", 1);

    let addr = conn::serve(boot, default_keys(), &[("127.0.0.1:0", mbbs_server::termcompat::Stack::modern)])
        .await
        .expect("bind 127.0.0.1:0")[0];

    let mut before = TcpStream::connect(addr).await.expect("connect before the stop");
    let mut before_buf = Vec::new();
    read_until(&mut before, &mut before_buf, "Enter your user ID: ").await;
    drop(before);

    tokio::time::sleep(Duration::from_millis(2500)).await;

    let mut after = TcpStream::connect(addr).await.expect("connect after the restart");
    let mut after_buf = Vec::new();
    read_until(&mut after, &mut after_buf, "Enter your user ID: ").await;
}

/// Path 1 of the double-free defect fixed alongside this test (see
/// `crates/mbbs-server/src/pool.rs`'s `give_back` doc, and `host.rs`'s
/// `apply`): a channel's output-send failure (`flush`) and a queued
/// `Disconnect` for the *same* connection (`apply`'s `In::Disconnect` arm)
/// can both reach `Pool::give_back` for the one disconnect. This predates
/// the restart supervisor entirely -- no module stop and no restart is
/// needed, just an ordinary client whose socket closed.
///
/// `builder::boots_and_runs_forever` is deliberately not one of the
/// fault-driven modules above: this test wants one life that keeps running,
/// so the duplicate free lands on the *same* life's `Pool` rather than a
/// fresh one after a restart -- that cross-life shape is Path 2, the next
/// test below.
///
/// This drives `host::run` directly over a raw `In`/`Out` channel
/// ([`connect_raw`]) rather than through real sockets: it has to inject a
/// *duplicate* `Disconnect` by hand, which no real client's `conn.rs` task
/// ever sends on its own.
#[tokio::test]
async fn a_duplicate_disconnect_after_a_send_failure_does_not_let_two_clients_share_a_channel() {
    let module = module_file(
        "mbbs-server-host-supervisor-duplicate-disconnect",
        &builder::boots_and_runs_forever(),
    );
    let boot = boot(module, "mbbs-server-host-supervisor-duplicate-disconnect-root", 1);

    let (tx, rx) = std::sync::mpsc::channel::<In>();
    let host_thread = tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx, no_bell()));

    // Connection A takes the only channel. Its output receiver is dropped
    // immediately -- `flush`'s next `try_send` to it will see `Closed`,
    // exactly as a real client's dropped `Sender<Out>` looks once its conn
    // task has exited on EOF (`conn.rs`'s `pump`, the `Ok(0) | Err(_)` arm).
    let (chan_a, out_rx_a) = connect_raw(&tx, "conn-a").await;
    let chan_a = chan_a.expect("the only channel");
    drop(out_rx_a);

    // A byte of input makes GSBL echo it straight back
    // (`gsbl::Channel::take`, step 11) -- that queues output for the
    // channel, which is what gives `flush` something to fail to send on its
    // next pass.
    tx.send(In::Input { chan: chan_a, bytes: b"x".to_vec() })
        .expect("host thread is alive");

    // Generous slack for the host thread to wake, drain the message, run a
    // cycle, and have `flush` discover the closed sender -- hangup, give the
    // channel back, and clear `conns[0]`. This is Path 1's first, legitimate
    // free.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The duplicate: a `Disconnect` for the very same channel, arriving
    // exactly as it would if `apply` drained a queued `Disconnect` after
    // `flush` had already hung the same connection up moments earlier.
    // Before this fix, `apply`'s `In::Disconnect` arm had no guard and
    // `Pool::give_back` had no guard either -- this would push a second
    // copy of channel 0 into the free list.
    tx.send(In::Disconnect { chan: chan_a }).expect("host thread is alive");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // With `terms == 1`, at most one of the next two connections may
    // succeed. Before the fix, the doubled free list would have handed
    // channel 0 to both. Sent as one batch ([`connect_two_at_once`]) rather
    // than two separate awaited connects, so there is no real-time gap for
    // anything else to land in between.
    let ((chan_b, _out_rx_b), (chan_c, _out_rx_c)) = connect_two_at_once(&tx, "conn-b", "conn-c").await;

    assert!(chan_b.is_some(), "the freed channel must be takeable once");
    assert!(
        chan_c.is_none(),
        "and only once -- a second successful connect on a one-channel \
         board means the duplicate Disconnect doubled the free list, and \
         chan_b and chan_c would be the same Chan sharing one real channel: \
         {chan_c:?}"
    );

    drop(tx);
    let result = tokio::time::timeout(Duration::from_secs(5), host_thread)
        .await
        .expect("host thread must exit once every sender is dropped")
        .expect("the host thread did not panic");
    assert!(result.is_ok(), "the host thread must exit cleanly: {result:?}");
}

/// Path 2 of the double-free defect: a connection whose `Out::Close` never
/// lands (`life`'s `let _ = conn.try_send(Out::Close)` silently drops on a
/// full or closed `Sender<Out>`) can survive past a restart holding a
/// channel identity that was only ever valid in the life that just ended.
/// The next life starts with a fresh `Pool` and fresh `conns`
/// (`host.rs`'s `life`), both all-unconnected, so a message using that stale
/// identity must be ignored rather than corrupting the new life's
/// bookkeeping.
///
/// This does not attempt to actually wedge a real client's bounded output
/// queue full -- there is no module output to fill it with here
/// (`faults_one_second_after_boot` registers no `lonrou`, so nothing is ever
/// queued for a connected channel to begin with). It instead does directly,
/// over the raw `In` channel, exactly what a straggling conn task would do
/// on its own once the restart has happened underneath it: send a
/// `Disconnect` and an `Input` naming a channel from the life that just
/// ended. `host::run`'s `rx` is the *same* receiver for the whole
/// supervisor -- `run` calls `life(&boot, &rx)` in a loop on it, never
/// building a new one -- so this is exactly the channel a real straggling
/// conn task would still hold a `Sender` for.
///
/// This test's black-box observation is the `Pool` corruption a stale
/// `Disconnect` would cause (a doubled free list, the same symptom the Path
/// 1 test above checks for). The stale `Input`'s harm -- a dead session's
/// keystrokes landing in GSBL for whichever connection takes the channel
/// next -- is not independently observable through this synthetic module,
/// which registers no `lonrou` to read them back out; that guard is pinned
/// precisely at the unit level instead, by
/// `apply_ignores_input_for_a_channel_nobody_is_connected_on` in
/// `crates/mbbs-server/src/host.rs`. It is still sent here, alongside the
/// stale `Disconnect`, so this test also stands as evidence that the guard
/// does not crash the host thread or otherwise disrupt the new life when
/// both stale messages arrive together.
#[tokio::test]
async fn a_stale_message_from_a_dead_life_does_not_corrupt_the_new_lifes_pool() {
    let module = module_file(
        "mbbs-server-host-supervisor-stale-cross-life",
        &builder::faults_one_second_after_boot(),
    );
    let boot = boot(module, "mbbs-server-host-supervisor-stale-cross-life-root", 1);

    let (tx, rx) = std::sync::mpsc::channel::<In>();
    let (deadline, bell) = real_bell(&tx);
    let host_thread = tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx, deadline));

    // The first life: connect once to get a genuine Chan value from *this*
    // board -- with terms == 1 it can only ever be channel 0, but obtaining
    // it through a real Connect (rather than minting one by hand) is what
    // makes this "a channel identity from an earlier life" rather than an
    // assumption about the type's representation.
    let (stale_chan, out_rx1) = connect_raw(&tx, "life-one").await;
    let stale_chan = stale_chan.expect("the only channel, in the first life");
    drop(out_rx1); // this connection's task, gone without ever sending Disconnect

    // Past the kick's one second, plus slack for the restart itself (a
    // fresh Machine, a fresh NE load -- this synthetic module is tiny, so
    // this is generous, not tight; the same budget the fault-driven tests
    // above use). Every life this module boots re-registers the same
    // one-second kick, so more than one restart can happen inside this
    // window -- that is fine: the test only needs to be *some* life after
    // the one `stale_chan` came from, never specifically the second.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // The stale messages: a Disconnect and an Input, both naming
    // `stale_chan` -- a channel identity from a life that has already
    // ended -- but arriving at whichever life is running now, which started
    // with a fresh, all-unconnected Pool and conns.
    tx.send(In::Disconnect { chan: stale_chan }).expect("host thread is alive");
    tx.send(In::Input { chan: stale_chan, bytes: b"EVIL\r".to_vec() })
        .expect("host thread is alive");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // If the stale Disconnect corrupted the current life's Pool (a second
    // free-list copy of the one channel), the second of these two connects
    // would succeed when it must not. Sent as one batch
    // ([`connect_two_at_once`]) rather than two separately-awaited connects:
    // this module keeps re-arming its one-second kick on every life it
    // boots, so a real-time gap between two sequential connects risks a
    // *fresh* restart landing in between, which would answer the second
    // connect with `Some` for a completely unrelated, correct reason (a new
    // life's legitimately empty `Pool`) and make this assertion flaky rather
    // than wrong.
    let ((b, out_rx_b), (c, out_rx_c)) = connect_two_at_once(&tx, "later-life-b", "later-life-c").await;
    assert!(b.is_some(), "the current life's channel must still be takeable");
    assert!(
        c.is_none(),
        "and only once -- a second successful connect means the stale \
         Disconnect doubled the current life's free list: {c:?}"
    );
    drop(out_rx_b);
    drop(out_rx_c);

    // The bell holds its own clone of `tx` (see `real_bell`'s doc) -- kill it
    // and wait for it to actually finish unwinding before dropping this
    // test's own `tx`, or that clone would keep the channel alive and
    // `Woke::Gone` would never come.
    bell.abort();
    let _ = bell.await;

    drop(tx);
    let result = tokio::time::timeout(Duration::from_secs(5), host_thread)
        .await
        .expect("host thread must exit once every sender is dropped")
        .expect("the host thread did not panic");
    assert!(
        result.is_ok(),
        "a stale cross-life Disconnect/Input must not poison the machine or \
         otherwise crash the host thread: {result:?}"
    );
}

// --- Survey mode (Task 2, docs/plans/2026-08-11-survivability-and-the-reachable-surface.md).
//
// `mbbs::survey`'s own unit tests, and `crates/mbbs/src/lib.rs`'s
// `Host::run` integration tests, cover the mechanics (continuation,
// counting, deduplication, the cleanup-convention refusal) against an
// in-memory `Inventory`. What only *this* file can prove is constraint 5:
// that the inventory survives `host::run`'s own restart loop, which rebuilds
// `Machine` and `Host` -- everything survey mode touches inside `mbbs` --
// from scratch on every life. `survey_then_faults_one_second_after_boot`
// fires the identical kick, calling the identical unimplemented symbol, on
// every life it boots; if the inventory were rebuilt along with `Host` each
// time, the file this test reads back could never show more than one
// occurrence.

/// The inventory a survey session leaves behind is the one shared across
/// every restart, not a fresh one per life.
///
/// If constraint 5 were broken -- an inventory attached to (or owned by) the
/// per-life `Host` instead of built once in `run` -- this module's kick
/// would still record its one call each life, but every life would start
/// counting from zero, and the file `run`'s clean-shutdown `finish()` writes
/// at the end could never show more than a count of `1` no matter how many
/// times the board restarted. Driven all the way to `RestartPolicy`'s own
/// give-up, the same way `a_module_that_crash_loops_makes_the_supervisor_give_up`
/// is, so the count this test asserts on is a hard lower bound
/// (`MAX_RESTARTS`, from `host.rs`), not a timing guess.
#[tokio::test]
async fn the_survey_inventory_survives_every_restart() {
    let module = module_file(
        "mbbs-server-host-supervisor-survey-restart",
        &builder::survey_then_faults_one_second_after_boot(),
    );
    let survey_path = mbbs::testing::scratch("mbbs-server-host-supervisor-survey-restart-out")
        .join("survey.log");
    let mut boot = boot(module, "mbbs-server-host-supervisor-survey-restart-root", 1);
    boot.survey = Some(survey_path.clone());

    let (_tx, rx) = std::sync::mpsc::channel();
    let (deadline, _bell) = real_bell(&_tx);
    // Same budget `a_module_that_crash_loops_makes_the_supervisor_give_up`
    // uses for the identical reason: five restarts, a second's kick delay
    // apiece, plus a fast synthetic-module reload each time. Real bell, same
    // reason: nothing here ever sends on `_tx`.
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx, deadline)),
    )
    .await
    .expect("the supervisor must give up well inside 30s, not hang")
    .expect("the host thread did not panic");
    assert!(
        result.is_err(),
        "this module faults every life; the supervisor must eventually give up: {result:?}"
    );

    let text = std::fs::read_to_string(&survey_path).expect("the survey file must exist");
    let row = text
        .lines()
        .find(|line| line.contains("definitely_not_a_real_host_routine"))
        .unwrap_or_else(|| panic!("no row for the recorded symbol in:\n{text}"));
    let count: u64 = row
        .split('\t')
        .next()
        .expect("a row always has a count column")
        .parse()
        .unwrap_or_else(|e| panic!("count column was not a number ({e}): {row:?}"));
    assert!(
        count >= 5,
        "MAX_RESTARTS (5) lives each recorded this same call once; a fresh \
         per-life inventory could never show more than 1: got {count} in {row:?}"
    );
}

/// The other half of constraint 6: what is on disk *without* `host::run`
/// ever reaching a clean exit -- the closest a test gets to simulating
/// `kill -9`, since nothing here ever signals or awaits the host thread's
/// own completion.
///
/// `mbbs::survey::Inventory`'s own unit tests already prove `record` flushes
/// a first sighting to its file directly; this test exists only to prove
/// `crates/mbbs-server/src/host.rs`'s wiring actually reaches that method at
/// all, end to end, through a real restart loop, before anything resembling
/// a graceful shutdown could have run.
#[tokio::test]
async fn the_survey_inventory_is_on_disk_long_before_any_clean_shutdown() {
    let module = module_file(
        "mbbs-server-host-supervisor-survey-durability",
        &builder::survey_then_faults_one_second_after_boot(),
    );
    let survey_path = mbbs::testing::scratch("mbbs-server-host-supervisor-survey-durability-out")
        .join("survey.log");
    let mut boot = boot(module, "mbbs-server-host-supervisor-survey-durability-root", 1);
    boot.survey = Some(survey_path.clone());

    // Held for the sleep below so the host thread's `wake` does not see
    // every sender gone and shut down gracefully before the kick ever
    // fires -- this test's whole point is to look *without* a graceful
    // shutdown ever having happened.
    let (tx, rx) = std::sync::mpsc::channel();
    let (deadline, _bell) = real_bell(&tx);
    let _host_thread = tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx, deadline));

    // Past the kick's one-second delay, comfortably short of the restart
    // that follows it -- this reads the file mid-flight, not after `run`
    // has returned (this test never awaits `_host_thread` at all).
    tokio::time::sleep(Duration::from_millis(1500)).await;
    drop(tx);

    let text = std::fs::read_to_string(&survey_path)
        .expect("the survey file must already exist -- record() flushes on first sight");
    assert!(
        text.contains("MAJORBBS") && text.contains("definitely_not_a_real_host_routine"),
        "the first sighting must be on disk with no clean shutdown in sight: {text:?}"
    );
}

/// `In::Shutdown` ends the host thread instead of being treated as a stop the
/// supervisor should restart around.
///
/// The distinction matters more than it looks. `RestartPolicy` exists to keep
/// a board alive through a module that faults, and a shutdown reaching that
/// path would rebuild the machine -- taking the board back up, and, for a
/// module like MajorMUD, rewriting the `WCCRECOV.FLG` its `finrou` had just
/// removed. "Shut down" and "died" have to be different answers.
///
/// The thread's exit is observed through the channel rather than a join
/// handle, which `spawn_machine` does not hand back: once the host thread
/// returns, its `Receiver<In>` drops, and every later `send` fails. Polled
/// with a deadline rather than slept on, so a slow machine does not make this
/// flaky and a broken one still fails in bounded time.
#[tokio::test]
async fn a_shutdown_ends_the_host_thread_and_does_not_restart_it() {
    let module = module_file(
        "mbbs-server-host-supervisor-shutdown",
        &builder::boots_and_runs_forever(),
    );
    let tx = conn::spawn_machine(boot(module, "mbbs-server-host-supervisor-shutdown-root", 1));

    let (done, wait) = tokio::sync::oneshot::channel();
    tx.send(In::Shutdown { done }).expect("the host thread is alive to receive it");

    tokio::time::timeout(Duration::from_secs(30), wait)
        .await
        .expect("shutdown must complete inside the grace period, not hang")
        .expect("the host thread answers rather than dropping the sender");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if tx.send(In::Alarm).is_err() {
            return; // the receiver is gone: the thread returned and stayed gone
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the host thread was still accepting messages 10s after it said it had shut down");
}

/// `In::Maintain` hangs up every connected channel and the next life serves
/// a fresh connect. Driven over the raw `In` channel: `connect_raw`'s reply
/// only arrives once the new life is polling, so no sleep is needed to know
/// the reboot finished.
#[tokio::test]
async fn a_maintain_closes_a_connected_channel_and_the_next_life_serves() {
    let module = module_file(
        "mbbs-server-host-supervisor-maintain",
        &builder::boots_and_runs_forever(),
    );
    let tx = conn::spawn_machine(boot(module, "mbbs-server-host-supervisor-maintain-root", 1));

    let (chan, mut out) = connect_raw(&tx, "before").await;
    assert!(chan.is_some(), "the first life serves the only channel");

    tx.send(In::Maintain).expect("the host thread is alive");

    wait_for_close(&mut out, "maintenance").await;

    let (chan, _out) = connect_raw(&tx, "after").await;
    assert!(chan.is_some(), "the life after maintenance serves the channel again");
}

/// The deadline fires without any message from outside: a two-second
/// interval closes a connected channel and the next life serves. An idle
/// module asks for `Wait::Blocked`, so without the clamp nothing would ever
/// wake the driver and this test hangs.
#[tokio::test]
async fn maintenance_fires_on_its_own_at_the_deadline() {
    let module = module_file(
        "mbbs-server-host-supervisor-maintain-timer",
        &builder::boots_and_runs_forever(),
    );
    let mut boot = boot(module, "mbbs-server-host-supervisor-maintain-timer-root", 1);
    boot.maintenance_interval = Duration::from_secs(2);
    let tx = conn::spawn_machine(boot);

    let (chan, mut out) = connect_raw(&tx, "before").await;
    assert!(chan.is_some());

    wait_for_close(&mut out, "the timed maintenance deadline").await;

    let (chan, _out) = connect_raw(&tx, "after").await;
    assert!(chan.is_some(), "the life after the timed maintenance serves again");
}

/// A maintenance reload is not a stop. `MAX_RESTARTS` is five, so six
/// reloads inside the window prove the restart policy was never consulted.
///
/// Each round waits for its own probe's `Out::Close` before the next
/// connect. `drain_turn` puts everything queued in one wake into a single
/// batch, in no particular order, so a `Connect` sent right after a
/// `Maintain` with no wait between them can land in the very same batch as
/// that `Maintain` and get applied against the old life's pool before the
/// teardown that would have freed it runs. Waiting for `Close`, which
/// `tear_down` sends only once that teardown has actually hung the probe
/// up, guarantees the next `Connect` is sent after the batch that carried
/// the `Maintain` is long over, so it lands in the new life instead.
#[tokio::test]
async fn six_maintenances_in_a_row_leave_the_board_serving() {
    let module = module_file(
        "mbbs-server-host-supervisor-maintain-six",
        &builder::boots_and_runs_forever(),
    );
    let tx = conn::spawn_machine(boot(module, "mbbs-server-host-supervisor-maintain-six-root", 1));

    for round in 0..6 {
        let (chan, mut out) = connect_raw(&tx, "probe").await;
        assert!(chan.is_some(), "round {round}: the board must be serving before each maintenance");
        tx.send(In::Maintain).expect("the host thread is alive");
        // Wait for this probe's hangup before the next connect. The Close is
        // sent inside the teardown, so a Connect sent after it cannot share
        // a batch with the Maintain and is answered by the next life.
        wait_for_close(&mut out, &format!("round {round}: maintenance")).await;
    }

    let (chan, _out) = connect_raw(&tx, "final").await;
    assert!(chan.is_some(), "after six maintenances the board still serves");
}

/// Slot 6 is what maintenance dispatches. The only thing this module's
/// `mcurou` does is call a symbol nothing else calls, and only the survey
/// inventory can see that it happened.
#[tokio::test]
async fn maintenance_runs_the_modules_mcurou() {
    let module = module_file(
        "mbbs-server-host-supervisor-mcurou-runs",
        &builder::cleans_up_via_unimplemented_symbol(),
    );
    let survey_path = mbbs::testing::scratch("mbbs-server-host-supervisor-mcurou-runs-out")
        .join("survey.log");
    let _ = std::fs::remove_file(&survey_path);
    let mut boot = boot(module, "mbbs-server-host-supervisor-mcurou-runs-root", 1);
    boot.survey = Some(survey_path.clone());
    let tx = conn::spawn_machine(boot);

    let (chan, mut out) = connect_raw(&tx, "before").await;
    assert!(chan.is_some());
    tx.send(In::Maintain).expect("alive");
    // Wait for this probe's hangup before the next connect. The Close is
    // sent inside the teardown, so a Connect sent after it cannot share a
    // batch with the Maintain and is answered by the next life.
    wait_for_close(&mut out, "maintenance").await;

    // Answered only once the next life is polling, so maintenance is over.
    let (chan, _out2) = connect_raw(&tx, "after").await;
    assert!(chan.is_some());

    let text = std::fs::read_to_string(&survey_path).expect("the survey file must exist");
    assert!(
        text.contains("definitely_not_a_real_host_routine"),
        "mcurou never ran: the symbol only it calls is missing from:\n{text}"
    );
}

/// A module that stops inside its `mcurou` ends the life `Stopped`, and the
/// restart policy applies: five stops are survived, the sixth is not.
#[tokio::test]
async fn a_stop_inside_mcurou_counts_against_the_restart_policy() {
    let module = module_file(
        "mbbs-server-host-supervisor-mcurou-stops",
        &builder::cleans_up_via_unimplemented_symbol(),
    );
    let tx = conn::spawn_machine(boot(module, "mbbs-server-host-supervisor-mcurou-stops-root", 1));

    for round in 0..5 {
        let (chan, mut out) = connect_raw(&tx, "probe").await;
        assert!(chan.is_some(), "round {round}: still serving after {round} stop(s)");
        tx.send(In::Maintain).expect("alive");
        // Same synchronisation as `six_maintenances_in_a_row_leave_the_board_serving`:
        // wait for this round's hangup before the next connect, so a
        // Connect sent right after cannot share a batch with the Maintain
        // and get applied against the dying life's pool.
        wait_for_close(&mut out, &format!("round {round}: maintenance")).await;
    }
    let (chan, _out) = connect_raw(&tx, "probe").await;
    assert!(chan.is_some(), "the fifth stop is still survived");
    tx.send(In::Maintain).expect("alive");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if tx.send(In::Alarm).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("six stops inside mcurou must make the supervisor give up, and it was still alive");
}
