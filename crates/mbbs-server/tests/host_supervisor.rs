//! Task 1's acceptance test: the host thread survives a module stop.
//!
//! `re/WCCMMUD.DLL` is not used here on purpose. Reaching a real wall in it
//! (`l2as` via a monster kill, say) needs a live character and a live
//! monster; this file needs a *deterministic* one, on demand, from a module
//! built byte by byte -- the same technique `mbbs16/tests/ne.rs` uses for the
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
use tokio::time::Instant;

use mbbs_server::conn::{self, default_keys};
use mbbs_server::host::Boot;

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
/// from `mbbs16/tests/ne.rs`'s own builder, which is private to that crate's
/// test binary and cannot be imported from here (the same situation
/// `mbbs::testing::minimal_module_bytes`'s doc comment already describes).
/// This is a smaller, single-purpose version: just enough NE format to
/// register with the host and, on cue, run `HLT` -- a privileged
/// instruction that raises `SIGSEGV` inside the sandboxed segment
/// (`crates/mbbs16/tests/fault.rs` pins the same trick) -- which is what
/// gives every test in this file a *deterministic* module stop instead of
/// one that depends on a live board and a monster kill.
mod builder {
    /// Logical sector alignment, as a shift count. Small, so a two-segment
    /// module is a few hundred bytes rather than a few thousand -- the same
    /// choice `mbbs16/tests/ne.rs` makes and for the same reason.
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

    /// `call far ptr16:16` -- `9A cd`, to a thunk the loader hands out for
    /// `MAJORBBS.<name>` (module reference 1, the only one this module
    /// imports). Every relocation here is `IMPORTNAME`/`FAR_ADDR`, a single
    /// non-additive link (the placeholder `0xFFFF` is `CHAIN_END`) -- the
    /// same shape `mbbs16/tests/ne.rs`'s `IMPORTNAME` case pins.
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

    /// The same shape as [`faults_one_second_after_boot`], but the kick's
    /// routine calls a symbol this host has no shim for
    /// (`shims::entry` falls through to `Entry::Unimplemented`) instead of
    /// executing `HLT`.
    ///
    /// Every other test in this file reaches its stop through
    /// `Poison::Fault` -- that is the shape every test up to this one
    /// shares, and `mbbs16::Machine::poison` does not care which `Poison`
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

    /// Assemble `ne` into the bytes [`mbbs16::Machine::load_ne`] (through
    /// [`mbbs::Host::load`]) accepts. Modelled on `mbbs16/tests/ne.rs`'s
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

        let mut restab = pstring("TESTMOD", 0);
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
/// returns its path -- `Boot::module` wants a path, not bytes in memory.
fn module_file(name: &str, bytes: &[u8]) -> PathBuf {
    let dir = mbbs::testing::scratch(name);
    let path = dir.join("TESTMOD.DLL");
    std::fs::write(&path, bytes).expect("write the synthetic module");
    path
}

fn boot(module: PathBuf, root_name: &str, terms: u16) -> Boot {
    Boot {
        root: mbbs::testing::scratch(root_name),
        module,
        terms: mbbs::Terms::new(terms),
        polls_per_wake: 8,
        passes: 32,
        clock_reads: None,
    }
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
        tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx)),
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
    // MAX_RESTARTS lives at 5 (see `host.rs`), each one about a second (the
    // kick's minimum delay) plus a fast synthetic-module reload: comfortably
    // inside this test's own timeout, and every real restart in between is
    // still exercised -- this is not a mocked policy, it is `run` itself.
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || mbbs_server::host::run(boot, rx)),
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

/// The restart path works for `Poison::Unimplemented`, not only
/// `Poison::Fault` -- every test above this one reaches its stop through
/// `HLT`, which is the shape this test exists to break. A real board's
/// actual walls (`l2as`, the fourth-wall symbol this whole plan was written
/// to survive -- see `docs/plans/2026-08-11-survivability-and-the-reachable-
/// surface.md`) are `Unimplemented`, never `Fault`: a mutation that special-
/// cased `Poison::Fault` in `host.rs`'s `life`/`run` (instead of treating
/// every `Poison` identically, as `mbbs16::Machine::poison` itself does)
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
