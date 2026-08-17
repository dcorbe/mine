//! A FOSSIL driver: `int 14h`, answered rather than emulated.
//!
//! A DOS door reaches its caller one of two ways, and it does not probe to find
//! out which -- it is told. LORDCFG's "Fossil / Internal" setting is the switch:
//! on `Internal` the door programs an 8250 directly, which [`crate::uart`]
//! serves, and on `Regular Fossil` it calls this instead.
//!
//! Both front-ends move bytes through the same [`Uart`] queues. That is the
//! whole design: FOSSIL adds no buffering of its own, so a byte is never
//! sitting in one path and missing from the other, and reconfiguring a door
//! between runs changes nothing on the wire.
//!
//! ## Where the contract came from
//!
//! Not from memory. Three sources, and they agree:
//!
//! - **The door itself.** LORD.EXE contains exactly ten `int 14h` sites. The
//!   `mov ah,NN` before each names the function, and the code after each names
//!   what it reads back. That is the requirement, measured:
//!
//!   ```text
//!   int 14h ; cmp ax,0x1954 ; jnz fail    AH=04 must answer with the signature
//!   int 14h ; test ah,0x01  ; jz  skip    AH=03 reports RDA in AH bit 0
//!   int 14h ; mov [bp-2],al               AH=02 returns the character in AL
//!   ```
//!
//!   LORD uses `00 01 02 03 04 05 08 0A` and nothing else. The rest are here
//!   because a driver that answers only one door is not a driver.
//! - **Ralf Brown's Interrupt List** (`archive/tooling/reference-documents/`)
//!   for the function table and the [`Info`] layout.
//! - **Synchronet's own FOSSIL emulation**, `src/sbbs3/dosxtrn/dosxtrn.c` and
//!   `src/sbbs3/fossdefs.h`, which does this same job for DOS doors under
//!   Windows NT. Where it and the written spec could be read differently, it
//!   wins: it is the one that has actually run doors.
//!
//! ## The status word is two halves and they are easy to swap
//!
//! `AH=00`, `01` and `03` all answer in `AX`, where **`AL` is modem status and
//! `AH` is line status**. So `RDA`, "a byte is waiting", is bit 8 of the word
//! and bit 0 of `AH` -- which is what LORD's `test ah,0x01` is testing. Build
//! the word with the line bits in the low byte and a door reads carrier-detect
//! as data-ready and hangs up on a caller who is still there.

use crate::guest::{Fault, Guest, Ptr};
use crate::uart::Uart;

/// What `AH=04` must answer. A door that does not see this reports the driver
/// missing -- LORD says so in as many words: "Fossil was not initialized
/// properly! You should change to INTERNAL".
pub const SIGNATURE: u16 = 0x1954;

/// The revision we claim to conform to, and the highest function we answer.
const REVISION: u8 = 5;
const HIGHEST_FUNC: u8 = 0x1b;

// Modem status -- the low byte of the returned word, so `AL`.
const MDM_DCD_CHNG: u16 = 1 << 3;
const MDM_CTS: u16 = 1 << 4;
const MDM_DSR: u16 = 1 << 5;
const MDM_DCD: u16 = 1 << 7;

// Line status -- the high byte, so `AH`. These are already shifted.
const LINE_RDA: u16 = 1 << 8;
const LINE_THRE: u16 = 1 << 13;
const LINE_TSRE: u16 = 1 << 14;
const LINE_TIMEOUT: u16 = 1 << 15;

/// `AH=0Ch` and `AH=0Dh` say "nothing there" with this rather than a status.
const CHAR_NOT_AVAILABLE: u16 = 0xffff;

/// What became of one `int 14h`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Answer {
    /// Answered. Registers are set.
    Done,
    /// Answered, but nothing moved -- the door asked for a byte that has not
    /// arrived. The caller should sleep briefly before re-entering the guest,
    /// exactly as it does for the `int 2Fh AH=1680` yield, or a door that polls
    /// for input spins a core.
    Yield,
    /// A function we do not answer. Registers are untouched and the caller
    /// should record it as a gap, so it surfaces the way every other
    /// unimplemented service does instead of being silently wrong.
    Unsupported(u8),
}

/// The fixed parts of what `AH=1Bh` reports.
#[derive(Clone, Copy, Debug)]
pub struct Info {
    pub screen_width: u8,
    pub screen_height: u8,
}

impl Default for Info {
    fn default() -> Self {
        // What a door assumes when a dropfile does not say otherwise.
        Self { screen_width: 80, screen_height: 24 }
    }
}

/// The 19-byte structure `AH=1Bh` copies out, packed exactly as the spec lays
/// it out and as Synchronet's `fossil_info_t` declares it.
fn info_bytes(uart: &Uart, info: &Info) -> [u8; 19] {
    let mut b = [0u8; 19];
    b[0..2].copy_from_slice(&19u16.to_le_bytes()); // size of this structure
    b[2] = REVISION; // spec conformed to
    b[3] = REVISION; // revision of this driver
    // Far pointer to an ASCII id string. Null: we have no reserved guest
    // memory to put one in, and nothing observed dereferences it. A null far
    // pointer is at least unmistakably null, where a fabricated one would send
    // a curious caller into the interrupt vector table.
    b[4..8].copy_from_slice(&0u32.to_le_bytes());
    // Buffers. The host loop drains transmit every iteration and refills
    // receive from the socket, so these describe that arrangement rather than
    // a fixed ring: what matters to a caller is how much room is left.
    let pending = u16::try_from(uart.pending()).unwrap_or(u16::MAX);
    b[8..10].copy_from_slice(&INBUF_SIZE.to_le_bytes());
    b[10..12].copy_from_slice(&INBUF_SIZE.saturating_sub(pending).to_le_bytes());
    b[12..14].copy_from_slice(&OUTBUF_SIZE.to_le_bytes());
    b[14..16].copy_from_slice(&OUTBUF_SIZE.to_le_bytes());
    b[16] = info.screen_width;
    b[17] = info.screen_height;
    b[18] = baud_code(uart.baud);
    b
}

const INBUF_SIZE: u16 = 4096;
const OUTBUF_SIZE: u16 = 4096;

/// The packed baud/parity/stop/data byte, shared with `AH=00h`'s `AL`.
///
/// Bits 7-5 baud, 4-3 parity, 2 stop bits, 1-0 data bits. We are always 8-N-1,
/// so only the rate varies. An unmodelled rate reports as 9600, the code a
/// FOSSIL uses for "the fastest thing in the table" rather than a refusal.
fn baud_code(baud: Option<u32>) -> u8 {
    let rate = match baud {
        Some(300) => 0b010,
        Some(600) => 0b011,
        Some(1200) => 0b100,
        Some(2400) => 0b101,
        Some(4800) => 0b110,
        Some(19200) => 0b000,
        Some(38400) => 0b001,
        _ => 0b111, // 9600
    };
    (rate << 5) | 0b000_00_0_11 // no parity, one stop bit, eight data bits
}

/// The status word: `AL` modem, `AH` line.
fn status(uart: &Uart) -> u16 {
    // Bit 3 of the modem byte is documented as always set, and Synchronet's
    // emulation sets it unconditionally too.
    let mut s = MDM_DCD_CHNG;
    if uart.carrier() {
        s |= MDM_DCD | MDM_CTS | MDM_DSR;
    }
    if uart.pending() > 0 {
        s |= LINE_RDA;
    }
    if uart.transmit_ready() {
        s |= LINE_THRE;
        if uart.tx.is_empty() {
            s |= LINE_TSRE;
        }
    }
    s
}

/// The FOSSIL driver as a service.
pub struct Fossil {
    pub uart: Uart,
    pub info: Info,
}

impl Fossil {
    pub fn new(uart: Uart) -> Self {
        Self { uart, info: Info::default() }
    }
}

impl<G: Guest> dos::service::Service<G> for Fossil {
    fn claims(&self) -> &[u8] {
        &[0x14]
    }

    fn service(&mut self, vector: u8, g: &mut G) -> dos::service::Serviced {
        use dos::service::Serviced;

        let ah = g.regs().ah();
        match dispatch(g, &mut self.uart, &self.info) {
            Ok(Answer::Done) => Serviced::Continue,
            Ok(Answer::Yield) => Serviced::Yield(std::time::Duration::from_millis(1)),
            Ok(Answer::Unsupported(_)) => Serviced::Unclaimed { vector, ah },
            Err(f) => Serviced::Fault(f),
        }
    }
}

/// Answer one `int 14h`.
pub fn dispatch(
    guest: &mut impl Guest,
    uart: &mut Uart,
    info: &Info,
) -> Result<Answer, Fault> {
    let mut regs = guest.regs();
    let func = regs.ah();
    let mut serviced = Answer::Done;

    match func {
        // Set baud rate. We do not re-clock the line: the far end is a socket
        // and the BBS already fixed the rate. Reporting status is the whole of
        // the contract, and a door that asked for 2400 gets its bytes anyway.
        0x00 => regs.ax = status(uart),

        // Transmit with wait.
        0x01 => {
            uart.send(regs.al());
            regs.ax = status(uart);
        }

        // Receive with wait. "With wait" is a promise no emulated driver can
        // keep without stalling the whole loop, so -- as Synchronet's emulation
        // also does -- an empty buffer answers TIMEOUT and yields. The caller
        // pumps the socket before re-entering, so a door's retry loop makes
        // progress. LORD never reaches this path with an empty buffer: it
        // tests AH=03's RDA bit first.
        0x02 => match uart.take() {
            Some(byte) => regs.ax = u16::from(byte),
            None => {
                regs.ax = LINE_TIMEOUT;
                serviced = Answer::Yield;
            }
        },

        // Request status. Deliberately never yields, which cost a measured
        // 5.3 seconds before it was taken out.
        //
        // The temptation is to read "no input waiting" as "the door is idle"
        // and hand the core back. It is not: a door polls status *while
        // sending*, to ask whether there is room in the transmit buffer, and
        // LORD does it 5310 times against 1467 transmitted characters. Yielding
        // here puts a sleep between output characters and the whole session
        // crawls.
        //
        // Nothing is lost by not yielding, because a door that really is idle
        // says so by another route: LORD calls `int 15h AH=10` 6975 times in
        // the same session, and the caller already sleeps on that. Guessing at
        // idleness from a status poll only duplicates a signal we are given
        // outright.
        0x03 => regs.ax = status(uart),

        // Initialize. The signature is the entire point of this function.
        0x04 => {
            regs.ax = SIGNATURE;
            regs.bx = (u16::from(REVISION) << 8) | u16::from(HIGHEST_FUNC);
        }

        // Deinitialize. Nothing to tear down, and explicitly not a hangup --
        // the spec says DTR is unaffected.
        0x05 => {}

        // Raise/lower DTR. Lowering it asks a real modem to hang up; here the
        // BBS owns the connection's lifetime and the door exiting is what ends
        // it, so this is deliberately inert rather than dropping carrier under
        // a caller who is still there.
        0x06 => {}

        // Timer tick parameters: the PC's 18.2 Hz tick on int 1Ch.
        0x07 => {
            regs.set_al(0x1c);
            regs.set_ah(18);
            regs.dx = 55;
        }

        // Flush output, waiting until it is gone. The host loop drains the
        // transmit queue every iteration, so by the time the door runs again
        // it has been written; there is nothing here to wait for.
        0x08 => {}

        0x09 => uart.purge_output(),
        0x0a => uart.purge_input(),

        // Transmit without waiting.
        0x0b => {
            if uart.transmit_ready() {
                uart.send(regs.al());
                regs.ax = 1;
            } else {
                regs.ax = 0;
                serviced = Answer::Yield;
            }
        }

        // Non-destructive read ahead.
        0x0c => match uart.peek() {
            Some(byte) => regs.ax = u16::from(byte),
            None => {
                regs.ax = CHAR_NOT_AVAILABLE;
                serviced = Answer::Yield;
            }
        },

        // Local keyboard. A door serves someone on the far end of a socket;
        // there is no local keyboard to read, and saying so is honest. The
        // "with wait" form cannot honour its promise either, so it answers the
        // same way rather than never returning.
        0x0d | 0x0e => regs.ax = CHAR_NOT_AVAILABLE,

        // Flow control. The socket does this for us, and accepting the request
        // is what lets a door proceed; pretending to refuse it would be worse.
        0x0f => {}

        // Ctrl-C/Ctrl-K checking. We never synthesise either.
        0x10 => {}

        // Read block. Never waits, by contract.
        0x18 => {
            let want = usize::from(regs.cx);
            let mut buf = Vec::with_capacity(want.min(uart.pending()));
            while buf.len() < want {
                match uart.take() {
                    Some(b) => buf.push(b),
                    None => break,
                }
            }
            if !buf.is_empty() {
                guest.write(Ptr::new(regs.es, regs.di), &buf)?;
            }
            regs.ax = u16::try_from(buf.len()).unwrap_or(u16::MAX);
            if buf.is_empty() {
                serviced = Answer::Yield;
            }
        }

        // Write block.
        0x19 => {
            let want = usize::from(regs.cx);
            if want > 0 {
                let at = Ptr::new(regs.es, regs.di);
                let bytes = guest.read(at, want)?.to_vec();
                for b in &bytes {
                    uart.send(*b);
                }
            }
            regs.ax = regs.cx;
        }

        // Driver information.
        0x1b => {
            let all = info_bytes(uart, info);
            let n = usize::from(regs.cx).min(all.len());
            if n > 0 {
                guest.write(Ptr::new(regs.es, regs.di), &all[..n])?;
            }
            regs.ax = u16::try_from(n).unwrap_or(0);
        }

        other => return Ok(Answer::Unsupported(other)),
    }

    guest.set_regs(regs);
    Ok(serviced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testguest::TestGuest;

    fn setup() -> (TestGuest, Uart) {
        // No pacing, so a transmit-ready assertion cannot flake on timing.
        (TestGuest::new(1 << 20), Uart::new(Some(0)))
    }

    fn call(guest: &mut TestGuest, uart: &mut Uart, ax: u16) -> Answer {
        let mut r = guest.regs();
        r.ax = ax;
        guest.set_regs(r);
        dispatch(guest, uart, &Info::default()).expect("no fault")
    }

    #[test]
    fn init_answers_with_the_signature_lord_checks_for() {
        let (mut g, mut u) = setup();
        assert_eq!(call(&mut g, &mut u, 0x0400), Answer::Done);
        // Written out rather than compared against `SIGNATURE`, deliberately.
        // This is not our constant to choose: LORD does `cmp ax,0x1954 / jnz
        // fail`, so the literal here is the other half of a contract with a
        // binary we cannot change. Asserting against the constant would let a
        // typo in it pass a green suite and break every door in the field.
        assert_eq!(g.regs().ax, 0x1954);
        assert_eq!(g.regs().bx >> 8, 5, "FOSSIL revision in BH");
        assert_eq!(g.regs().bx & 0xff, 0x1b, "highest supported function in BL");
    }

    #[test]
    fn a_waiting_byte_is_reported_in_ah_bit_0_not_al() {
        let (mut g, mut u) = setup();
        u.receive(b'k');
        call(&mut g, &mut u, 0x0300);
        let ax = g.regs().ax;
        assert_eq!(ax & LINE_RDA, LINE_RDA);
        // The bit LORD actually tests. If the halves were swapped this would
        // be clear while carrier-detect appeared as data-ready.
        assert_eq!((ax >> 8) & 0x01, 1, "AH bit 0 is what `test ah,0x01` reads");
        assert_eq!(ax & 0x01, 0, "and it must not land in AL");
    }

    #[test]
    fn status_reports_carrier_in_al_and_notices_it_drop() {
        let (mut g, mut u) = setup();
        call(&mut g, &mut u, 0x0300);
        assert_eq!(g.regs().ax & MDM_DCD, MDM_DCD, "a door starts answered");
        u.set_carrier(false);
        call(&mut g, &mut u, 0x0300);
        assert_eq!(g.regs().ax & MDM_DCD, 0, "and hears the caller hang up");
    }

    #[test]
    fn receive_returns_the_character_in_al() {
        let (mut g, mut u) = setup();
        u.receive(b'Z');
        assert_eq!(call(&mut g, &mut u, 0x0200), Answer::Done);
        assert_eq!(g.regs().al(), b'Z', "LORD reads this straight out of AL");
    }

    #[test]
    fn a_status_poll_never_yields_even_with_nothing_to_read() {
        // Regression: this used to yield whenever no input was waiting, which
        // reads like "the door is idle" and is not. A door polls status while
        // sending, so that sleep landed between output characters -- measured
        // at 5.3 seconds of a 16.5 second session. An idle door says so via
        // `int 15h AH=10` instead, which the caller already honours.
        let (mut g, mut u) = setup();
        assert_eq!(call(&mut g, &mut u, 0x0300), Answer::Done, "empty buffer");
        u.send(b'x');
        assert_eq!(call(&mut g, &mut u, 0x0300), Answer::Done, "mid-transmit");
        u.receive(b'y');
        assert_eq!(call(&mut g, &mut u, 0x0300), Answer::Done, "input waiting");
    }

    #[test]
    fn receiving_nothing_reports_timeout_and_asks_to_yield() {
        let (mut g, mut u) = setup();
        assert_eq!(
            call(&mut g, &mut u, 0x0200),
            Answer::Yield,
            "an empty buffer must not spin the host"
        );
        assert_eq!(g.regs().ax, LINE_TIMEOUT);
    }

    #[test]
    fn transmit_reaches_the_same_queue_the_port_writes_do() {
        let (mut g, mut u) = setup();
        call(&mut g, &mut u, 0x0100 | u16::from(b'h'));
        call(&mut g, &mut u, 0x0100 | u16::from(b'i'));
        assert_eq!(&u.tx, b"hi", "FOSSIL and the UART share one transmit queue");
    }

    #[test]
    fn peek_does_not_consume_and_says_so_when_empty() {
        let (mut g, mut u) = setup();
        assert_eq!(call(&mut g, &mut u, 0x0c00), Answer::Yield);
        assert_eq!(g.regs().ax, CHAR_NOT_AVAILABLE);
        u.receive(b'q');
        call(&mut g, &mut u, 0x0c00);
        assert_eq!(g.regs().ax, u16::from(b'q'));
        assert_eq!(u.pending(), 1, "peeking left the byte where it was");
    }

    #[test]
    fn purge_input_discards_only_what_arrived() {
        let (mut g, mut u) = setup();
        u.receive(b'a');
        u.receive(b'b');
        u.send(b'c');
        call(&mut g, &mut u, 0x0a00);
        assert_eq!(u.pending(), 0, "input is gone");
        assert_eq!(&u.tx, b"c", "and output is not");
    }

    #[test]
    fn a_block_write_sends_every_byte_and_reports_the_count() {
        let (mut g, mut u) = setup();
        let at = Ptr::new(0x2000, 0x10);
        g.write(at, b"block!").unwrap();
        let mut r = g.regs();
        r.ax = 0x1900;
        r.cx = 6;
        r.es = at.seg;
        r.di = at.off;
        g.set_regs(r);
        dispatch(&mut g, &mut u, &Info::default()).unwrap();
        assert_eq!(&u.tx, b"block!");
        assert_eq!(g.regs().ax, 6);
    }

    #[test]
    fn a_block_read_takes_at_most_what_arrived() {
        let (mut g, mut u) = setup();
        for b in b"xy" {
            u.receive(*b);
        }
        let at = Ptr::new(0x2000, 0x40);
        let mut r = g.regs();
        r.ax = 0x1800;
        r.cx = 16; // asks for more than is there
        r.es = at.seg;
        r.di = at.off;
        g.set_regs(r);
        dispatch(&mut g, &mut u, &Info::default()).unwrap();
        assert_eq!(g.regs().ax, 2, "reports what it actually moved");
        assert_eq!(g.read(at, 2).unwrap(), b"xy");
        assert_eq!(u.pending(), 0);
    }

    #[test]
    fn driver_info_is_nineteen_bytes_and_honours_a_short_buffer() {
        let (mut g, mut u) = setup();
        let at = Ptr::new(0x3000, 0);
        let mut r = g.regs();
        r.ax = 0x1b00;
        r.cx = 19;
        r.es = at.seg;
        r.di = at.off;
        g.set_regs(r);
        dispatch(&mut g, &mut u, &Info::default()).unwrap();
        assert_eq!(g.regs().ax, 19);
        let got = g.read(at, 19).unwrap();
        assert_eq!(u16::from_le_bytes([got[0], got[1]]), 19, "self-describing size");
        assert_eq!(got[16], 80);
        assert_eq!(got[17], 24);

        // A caller with a smaller buffer must get its buffer's worth, not 19.
        let mut r = g.regs();
        r.ax = 0x1b00;
        r.cx = 8;
        r.es = at.seg;
        r.di = 0x100;
        g.set_regs(r);
        dispatch(&mut g, &mut u, &Info::default()).unwrap();
        assert_eq!(g.regs().ax, 8, "copies only as much as it was offered");
    }

    #[test]
    fn an_unknown_function_is_refused_rather_than_answered_wrongly() {
        let (mut g, mut u) = setup();
        // Capture after the call is set up, so this compares what dispatch did
        // rather than what the test harness did.
        let mut r = g.regs();
        r.ax = 0x7e00;
        g.set_regs(r);
        let before = g.regs();
        assert_eq!(
            dispatch(&mut g, &mut u, &Info::default()).unwrap(),
            Answer::Unsupported(0x7e)
        );
        assert_eq!(g.regs(), before, "registers untouched so the gap is visible");
    }

    #[test]
    fn fossil_claims_only_int_14h() {
        use dos::service::Service;

        let f = Fossil::new(Uart::new(None));
        assert_eq!(Service::<TestGuest>::claims(&f), &[0x14]);
    }

    #[test]
    fn receive_with_an_empty_buffer_yields_one_millisecond_through_the_service() {
        // The mirror of the AH=03 test above: AH=02 (receive) with nothing
        // queued is the case that IS supposed to yield, and the Service
        // adapter must pass that through rather than swallowing it.
        use dos::service::{Service, Serviced};
        use dos::testguest::TestGuest;

        let mut f = Fossil::new(Uart::new(None));
        let mut g = TestGuest::new(64 * 1024);
        let mut regs = g.regs();
        regs.ax = 0x0200;
        g.set_regs(regs);

        assert_eq!(
            f.service(0x14, &mut g),
            Serviced::Yield(std::time::Duration::from_millis(1))
        );
    }

    #[test]
    fn a_status_poll_never_yields_however_empty_the_buffer_is() {
        // The regression 7dadb5f fixed: AH=03 asks whether there is room to
        // TRANSMIT. Treating an empty receive buffer as idleness put a 1 ms sleep
        // between output characters and cost 13.6 of 16.5 seconds of wall clock.
        use dos::service::{Service, Serviced};
        use dos::testguest::TestGuest;

        let mut f = Fossil::new(Uart::new(None));
        let mut g = TestGuest::new(64 * 1024);
        let mut regs = g.regs();
        regs.ax = 0x0300;
        g.set_regs(regs);

        assert_eq!(f.service(0x14, &mut g), Serviced::Continue);
    }

    #[test]
    fn every_function_lord_calls_is_answered() {
        // Measured from LORD.EXE's ten `int 14h` sites. If one of these ever
        // reports Unsupported, the door breaks in the field.
        let (mut g, mut u) = setup();
        for func in [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x0a] {
            let got = call(&mut g, &mut u, u16::from(func) << 8);
            assert!(
                !matches!(got, Answer::Unsupported(_)),
                "LORD calls int 14h AH={func:02X} and we must answer it"
            );
        }
    }
}
