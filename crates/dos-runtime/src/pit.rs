//! An 8253 programmable interval timer, channel 0 only.
//!
//! Measured under `runexe`, `WCCMMUTL.EXE` (1996, Borland C) never reaches its
//! own `main`: it spins in the C runtime's delay-calibration loop, reading
//! port `0x40` 1,391,218 times and `0x43` 695,609 times before the watchdog
//! ends the run. The loop reads the counter twice and waits for the value to
//! change; against an unmodelled port -- a constant `0xff`, [`crate::kvm`]'s
//! documented answer for an absent device -- it never does. This is the fix:
//! a counter that genuinely advances between two reads separated by real
//! time, which is the entire property the loop is waiting on.
//!
//! Modelled: channel 0 as a free-running down-counter at the real 8253 input
//! frequency (1.193182 MHz), counter-latch and lo/hi-byte access on `0x43`,
//! and low-then-high alternating reads on `0x40`. Not modelled: IRQ0 (the PIC
//! in [`crate::uart`] already exists, and nothing here should raise it), BCD
//! mode, hi-only/lo-only access, or any mode other than the rate-generator
//! behaviour a down-counter already gives -- YAGNI, since no caller measured
//! so far programs a divisor or asks for anything else. Channels 1 and 2
//! accept writes and answer reads without panicking, and nothing more; only
//! channel 0 is on the path a calibration loop uses.

use std::time::Instant;

/// The 8253's real input clock. Elapsed wall time divided by this period is
/// how many ticks the counter has counted down, which is the whole trick:
/// the counter needs no `advance()` call from the main loop, because it is
/// wall time itself, reinterpreted.
const CLOCK_HZ: u128 = 1_193_182;

/// One channel's read/latch state. Channel 0 is the only one whose `Counter`
/// is ever consulted for a value; channels 1 and 2 exist so a control-byte
/// write naming them does not panic, per the 8253's own per-channel select.
#[derive(Default)]
struct Counter {
    /// Set by a counter-latch control write (access bits `00`); holds the
    /// count still across however many read pairs follow, until the next
    /// latch command. `None` means "answer from the live, still-running
    /// count" -- the default lo/hi access mode.
    latched: Option<u16>,
    /// The value a low-byte read sampled, waiting for the high-byte read
    /// that completes the pair. Without this, two reads a few hundred
    /// nanoseconds apart on the *live* counter could each sample the clock
    /// fresh and return low and high bytes of two different counts.
    pending: Option<u16>,
}

/// An 8253, modelled only as far as a calibration loop needs.
///
/// Shaped like [`crate::uart::Pic`]: a plain struct with `read`/`write`,
/// constructed once and routed by port number in `runexe.rs`'s match arms.
/// Unlike `Pic`, its state includes a wall-clock reference rather than only
/// counters, because the value it answers with *is* elapsed time -- see the
/// module doc.
pub struct Pit {
    /// The instant channel 0's count last free-ran from `0xffff`. Nothing in
    /// this runtime has been measured writing a reload divisor to `0x40` for
    /// channel 0, so it free-runs as if reloaded with 0 -- the 8253's own
    /// encoding for 65536, the full 16-bit range -- from construction.
    start: Instant,
    ch0: Counter,
}

impl Pit {
    pub fn new() -> Self {
        Pit { start: Instant::now(), ch0: Counter::default() }
    }

    /// The live count: elapsed time since construction, in 8253 ticks,
    /// counted down (not up) from `0xffff` and wrapped every 65536 ticks --
    /// the down-counter behaviour a real channel 0 free-run gives.
    fn live_count(&self) -> u16 {
        let elapsed = self.start.elapsed();
        let ticks = elapsed.as_nanos() * CLOCK_HZ / 1_000_000_000;
        0xffffu32.wrapping_sub((ticks % 0x1_0000) as u32) as u16
    }

    pub fn read(&mut self, port: u16) -> u8 {
        match port {
            0x40 => {
                if let Some(pending) = self.ch0.pending {
                    // The pair opened by the last low-byte read closes here.
                    self.ch0.pending = None;
                    return (pending >> 8) as u8;
                }
                // No pair open: sample now (latched value if one is pending,
                // otherwise the live count) and open a new pair, so the high
                // byte this pair's second read returns describes the same
                // count as the low byte does, not a later one.
                let value = self.ch0.latched.unwrap_or_else(|| self.live_count());
                self.ch0.pending = Some(value);
                (value & 0xff) as u8
            }
            // Channels 1 and 2: accepted so a program that merely selects
            // them does not panic. Nothing measured so far reads them.
            0x41 | 0x42 => 0,
            _ => 0,
        }
    }

    pub fn write(&mut self, port: u16, value: u8) {
        match port {
            0x43 => {
                let channel = value >> 6;
                let access = (value >> 4) & 0b11;
                if channel == 0 {
                    match access {
                        // Counter-latch command: freeze the live count so
                        // every read pair up to the next latch (or the next
                        // switch back to lo/hi access) sees one still value
                        // instead of the counter changing under it.
                        0b00 => {
                            self.ch0.latched = Some(self.live_count());
                            self.ch0.pending = None;
                        }
                        // Lo/hi access: the common case a calibration loop
                        // programs. Release any latch and start clean.
                        0b11 => {
                            self.ch0.latched = None;
                            self.ch0.pending = None;
                        }
                        // Hi-only / lo-only access: not modelled. YAGNI --
                        // nothing measured so far uses either.
                        _ => {}
                    }
                }
                // Channels 1 and 2: accepted, no effect -- `read` never
                // consults their state.
            }
            // A reload-divisor write to the counter itself. Not modelled:
            // see the module doc for why channel 0 free-runs unconditionally
            // instead.
            0x40 | 0x41 | 0x42 => {}
            _ => {}
        }
    }
}

impl Default for Pit {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Read a low/high pair from `port` and combine them into the 16-bit
    /// count they describe.
    fn read_pair(pit: &mut Pit, port: u16) -> u16 {
        let lo = pit.read(port) as u16;
        let hi = pit.read(port) as u16;
        lo | (hi << 8)
    }

    #[test]
    fn the_count_changes_over_real_time() {
        let mut pit = Pit::new();
        let a = read_pair(&mut pit, 0x40);
        std::thread::sleep(Duration::from_millis(5));
        let b = read_pair(&mut pit, 0x40);
        // At 1.193182 MHz, 5ms is ~5966 ticks: far more than any scheduling
        // jitter could account for by coincidence, so this cannot flake on a
        // rounding boundary the way a 1-tick margin could.
        assert_ne!(a, b, "a calibration loop is waiting on exactly this: the count must move");
    }

    #[test]
    fn latching_freezes_the_value_until_relatched() {
        let mut pit = Pit::new();
        pit.write(0x43, 0x00); // channel 0, counter-latch
        let first_a = read_pair(&mut pit, 0x40);
        // Real time passes with no latch command in between: if the latch
        // is doing its job, a second read pair from it still agrees with
        // the first, rather than drifting the way an unlatched live read
        // would over the same interval.
        std::thread::sleep(Duration::from_millis(5));
        let first_b = read_pair(&mut pit, 0x40);
        assert_eq!(first_a, first_b, "two reads of the same latch must agree, even across real time");

        pit.write(0x43, 0x00); // re-latch: captures a fresh live sample
        let second = read_pair(&mut pit, 0x40);
        assert_ne!(first_a, second, "re-latching must capture a new count");
    }

    #[test]
    fn lo_hi_access_alternates_then_a_third_read_starts_a_new_pair() {
        let mut pit = Pit::new();
        let lo1 = pit.read(0x40);
        let opened = pit.ch0.pending.expect("a low-byte read opens a pending high byte");
        assert_eq!(lo1, (opened & 0xff) as u8);
        let hi1 = pit.read(0x40);
        assert_eq!(hi1, (opened >> 8) as u8, "the high byte must match the low byte's own sample");
        assert!(pit.ch0.pending.is_none(), "the pair closes once the high byte is read");

        let _lo2 = pit.read(0x40);
        assert!(pit.ch0.pending.is_some(), "the third read opens a new pair rather than repeating the old one");
    }

    #[test]
    fn an_unmodelled_channel_does_not_panic() {
        let mut pit = Pit::new();
        pit.write(0x43, 0b0111_0000); // channel 1, lo/hi access
        let _ = pit.read(0x41);
        pit.write(0x43, 0b1011_0000); // channel 2, lo/hi access
        let _ = pit.read(0x42);
    }
}
