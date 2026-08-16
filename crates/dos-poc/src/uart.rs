//! An 8250/16450 serial port, and the 8259 that carries its interrupt.
//!
//! This is the piece a door needs and a local session does not. LORD in door
//! mode does not use `int 14h` or a FOSSIL driver -- measured, it programs the
//! chip and spins on the interrupt-enable register -- so serving it over a BBS
//! means being a UART, not answering an API.
//!
//! Two things here are easy to get subtly wrong and expensive to debug, so both
//! are stated rather than implied:
//!
//! - **The interrupt is gated by `OUT2` in the MCR.** On a PC the UART's INTR
//!   pin reaches the 8259 only when OUT2 is asserted, and every DOS comm
//!   routine sets it. A model that raises interrupts without checking OUT2
//!   delivers them to a guest that has not finished setting up.
//! - **Reading IIR acknowledges the transmit interrupt.** If reading it does
//!   not clear that condition, the guest takes the same interrupt forever.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// COM1. The vector is where DOS maps IRQ4.
pub const COM1_BASE: u16 = 0x3f8;
pub const IRQ4_VECTOR: u8 = 0x0c;

// Line Status Register bits.
const LSR_DR: u8 = 1 << 0; // data ready
const LSR_THRE: u8 = 1 << 5; // transmit holding register empty
const LSR_TEMT: u8 = 1 << 6; // transmitter entirely empty

// Modem Status Register bits.
const MSR_DCTS: u8 = 1 << 0;
const MSR_DDCD: u8 = 1 << 3;
const MSR_CTS: u8 = 1 << 4;
const MSR_DSR: u8 = 1 << 5;
const MSR_DCD: u8 = 1 << 7;

// Interrupt Enable Register bits.
const IER_RX: u8 = 1 << 0;
const IER_THRE: u8 = 1 << 1;
const IER_MSR: u8 = 1 << 3;

// Modem Control Register bits.
const MCR_OUT2: u8 = 1 << 3;

/// Which condition IIR should report, highest priority first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cause {
    Rx,
    Thre,
    Modem,
}

impl Cause {
    /// The IIR encoding. Bit 0 clear means "an interrupt is pending".
    fn iir(self) -> u8 {
        match self {
            Cause::Rx => 0x04,
            Cause::Thre => 0x02,
            Cause::Modem => 0x00,
        }
    }
}

/// An 8250 with a byte queue on each side.
pub struct Uart {
    rx: VecDeque<u8>,
    /// Bytes the guest has transmitted, waiting to be handed to the host.
    pub tx: Vec<u8>,
    ier: u8,
    lcr: u8,
    mcr: u8,
    msr: u8,
    scratch: u8,
    divisor: u16,
    /// When the transmitter next accepts a byte. This is the whole of baud
    /// modelling: a byte written now is not gone until its bits would have
    /// been clocked out.
    tx_free_at: Instant,
    /// Set when the transmitter drained; cleared by reading IIR.
    thre_pending: bool,
    /// Bytes per second the line is clocked at, or `None` for no limit.
    pub baud: Option<u32>,
}

impl Uart {
    pub fn new(baud: Option<u32>) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: Vec::new(),
            ier: 0,
            lcr: 0x03, // 8N1, which is what everything uses
            mcr: 0,
            // Carrier up, and the far end ready: a door is answered before the
            // program starts, so the program must never see it come up.
            msr: MSR_CTS | MSR_DSR | MSR_DCD,
            scratch: 0,
            divisor: 12, // 9600 at the 115200 base clock
            tx_free_at: Instant::now(),
            thre_pending: true,
            baud,
        }
    }

    /// How long one byte occupies the line: a start bit, eight data, one stop.
    fn byte_time(&self) -> Duration {
        let baud = self
            .baud
            .or_else(|| (self.divisor != 0).then(|| 115_200 / u32::from(self.divisor)))
            .unwrap_or(0);
        if baud == 0 {
            Duration::ZERO
        } else {
            // Ten bit-times per byte, and a second is 1e9 ns.
            Duration::from_nanos(10_000_000_000u64 / u64::from(baud))
        }
    }

    /// Hand the guest a byte that arrived from the far end.
    pub fn receive(&mut self, byte: u8) {
        self.rx.push_back(byte);
    }

    /// Has the far end hung up?
    pub fn set_carrier(&mut self, up: bool) {
        let was = self.msr & MSR_DCD != 0;
        if was != up {
            self.msr = if up {
                self.msr | MSR_DCD | MSR_CTS | MSR_DSR
            } else {
                self.msr & !(MSR_DCD | MSR_CTS)
            };
            // The delta bits are how a program notices at all.
            self.msr |= MSR_DDCD | MSR_DCTS;
        }
    }

    fn transmitter_free(&self) -> bool {
        Instant::now() >= self.tx_free_at
    }

    fn lsr(&self) -> u8 {
        let mut v = 0;
        if !self.rx.is_empty() {
            v |= LSR_DR;
        }
        if self.transmitter_free() {
            v |= LSR_THRE | LSR_TEMT;
        }
        v
    }

    /// The highest-priority condition currently asserted and enabled.
    fn cause(&self) -> Option<Cause> {
        if self.ier & IER_RX != 0 && !self.rx.is_empty() {
            return Some(Cause::Rx);
        }
        if self.ier & IER_THRE != 0 && self.thre_pending && self.transmitter_free() {
            return Some(Cause::Thre);
        }
        if self.ier & IER_MSR != 0 && self.msr & 0x0f != 0 {
            return Some(Cause::Modem);
        }
        None
    }

    /// Is the chip asserting its interrupt line?
    ///
    /// Gated on OUT2, because that is how the pin is wired to the 8259 on a PC.
    pub fn interrupting(&self) -> bool {
        self.mcr & MCR_OUT2 != 0 && self.cause().is_some()
    }

    /// When something will change on its own, so a caller can sleep until then
    /// rather than spin.
    pub fn next_event(&self) -> Option<Instant> {
        (!self.transmitter_free()).then_some(self.tx_free_at)
    }

    pub fn read(&mut self, port: u16) -> u8 {
        let dlab = self.lcr & 0x80 != 0;
        match port - COM1_BASE {
            0 if dlab => (self.divisor & 0xff) as u8,
            0 => self.rx.pop_front().unwrap_or(0),
            1 if dlab => (self.divisor >> 8) as u8,
            1 => self.ier,
            2 => {
                let v = self.cause().map_or(0x01, Cause::iir);
                // Reading IIR acknowledges a transmit interrupt and nothing
                // else. Failing to clear it here is an interrupt storm.
                self.thre_pending = false;
                v
            }
            3 => self.lcr,
            4 => self.mcr,
            5 => self.lsr(),
            6 => {
                let v = self.msr;
                self.msr &= !0x0f; // reading clears the delta bits
                v
            }
            _ => self.scratch,
        }
    }

    pub fn write(&mut self, port: u16, value: u8) {
        let dlab = self.lcr & 0x80 != 0;
        match port - COM1_BASE {
            0 if dlab => self.divisor = (self.divisor & 0xff00) | u16::from(value),
            0 => {
                self.tx.push(value);
                let from = self.tx_free_at.max(Instant::now());
                self.tx_free_at = from + self.byte_time();
                self.thre_pending = true;
            }
            1 if dlab => self.divisor = (self.divisor & 0x00ff) | (u16::from(value) << 8),
            1 => {
                self.ier = value & 0x0f;
                // Enabling the transmit interrupt on an already-empty
                // transmitter must raise it immediately, or a program that
                // enables it and waits never sends its first byte.
                if value & IER_THRE != 0 && self.transmitter_free() {
                    self.thre_pending = true;
                }
            }
            2 => {}  // FCR: no FIFO modelled, and none is required
            3 => self.lcr = value,
            4 => self.mcr = value,
            5 | 6 => {} // LSR and MSR are read-only
            _ => self.scratch = value,
        }
    }
}

/// Just enough 8259 to mask an interrupt and to be told when one is finished.
///
/// Without the in-service latch a guest's handler is re-entered before its
/// `iret`, and without the mask a program that disables IRQ4 during setup still
/// gets interrupted mid-configuration.
#[derive(Default)]
pub struct Pic {
    mask: u8,
    in_service: u8,
}

impl Pic {
    /// IRQ4, the line COM1 sits on.
    const IRQ4: u8 = 1 << 4;

    pub fn read(&self, port: u16) -> u8 {
        match port {
            0x21 => self.mask,
            _ => 0,
        }
    }

    pub fn write(&mut self, port: u16, value: u8) {
        match port {
            // A non-specific EOI ends the highest-priority service in progress;
            // this models one line, so any EOI clears it.
            0x20 if value & 0x20 != 0 => self.in_service = 0,
            0x20 => {}
            0x21 => self.mask = value,
            _ => {}
        }
    }

    /// May IRQ4 be delivered right now?
    pub fn may_deliver_irq4(&self) -> bool {
        self.mask & Self::IRQ4 == 0 && self.in_service & Self::IRQ4 == 0
    }

    pub fn begin_irq4(&mut self) {
        self.in_service |= Self::IRQ4;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_uart() -> Uart {
        let mut u = Uart::new(Some(0)); // no pacing, so timing cannot flake
        u.write(COM1_BASE + 3, 0x03); // 8N1, DLAB clear
        u.write(COM1_BASE + 4, MCR_OUT2); // wire the interrupt through
        u
    }

    #[test]
    fn no_interrupt_reaches_the_guest_until_out2_is_set() {
        let mut u = Uart::new(Some(0));
        u.write(COM1_BASE + 1, IER_RX);
        u.receive(b'x');
        assert!(
            !u.interrupting(),
            "the INTR pin is not wired to the 8259 until OUT2 is asserted"
        );
        u.write(COM1_BASE + 4, MCR_OUT2);
        assert!(u.interrupting());
    }

    #[test]
    fn a_received_byte_raises_and_reading_it_clears() {
        let mut u = ready_uart();
        u.write(COM1_BASE + 1, IER_RX);
        u.receive(b'A');
        assert!(u.interrupting());
        assert_eq!(u.read(COM1_BASE + 5) & LSR_DR, LSR_DR, "LSR reports data");
        assert_eq!(u.read(COM1_BASE), b'A');
        assert!(!u.interrupting(), "and the condition goes away with the byte");
    }

    #[test]
    fn reading_iir_acknowledges_the_transmit_interrupt() {
        let mut u = ready_uart();
        u.write(COM1_BASE + 1, IER_THRE);
        assert!(u.interrupting(), "an empty transmitter with THRE enabled");
        let iir = u.read(COM1_BASE + 2);
        assert_eq!(iir & 0x0f, 0x02, "IIR names the transmit condition");
        assert!(
            !u.interrupting(),
            "reading IIR clears it -- otherwise the guest takes it forever"
        );
    }

    #[test]
    fn receive_outranks_transmit_when_both_are_pending() {
        let mut u = ready_uart();
        u.write(COM1_BASE + 1, IER_RX | IER_THRE);
        u.receive(b'z');
        assert_eq!(u.read(COM1_BASE + 2) & 0x0f, 0x04, "receive is higher priority");
    }

    #[test]
    fn the_divisor_latch_swaps_which_registers_are_visible() {
        let mut u = ready_uart();
        u.write(COM1_BASE + 3, 0x83); // DLAB on
        u.write(COM1_BASE, 0x0c);
        u.write(COM1_BASE + 1, 0x00);
        u.write(COM1_BASE + 3, 0x03); // DLAB off
        // With DLAB clear the same port is the receive register, not the
        // divisor -- writing 0x0c above must not have set IER.
        assert_eq!(u.read(COM1_BASE + 1), 0, "IER was not clobbered by the latch");
    }

    #[test]
    fn carrier_loss_is_reported_and_latched_until_read() {
        let mut u = ready_uart();
        assert_eq!(u.read(COM1_BASE + 6) & MSR_DCD, MSR_DCD, "carrier starts up");
        u.set_carrier(false);
        let msr = u.read(COM1_BASE + 6);
        assert_eq!(msr & MSR_DCD, 0, "carrier is down");
        assert_eq!(msr & MSR_DDCD, MSR_DDCD, "and the change is flagged");
        assert_eq!(
            u.read(COM1_BASE + 6) & MSR_DDCD,
            0,
            "reading MSR clears the delta"
        );
    }

    #[test]
    fn a_pic_mask_stops_delivery_and_an_eoi_ends_service() {
        let mut pic = Pic::default();
        assert!(pic.may_deliver_irq4());
        pic.write(0x21, 1 << 4);
        assert!(!pic.may_deliver_irq4(), "masked");
        pic.write(0x21, 0);
        pic.begin_irq4();
        assert!(!pic.may_deliver_irq4(), "not while its handler is running");
        pic.write(0x20, 0x20);
        assert!(pic.may_deliver_irq4(), "the EOI lets the next one through");
    }
}
