//! Virtual interrupt-enable flag and pending-IRQ bookkeeping.
//!
//! Pure logic: no signals, no context. The signal handler decides *when* to
//! consult this; this type only answers "is a delivery owed right now, and for
//! which line". Sixteen IRQ lines (two cascaded 8259s) tracked as bitsets.
//!
//! IF starts *set*: a DOS/4GW guest reaches its first instruction with
//! interrupts enabled, exactly as real hardware does once the extender's
//! startup `sti` has run.

/// Virtual PIC + interrupt-enable state for one guest.
pub struct Virq {
    if_set: bool,
    pending: u16,
    masked: u16,
}

impl Default for Virq {
    fn default() -> Self {
        Self::new()
    }
}

impl Virq {
    pub fn new() -> Self {
        Self {
            if_set: true,
            pending: 0,
            masked: 0,
        }
    }

    /// Set or clear the virtual interrupt-enable flag (`sti`/`cli`).
    pub fn set_if(&mut self, enabled: bool) {
        self.if_set = enabled;
    }

    /// Is the virtual IF set?
    pub fn if_set(&self) -> bool {
        self.if_set
    }

    /// Mark an IRQ line pending. `line` is `0..=15`.
    pub fn raise(&mut self, line: u8) {
        debug_assert!(line < 16, "IRQ line out of range: {line}");
        self.pending |= 1 << line;
    }

    /// Mask (disable) or unmask an IRQ line at the virtual PIC.
    pub fn set_mask(&mut self, line: u8, masked: bool) {
        debug_assert!(line < 16, "IRQ line out of range: {line}");
        let bit = 1u16 << line;
        if masked {
            self.masked |= bit;
        } else {
            self.masked &= !bit;
        }
    }

    /// The lowest-numbered pending, unmasked line, cleared atomically. `None`
    /// when IF is clear, every pending line is masked, or nothing is pending.
    ///
    /// Multiple `raise`s of the same line before a `take` coalesce to one
    /// delivery -- an edge-triggered line, which is what a spinning timer that
    /// fires while masked must look like on `sti`.
    pub fn take_pending(&mut self) -> Option<u8> {
        if !self.if_set {
            return None;
        }
        let deliverable = self.pending & !self.masked;
        if deliverable == 0 {
            return None;
        }
        let line = deliverable.trailing_zeros() as u8;
        self.pending &= !(1 << line);
        Some(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn if_gates_delivery() {
        let mut v = Virq::new();
        v.raise(0);
        assert_eq!(v.take_pending(), Some(0), "IF set + unmasked -> deliver");
        assert_eq!(v.take_pending(), None, "cleared after take");

        v.set_if(false);
        v.raise(1);
        assert_eq!(v.take_pending(), None, "IF clear -> hold");
        v.set_if(true);
        assert_eq!(v.take_pending(), Some(1), "re-enabled -> deliver held IRQ");
    }

    #[test]
    fn mask_gates_and_priority_is_lowest_line() {
        let mut v = Virq::new();
        v.set_mask(0, true);
        v.raise(0);
        v.raise(1);
        assert_eq!(v.take_pending(), Some(1), "IRQ0 masked, IRQ1 wins");
        assert_eq!(v.take_pending(), None, "IRQ0 still masked and held");
        v.set_mask(0, false);
        assert_eq!(v.take_pending(), Some(0), "unmasked -> now delivers");
    }

    #[test]
    fn repeated_raises_coalesce() {
        let mut v = Virq::new();
        for _ in 0..5 {
            v.raise(0);
        }
        assert_eq!(v.take_pending(), Some(0), "five raises -> one delivery");
        assert_eq!(v.take_pending(), None, "edge-triggered, not level");
    }
}
