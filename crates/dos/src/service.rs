//! The behaviour seam: something that services a software interrupt, and the
//! one answer every such thing gives.
//!
//! Before this existed there were five dispatch functions with five signatures
//! and five return types -- `Outcome`, `Result<Serviced, Fault>`, `()`, `bool`
//! and `Option<Duration>` -- and each consumer wrote its own routing loop over
//! them. The trait is what lets a runtime *compose* the services it wants
//! instead of reimplementing the routing.

use std::time::Duration;

use crate::guest::{Fault, Guest};

/// What became of one serviced interrupt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Serviced {
    /// Answered. Registers are set; resume the guest.
    Continue,

    /// Answered, and the guest has *said* it is idle. The caller should sleep
    /// this long before re-entering.
    ///
    /// Only ever returned where the guest asked to wait. Never inferred from
    /// "no data available": `7dadb5f` measured that mistake at 13.6 of 16.5
    /// seconds of wall clock, because a door polls its transmit status while
    /// sending and an empty receive buffer does not mean it has nothing to do.
    Yield(Duration),

    /// The program asked to exit, with this return code.
    Terminate(u8),

    /// A function this service does not model. Registers are untouched and the
    /// caller should record it as a gap.
    ///
    /// A return value rather than a separate `is_implemented(ah)` predicate on
    /// purpose: a predicate maintained alongside a match drifts from it, and
    /// has.
    Unclaimed { vector: u8, ah: u8 },

    /// The program handed over a pointer that does not name memory.
    ///
    /// Deliberately not laundered into a DOS error code -- real DOS would have
    /// read whatever happened to be there, and reporting it turns silent
    /// corruption into a stop.
    Fault(Fault),
}

/// Something that services a software interrupt on behalf of a guest.
///
/// Generic over the guest rather than taking `&mut dyn Guest`: every memory
/// access a service makes goes through this parameter, so a trait object would
/// buy one indirection per *access* rather than per interrupt. The consumers
/// are known statically and none of them needs runtime composition.
pub trait Service<G: Guest> {
    /// Which vectors this service answers.
    ///
    /// A positive claim. A router must never decide ownership by ruling other
    /// services out.
    fn claims(&self) -> &[u8];

    /// Service one interrupt. `vector` is always one of [`Service::claims`].
    fn service(&mut self, vector: u8, g: &mut G) -> Serviced;
}

/// The composed set of services, and the routing that was previously written
/// out by hand in every consumer.
///
/// Boxed because the composed services have different concrete types and the
/// set is built at runtime by a `with` chain. This is one indirection per
/// *interrupt*, against a measured 40.4 us per live DOS call -- the guest's
/// memory accesses, which are the hot path, stay monomorphised through `G`.
pub struct Services<G: Guest> {
    services: Vec<Box<dyn Service<G>>>,
    /// Vector -> index into `services`. 256 entries; `u8::MAX` means unclaimed.
    route: [u8; 256],
}

impl<G: Guest> Default for Services<G> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: Guest> Services<G> {
    pub fn new() -> Self {
        Self { services: Vec::new(), route: [u8::MAX; 256] }
    }

    /// Add a service, claiming its vectors.
    ///
    /// # Panics
    ///
    /// If two services claim the same vector. That is a table bug, and the
    /// house rule is to crash rather than pick one -- a silently shadowed
    /// service is the defect that took 44 shim registrations dead once before.
    pub fn with(mut self, s: impl Service<G> + 'static) -> Self {
        let index = u8::try_from(self.services.len())
            .expect("more than 255 services composed");
        for &v in s.claims() {
            assert!(
                self.route[usize::from(v)] == u8::MAX,
                "two services claim int {v:#04x}"
            );
            self.route[usize::from(v)] = index;
        }
        self.services.push(Box::new(s));
        self
    }

    /// Route one interrupt. `None` means nothing claims this vector.
    pub fn service(&mut self, vector: u8, g: &mut G) -> Option<Serviced> {
        let index = self.route[usize::from(vector)];
        if index == u8::MAX {
            return None;
        }
        Some(self.services[usize::from(index)].service(vector, g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::Dos;
    use crate::testguest::TestGuest;

    #[test]
    fn dos_claims_only_int_21h() {
        let d = Dos::default();
        assert_eq!(Service::<TestGuest>::claims(&d), &[0x21]);
    }

    #[test]
    fn an_unmodelled_function_is_unclaimed_rather_than_an_error_code() {
        // AH=0x99 is not a DOS call this kernel answers. The old code reported
        // that through a separate `is_implemented` predicate the match could
        // drift from; the return value cannot drift.
        let mut g = TestGuest::new(64 * 1024);
        let mut regs = g.regs();
        regs.ax = 0x9900;
        g.set_regs(regs);

        let mut d = Dos::default();
        assert_eq!(
            d.service(0x21, &mut g),
            Serviced::Unclaimed { vector: 0x21, ah: 0x99 }
        );
    }

    #[test]
    fn terminate_carries_the_programs_exit_code() {
        let mut g = TestGuest::new(64 * 1024);
        let mut regs = g.regs();
        regs.ax = 0x4C07; // AH=4C terminate, AL=07 exit code
        g.set_regs(regs);

        let mut d = Dos::default();
        assert_eq!(d.service(0x21, &mut g), Serviced::Terminate(7));
    }

    #[test]
    fn a_bad_pointer_faults_rather_than_returning_a_dos_error() {
        // AH=09 display string, DS:DX pointing past the end of memory.
        let mut g = TestGuest::new(4096);
        let mut regs = g.regs();
        regs.ax = 0x0900;
        regs.ds = 0xffff;
        regs.dx = 0xfff0;
        g.set_regs(regs);

        let mut d = Dos::default();
        assert!(matches!(d.service(0x21, &mut g), Serviced::Fault(_)));
    }

    struct Fake(Vec<u8>, u8);

    impl Service<TestGuest> for Fake {
        fn claims(&self) -> &[u8] { &self.0 }
        fn service(&mut self, _v: u8, _g: &mut TestGuest) -> Serviced {
            Serviced::Terminate(self.1)
        }
    }

    #[test]
    fn the_router_sends_a_vector_to_the_service_that_claims_it() {
        let mut g = TestGuest::new(4096);
        let mut s = Services::new()
            .with(Fake(vec![0x21], 1))
            .with(Fake(vec![0x10, 0x16], 2));

        assert_eq!(s.service(0x21, &mut g), Some(Serviced::Terminate(1)));
        assert_eq!(s.service(0x16, &mut g), Some(Serviced::Terminate(2)));
    }

    #[test]
    fn an_unclaimed_vector_routes_nowhere_rather_than_to_a_default() {
        let mut g = TestGuest::new(4096);
        let mut s = Services::new().with(Fake(vec![0x21], 1));
        assert_eq!(s.service(0x14, &mut g), None);
    }

    #[test]
    #[should_panic(expected = "0x21")]
    fn two_services_claiming_one_vector_is_a_table_bug_and_panics() {
        let _ = Services::<TestGuest>::new()
            .with(Fake(vec![0x21], 1))
            .with(Fake(vec![0x21], 2));
    }
}
