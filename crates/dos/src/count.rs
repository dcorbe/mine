//! Instrumentation that wraps a service instead of living inside the loop.
//!
//! `runexe` grew its counters interleaved with the routing match, so every new
//! consumer would have had to reimplement them. A decorator sees both sides of
//! a call -- the registers on the way in, the verdict on the way out -- which
//! is everything the reports need, and it is absent entirely when it is not
//! composed.

use std::collections::BTreeMap;

use crate::guest::Guest;
use crate::service::{Service, Serviced};

/// How many `(vector, ah)` pairs to keep in arrival order. The report only
/// ever printed the first 40; keeping the bound here rather than at the print
/// site means a long session cannot grow this without limit.
const ORDER_LIMIT: usize = 40;

/// What a decorator can tell a report, independent of what it decorates.
///
/// A separate trait from `Counting`'s own inherent methods because a report
/// only ever holds a `&dyn Service<G>` (from [`crate::service::Services::claiming`]),
/// and a trait object cannot expose a concrete type's inherent methods --
/// only what a trait names.
pub trait Counters {
    fn calls(&self) -> u32;
    fn order(&self) -> &[(u8, u8)];
    fn seen(&self) -> &BTreeMap<(u8, u8), u32>;
    fn unclaimed(&self) -> &BTreeMap<(u8, u8), u32>;
}

pub struct Counting<S> {
    inner: S,
    calls: u32,
    order: Vec<(u8, u8)>,
    seen: BTreeMap<(u8, u8), u32>,
    unclaimed: BTreeMap<(u8, u8), u32>,
}

impl<S> Counting<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            calls: 0,
            order: Vec::new(),
            seen: BTreeMap::new(),
            unclaimed: BTreeMap::new(),
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S> Counters for Counting<S> {
    fn calls(&self) -> u32 {
        self.calls
    }

    fn order(&self) -> &[(u8, u8)] {
        &self.order
    }

    fn seen(&self) -> &BTreeMap<(u8, u8), u32> {
        &self.seen
    }

    fn unclaimed(&self) -> &BTreeMap<(u8, u8), u32> {
        &self.unclaimed
    }
}

impl<G: Guest, S: Service<G> + 'static> Service<G> for Counting<S> {
    fn claims(&self) -> &[u8] {
        self.inner.claims()
    }

    fn service(&mut self, vector: u8, g: &mut G) -> Serviced {
        let ah = g.regs().ah();
        self.calls += 1;
        *self.seen.entry((vector, ah)).or_insert(0) += 1;
        if self.order.len() < ORDER_LIMIT {
            self.order.push((vector, ah));
        }

        let verdict = self.inner.service(vector, g);
        if let Serviced::Unclaimed { vector, ah } = verdict {
            *self.unclaimed.entry((vector, ah)).or_insert(0) += 1;
        }
        verdict
    }

    fn counters(&self) -> Option<&dyn Counters> {
        Some(self)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{Service, Serviced};
    use crate::testguest::TestGuest;

    struct Echo;
    impl Service<TestGuest> for Echo {
        fn claims(&self) -> &[u8] { &[0x21] }
        fn service(&mut self, vector: u8, g: &mut TestGuest) -> Serviced {
            let ah = g.regs().ah();
            if ah == 0x99 {
                Serviced::Unclaimed { vector, ah }
            } else {
                Serviced::Continue
            }
        }
        fn as_any(&self) -> &dyn std::any::Any { self }
    }

    fn call(c: &mut Counting<Echo>, g: &mut TestGuest, ah: u8) {
        let mut regs = g.regs();
        regs.ax = u16::from(ah) << 8;
        g.set_regs(regs);
        c.service(0x21, g);
    }

    #[test]
    fn claims_forwards_the_inner_services_claim() {
        let c = Counting::new(Echo);
        assert_eq!(c.claims(), Echo.claims());
        assert_eq!(c.claims(), &[0x21]);
    }

    #[test]
    fn it_counts_calls_and_preserves_the_order_they_arrived_in() {
        let mut g = TestGuest::new(4096);
        let mut c = Counting::new(Echo);

        call(&mut c, &mut g, 0x30);
        call(&mut c, &mut g, 0x09);
        call(&mut c, &mut g, 0x30);

        assert_eq!(c.calls(), 3);
        assert_eq!(c.order(), &[(0x21, 0x30), (0x21, 0x09), (0x21, 0x30)]);
        assert_eq!(c.seen().get(&(0x21, 0x30)), Some(&2));
    }

    #[test]
    fn an_unclaimed_call_is_recorded_as_a_gap_as_well_as_a_call() {
        let mut g = TestGuest::new(4096);
        let mut c = Counting::new(Echo);

        call(&mut c, &mut g, 0x99);

        assert_eq!(c.calls(), 1);
        assert_eq!(c.unclaimed().get(&(0x21, 0x99)), Some(&1));
        assert!(c.unclaimed().get(&(0x21, 0x30)).is_none());
    }

    #[test]
    fn the_decorator_forwards_the_inner_verdict_unchanged() {
        let mut g = TestGuest::new(4096);
        let mut c = Counting::new(Echo);
        let mut regs = g.regs();
        regs.ax = 0x3000;
        g.set_regs(regs);
        assert_eq!(c.service(0x21, &mut g), Serviced::Continue);
    }

    /// `runexe`'s report currently prints only the first 40 `(vector, ah)`
    /// pairs (`if order.len() < 40`), so the cap here has to be the same
    /// number and it has to hold under load, not just stop growing "soon".
    #[test]
    fn order_stops_growing_at_forty_entries_even_after_more_calls() {
        let mut g = TestGuest::new(4096);
        let mut c = Counting::new(Echo);

        for i in 0..50u8 {
            call(&mut c, &mut g, i);
        }

        assert_eq!(c.calls(), 50);
        assert_eq!(c.order().len(), 40);
        // The kept entries are the first 40 in arrival order, not some other
        // 40 -- e.g. not the last 40, and not silently overwritten.
        let expected: Vec<(u8, u8)> = (0..40u8).map(|i| (0x21, i)).collect();
        assert_eq!(c.order(), expected.as_slice());
    }

    /// `ah` names *what was asked for*. A service is free to leave the guest's
    /// registers in whatever state its answer requires -- including a
    /// different `AH` -- so the pair recorded here has to come from the
    /// request, not from whatever the inner service left behind afterward.
    struct ClobbersAh;
    impl Service<TestGuest> for ClobbersAh {
        fn claims(&self) -> &[u8] { &[0x21] }
        fn service(&mut self, _vector: u8, g: &mut TestGuest) -> Serviced {
            let mut regs = g.regs();
            regs.set_ah(0xaa);
            g.set_regs(regs);
            Serviced::Continue
        }
        fn as_any(&self) -> &dyn std::any::Any { self }
    }

    #[test]
    fn the_recorded_pair_is_the_request_ah_not_whatever_the_inner_service_leaves_behind() {
        let mut g = TestGuest::new(4096);
        let mut c = Counting::new(ClobbersAh);
        let mut regs = g.regs();
        regs.ax = 0x3000; // AH=0x30
        g.set_regs(regs);

        c.service(0x21, &mut g);

        assert_eq!(c.order(), &[(0x21, 0x30)]);
        assert_eq!(c.seen().get(&(0x21, 0x30)), Some(&1));
        assert!(c.seen().get(&(0x21, 0xaa)).is_none());
    }
}
