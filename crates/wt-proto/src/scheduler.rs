//! Send scheduling for streams and datagram writables.
//!
//! The W3C spec gives `sendOrder` a 64-bit range and makes each
//! `WebTransportSendGroup` an equal claimant on bandwidth with its own
//! `sendOrder` numberspace. QUIC offers one flat 32-bit priority space per
//! connection, which can express neither. So scheduling happens here instead:
//! this module decides which stream sends next, and the transport is told only
//! to write that stream's bytes.
//!
//! The policy is:
//!
//! - Groups take turns, round-robin, so each gets an equal share of the
//!   opportunities to send. The null group is one claimant like any other.
//! - Within a group, streams that opted into strict ordering drain in
//!   descending `sendOrder`; the full 64-bit range is compared, never truncated.
//! - Streams without strict ordering share what is left of their group's turn,
//!   also round-robin, so one of them cannot starve its siblings.
//!
//! No I/O happens here. The scheduler is a decision function over queue state,
//! which is what makes ordering and fairness testable without a network.

use std::collections::HashMap;

/// Identifies a send group. The null group (the spec's default) is `None`.
pub type GroupId = Option<u64>;

/// Identifies a stream registered with the scheduler.
pub type StreamId = u64;

/// What the scheduler knows about one registered stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    group: GroupId,
    /// The spec's `sendOrder`. `None` means the stream did not opt into strict
    /// ordering and simply shares its group's turn.
    send_order: Option<i64>,
    /// Bytes waiting to be written for this stream.
    pending: u64,
    /// Increments each time the stream is chosen, for round-robin fairness
    /// among equals.
    turns: u64,
}

/// Decides which stream sends next.
#[derive(Debug, Default)]
pub struct Scheduler {
    entries: HashMap<StreamId, Entry>,
    /// Turns taken per group, so groups can be rotated fairly.
    group_turns: HashMap<GroupId, u64>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a stream, or updates its group and order if already present.
    pub fn register(&mut self, stream: StreamId, group: GroupId, send_order: Option<i64>) {
        let entry = self.entries.entry(stream).or_insert(Entry {
            group,
            send_order,
            pending: 0,
            turns: 0,
        });
        entry.group = group;
        entry.send_order = send_order;
        self.group_turns.entry(group).or_insert(0);
    }

    /// Forgets a stream. Its pending bytes stop competing for bandwidth.
    pub fn remove(&mut self, stream: StreamId) {
        if let Some(entry) = self.entries.remove(&stream) {
            // Keep the group's turn count only while it still has members, so a
            // group that comes back later starts level with its peers.
            if !self.entries.values().any(|e| e.group == entry.group) {
                self.group_turns.remove(&entry.group);
            }
        }
    }

    /// Records bytes queued for a stream.
    pub fn enqueue(&mut self, stream: StreamId, bytes: u64) {
        if let Some(entry) = self.entries.get_mut(&stream) {
            entry.pending = entry.pending.saturating_add(bytes);
        }
    }

    /// Records bytes written, so the stream stops competing once drained.
    pub fn wrote(&mut self, stream: StreamId, bytes: u64) {
        if let Some(entry) = self.entries.get_mut(&stream) {
            entry.pending = entry.pending.saturating_sub(bytes);
        }
    }

    /// Changes a stream's group, moving it into a different numberspace.
    pub fn set_group(&mut self, stream: StreamId, group: GroupId) {
        if let Some(entry) = self.entries.get_mut(&stream) {
            entry.group = group;
            self.group_turns.entry(group).or_insert(0);
        }
    }

    /// Changes a stream's send order.
    pub fn set_send_order(&mut self, stream: StreamId, send_order: Option<i64>) {
        if let Some(entry) = self.entries.get_mut(&stream) {
            entry.send_order = send_order;
        }
    }

    pub fn pending(&self, stream: StreamId) -> u64 {
        self.entries.get(&stream).map_or(0, |e| e.pending)
    }

    /// Whether any registered stream has bytes waiting.
    pub fn has_work(&self) -> bool {
        self.entries.values().any(|e| e.pending > 0)
    }

    /// Bytes waiting across every registered stream.
    ///
    /// Applications use this as a backpressure signal (how far behind a peer
    /// has fallen), so it saturates rather than overflowing.
    pub fn total_pending(&self) -> u64 {
        self.entries
            .values()
            .fold(0u64, |sum, e| sum.saturating_add(e.pending))
    }

    /// Chooses the stream that should send next, without recording a turn.
    ///
    /// Separate from [`next`](Self::next) so a caller can ask whose turn it is
    /// without consuming it: a poll that advanced the schedule would skew the
    /// very fairness it is asking about.
    pub fn peek(&self) -> Option<StreamId> {
        // Pick the group with the fewest turns among those with work, so
        // bandwidth is shared equally between groups.
        let group = self
            .entries
            .values()
            .filter(|e| e.pending > 0)
            .map(|e| e.group)
            .min_by_key(|g| (self.group_turns.get(g).copied().unwrap_or(0), group_key(*g)))?;

        // Within the group, strict ordering wins: highest sendOrder first. The
        // comparison is over the full i64, so large orders are not truncated.
        // Among equals (including unordered streams) the least recently served
        // goes next.
        self.entries
            .iter()
            .filter(|(_, e)| e.group == group && e.pending > 0)
            .max_by(|(a_id, a), (b_id, b)| {
                a.send_order
                    .cmp(&b.send_order)
                    .then_with(|| b.turns.cmp(&a.turns))
                    .then_with(|| b_id.cmp(a_id))
            })
            .map(|(id, _)| *id)
    }

    /// Chooses the stream that should send next, and records its turn.
    ///
    /// Returns `None` when nothing is waiting.
    ///
    /// Deliberately named `next` despite not being `Iterator::next`: the
    /// sequence it yields depends on writes that land between calls, so it
    /// cannot satisfy the iterator contract even though it reads like one.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<StreamId> {
        let stream = self.peek()?;
        let group = self.entries.get(&stream)?.group;

        *self.group_turns.entry(group).or_insert(0) += 1;
        if let Some(entry) = self.entries.get_mut(&stream) {
            entry.turns += 1;
        }
        Some(stream)
    }
}

/// Orders groups deterministically when their turn counts tie.
///
/// The null group sorts first so an application that never creates a group
/// still gets a stable order.
fn group_key(group: GroupId) -> (u8, u64) {
    match group {
        None => (0, 0),
        Some(id) => (1, id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the scheduler until everything drains, recording the order in which
    /// streams were served.
    fn drain(scheduler: &mut Scheduler, chunk: u64) -> Vec<StreamId> {
        let mut order = Vec::new();
        while let Some(stream) = scheduler.next() {
            order.push(stream);
            scheduler.wrote(stream, chunk);
            if order.len() > 10_000 {
                panic!("scheduler did not drain");
            }
        }
        order
    }

    #[test]
    fn nothing_to_send_means_no_choice() {
        let mut s = Scheduler::new();
        assert_eq!(s.next(), None);
        s.register(1, None, None);
        assert_eq!(s.next(), None, "a registered but idle stream is not chosen");
        assert!(!s.has_work());
    }

    #[test]
    fn a_lone_stream_is_always_chosen() {
        let mut s = Scheduler::new();
        s.register(1, None, None);
        s.enqueue(1, 10);
        assert!(s.has_work());
        assert_eq!(s.next(), Some(1));
    }

    /// Peeking must not advance the schedule: a caller that asks repeatedly
    /// whose turn it is would otherwise skew the fairness it is asking about.
    #[test]
    fn peeking_does_not_consume_a_turn() {
        let mut s = Scheduler::new();
        s.register(1, None, None);
        s.register(2, None, None);
        s.enqueue(1, 10);
        s.enqueue(2, 10);

        let first = s.peek();
        for _ in 0..50 {
            assert_eq!(s.peek(), first, "repeated peeks must agree");
        }
        assert_eq!(s.next(), first, "next follows peek");
        assert_ne!(s.peek(), first, "the turn moves on once taken");
    }

    #[test]
    fn total_pending_sums_every_stream() {
        let mut s = Scheduler::new();
        assert_eq!(s.total_pending(), 0);

        s.register(1, None, None);
        s.register(2, Some(9), None);
        s.enqueue(1, 100);
        s.enqueue(2, 250);
        assert_eq!(s.total_pending(), 350);

        s.wrote(1, 100);
        assert_eq!(s.total_pending(), 250);

        // A removed stream no longer counts against the backlog.
        s.remove(2);
        assert_eq!(s.total_pending(), 0);
    }

    /// The backlog is a signal, not an accumulator: it must not overflow into a
    /// small number and read as "the peer is keeping up".
    #[test]
    fn total_pending_saturates() {
        let mut s = Scheduler::new();
        s.register(1, None, None);
        s.register(2, None, None);
        s.enqueue(1, u64::MAX);
        s.enqueue(2, u64::MAX);
        assert_eq!(s.total_pending(), u64::MAX);
    }

    #[test]
    fn peek_reports_nothing_when_idle() {
        let mut s = Scheduler::new();
        assert_eq!(s.peek(), None);
        s.register(1, None, None);
        assert_eq!(s.peek(), None, "a registered but idle stream is not chosen");
        s.enqueue(1, 1);
        assert_eq!(s.peek(), Some(1));
    }

    /// Strict ordering: within a group, a higher sendOrder drains first.
    #[test]
    fn higher_send_order_goes_first() {
        let mut s = Scheduler::new();
        s.register(1, None, Some(10));
        s.register(2, None, Some(30));
        s.register(3, None, Some(20));
        for id in [1, 2, 3] {
            s.enqueue(id, 1);
        }
        assert_eq!(drain(&mut s, 1), vec![2, 3, 1]);
    }

    /// The whole reason for our own scheduler: sendOrder is 64-bit, and values
    /// beyond i32 must order correctly rather than clamp together.
    #[test]
    fn send_order_uses_the_full_64_bit_range() {
        let mut s = Scheduler::new();
        // Both of these clamp to i32::MAX; only a 64-bit compare separates them.
        s.register(1, None, Some(i64::from(i32::MAX) + 1));
        s.register(2, None, Some(i64::from(i32::MAX) + 2));
        s.register(3, None, Some(i64::MIN));
        s.register(4, None, Some(i64::MAX));
        for id in [1, 2, 3, 4] {
            s.enqueue(id, 1);
        }
        assert_eq!(drain(&mut s, 1), vec![4, 2, 1, 3]);
    }

    #[test]
    fn negative_send_orders_sort_below_positive_ones() {
        let mut s = Scheduler::new();
        s.register(1, None, Some(-5));
        s.register(2, None, Some(0));
        s.register(3, None, Some(5));
        for id in [1, 2, 3] {
            s.enqueue(id, 1);
        }
        assert_eq!(drain(&mut s, 1), vec![3, 2, 1]);
    }

    /// An ordered stream outranks an unordered one in the same group: opting
    /// into strict ordering is what asks to go first.
    #[test]
    fn ordered_streams_precede_unordered_ones() {
        let mut s = Scheduler::new();
        s.register(1, None, None);
        s.register(2, None, Some(0));
        s.enqueue(1, 1);
        s.enqueue(2, 1);
        assert_eq!(drain(&mut s, 1), vec![2, 1]);
    }

    /// Unordered streams in one group share its turn rather than one starving
    /// the others.
    #[test]
    fn unordered_streams_take_turns() {
        let mut s = Scheduler::new();
        s.register(1, None, None);
        s.register(2, None, None);
        for id in [1, 2] {
            s.enqueue(id, 4);
        }
        let order = drain(&mut s, 1);
        assert_eq!(order.len(), 8);
        // Neither stream may run twice before the other has run once.
        for window in order.windows(2) {
            assert_ne!(window[0], window[1], "a stream was served twice in a row");
        }
    }

    /// Groups are equal claimants on bandwidth: while both have work, each gets
    /// about half the turns however many streams it contains.
    ///
    /// Fairness is only meaningful while both groups are actually competing, so
    /// this measures the turns taken before the first group runs dry.
    #[test]
    fn groups_receive_equal_shares_while_both_have_work() {
        let mut s = Scheduler::new();
        // One stream in group A, three in group B, all with ample work.
        s.register(1, Some(1), None);
        for id in [2, 3, 4] {
            s.register(id, Some(2), None);
        }
        for id in [1, 2, 3, 4] {
            s.enqueue(id, 100);
        }

        let mut a = 0usize;
        let mut b = 0usize;
        for _ in 0..120 {
            let stream = s.next().expect("both groups still have work");
            s.wrote(stream, 1);
            if stream == 1 {
                a += 1;
            } else {
                b += 1;
            }
        }

        // Group A's single stream should get about as many turns as group B's
        // three streams put together.
        assert!(
            a.abs_diff(b) <= 2,
            "expected an even split between groups, got {a} vs {b}"
        );
    }

    /// Once a group runs out of work the others take the whole capacity, rather
    /// than idling on its behalf.
    #[test]
    fn a_drained_group_yields_its_share() {
        let mut s = Scheduler::new();
        s.register(1, Some(1), None);
        s.register(2, Some(2), None);
        s.enqueue(1, 2);
        s.enqueue(2, 10);

        let order = drain(&mut s, 1);
        assert_eq!(order.iter().filter(|id| **id == 1).count(), 2);
        assert_eq!(order.iter().filter(|id| **id == 2).count(), 10);
    }

    /// Each group is its own numberspace, so a high sendOrder in one group does
    /// not outrank a low one in another: the groups still alternate.
    #[test]
    fn send_order_does_not_compare_across_groups() {
        let mut s = Scheduler::new();
        s.register(1, Some(1), Some(i64::MAX));
        s.register(2, Some(2), Some(i64::MIN));
        s.enqueue(1, 3);
        s.enqueue(2, 3);

        let order = drain(&mut s, 1);
        let first_two: Vec<_> = order.iter().take(2).copied().collect();
        assert!(
            first_two.contains(&1) && first_two.contains(&2),
            "groups must alternate regardless of send order, got {order:?}"
        );
    }

    /// The null group competes on equal terms with named groups.
    #[test]
    fn the_null_group_is_an_equal_claimant() {
        let mut s = Scheduler::new();
        s.register(1, None, None);
        s.register(2, Some(7), None);
        s.enqueue(1, 10);
        s.enqueue(2, 10);

        let order = drain(&mut s, 1);
        let null = order.iter().filter(|id| **id == 1).count();
        let named = order.len() - null;
        assert!(null.abs_diff(named) <= 1, "got {null} vs {named}");
    }

    #[test]
    fn a_drained_stream_stops_competing() {
        let mut s = Scheduler::new();
        s.register(1, None, None);
        s.register(2, None, None);
        s.enqueue(1, 1);
        s.enqueue(2, 3);

        let order = drain(&mut s, 1);
        assert_eq!(order.iter().filter(|id| **id == 1).count(), 1);
        assert_eq!(order.iter().filter(|id| **id == 2).count(), 3);
        assert!(!s.has_work());
    }

    #[test]
    fn removing_a_stream_withdraws_its_work() {
        let mut s = Scheduler::new();
        s.register(1, None, None);
        s.register(2, None, None);
        s.enqueue(1, 5);
        s.enqueue(2, 5);
        s.remove(1);

        let order = drain(&mut s, 1);
        assert!(order.iter().all(|id| *id == 2), "got {order:?}");
    }

    /// Reassigning a group moves the stream into that numberspace immediately.
    #[test]
    fn a_stream_can_change_group() {
        let mut s = Scheduler::new();
        s.register(1, Some(1), None);
        s.enqueue(1, 1);
        s.set_group(1, Some(2));
        assert_eq!(s.next(), Some(1));

        s.register(2, Some(2), Some(5));
        s.set_send_order(1, Some(9));
        s.enqueue(1, 1);
        s.enqueue(2, 1);
        // Both are now in group 2, so the higher order wins.
        assert_eq!(s.next(), Some(1));
    }

    /// Writing more than is pending must not underflow into a huge backlog.
    #[test]
    fn over_writing_does_not_underflow() {
        let mut s = Scheduler::new();
        s.register(1, None, None);
        s.enqueue(1, 10);
        s.wrote(1, 999);
        assert_eq!(s.pending(1), 0);
        assert!(!s.has_work());
    }

    #[test]
    fn enqueue_saturates_rather_than_overflowing() {
        let mut s = Scheduler::new();
        s.register(1, None, None);
        s.enqueue(1, u64::MAX);
        s.enqueue(1, u64::MAX);
        assert_eq!(s.pending(1), u64::MAX);
    }

    /// An unregistered stream is simply not scheduled, rather than panicking.
    #[test]
    fn unknown_streams_are_ignored() {
        let mut s = Scheduler::new();
        s.enqueue(99, 10);
        s.wrote(99, 1);
        s.set_group(99, Some(1));
        assert_eq!(s.pending(99), 0);
        assert_eq!(s.next(), None);
    }

    /// Scheduling many streams must stay deterministic, so a decision can be
    /// reproduced when debugging.
    #[test]
    fn scheduling_is_deterministic() {
        let build = || {
            let mut s = Scheduler::new();
            for id in 0..20u64 {
                s.register(id, Some(id % 3), Some(id as i64));
                s.enqueue(id, 5);
            }
            s
        };
        assert_eq!(drain(&mut build(), 1), drain(&mut build(), 1));
    }
}
