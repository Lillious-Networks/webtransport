//! The async face of [`wt_proto::scheduler`].
//!
//! The policy (which stream sends next, and how groups share bandwidth) lives
//! in `wt-proto` as a pure decision function. This wraps it in the
//! synchronisation a live connection needs: writers wait for their turn, and
//! each completed write wakes whoever is next.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::Notify;
use wt_proto::scheduler::{GroupId, Scheduler};

/// Schedules the send streams of one session.
#[derive(Debug)]
pub struct SendScheduler {
    inner: Mutex<Scheduler>,
    /// Woken whenever the schedule changes, so waiters re-check their turn.
    changed: Notify,
    next_id: AtomicU64,
}

impl Default for SendScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl SendScheduler {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Scheduler::new()),
            changed: Notify::new(),
            next_id: AtomicU64::new(0),
        }
    }

    /// Registers a stream and returns the id the scheduler knows it by.
    pub fn register(&self, group: GroupId, send_order: Option<i64>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().unwrap().register(id, group, send_order);
        id
    }

    pub fn remove(&self, id: u64) {
        self.inner.lock().unwrap().remove(id);
        // Removing a stream can hand the turn to someone else.
        self.changed.notify_waiters();
    }

    pub fn enqueue(&self, id: u64, bytes: u64) {
        self.inner.lock().unwrap().enqueue(id, bytes);
        self.changed.notify_waiters();
    }

    pub fn wrote(&self, id: u64, bytes: u64) {
        self.inner.lock().unwrap().wrote(id, bytes);
        self.changed.notify_waiters();
    }

    pub fn set_group(&self, id: u64, group: GroupId) {
        self.inner.lock().unwrap().set_group(id, group);
        self.changed.notify_waiters();
    }

    pub fn set_send_order(&self, id: u64, send_order: Option<i64>) {
        self.inner.lock().unwrap().set_send_order(id, send_order);
        self.changed.notify_waiters();
    }

    /// Total bytes queued across every stream this scheduler governs.
    pub fn queued_bytes(&self) -> u64 {
        self.inner.lock().unwrap().total_pending()
    }

    /// Takes this stream's turn if the scheduler would choose it.
    ///
    /// Consuming the turn only when the caller actually proceeds is what keeps
    /// the round-robin honest: polling must not inflate another stream's turn
    /// count, or repeated checks would skew the very fairness being scheduled.
    fn take_turn(&self, id: u64) -> bool {
        let mut scheduler = self.inner.lock().unwrap();
        match scheduler.peek() {
            Some(chosen) if chosen == id => {
                scheduler.next();
                true
            }
            Some(_) => false,
            // Nothing queued: let the writer proceed rather than deadlock.
            None => true,
        }
    }

    /// Waits until the scheduler picks this stream.
    ///
    /// A stream that wins its turn and then blocks on flow control would hold
    /// the transport indefinitely, so waiting is bounded: on timeout the writer
    /// proceeds anyway and lets QUIC's own flow control arbitrate. Scheduling
    /// is a bandwidth preference, not a correctness guarantee, and a strict
    /// wait here would turn one stalled peer into a stalled session.
    pub async fn wait_for_turn(&self, id: u64) {
        const MAX_WAIT: std::time::Duration = std::time::Duration::from_millis(50);
        let deadline = tokio::time::Instant::now() + MAX_WAIT;
        loop {
            // Register for notification before testing, so a change between the
            // test and the wait cannot be missed.
            let notified = self.changed.notified();
            if self.take_turn(id) {
                return;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn a_lone_stream_never_waits() {
        let s = SendScheduler::new();
        let id = s.register(None, None);
        s.enqueue(id, 10);
        // Completes immediately rather than hanging.
        tokio::time::timeout(std::time::Duration::from_secs(1), s.wait_for_turn(id))
            .await
            .expect("a lone stream should be scheduled at once");
    }

    /// An idle scheduler must not block a writer: with nothing queued there is
    /// no contention to arbitrate.
    #[tokio::test]
    async fn an_unqueued_stream_proceeds() {
        let s = SendScheduler::new();
        let id = s.register(None, None);
        tokio::time::timeout(std::time::Duration::from_secs(1), s.wait_for_turn(id))
            .await
            .expect("an idle scheduler should not block");
    }

    /// The higher send order is chosen first: the lower one does not get the
    /// turn while its rival is queued.
    #[tokio::test]
    async fn a_lower_priority_stream_does_not_take_the_turn() {
        let s = Arc::new(SendScheduler::new());
        let low = s.register(None, Some(1));
        let high = s.register(None, Some(100));
        s.enqueue(low, 10);
        s.enqueue(high, 10);

        assert!(
            !s.take_turn(low),
            "the low-order stream must not win the turn"
        );
        assert!(s.take_turn(high), "the high-order stream should win it");
    }

    /// Waiting is bounded: a stream that would otherwise wait forever behind a
    /// stalled peer proceeds anyway, letting QUIC's flow control arbitrate.
    /// Scheduling is a bandwidth preference, not a lock.
    #[tokio::test]
    async fn waiting_for_a_turn_is_bounded() {
        let s = Arc::new(SendScheduler::new());
        let low = s.register(None, Some(1));
        let high = s.register(None, Some(100));
        s.enqueue(low, 10);
        // The high-order stream is queued and never drains, so the low one is
        // outranked for as long as it waits.
        s.enqueue(high, u64::MAX);

        tokio::time::timeout(std::time::Duration::from_secs(2), s.wait_for_turn(low))
            .await
            .expect("a bounded wait must not block indefinitely");
    }

    /// Once the higher-priority stream drains, the lower one is released
    /// promptly rather than waiting out its timeout.
    #[tokio::test]
    async fn draining_the_rival_releases_the_waiter() {
        let s = Arc::new(SendScheduler::new());
        let low = s.register(None, Some(1));
        let high = s.register(None, Some(100));
        s.enqueue(low, 10);
        s.enqueue(high, 10);

        let scheduler = s.clone();
        let waiter = tokio::spawn(async move { scheduler.wait_for_turn(low).await });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        s.wrote(high, 10);

        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("the low priority stream should proceed once the other drains")
            .expect("task");
    }

    #[tokio::test]
    async fn removing_a_stream_releases_the_next_one() {
        let s = Arc::new(SendScheduler::new());
        let low = s.register(None, Some(1));
        let high = s.register(None, Some(100));
        s.enqueue(low, 10);
        s.enqueue(high, 10);

        let scheduler = s.clone();
        let waiter = tokio::spawn(async move { scheduler.wait_for_turn(low).await });

        // Give the waiter a chance to block, then withdraw its competitor.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        s.remove(high);

        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("removing the competitor should release the waiter")
            .expect("task");
    }

    #[tokio::test]
    async fn ids_are_unique() {
        let s = SendScheduler::new();
        let ids: Vec<_> = (0..100).map(|_| s.register(None, None)).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len());
    }
}
