//! Orderly endpoint shutdown before the host runtime goes away.
//!
//! A quinn endpoint's driver runs as a task on the Tokio runtime that created
//! it. The addon does not own that runtime: napi does, and it shuts the runtime
//! down as the module unloads at process exit. An endpoint still live at that
//! point has its driver dropped mid-flight, and the process aborts.
//!
//! From the outside that looks like a crash after everything succeeded: the
//! test suite passes, then the process dies, which a shell reports only as a
//! non-zero exit. Nothing in the run points at the endpoint, because by then
//! the work is long finished.
//!
//! So every endpoint registers here when it is created, and the addon closes
//! them all before the environment goes away. The trigger is the JS `exit`
//! event: it fires before teardown begins, so the settle window in
//! [`close_all_and_settle`] can safely let parked work drain. A napi cleanup
//! hook also calls [`close_all`] as a fallback, but on Bun it fires while the
//! environment is already being destroyed, so it must not block.

use std::sync::Mutex;

/// Every endpoint created in this process.
///
/// Closing an endpoint is idempotent and cheap, and this only ever runs at
/// teardown, so entries are kept rather than reaped as endpoints go idle.
static ENDPOINTS: Mutex<Vec<quinn::Endpoint>> = Mutex::new(Vec::new());

/// Registers an endpoint to be closed before the runtime is torn down.
pub fn register(endpoint: &quinn::Endpoint) {
    if let Ok(mut endpoints) = ENDPOINTS.lock() {
        endpoints.push(endpoint.clone());
    }
}

/// Closes every registered endpoint, signalling only.
///
/// The closes are synchronous, but the fallout — parked futures resolving,
/// drivers retiring — is not waited for. That makes this safe to run from a
/// napi cleanup hook, which fires while teardown is already underway and must
/// not block; it is a fallback for paths that never ran
/// [`close_all_and_settle`], which is the real exit-time entry point.
pub fn close_all() {
    let endpoints = match ENDPOINTS.lock() {
        Ok(mut endpoints) => std::mem::take(&mut *endpoints),
        Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
    };
    for endpoint in endpoints {
        endpoint.close(0u32.into(), b"process exit");
    }
}

/// Closes every registered endpoint and waits out the fallout, synchronously.
///
/// The settle window gives the runtime the time to complete whatever was
/// parked on the endpoints — pending `accept`s, stream `read`s, `closed`
/// waiters — so that by the time the caller proceeds to teardown nothing
/// async is still in flight. Bounded, and only paid when there was anything
/// to close.
pub fn close_all_and_settle() {
    let endpoints = match ENDPOINTS.lock() {
        Ok(mut endpoints) => std::mem::take(&mut *endpoints),
        Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
    };
    if endpoints.is_empty() {
        return;
    }
    for endpoint in endpoints {
        endpoint.close(0u32.into(), b"process exit");
    }
    // The closes above only signal; the runtime polls the woken tasks and
    // settles their deferreds on its own threads, so a brief block here is
    // what lets that drain before the environment goes away. This must not
    // run during teardown itself, where the environment is being destroyed
    // concurrently; it runs from the JS `exit` event, before teardown begins.
    std::thread::sleep(std::time::Duration::from_millis(200));
}
