//! Orderly endpoint shutdown before the host runtime goes away.
//!
//! A quinn endpoint's driver runs as a task on the Tokio runtime that created
//! it. The addon does not own that runtime: napi does, and it shuts the runtime
//! down as the module unloads at process exit. If an endpoint is still live at
//! that point its driver is dropped mid-flight, and quinn aborts the process.
//!
//! From the outside that looks like a crash after everything succeeded: the
//! test suite passes, then the process dies with `abort()` (`Abort trap: 6` on
//! macOS, `0xC0000409` on Windows), which a shell reports as a bare non-zero
//! exit. Nothing in the run points at the endpoint, because by then the work is
//! long finished.
//!
//! So every endpoint registers here when it is created, and the addon closes
//! them all from a module-teardown hook while the runtime is still alive.

use std::sync::Mutex;

/// Every endpoint created in this process, weakly identified.
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

/// Closes every registered endpoint.
///
/// Call from module teardown, while the Tokio runtime still exists. `close` is
/// synchronous and tells each driver to finish, which is what lets the runtime
/// shut down without dropping a live driver. Peers get a connection close
/// rather than silence.
///
/// A poisoned lock is ignored rather than propagated: this runs while the
/// process is going away, and panicking there loses the clean exit it exists to
/// produce.
pub fn close_all() {
    let endpoints = match ENDPOINTS.lock() {
        Ok(mut endpoints) => std::mem::take(&mut *endpoints),
        Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
    };
    if endpoints.is_empty() {
        return;
    }

    for endpoint in &endpoints {
        endpoint.close(0u32.into(), b"process exit");
    }

    // `close` only signals the drivers; each finishes asynchronously, and the
    // abort happens precisely when the runtime disappears before they do.
    // `wait_idle` is what actually waits for a driver to retire, so drive it
    // to completion here, on a runtime of our own.
    //
    // A private current-thread runtime rather than the caller's: this runs
    // from a napi cleanup hook on the JS thread, where the addon's runtime is
    // already being shut down, so blocking on it would deadlock. The wait is
    // bounded because a peer that never acknowledges a close must not hang
    // process exit.
    let waiter = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let Ok(waiter) = waiter else {
        return;
    };
    waiter.block_on(async {
        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            for endpoint in &endpoints {
                endpoint.wait_idle().await;
            }
        })
        .await;
    });
}
