use std::sync::Mutex;

/// Both borrows end inside this synchronous call. A poisoned acquisition
/// skips the operation and releases any guard already acquired.
pub(crate) fn with_snapshot<G, H, R>(
    generation: &Mutex<G>,
    health: &Mutex<H>,
    operation: impl FnOnce(&G, &H) -> R,
) -> Option<R> {
    let generation = generation.lock().ok()?;
    let health = health.lock().ok()?;
    Some(operation(&generation, &health))
}
