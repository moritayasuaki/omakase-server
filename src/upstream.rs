//! Pure gates for explicit, anonymous resource discovery before one exchange.

/// Discovery must not carry a client body, credentials, or a mutating method.
pub fn probe_allowed(
    get: bool,
    body: u64,
    credentials: bool,
    resource: bool,
    candidates: u64,
) -> bool {
    get && body == 0 && !credentials && resource && candidates > 0 && candidates <= 32
}

/// Only absence permits trying the next discovery endpoint. Authorization,
/// gone, overload, connection errors and server errors must never fall through.
pub fn probe_next(status: u16, remaining: u64) -> bool {
    status == 404 && remaining > 0 && remaining < 32
}

#[allow(clippy::manual_range_contains)] // scalar comparisons in the extracted model
pub fn probe_owned(status: u16) -> bool {
    (status >= 200 && status < 300) || status == 401 || status == 403 || status == 410
}

/// Query headers conservatively apply to encoded/ambiguous keys as well.
pub fn query_match(exact: bool, ambiguous: bool) -> bool {
    exact || ambiguous
}

/// Return the actual route member, never an address supplied by the request.
/// Zero is outside the encoding of a permitted loopback socket address.
pub fn pool_select(members: &[u32], index: usize, ready: bool, draining: bool, sent: bool) -> u32 {
    if ready && !draining && !sent && members.len() <= 32 && index < members.len() {
        members[index]
    } else {
        0
    }
}

/// Consume this request's only dispatch permission before its first socket write.
pub fn begin_dispatch(sent: &mut bool) -> bool {
    let allowed = !*sent;
    *sent = true;
    allowed
}
