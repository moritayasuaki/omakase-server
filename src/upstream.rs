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

/// Monotonic nanoseconds since this pool generation was created. Revision zero
/// denotes a cold member; an exhausted revision permanently refuses dispatch.
#[derive(Clone, Copy, Default)]
pub struct PoolHealth {
    pub revision: u64,
    pub at: u64,
    pub status: u16,
}

pub fn publish_health(old: PoolHealth, expected: u64, now: u64, status: u16) -> PoolHealth {
    if expected != old.revision || expected == u64::MAX || now < old.at {
        return old;
    }
    PoolHealth {
        revision: expected + 1,
        at: now,
        status,
    }
}

pub fn fresh_health(h: PoolHealth, now: u64) -> bool {
    h.revision != 0
        && h.revision != u64::MAX
        && now != u64::MAX
        && now >= h.at
        && now - h.at < 5_000_000_000
}

#[allow(clippy::manual_range_contains)]
pub fn healthy_response(status: u16) -> bool {
    status >= 200 && status < 300
}

pub fn retire_pool(retired: &mut bool) {
    *retired = true;
}

pub struct FirstWriteGate {
    pub peer: u32,
    pub health: PoolHealth,
    pub now: u64,
    pub draining: bool,
    pub retired: bool,
}

pub fn first_write_allowed(
    members: &[u32],
    index: usize,
    gate: &FirstWriteGate,
    sent: bool,
) -> bool {
    let ready = fresh_health(gate.health, gate.now) && healthy_response(gate.health.status);
    gate.peer != 0
        && pool_select(members, index, ready, gate.draining || gate.retired, sent) == gate.peer
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirstIo {
    Wait,
    Written(usize),
    Failed,
}

/// The socket adapter implements this effect as one nonblocking write on the
/// same connected descriptor whose peer was checked. There is no reconnect here.
pub trait FirstWriter {
    fn write_once(&mut self) -> FirstIo;
}

pub fn guarded_first_write<W: FirstWriter>(
    members: &[u32],
    index: usize,
    gate: &FirstWriteGate,
    sent: &mut bool,
    writer: &mut W,
) -> Option<FirstIo> {
    if !first_write_allowed(members, index, gate, *sent) {
        return None;
    }
    let outcome = writer.write_once();
    if let FirstIo::Wait = outcome {
        return Some(FirstIo::Wait);
    }
    begin_dispatch(sent);
    Some(match outcome {
        FirstIo::Written(0) => FirstIo::Failed,
        other => other,
    })
}
