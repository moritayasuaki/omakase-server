//! Local replica selection. An application request is serialized only after this
//! module returns one connected socket. Probes carry no client data.
use crate::{async_http, http, proxy};
use pathward::upstream::{begin_dispatch, pool_select};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const HEALTH_TTL: Duration = Duration::from_secs(5);

struct Member {
    address: SocketAddr,
    draining: bool,
    checking: AtomicBool,
    observation: Mutex<Option<(Instant, bool)>>,
}

impl Member {
    fn cached(&self) -> Option<bool> {
        self.observation
            .lock()
            .ok()?
            .as_ref()
            .filter(|(at, _)| at.elapsed() < HEALTH_TTL)
            .map(|(_, ready)| *ready)
    }

    fn observe(&self, started: Instant, ready: bool) {
        if let Ok(mut last) = self.observation.lock()
            && last.is_none_or(|(at, _)| at <= started)
        {
            *last = Some((Instant::now(), ready));
        }
    }
}

struct ProbeGuard<'a>(&'a AtomicBool);
impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(crate) struct Pool {
    members: Vec<Member>,
    /// Bit 16 selects IPv6 loopback. The low sixteen bits are a nonzero port.
    keys: Vec<u32>,
    probe: String,
    next: AtomicUsize,
    /// Serializes retirement with permission to start one application exchange.
    retired: Mutex<bool>,
}

fn key(addr: SocketAddr) -> u32 {
    (u32::from(addr.is_ipv6()) << 16) | u32::from(addr.port())
}

fn address(key: u32) -> Option<SocketAddr> {
    let port = key as u16;
    match (key >> 16, port) {
        (0, 1..) => Some(SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
        (1, 1..) => Some(SocketAddr::from((Ipv6Addr::LOCALHOST, port))),
        _ => None,
    }
}

impl Pool {
    pub fn new(host: &str, path: &str, addresses: &[SocketAddr], drains: &[SocketAddr]) -> Self {
        Self {
            keys: addresses.iter().copied().map(key).collect(),
            members: addresses
                .iter()
                .map(|&address| Member {
                    address,
                    draining: drains.contains(&address),
                    checking: AtomicBool::new(false),
                    observation: Mutex::new(None),
                })
                .collect(),
            probe: format!(
                "GET {path} HTTP/1.1\r\nHost: {host}\r\nVia: 1.1 pathward\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            ),
            next: AtomicUsize::new(0),
            retired: Mutex::new(false),
        }
    }

    pub fn retire(&self) {
        if let Ok(mut retired) = self.retired.lock() {
            *retired = true;
        }
    }

    async fn check(&self, member: &Member, deadline: Instant) -> io::Result<bool> {
        let mut socket = async_http::connect(member.address, http::remaining(deadline)?).await?;
        async_http::write_all(&mut socket, self.probe.as_bytes(), deadline).await?;
        let status = proxy::probe_status(&mut socket, deadline).await?;
        Ok((200..300).contains(&status))
    }

    async fn ready(&self, member: &Member, deadline: Instant) -> bool {
        loop {
            if member.draining
                || Instant::now() >= deadline
                || self.retired.lock().map_or(true, |r| *r)
            {
                return false;
            }
            if let Some(ready) = member.cached() {
                return ready;
            }
            if !member.checking.swap(true, Ordering::AcqRel) {
                let _guard = ProbeGuard(&member.checking);
                if let Some(ready) = member.cached() {
                    return ready;
                }
                let start = Instant::now();
                let probe_deadline = start + PROBE_TIMEOUT;
                let ready = self
                    .check(member, deadline.min(probe_deadline))
                    .await
                    .unwrap_or(false);
                // A short client deadline must not poison the health of a replica.
                if ready || Instant::now() < deadline || probe_deadline <= deadline {
                    member.observe(start, ready);
                }
                return ready;
            }
            async_http::pause().await;
        }
    }

    pub(crate) async fn refresh(&self, local_ports: &[u16], shutdown: &AtomicBool) {
        for member in &self.members {
            if shutdown.load(Ordering::Acquire) {
                return;
            }
            if !local_ports.contains(&member.address.port())
                && proxy::allowed_endpoint(member.address, 0)
            {
                self.ready(member, Instant::now() + PROBE_TIMEOUT).await;
            }
            // One member per poll, including cached/drained members of a large config.
            futures_lite::future::yield_now().await;
        }
    }

    pub(crate) async fn connect(
        &self,
        local_port: u16,
        deadline: Instant,
        connect_timeout: Duration,
        sent: &mut bool,
    ) -> Result<TcpStream, http::Rejection> {
        let count = self.members.len();
        if count == 0 || *sent {
            return Err(http::Rejection(503));
        }
        let first = self.next.fetch_add(1, Ordering::Relaxed) % count;
        let mut dials = 0;
        for offset in 0..count {
            let i = (first + offset) % count;
            let member = &self.members[i];
            if !proxy::allowed_endpoint(member.address, local_port) {
                continue;
            }
            let ready = self.ready(member, deadline).await;
            if *self.retired.lock().map_err(|_| http::Rejection(503))? {
                return Err(http::Rejection(503));
            }
            let selected = pool_select(&self.keys, i, ready, member.draining, *sent);
            let Some(addr) = address(selected) else {
                continue;
            };
            if addr != member.address {
                return Err(http::Rejection(503));
            }
            let timeout = http::remaining(deadline)
                .map_err(|_| http::Rejection(504))?
                .min(connect_timeout);
            let start = Instant::now();
            dials += 1;
            match async_http::connect(addr, timeout).await {
                Ok(socket) => {
                    let retired = self.retired.lock().map_err(|_| http::Rejection(503))?;
                    let permitted = pool_select(
                        &self.keys,
                        i,
                        member.cached() == Some(true),
                        *retired || member.draining,
                        *sent,
                    );
                    if permitted == selected && begin_dispatch(sent) {
                        return Ok(socket);
                    }
                }
                Err(_) => member.observe(start, false),
            }
            if dials == 2 {
                break;
            }
        }
        Err(http::Rejection(503))
    }
}

impl crate::Server {
    pub(crate) async fn refresh_backend_pools(&self, local_ports: [u16; 2], shutdown: &AtomicBool) {
        while !shutdown.load(Ordering::Acquire) {
            let snapshot = match self.state.read() {
                Ok(state) => state.snapshot.clone(),
                Err(_) => return,
            };
            for route in snapshot.sites.iter().flat_map(|site| &site.proxy_routes) {
                if let Some(pool) = &route.pool {
                    pool.refresh(&local_ports, shutdown).await;
                }
            }
            drop(snapshot);
            async_io::Timer::after(Duration::from_secs(1)).await;
        }
    }
}
