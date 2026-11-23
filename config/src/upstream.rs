use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct ProxyRoute<'a> {
    pub prefix: &'a str,
    /// Positive widths discover a hex resource. A zero width selects a fixed endpoint or a pool.
    pub width: usize,
    pub candidates: Vec<SocketAddr>,
    pub health_path: Option<&'a str>,
    pub drained: Vec<SocketAddr>,
}
pub(crate) fn prefix(s: &str) -> bool {
    omakase::valid_path(s.as_bytes()) && (s == "/" || !s.ends_with('/'))
}
impl<'a> ProxyRoute<'a> {
    pub(crate) fn parse(v: &[&'a str], kind: &str) -> Option<Self> {
        let resource = kind == "proxy-resource";
        let pool = kind == "proxy-pool";
        if !prefix(v[0]) || (resource && v[0] == "/") {
            return None;
        }
        let width = if resource {
            let n: usize = v[1].parse().ok()?;
            if n == 0 || n > 64 || n.to_string() != v[1] {
                return None;
            }
            n
        } else {
            0
        };
        let candidates = endpoints(v[if resource || pool { 2 } else { 1 }])?;
        if (!resource && !pool && candidates.len() != 1)
            || (pool
                && (!omakase::valid_path(v[1].as_bytes())
                    || candidates
                        .iter()
                        .any(|a| SocketAddr::new(a.ip(), a.port()) != *a)))
        {
            return None;
        }
        Some(Self {
            prefix: v[0],
            width,
            candidates,
            health_path: pool.then_some(v[1]),
            drained: Vec::new(),
        })
    }
}

pub(crate) fn endpoints(value: &str) -> Option<Vec<SocketAddr>> {
    let mut result = Vec::new();
    for endpoint in value.split(',') {
        let addr: SocketAddr = endpoint.parse().ok()?;
        if addr.to_string() != endpoint
            || !omakase::proxy::endpoint_allowed(addr.ip().to_string().as_bytes(), addr.port())
            || result.contains(&addr)
            || result.len() == 32
        {
            return None;
        }
        result.push(addr);
    }
    Some(result)
}
