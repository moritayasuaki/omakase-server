//! Read-only inventory and point-in-time observations for Linux pooled routes.
use crate::{control, deployment, sleep_fence};
use pathward::upstream::{pool_preflight_ready, pool_witness_current};
use rustix::time::{DynamicClockId, clock_gettime_dynamic};
use std::{
    fs,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
    time::Duration,
};

#[path = "pool_sleep_units.rs"]
mod units;

fn invalid() -> io::Error {
    io::Error::other("invalid service fence observation")
}

fn clock_domain() -> io::Result<String> {
    let s = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let id = s.trim_end();
    if id.len() != 36
        || !id.bytes().enumerate().all(|(n, b)| {
            if [8, 13, 18, 23].contains(&n) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(invalid());
    }
    let ns = fs::metadata("/proc/self/ns/time")?;
    Ok(format!("{id}:{}:{}", ns.dev(), ns.ino()))
}

fn boot_ms() -> io::Result<u64> {
    let t = clock_gettime_dynamic(DynamicClockId::Boottime)?;
    Duration::try_from(t)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or_else(invalid)
}

/// Run in the service's actual credentials and mount namespace. Records no
/// client data, makes no probes, and releases the shared flock before returning.
pub fn witness() -> io::Result<String> {
    let boot = clock_domain()?;
    let time = boot_ms()?;
    let (identity, check) = sleep_fence::inspect();
    let state = check.map_or_else(|e| e.label(), |()| "awake");
    let id = identity.map_or_else(|| "-".into(), |(dev, ino)| format!("{dev}:{ino}"));
    Ok(format!("OK F1 {boot} {time} {id} {state}"))
}

struct Observation<'a> {
    identity: Option<(u64, u64)>,
    state: &'a str,
}

fn parse_witness<'a>(line: &'a str, boot: &str, now: u64) -> io::Result<Observation<'a>> {
    let words: Vec<_> = line.strip_suffix('\n').unwrap_or(line).split(' ').collect();
    let ["OK", "F1", observed_boot, at, id, state] = words.as_slice() else {
        return Err(invalid());
    };
    let at = at.parse().map_err(|_| invalid())?;
    if !pool_witness_current(*observed_boot == boot, at, now) {
        return Err(io::Error::other(
            "service observation is stale or from another boot or time namespace",
        ));
    }
    let identity = if *id == "-" {
        None
    } else {
        let (dev, ino) = id.split_once(':').ok_or_else(invalid)?;
        Some((
            dev.parse().map_err(|_| invalid())?,
            ino.parse().map_err(|_| invalid())?,
        ))
    };
    if !matches!(
        *state,
        "awake" | "missing" | "permission" | "untrusted" | "busy" | "closed" | "malformed" | "io"
    ) || (*state == "awake" && identity.is_none())
    {
        return Err(invalid());
    }
    Ok(Observation { identity, state })
}

pub enum ServiceView<'a> {
    Control(&'a Path),
    Stdin,
    Unobserved,
}

fn service_report(view: ServiceView<'_>) -> io::Result<String> {
    match view {
        ServiceView::Control(dir) => deployment::command(dir, "POOL-FENCE", None, &[]),
        ServiceView::Stdin => {
            let mut s = String::new();
            io::stdin().take(161).read_to_string(&mut s)?;
            if s.len() > 160 {
                return Err(invalid());
            }
            Ok(s)
        }
        ServiceView::Unobserved => Err(io::Error::other("supply --control-dir or --service-stdin")),
    }
}

fn same_object(a: &str, b: &str) -> io::Result<bool> {
    let a = fs::metadata(a)?;
    let b = fs::metadata(b)?;
    Ok((a.dev(), a.ino()) == (b.dev(), b.ino()))
}

pub fn run(config: &Path, view: ServiceView<'_>) -> io::Result<()> {
    let parsed = control::read_config(config)?;
    let config = parsed.compile().map_err(io::Error::other)?;
    let mut pools = 0;
    for site in config.sites() {
        for route in site
            .proxy_routes()
            .iter()
            .filter(|r| r.health_path.is_some())
        {
            println!(
                "pool host={} path={} members={} draining={}",
                site.host(),
                route.prefix,
                route.candidates.len(),
                route.drained.len()
            );
            pools += 1;
        }
    }
    println!(
        "sites={} proxy_pools={pools} revision={}",
        config.sites().len(),
        deployment::revision(config.source().as_bytes())
    );
    if pools == 0 {
        println!("NOT_REQUIRED");
        return Ok(());
    }
    let manager = same_object("/proc/self/ns/mnt", "/proc/1/ns/mnt").unwrap_or(false)
        && same_object("/", "/proc/1/root").unwrap_or(false);
    let binary = units::coordinator_matches().unwrap_or(false);
    let modes = units::inspect();
    let raw = service_report(view);
    let service = raw
        .as_deref()
        .map_err(|_| invalid())
        .and_then(|s| parse_witness(s, &clock_domain()?, boot_ms()?));
    let (host_id, host) = sleep_fence::inspect();
    let same = host_id.is_some() && service.as_ref().is_ok_and(|s| s.identity == host_id);
    println!(
        "host_namespace={manager} coordinator_binary={binary} host_fence={} service_fence={} same_inode={same}",
        host.map_or_else(|e| e.label(), |()| "awake"),
        service.as_ref().map_or("unverified", |s| s.state)
    );
    if let Err(e) = &raw {
        eprintln!("Service witness unavailable: {e}");
    } else if let Err(e) = &service {
        eprintln!("Service witness rejected: {e}");
    }
    if pool_preflight_ready(
        service.is_ok_and(|s| s.state == "awake"),
        host.is_ok() && manager && binary,
        same,
        modes,
    ) {
        println!("READY");
        Ok(())
    } else {
        println!("BLOCKED");
        Err(io::Error::other("pool prerequisites are incomplete"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_must_be_recent_same_boot_and_have_a_descriptor() {
        let line = "OK F1 boot 100 1:19 awake";
        assert!(parse_witness(line, "boot", 30_099).is_ok());
        for (boot, now) in [("boot", 30_100), ("boot", 99), ("other", 100)] {
            assert!(parse_witness(line, boot, now).is_err());
        }
        for invalid in [
            "OK F1 boot 100 - awake",
            "OK F1 boot 100 1:19 anything",
            "OK F1 boot 100 1:19 awake extra",
        ] {
            assert!(parse_witness(invalid, "boot", 100).is_err());
        }
    }
}
