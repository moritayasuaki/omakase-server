//! Durable registrations for work outside the four local sleep cgroups.
//! Writers and hooks lock the directory inode; replacing the state file never
//! changes the lock. Nothing in the boot or recovery path creates idle state.
use crate::{pool_preflight, pool_recovery, sleep_fence::Failure, sleep_ticket::*};
use pathward::upstream::{delegate_can_retire, delegates_allow_write};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{ED25519, UnparsedPublicKey},
};
use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, fchmod, flock, fstatfs, open, openat, renameat, unlinkat,
};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
};

const DIR: &str = "/var/lib/pathward-sleep-delegates";
const ANCHOR: &str = "/etc/pathward-sleep-delegates.id";
const RECORD: &str = "state";
const READ: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

fn bad(msg: &'static str) -> io::Error {
    io::Error::other(msg)
}

#[derive(Default)]
struct State {
    installation: String,
    provider: Option<(String, [u8; 32])>,
    service: Option<(String, String)>, // ticket, original boot/time namespace
    hypervisor: Option<String>,
}

fn ticket(s: &str) -> io::Result<String> {
    decode::<32>(s)
        .map(|_| s.to_owned())
        .ok_or_else(|| bad("invalid delegation ticket"))
}

impl State {
    fn text(&self) -> String {
        let (vm, key) = self
            .provider
            .as_ref()
            .map(|(vm, k)| (vm.as_str(), encode(k)))
            .unwrap_or(("-", "-".into()));
        let (service, boot) = self
            .service
            .as_ref()
            .map(|(t, b)| (t.as_str(), b.as_str()))
            .unwrap_or(("-", "-"));
        format!(
            "PW1 {} {vm} {key} {service} {boot} {}\n",
            self.installation,
            self.hypervisor.as_deref().unwrap_or("-")
        )
    }

    fn parse(s: &str) -> io::Result<Self> {
        let fields: Vec<_> = s.split_ascii_whitespace().collect();
        let ["PW1", installation, vm, key, service, boot, hv] = fields.as_slice() else {
            return Err(bad("invalid delegation ledger"));
        };
        let provider = match (*vm, *key) {
            ("-", "-") => None,
            (v, k) if uuid(v) => Some((
                v.to_owned(),
                decode(k).ok_or_else(|| bad("invalid provider key"))?,
            )),
            _ => return Err(bad("invalid provider identity")),
        };
        let service = match (*service, *boot) {
            ("-", "-") => None,
            (id, domain)
                if domain.split_once(':').is_some_and(|(boot, ns)| {
                    uuid(boot)
                        && ns.split_once(':').is_some_and(|(a, b)| {
                            a.parse::<u64>().is_ok() && b.parse::<u64>().is_ok()
                        })
                }) =>
            {
                Some((ticket(id)?, domain.to_owned()))
            }
            _ => return Err(bad("invalid service registration")),
        };
        let hypervisor = if *hv == "-" { None } else { Some(ticket(hv)?) };
        let state = Self {
            installation: ticket(installation)?,
            provider,
            service,
            hypervisor,
        };
        if state.text() != s || (state.provider.is_none() && state.hypervisor.is_some()) {
            return Err(bad("invalid delegation ledger"));
        }
        Ok(state)
    }

    fn idle(&self) -> bool {
        delegates_allow_write(self.service.is_some(), self.hypervisor.is_some())
    }
}

fn directory() -> io::Result<File> {
    let dir = File::from(open(DIR, READ | OFlags::DIRECTORY, Mode::empty())?);
    let m = dir.metadata()?;
    if m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(bad("untrusted delegation directory"));
    }
    Ok(dir)
}

pub(crate) fn identity() -> io::Result<(u64, u64)> {
    let m = directory()?.metadata()?;
    Ok((m.dev(), m.ino()))
}

fn read_record(f: File) -> io::Result<String> {
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.nlink() != 1 || m.len() > 512 {
        return Err(bad("untrusted delegation ledger"));
    }
    let mut text = String::new();
    f.take(513).read_to_string(&mut text)?;
    Ok(text)
}

fn anchor_text(installation: &str, dir: &File) -> io::Result<String> {
    Ok(format!("PW1 {installation} {}\n", dir.metadata()?.ino()))
}

fn load(dir: &File) -> io::Result<State> {
    let state = State::parse(&read_record(File::from(openat(
        dir,
        RECORD,
        READ,
        Mode::empty(),
    )?))?)?;
    let anchor = read_record(File::from(open(ANCHOR, READ, Mode::empty())?))?;
    if anchor != anchor_text(&state.installation, dir)? {
        return Err(bad("foreign delegation ledger"));
    }
    Ok(state)
}

fn new_ticket() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| bad("OS randomness unavailable"))?;
    Ok(encode(&bytes))
}

fn save(dir: &File, state: &State) -> io::Result<()> {
    // A single fixed scratch name is safe under this exclusive directory flock.
    // An interrupted pre-rename update leaves the previous record authoritative.
    let tmp = "state.next";
    match unlinkat(dir, tmp, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => (),
        Err(e) => return Err(e.into()),
    }
    let mut f = File::from(openat(
        dir,
        tmp,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    f.write_all(state.text().as_bytes())?;
    fchmod(&f, Mode::from_raw_mode(0o644))?;
    f.sync_all()?;
    renameat(dir, tmp, dir, RECORD)?;
    dir.sync_all()
}

pub(crate) fn reader() -> Result<File, Failure> {
    let dir = directory()?;
    flock(&dir, FlockOperation::NonBlockingLockShared).map_err(|e| {
        if e == rustix::io::Errno::WOULDBLOCK {
            Failure::Busy
        } else {
            Failure::Io
        }
    })?;
    if !load(&dir)?.idle() {
        return Err(Failure::Closed);
    }
    Ok(dir)
}

fn administrator() -> io::Result<()> {
    if !rustix::process::geteuid().is_root() {
        return Err(bad("delegation requires administrator"));
    }
    Ok(())
}

fn exclusive() -> io::Result<File> {
    administrator()?;
    let dir = directory()?;
    let host = fs::metadata("/proc/1/root/var/lib/pathward-sleep-delegates")?;
    let m = dir.metadata()?;
    if (host.dev(), host.ino()) != (m.dev(), m.ino()) {
        return Err(bad("foreign delegation directory"));
    }
    flock(&dir, FlockOperation::LockExclusive)?;
    Ok(dir)
}

fn provision(provider: Option<(&str, &str)>) -> io::Result<String> {
    administrator()?;
    if !pool_preflight::host_mount()? {
        return Err(bad("provision delegation in the host mount namespace"));
    }
    let binding = match provider {
        None => None,
        Some((vm, key)) if uuid(vm) => Some((
            vm.to_owned(),
            decode::<32>(key).ok_or_else(|| bad("invalid provider key"))?,
        )),
        _ => return Err(bad("invalid VM UUID")),
    };
    // Only a freshly created directory can acquire a new empty ledger. Losing
    // the state of an existing installation can never reinitialize it.
    let fresh = match fs::symlink_metadata(ANCHOR) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(DIR)?;
            fs::set_permissions(DIR, fs::Permissions::from_mode(0o755))?;
            File::open("/var/lib")?.sync_all()?;
            true
        }
        Ok(_) => false,
        Err(e) => return Err(e),
    };
    let dir = exclusive()?;
    let mut state = if fresh {
        State {
            installation: new_ticket()?,
            ..State::default()
        }
    } else {
        load(&dir)?
    };
    if state.provider.is_some() && state.provider != binding {
        return Err(bad("existing provider binding differs"));
    }
    if binding.is_some()
        && !matches!(
            fstatfs(&dir)?.f_type as u64,
            0xef53 | 0x58465342 | 0x9123683e
        )
    {
        return Err(bad(
            "remote delegations require local ext4, XFS or Btrfs storage",
        ));
    }
    if !fresh && binding == state.provider {
        return Ok("ALREADY_PROVISIONED".into());
    }
    if !state.idle() {
        return Err(bad("unfinished delegation"));
    }
    state.provider = binding;
    save(&dir, &state)?;
    if fresh {
        let mut f = File::from(open(
            ANCHOR,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        f.write_all(anchor_text(&state.installation, &dir)?.as_bytes())?;
        fchmod(&f, Mode::from_raw_mode(0o644))?;
        f.sync_all()?;
        File::open("/etc")?.sync_all()?;
    }
    Ok("PROVISIONED".into())
}

fn service_name(id: &str) -> String {
    format!("pathward-delegated-sleep@{id}.service")
}

fn service_properties(unit: &str) -> io::Result<String> {
    let properties = concat!(
        "Id,LoadState,NeedDaemonReload,Type,RemainAfterExit,Restart,ActiveState,SubState,",
        "InvocationID,Job,Result,MainPID,ControlPID,ExecMainCode,ExecMainStatus,",
        "ExecMainExitTimestampMonotonic,Slice,ControlGroup,Delegate,ProtectControlGroups,",
        "ExecCondition,ExecStartPre,ExecStartPost,ExecReload,ExecStop,ExecStopPost",
    );
    pool_preflight::units::output(
        "/usr/bin/systemctl",
        &["--system", "show", "--all", "--property", properties, unit],
    )
}

fn service_profile<'a>(unit: &str, raw: &'a str) -> io::Result<BTreeMap<&'a str, &'a str>> {
    let p: BTreeMap<_, _> = raw.lines().filter_map(|l| l.split_once('=')).collect();
    let expected = [
        ("Id", unit),
        ("LoadState", "loaded"),
        ("NeedDaemonReload", "no"),
        ("Type", "oneshot"),
        ("RemainAfterExit", "yes"),
        ("Restart", "no"),
        ("Job", ""),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("Slice", "system.slice"),
        ("Delegate", "no"),
        ("ProtectControlGroups", "yes"),
    ];
    let single_work_item = [
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
    ]
    .iter()
    .all(|key| p.get(key) == Some(&""));
    if !single_work_item || !expected.iter().all(|(k, v)| p.get(k) == Some(v)) {
        return Err(bad("delegated service profile or job state unconfirmed"));
    }
    Ok(p)
}

fn service_terminal(id: &str) -> io::Result<bool> {
    if !pool_preflight::host_mount()? || !pool_recovery::host_cgroup_domain()? {
        return Err(bad(
            "confirm service completion in the host mount and cgroup namespaces",
        ));
    }
    let unit = service_name(id);
    let raw = service_properties(&unit)?;
    let p = service_profile(&unit, &raw)?;
    let cgroup = format!("/system.slice/{unit}");
    let finished = [
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("Result", "success"),
        ("ExecMainCode", "1"),
        ("ExecMainStatus", "0"),
    ]
    .iter()
    .all(|(k, v)| p.get(k) == Some(v))
        && p.get("InvocationID")
            .and_then(|s| decode::<16>(s))
            .is_some_and(|v| v != [0; 16])
        && p.get("ExecMainExitTimestampMonotonic")
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|t| t > 0)
        && p.get("ControlGroup")
            .is_some_and(|p| p.is_empty() || *p == cgroup);
    Ok(finished && pool_recovery::empty_subtree(&unit)? && service_properties(&unit)? == raw)
}

pub fn command(args: &[&str]) -> io::Result<String> {
    match args {
        ["init-local"] => return provision(None),
        ["enroll", vm, key] => return provision(Some((vm, key))),
        ["status"] => {
            let dir = directory()?;
            flock(&dir, FlockOperation::LockShared)?;
            let s = load(&dir)?;
            return Ok(format!(
                "service={} hypervisor={}",
                s.service.as_ref().map_or("-", |s| s.0.as_str()),
                s.hypervisor.as_deref().unwrap_or("-")
            ));
        }
        _ => (),
    }
    let dir = exclusive()?;
    let mut state = load(&dir)?;
    match args {
        ["service-start"] if state.service.is_none() => {
            let id = new_ticket()?;
            let unit = service_name(&id);
            let raw = service_properties(&unit)?;
            if service_profile(&unit, &raw)?.get("ActiveState") != Some(&"inactive") {
                return Err(bad("delegated service instance is not idle"));
            }
            state.service = Some((id.clone(), pool_preflight::clock_domain()?));
            save(&dir, &state)?;
            drop(dir);
            pool_preflight::units::output(
                "/usr/bin/systemctl",
                &["--system", "--no-block", "start", &unit],
            )?;
            Ok(id)
        }
        ["service-check", id] => {
            let same = state.service.as_ref().is_some_and(|(t, _)| t == id);
            let boot = pool_preflight::clock_domain()?;
            let terminal = same
                && state.service.as_ref().is_some_and(|(_, b)| b == &boot)
                && service_terminal(id)?;
            if !delegate_can_retire(state.service.is_some(), same, terminal) {
                return Err(bad("service completion unconfirmed"));
            }
            state.service = None;
            save(&dir, &state)?;
            Ok("SERVICE_CONFIRMED".into())
        }
        ["hypervisor-begin"] if state.provider.is_some() && state.hypervisor.is_none() => {
            let id = new_ticket()?;
            state.hypervisor = Some(id.clone());
            save(&dir, &state)?;
            Ok(id)
        }
        ["hypervisor-confirm", id, signature] => {
            let (vm, key) = state
                .provider
                .as_ref()
                .ok_or_else(|| bad("no enrolled hypervisor"))?;
            let sig = decode::<64>(signature).ok_or_else(|| bad("invalid receipt encoding"))?;
            let same = state.hypervisor.as_deref() == Some(id);
            let terminal = same
                && UnparsedPublicKey::new(&ED25519, key)
                    .verify(terminal_message(vm, id).as_bytes(), &sig)
                    .is_ok();
            if !delegate_can_retire(state.hypervisor.is_some(), same, terminal) {
                return Err(bad("hypervisor completion unconfirmed"));
            }
            state.hypervisor = None;
            save(&dir, &state)?;
            Ok("HYPERVISOR_CONFIRMED".into())
        }
        _ => Err(bad(
            "invalid delegation command, missing provider or occupied slot",
        )),
    }
}
