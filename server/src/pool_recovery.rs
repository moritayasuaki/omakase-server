//! Online recovery holds the same host flock as the coordinator. A dead
//! main PID alone cannot establish that its sleep hooks have finished.
use crate::{
    pool_preflight::{self, units},
    sleep_fence,
};
use pathward::upstream::sleep_recovery_allowed;
use rustix::fs::{
    FlockOperation, Mode, OFlags, XattrFlags, fgetxattr, flock, fsetxattr, fstatfs, openat,
};
use std::{
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::{FileExt, MetadataExt},
    path::Path,
};

// The privileged xattr is on the descriptor we lock. Bind it to this boot
// and inode as well, so restoring a copied receipt cannot authorize recovery.
const RECEIPT: &str = "trusted.pathward.sleep-v1";
const SYSTEM_SLICE: &str = "/sys/fs/cgroup/system.slice";
const CGROUP2_SUPER_MAGIC: u64 = 0x63677270;

fn deny(msg: &'static str) -> io::Error {
    io::Error::other(msg)
}

pub(crate) struct Receipt {
    identity: String,
    owner: String,
}

impl Receipt {
    fn identity(file: &File) -> io::Result<String> {
        let m = file.metadata()?;
        Ok(format!(
            "v1 {} {}:{}",
            pool_preflight::clock_domain()?,
            m.dev(),
            m.ino()
        ))
    }

    fn save(&self, file: &File, owner: &str) -> io::Result<()> {
        let value = format!("{} {owner}", self.identity);
        Ok(fsetxattr(
            file,
            RECEIPT,
            value.as_bytes(),
            XattrFlags::empty(),
        )?)
    }

    fn read(file: &File) -> io::Result<Self> {
        let identity = Self::identity(file)?;
        let mut buf = [0u8; 192];
        let len = fgetxattr(file, RECEIPT, &mut buf[..])
            .map_err(|_| deny("missing or unreadable recovery receipt"))?;
        let text =
            std::str::from_utf8(&buf[..len]).map_err(|_| deny("invalid recovery receipt"))?;
        let (origin, owner) = text
            .rsplit_once(' ')
            .ok_or_else(|| deny("invalid recovery receipt"))?;
        if origin != identity || (owner != "idle" && !units::MODES.contains(&owner)) {
            return Err(deny("foreign or invalid recovery receipt"));
        }
        Ok(Self {
            identity,
            owner: owner.to_owned(),
        })
    }

    // Q is closed to writers and has no running payload. A always carries
    // at most an idle receipt, including at every crash boundary.
    pub(crate) fn begin(&self, file: &File) -> io::Result<()> {
        file.write_all_at(b"Q", 0)?;
        self.save(file, &self.owner)?;
        file.write_all_at(b"S", 0)
    }

    pub(crate) fn finish(&self, file: &File) -> io::Result<()> {
        file.write_all_at(b"Q", 0)?;
        self.save(file, "idle")?;
        file.write_all_at(b"A", 0)
    }
}

pub(crate) fn host_cgroup_domain() -> io::Result<bool> {
    Ok(
        pool_preflight::same_object("/proc/self/ns/cgroup", "/proc/1/ns/cgroup")?
            && fs::read_to_string("/proc/1/cgroup")? == "0::/init.scope\n",
    )
}

pub(crate) fn managed_origin(entry: &str, file: &File) -> io::Result<Option<Receipt>> {
    let Some(mode) = entry.strip_prefix("systemd-") else {
        return Ok(None);
    };
    let unit = format!("{entry}.service");
    if !units::MODES.contains(&mode)
        || !host_cgroup_domain()?
        || fs::read_to_string("/proc/self/cgroup")? != format!("0::/system.slice/{unit}\n")
        || !units::inspect_unit(mode)?
        || !units::protected_cgroup(&unit)?
        || !rustix::fs::statvfs(SYSTEM_SLICE)?
            .f_flag
            .contains(rustix::fs::StatVfsMountFlags::RDONLY)
    {
        return Ok(None);
    }
    let receipt = Receipt {
        identity: Receipt::identity(file)?,
        owner: mode.to_owned(),
    };
    // Still under A. If this host cannot store privileged xattrs the caller
    // can keep using the original closed fence without claiming an owner.
    receipt.save(file, "idle")?;
    Ok(Some(receipt))
}

fn populated(text: &str) -> io::Result<bool> {
    let mut values = text.lines().filter_map(|s| s.strip_prefix("populated "));
    match (values.next(), values.next()) {
        (Some("1"), None) => Ok(true),
        (Some("0"), None) => Ok(false),
        _ => Err(deny("unrecognized cgroup population")),
    }
}

pub(crate) fn empty_subtree(unit: &str) -> io::Result<bool> {
    // A missing child of a pinned cgroup-v2 parent is empty: Linux refuses
    // to remove a populated subtree. An unreadable existing group is unknown.
    let parent = File::open(SYSTEM_SLICE)?;
    if !parent.metadata()?.is_dir() || fstatfs(&parent)?.f_type as u64 != CGROUP2_SUPER_MAGIC {
        return Err(deny("system.slice is not on the cgroup v2 hierarchy"));
    }
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match openat(&parent, unit, flags | OFlags::DIRECTORY, Mode::empty()) {
        Err(rustix::io::Errno::NOENT) => Ok(true),
        Err(e) => Err(e.into()),
        Ok(group) => {
            let fd = openat(&group, "cgroup.events", flags, Mode::empty())?;
            let mut text = String::new();
            File::from(fd).take(4097).read_to_string(&mut text)?;
            if text.len() > 4096 {
                return Err(deny("oversize cgroup.events"));
            }
            Ok(!populated(&text)?)
        }
    }
}

fn empty_groups() -> io::Result<u8> {
    let mut mask = 0u8;
    for (i, mode) in units::MODES.iter().enumerate() {
        let unit = format!("systemd-{mode}.service");
        let empty = empty_subtree(&unit)?;
        println!("unit={unit} descendant_cgroup_empty={empty}");
        if empty {
            mask |= 1 << i;
        }
    }
    Ok(mask)
}

pub fn recover(control_dir: &Path) -> io::Result<&'static str> {
    if !rustix::process::geteuid().is_root()
        || !pool_preflight::host_mount()?
        || !host_cgroup_domain()?
    {
        return Err(deny(
            "online recovery requires the host administrator and host namespaces",
        ));
    }
    // An idempotent call on a healthy site need not take an exclusive lock.
    match sleep_fence::inspect().1 {
        Ok(()) => return Ok("ALREADY_AWAKE"),
        Err(sleep_fence::Failure::Closed) => {}
        Err(e) => return Err(e.into()),
    }
    let file = sleep_fence::open_fence(OFlags::RDWR)?;
    flock(&file, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| deny("recovery lease unavailable"))?;
    let marker = sleep_fence::marker(&file)?;
    let _delegates = crate::sleep_delegates::reader()?;
    if marker == b'A' {
        return Ok("ALREADY_AWAKE");
    }
    let receipt = Receipt::read(&file)?;
    let m = file.metadata()?;
    let id = (m.dev(), m.ino());
    if !units::coordinator_matches()? || units::inspect() != 15 {
        return Err(deny("reviewed coordinator or sleep units unavailable"));
    }
    let idle = units::power_idle()?;
    let groups = empty_groups()?;
    let same = pool_preflight::service_sees_exclusive(control_dir, id)?;
    let current = sleep_fence::open_fence(OFlags::RDONLY)?.metadata()?;
    let same = same && (current.dev(), current.ino()) == id;
    if !sleep_recovery_allowed(marker, true, receipt.owner != "idle", same, idle, groups) {
        return Err(deny(
            "closed: untracked owner, different fence, or outstanding power work",
        ));
    }
    receipt.finish(&file)?;
    Ok("RECOVERED_AWAKE")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn population_requires_a_single_kernel_boolean() {
        assert!(!populated("populated 0\nfrozen 0\n").unwrap());
        assert!(populated("frozen 0\npopulated 1\n").unwrap());
        for bad in [
            "",
            "populated 0\npopulated 1",
            "populated 2",
            "populated 0extra",
        ] {
            assert!(populated(bad).is_err());
        }
    }
}
