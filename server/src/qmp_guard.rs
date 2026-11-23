//! A dedicated, independently retained virtio block volume. Its ticket stays
//! authoritative when the guest's ordinary root disk is restored.
use super::*;
use std::os::unix::fs::FileTypeExt;

const MOUNT: &str = "/var/lib/pathward-qmp-guard";
const DEVICE: &str = "/dev/disk/by-id/virtio-pathward-qmp-guard";
const SLOT: &str = "ledger";

fn present() -> io::Result<bool> {
    for path in [MOUNT, DEVICE] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

fn mount() -> io::Result<File> {
    let dir = File::from(open(MOUNT, READ | OFlags::DIRECTORY, Mode::empty())?);
    let m = dir.metadata()?;
    let dev = fs::metadata(DEVICE)?;
    if !dev.file_type().is_block_device()
        || dev.rdev() != m.dev()
        || m.dev() == fs::metadata(DIR)?.dev()
        || m.uid() != 0
        || m.mode() & 0o022 != 0
        || !matches!(fstatfs(&dir)?.f_type as u64, 0xef53 | 0x58465342)
    {
        return Err(bad("expected dedicated ext4 or XFS QEMU guard disk"));
    }
    Ok(dir)
}

fn slot(root: &File) -> io::Result<File> {
    let dir = File::from(openat(root, SLOT, READ | OFlags::DIRECTORY, Mode::empty())?);
    let m = dir.metadata()?;
    if m.dev() != root.metadata()?.dev() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(bad("untrusted QEMU guard directory"));
    }
    Ok(dir)
}

fn read(dir: &File, expected: &State) -> io::Result<State> {
    let file = File::from(openat(dir, RECORD, READ, Mode::empty())?);
    let record = State::parse(&read_record(file)?)?;
    if !record.recoverable
        || record.installation != expected.installation
        || record.provider != expected.provider
        || record.service.is_some()
    {
        return Err(bad("foreign QEMU guard binding"));
    }
    Ok(record)
}

pub(super) fn provision(state: &State) -> io::Result<()> {
    let root = mount()?;
    let fresh = match rustix::fs::mkdirat(&root, SLOT, Mode::from_raw_mode(0o755)) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(e) => return Err(e.into()),
    };
    let dir = slot(&root)?;
    flock(&dir, FlockOperation::LockExclusive)?;
    if fresh {
        fchmod(&dir, Mode::from_raw_mode(0o755))?;
        root.sync_all()?;
        save(&dir, state)?;
    } else {
        // Re-provisioning after a root-disk rollback must retain the pending slot.
        read(&dir, state)?;
    }
    Ok(())
}

pub(super) fn required(state: &State) -> io::Result<bool> {
    if !state.recoverable && present()? {
        return Err(bad(
            "guard disk present with a legacy or restored guest contract",
        ));
    }
    Ok(state.recoverable)
}

pub(super) fn exclusive(state: &State) -> io::Result<Option<(File, State)>> {
    if !required(state)? {
        return Ok(None);
    }
    let dir = slot(&mount()?)?;
    flock(&dir, FlockOperation::LockExclusive)?;
    let copy = read(&dir, state)?;
    Ok(Some((dir, copy)))
}

pub(super) fn status(state: &State) -> io::Result<Option<String>> {
    let dir = slot(&mount()?)?;
    flock(&dir, FlockOperation::LockShared)?;
    Ok(read(&dir, state)?.hypervisor)
}

pub(super) fn read_lease(state: &State) -> Result<Option<File>, Failure> {
    if !required(state)? {
        return Ok(None);
    }
    let dir = slot(&mount()?)?;
    flock(&dir, FlockOperation::NonBlockingLockShared).map_err(|e| {
        if e == rustix::io::Errno::WOULDBLOCK {
            Failure::Busy
        } else {
            Failure::Io
        }
    })?;
    if read(&dir, state)?.hypervisor.is_some() {
        return Err(Failure::Closed);
    }
    Ok(Some(dir))
}
