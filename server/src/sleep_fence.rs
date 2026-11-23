//! Linux pooled first writes and managed sleep use independent opens of one
//! boot-scoped inode. Only the power manager can change its one-byte state.
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use std::{
    fs::File,
    io::{self, Write},
    os::unix::fs::{FileExt, MetadataExt},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

const FENCE: &str = "/run/pathward-sleep.gate";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    Missing,
    Permission,
    Untrusted,
    Busy,
    Closed,
    Malformed,
    Io,
}

const FAILURES: [Failure; 7] = [
    Failure::Missing,
    Failure::Permission,
    Failure::Untrusted,
    Failure::Busy,
    Failure::Closed,
    Failure::Malformed,
    Failure::Io,
];
static REJECTIONS: [AtomicU64; FAILURES.len()] = [const { AtomicU64::new(0) }; FAILURES.len()];

impl Failure {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Permission => "permission",
            Self::Untrusted => "untrusted",
            Self::Busy => "busy",
            Self::Closed => "closed",
            Self::Malformed => "malformed",
            Self::Io => "io",
        }
    }
    pub(crate) fn count_rejection(self) {
        REJECTIONS[self as usize].fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn rejection_metrics(out: &mut String) {
    use std::fmt::Write;
    for reason in FAILURES {
        let n = REJECTIONS[reason as usize].load(Ordering::Relaxed);
        writeln!(
            out,
            "pathward_pool_fence_rejections_total{{reason=\"{}\"}} {n}",
            reason.label()
        )
        .unwrap();
    }
}

impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::NotFound => Self::Missing,
            io::ErrorKind::PermissionDenied => Self::Permission,
            _ => Self::Io,
        }
    }
}
impl From<Failure> for io::Error {
    fn from(value: Failure) -> Self {
        io::Error::other(value.label())
    }
}

pub(crate) fn open_fence(access: OFlags) -> Result<File, Failure> {
    let fd = open(
        FENCE,
        access | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| {
        if e == rustix::io::Errno::LOOP {
            Failure::Untrusted
        } else {
            io::Error::from(e).into()
        }
    })?;
    let file = File::from(fd);
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.nlink() != 1 {
        return Err(Failure::Untrusted);
    }
    Ok(file)
}

pub(crate) fn marker(file: &File) -> Result<u8, Failure> {
    let mut state = [0; 1];
    if file.metadata()?.len() != 1 {
        return Err(Failure::Malformed);
    }
    file.read_exact_at(&mut state, 0)?;
    Ok(state[0])
}

fn require_awake(file: &File) -> Result<(), Failure> {
    let state = marker(file)?;
    if !omakase::upstream::sleep_fence_awake(1, state) {
        return Err(if matches!(state, b'S' | b'Q') {
            Failure::Closed
        } else {
            Failure::Malformed
        });
    }
    Ok(())
}

/// Drop releases this independent shared flock. No wait or await under the lease.
pub(crate) fn first_write_lease() -> Result<(File, File), Failure> {
    let file = open_fence(OFlags::RDONLY)?;
    check_reader(&file)?;
    let delegates = crate::sleep_delegates::reader()?;
    Ok((file, delegates))
}

fn check_reader(file: &File) -> Result<(), Failure> {
    flock(file, FlockOperation::NonBlockingLockShared).map_err(|e| {
        if e == rustix::io::Errno::WOULDBLOCK {
            Failure::Busy
        } else {
            io::Error::from(e).into()
        }
    })?;
    require_awake(file)
}

pub(crate) fn inspect() -> (Option<(u64, u64)>, Result<(), Failure>) {
    let file = match open_fence(OFlags::RDONLY) {
        Ok(f) => f,
        Err(e) => return (None, Err(e)),
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => return (None, Err(e.into())),
    };
    let check = check_reader(&file).and_then(|()| crate::sleep_delegates::reader().map(drop));
    (Some((meta.dev(), meta.ino())), check)
}

/// Privileged entry for systemd sleep units and direct, coordinated kernel sleep.
/// Neither the command nor the power-control path comes from the environment.
pub fn coordinated_sleep(mode: &str) -> io::Result<()> {
    let kernel_state = match mode {
        "kernel-mem" => Some(b"mem".as_slice()),
        "kernel-disk" => Some(b"disk".as_slice()),
        "systemd-suspend"
        | "systemd-hibernate"
        | "systemd-hybrid-sleep"
        | "systemd-suspend-then-hibernate" => None,
        _ => return Err(io::Error::other("unknown coordinated sleep mode")),
    };
    let file = open_fence(OFlags::RDWR)?;
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => {
            eprintln!("Waiting for the Omakase sleep fence");
            flock(&file, FlockOperation::LockExclusive)?;
        }
        Err(e) => return Err(e.into()),
    }
    require_awake(&file)?;
    let receipt = crate::pool_recovery::managed_origin(mode, &file).unwrap_or_else(|e| {
        eprintln!("Online sleep recovery unavailable for this invocation: {e}");
        None
    });
    if kernel_state.is_none() {
        // Orphans from hooks are adopted here, including double forks.
        rustix::process::set_child_subreaper(Some(rustix::process::Pid::INIT))?;
    }
    if let Some(receipt) = &receipt {
        receipt.begin(&file)?;
    } else {
        file.write_all_at(b"S", 0)?;
    }
    if let Some(state) = kernel_state {
        File::options()
            .write(true)
            .open("/sys/power/state")?
            .write_all(state)?;
    } else {
        let action = mode.strip_prefix("systemd-").expect("validated sleep mode");
        let status = Command::new("/usr/lib/systemd/systemd-sleep")
            .arg(action)
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "systemd-sleep exited with {status}"
            )));
        }
        // Linux __WALL includes clone children with a non-SIGCHLD exit signal.
        const ALL_CHILDREN: rustix::process::WaitOptions =
            rustix::process::WaitOptions::from_bits_retain(0x4000_0000);
        loop {
            match rustix::process::wait(ALL_CHILDREN) {
                Ok(Some(_)) | Err(rustix::io::Errno::INTR) => continue,
                Err(rustix::io::Errno::CHILD) => break,
                Ok(None) => return Err(io::Error::other("incomplete sleep child wait")),
                Err(e) => return Err(e.into()),
            }
        }
    }
    match receipt {
        Some(r) => r.finish(&file),
        None => file.write_all_at(b"A", 0),
    }
}
