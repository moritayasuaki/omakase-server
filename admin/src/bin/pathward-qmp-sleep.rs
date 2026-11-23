//! QEMU host-side witness for one registered vCPU pause/resume. The guest
//! receives only the public key and signed terminal receipts.
#[path = "qmp/authority.rs"]
mod authority;
#[path = "../../../shared/sleep_ticket.rs"]
mod sleep_ticket;
use ring::{
    rand::SystemRandom,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use serde_json::{Value, json};
use sleep_ticket::{decode, encode, terminal_message, uuid};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt},
        net::UnixStream,
    },
    path::Path,
    time::Duration,
};

fn bad(msg: &'static str) -> io::Error {
    io::Error::other(msg)
}
fn ensure(v: bool, msg: &'static str) -> io::Result<()> {
    if v { Ok(()) } else { Err(bad(msg)) }
}

fn parent_directory(path: &Path) -> io::Result<&Path> {
    let parent = path.parent().ok_or_else(|| bad("missing parent"))?;
    Ok(if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    })
}

fn create(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    File::open(parent_directory(path)?)?.sync_all()
}

fn stop_claim(dir: &Path, id: &str) -> std::path::PathBuf {
    dir.join(format!("{id}.started"))
}

fn owned(dir: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(dir)?;
    ensure(
        m.is_dir() && m.uid() == rustix::process::geteuid().as_raw() && m.mode() & 0o077 == 0,
        "private witness directory required",
    )
}

fn read_file(path: &Path) -> io::Result<Vec<u8>> {
    let f = File::from(rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?);
    let m = f.metadata()?;
    ensure(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == rustix::process::geteuid().as_raw()
            && m.mode() & 0o077 == 0
            && m.len() <= 512,
        "invalid private witness file",
    )?;
    let mut b = Vec::new();
    f.take(513).read_to_end(&mut b)?;
    ensure(b.len() <= 512, "oversize witness file")?;
    Ok(b)
}

fn line<R: BufRead>(r: &mut R, limit: u64) -> io::Result<Vec<u8>> {
    let mut b = Vec::new();
    r.take(limit + 1).read_until(b'\n', &mut b)?;
    ensure(
        b.last() == Some(&b'\n') && b.len() as u64 <= limit,
        "unterminated or oversize message",
    )?;
    Ok(b)
}

struct Qmp {
    stream: BufReader<UnixStream>,
    id: u32,
    stopped: bool,
    resumed: bool,
}
impl Qmp {
    fn connect(path: &Path) -> io::Result<Self> {
        owned(parent_directory(path)?)?;
        let meta = fs::symlink_metadata(path)?;
        ensure(
            meta.file_type().is_socket() && meta.uid() == rustix::process::geteuid().as_raw(),
            "expected private QMP Unix socket",
        )?;
        let socket = UnixStream::connect(path)?;
        let timeout = Some(Duration::from_secs(10));
        socket.set_read_timeout(timeout)?;
        socket.set_write_timeout(timeout)?;
        let mut q = Self {
            stream: BufReader::new(socket),
            id: 0,
            stopped: false,
            resumed: false,
        };
        ensure(
            q.message()?["QMP"]["version"].is_object(),
            "missing QMP greeting",
        )?;
        q.call("qmp_capabilities")?;
        Ok(q)
    }
    fn message(&mut self) -> io::Result<Value> {
        pathward_admin::codec::parse(&line(&mut self.stream, 65536)?).map_err(io::Error::other)
    }
    fn event(&mut self, event: &str) -> io::Result<()> {
        match event {
            "STOP" if !self.stopped && !self.resumed => self.stopped = true,
            "RESUME" if self.stopped && !self.resumed => self.resumed = true,
            "RESET" | "SHUTDOWN" | "SUSPEND" | "SUSPEND_DISK" | "WAKEUP" | "STOP" | "RESUME"
            | "MIGRATION" | "GUEST_PANICKED" => {
                return Err(bad("unexpected VM lifecycle transition"));
            }
            _ => (),
        }
        Ok(())
    }
    fn call(&mut self, command: &str) -> io::Result<Value> {
        self.id += 1;
        writeln!(
            self.stream.get_mut(),
            "{}",
            json!({"execute":command,"id":self.id})
        )?;
        for _ in 0..128 {
            let v = self.message()?;
            if let Some(event) = v["event"].as_str() {
                self.event(event)?;
                continue;
            }
            ensure(
                v["id"] == self.id && v.get("return").is_some() && v.get("error").is_none(),
                "unconfirmed QMP command",
            )?;
            return Ok(v["return"].clone());
        }
        Err(bad("too many QMP events"))
    }
    fn check(&mut self, vm: &str, status: &str, running: bool) -> io::Result<()> {
        ensure(self.call("query-uuid")?["UUID"] == vm, "foreign VM UUID")?;
        let s = self.call("query-status")?;
        ensure(
            s["status"] == status && s["running"] == running,
            "unexpected VM state",
        )
    }

    fn pause(&mut self, vm: &str) -> io::Result<()> {
        self.call("stop")?;
        self.check(vm, "paused", false)?;
        ensure(self.stopped && !self.resumed, "pause not witnessed")
    }

    fn resume(&mut self, vm: &str, id: &str) -> io::Result<()> {
        println!("PAUSED {id}");
        io::stdout().flush()?;
        ensure(
            line(&mut io::stdin().lock(), 96)? == format!("resume {id}\n").as_bytes(),
            "resume requires the same ticket",
        )?;
        self.check(vm, "paused", false)?;
        ensure(!self.resumed, "VM changed before the requested resume")?;
        self.call("cont")?;
        self.check(vm, "running", true)?;
        ensure(self.resumed, "resume not witnessed")
    }
}

fn run(args: &[String]) -> io::Result<()> {
    let words: Vec<_> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["observe", dir, socket, id] => {
            return authority::observe(Path::new(dir), Path::new(socket), id);
        }
        ["pause-once", mirror, dir, socket, id] => {
            return authority::dispatch(Path::new(mirror), Path::new(dir), Path::new(socket), id);
        }
        ["reconcile", dir, id] => return authority::receipt(Path::new(dir), id),
        _ => (),
    }
    if let ["keygen", dir, vm] = words.as_slice() {
        ensure(uuid(vm), "invalid VM UUID")?;
        let dir = Path::new(dir);
        fs::DirBuilder::new().mode(0o700).create(dir)?;
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| bad("key generation failed"))?;
        create(&dir.join("provider.pk8"), key.as_ref())?;
        create(&dir.join("vm"), vm.as_bytes())?;
        File::open(parent_directory(dir)?)?.sync_all()?;
        let signer =
            Ed25519KeyPair::from_pkcs8(key.as_ref()).map_err(|_| bad("invalid private key"))?;
        create(&dir.join("provider.pub"), signer.public_key().as_ref())?;
        println!("{}", encode(signer.public_key().as_ref()));
        return Ok(());
    }
    let (dir, id, socket) = match words.as_slice() {
        ["pause", dir, socket, id] => (Path::new(dir), *id, Some(Path::new(socket))),
        ["receipt", dir, id] => (Path::new(dir), *id, None),
        _ => {
            return Err(bad(
                "expected keygen DIR UUID, pause DIR QMP_SOCKET TICKET, receipt DIR TICKET, observe AUTH OBS_QMP TICKET, pause-once MIRROR AUTH CMD_QMP TICKET, or reconcile AUTH TICKET",
            ));
        }
    };
    ensure(decode::<32>(id).is_some(), "invalid ticket")?;
    owned(dir)?;
    let vm = String::from_utf8(read_file(&dir.join("vm"))?).map_err(|_| bad("invalid VM UUID"))?;
    ensure(uuid(&vm), "invalid VM UUID")?;
    let signer = Ed25519KeyPair::from_pkcs8(&read_file(&dir.join("provider.pk8"))?)
        .map_err(|_| bad("invalid private key"))?;
    let message = terminal_message(&vm, id);
    let done = dir.join(format!("{id}.done"));
    if let Some(socket) = socket {
        let mut q = Qmp::connect(socket)?;
        q.check(&vm, "running", true)?;
        ensure(
            !q.stopped && !q.resumed,
            "VM state changed before submission",
        )?;
        // An existing claim, including one left after a crash, never submits again.
        create(&stop_claim(dir, id), b"started\n").map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                bad("original stop already spent")
            } else {
                e
            }
        })?;
        q.pause(&vm)?;
        q.resume(&vm, id)?;
        create(&done, signer.sign(message.as_bytes()).as_ref())?;
    }
    let sig = read_file(&done)?;
    UnparsedPublicKey::new(&ED25519, signer.public_key().as_ref())
        .verify(message.as_bytes(), &sig)
        .map_err(|_| bad("unconfirmed receipt"))?;
    println!("COMPLETED {id} {}", encode(&sig));
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("PathWard QMP witness: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
