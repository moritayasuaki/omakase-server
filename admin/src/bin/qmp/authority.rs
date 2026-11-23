//! Independent QMP event observer and single-use submission journal.
//! The authority directory is outside the submitter's rollback domain.
use super::*;
use pathward::upstream::{original_resume_proven, original_stop_permitted};
use rustix::fs::{FlockOperation, flock};

struct Operation<'a> {
    dir: &'a Path,
    id: &'a str,
    vm: String,
}

// Both private monitor sockets must belong to one live emulator on the same
// hypervisor. A second VM can have the same configured UUID. Hot-unplug or
// replacement of vCPU 0 during the observation invalidates the evidence.
fn vcpu_thread(q: &mut Qmp) -> io::Result<String> {
    let cpus = q.call("query-cpus-fast")?;
    let mut zero = cpus
        .as_array()
        .ok_or_else(|| bad("invalid QMP CPU list"))?
        .iter()
        .filter(|c| c["cpu-index"].as_u64() == Some(0));
    let thread = zero
        .next()
        .and_then(|c| c["thread-id"].as_u64())
        .filter(|id| *id != 0)
        .ok_or_else(|| bad("missing vCPU thread identity"))?;
    ensure(zero.next().is_none(), "duplicate vCPU identity")?;
    Ok(thread.to_string())
}

impl<'a> Operation<'a> {
    fn open(dir: &'a Path, id: &'a str) -> io::Result<Self> {
        ensure(decode::<32>(id).is_some(), "invalid ticket")?;
        owned(dir)?;
        let vm =
            String::from_utf8(read_file(&dir.join("vm"))?).map_err(|_| bad("invalid VM UUID"))?;
        ensure(uuid(&vm), "invalid VM UUID")?;
        Ok(Self { dir, id, vm })
    }

    fn marker(&self, phase: &str) -> std::path::PathBuf {
        self.dir.join(format!("{}.{}", self.id, phase))
    }

    fn recorded(&self, phase: &str) -> io::Result<bool> {
        Ok(read_file(&self.marker(phase))? == self.id.as_bytes())
    }

    fn record(&self, phase: &str) -> io::Result<()> {
        create(&self.marker(phase), self.id.as_bytes())
    }

    fn submitted(&self) -> io::Result<bool> {
        Ok(read_file(&stop_claim(self.dir, self.id))? == self.id.as_bytes())
    }

    fn active(&self) -> io::Result<bool> {
        Ok(read_file(&self.dir.join("active"))? == self.id.as_bytes())
    }

    fn connection(&self, socket: &Path) -> io::Result<Qmp> {
        let mut q = Qmp::connect(socket)?;
        q.check(&self.vm, "running", true)?;
        ensure(!q.stopped && !q.resumed, "VM changed before registration")?;
        Ok(q)
    }

    fn signer(&self) -> io::Result<Ed25519KeyPair> {
        Ed25519KeyPair::from_pkcs8(&read_file(&self.dir.join("provider.pk8"))?)
            .map_err(|_| bad("invalid authority key"))
    }

    fn signed_terminal(&self) -> io::Result<Vec<u8>> {
        let sig = read_file(&self.marker("terminal"))?;
        let key = read_file(&self.dir.join("provider.pub"))?;
        ensure(key.len() == 32, "invalid authority public key")?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(
                sleep_ticket::observed_terminal_message(&self.vm, self.id).as_bytes(),
                &sig,
            )
            .map_err(|_| bad("unconfirmed original operation"))?;
        Ok(sig)
    }
}

pub(super) fn observe(dir: &Path, socket: &Path, id: &str) -> io::Result<()> {
    let op = Operation::open(dir, id)?;
    let directory = File::open(dir)?;
    flock(&directory, FlockOperation::NonBlockingLockExclusive)?;
    let signer = op.signer()?;
    let public = dir.join("provider.pub");
    match read_file(&public) {
        Ok(key) => ensure(
            key == signer.public_key().as_ref(),
            "authority key mismatch",
        )?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            create(&public, signer.public_key().as_ref())?
        }
        Err(e) => return Err(e),
    }
    let active = dir.join("active");
    match read_file(&active) {
        Ok(old) => {
            // Recover a crash *after* terminal publication without erasing an
            // uncertain claim. Submission markers are permanent under this key.
            let old = std::str::from_utf8(&old).map_err(|_| bad("invalid active ticket"))?;
            Operation::open(dir, old)?.signed_terminal()?;
            fs::remove_file(&active)?;
            directory.sync_all()?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    // Both protocols spend the same permanent filename. An existing v1
    // operation cannot acquire a second dispatch via the new protocol.
    match fs::symlink_metadata(stop_claim(dir, id)) {
        Ok(_) => return Err(bad("original stop already spent")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let mut q = op.connection(socket)?;
    let original_thread = vcpu_thread(&mut q)?;
    ensure(!q.stopped && !q.resumed, "VM changed before observation")?;
    op.record("armed")?;
    create(&op.marker("vcpu"), original_thread.as_bytes())?;
    create(&active, id.as_bytes())?;
    println!("ARMED {id}");
    io::stdout().flush()?;

    // Remain on this connection. A reconnect loses event order and identity.
    q.stream.get_ref().set_read_timeout(None)?;
    while !q.resumed {
        let event = q.message()?;
        let event = event["event"]
            .as_str()
            .ok_or_else(|| bad("unexpected observer reply"))?;
        if event == "STOP" {
            ensure(op.submitted()?, "stop preceded submission")?;
        }
        q.event(event)?;
    }
    q.stream
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(10)))?;
    q.check(&op.vm, "running", true)?;
    ensure(
        vcpu_thread(&mut q)? == original_thread,
        "original emulator thread changed",
    )?;
    ensure(
        op.active()?
            && original_resume_proven(
                op.submitted()?,
                op.recorded("paused")?,
                q.stopped,
                q.resumed,
            ),
        "missing original stop or resume evidence",
    )?;
    let signed = signer.sign(sleep_ticket::observed_terminal_message(&op.vm, id).as_bytes());
    create(&op.marker("terminal"), signed.as_ref())?;
    fs::remove_file(&active)?;
    directory.sync_all()?;
    println!("OBSERVED {id}");
    Ok(())
}

pub(super) fn dispatch(mirror: &Path, dir: &Path, socket: &Path, id: &str) -> io::Result<()> {
    let op = Operation::open(dir, id)?;
    owned(mirror)?;
    ensure(
        fs::canonicalize(mirror)? != fs::canonicalize(dir)?,
        "separate witness store required",
    )?;
    let armed = op.active()? && op.recorded("armed")?;
    ensure(armed, "observer has not armed this ticket")?;
    // O_EXCL and fsync on the independent volume precede even connecting to
    // the command monitor. Rewinding the submitter cannot recreate this right.
    ensure(
        original_stop_permitted(armed, create(&stop_claim(dir, id), id.as_bytes()).is_ok()),
        "original stop already spent or could not be persisted",
    )?;
    create(&mirror.join(format!("{id}.started")), id.as_bytes())?;
    let mut q = op.connection(socket)?;
    ensure(
        read_file(&op.marker("vcpu"))? == vcpu_thread(&mut q)?.as_bytes()
            && !q.stopped
            && !q.resumed,
        "command monitor belongs to a different emulator or episode",
    )?;
    q.pause(&op.vm)?;
    op.record("paused")?;
    q.resume(&op.vm, id)?;
    create(&mirror.join(format!("{id}.resumed")), id.as_bytes())?;
    println!("RESUMED {id}");
    Ok(())
}

/// Lookup needs no QMP endpoint and never sends a VM command.
pub(super) fn receipt(dir: &Path, id: &str) -> io::Result<()> {
    let op = Operation::open(dir, id)?;
    let sig = op.signed_terminal()?;
    println!("COMPLETED {id} {}", encode(&sig));
    Ok(())
}
