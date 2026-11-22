use ring::digest::{Context, SHA256};
use rustix::fs::{Mode, OFlags, open};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
};

const BIN: &str = "/usr/local/libexec/pathward-server";
pub(crate) const MODES: [&str; 4] = [
    "suspend",
    "hibernate",
    "hybrid-sleep",
    "suspend-then-hibernate",
];

fn hash(file: &mut File, size: u64) -> io::Result<ring::digest::Digest> {
    let mut ctx = Context::new(&SHA256);
    let mut buf = [0; 32768];
    let mut file = file.take(size + 1);
    let mut read = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return if read == size {
                Ok(ctx.finish())
            } else {
                Err(io::Error::other("coordinator size changed"))
            };
        }
        read += n as u64;
        ctx.update(&buf[..n]);
    }
}

pub(crate) fn coordinator_matches() -> io::Result<bool> {
    for path in Path::new(BIN).ancestors().skip(1) {
        let m = fs::symlink_metadata(path)?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 || !m.is_dir() {
            return Ok(false);
        }
    }
    let mut installed = File::from(open(
        BIN,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let m = installed.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.mode() & 0o111 == 0 {
        return Ok(false);
    }
    let mut candidate = File::open("/proc/self/exe")?;
    let c = candidate.metadata()?;
    if (m.dev(), m.ino()) == (c.dev(), c.ino()) {
        return Ok(true);
    }
    Ok(m.len() == c.len()
        && m.len() <= 256 << 20
        && hash(&mut installed, m.len())?.as_ref() == hash(&mut candidate, c.len())?.as_ref())
}

// A typed busctl reply retains argv boundaries and the ExecStartEx flag
// vector. systemctl's human-readable argv rendering conflates embedded spaces.
fn correct_exec(reply: &str, unit: &str) -> bool {
    let prefix =
        format!("a(sasasttttuii) 1 \"{BIN}\" 3 \"{BIN}\" \"coordinated-sleep\" \"{unit}\" 0 ");
    let Some(rest) = reply.trim_end().strip_prefix(&prefix) else {
        return false;
    };
    let n: Vec<_> = rest.split(' ').collect();
    n.len() == 7
        && n[..4].iter().all(|v| v.parse::<u64>().is_ok())
        && n[4].parse::<u32>().is_ok()
        && n[5..].iter().all(|v| v.parse::<i32>().is_ok())
}

const EMPTY: &[&str] = &[
    "RootDirectory",
    "RootImage",
    "BindPaths",
    "BindReadOnlyPaths",
    "TemporaryFileSystem",
    "InaccessiblePaths",
    "ReadOnlyPaths",
    "MountImages",
    "ExtensionImages",
    "ExtensionDirectories",
    "JoinsNamespaceOf",
    "PAMName",
];

pub(crate) fn output(bin: &str, args: &[&str]) -> io::Result<String> {
    let mut child = Command::new(bin)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("SYSTEMD_BUS_TIMEOUT", "3s")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut bytes = Vec::new();
    let result = child
        .stdout
        .take()
        .expect("piped stdout")
        .take(65537)
        .read_to_end(&mut bytes);
    if result.is_err() || bytes.len() > 65536 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("invalid systemd reply"));
    }
    if !child.wait()?.success() {
        return Err(io::Error::other("systemd query failed"));
    }
    String::from_utf8(bytes).map_err(io::Error::other)
}

pub(crate) fn inspect_unit(mode: &str) -> io::Result<bool> {
    let unit = format!("systemd-{mode}");
    let service = format!("{unit}.service");
    let fields = [
        "LoadState",
        "NeedDaemonReload",
        "Type",
        "RemainAfterExit",
        "User",
        "DynamicUser",
        "Slice",
        "Delegate",
        "PrivateUsers",
        "ProtectSystem",
        "Result",
        "ExecMainCode",
        "ExecMainStatus",
    ]
    .into_iter()
    .chain(EMPTY.iter().copied())
    .collect::<Vec<_>>()
    .join(",");
    let raw = output(
        "/usr/bin/systemctl",
        &[
            "--system",
            "--no-pager",
            "show",
            "--all",
            "--property",
            &fields,
            &service,
        ],
    )?;
    let props: BTreeMap<_, _> = raw.lines().filter_map(|s| s.split_once('=')).collect();
    let get = |key| props.get(key).copied();
    let profile = get("LoadState") == Some("loaded")
        && get("NeedDaemonReload") == Some("no")
        && get("Type") == Some("oneshot")
        && get("RemainAfterExit") == Some("no")
        && get("Slice") == Some("system.slice")
        && get("Delegate") == Some("no")
        && matches!(get("User"), Some("" | "root" | "0"))
        && ["PrivateUsers", "ProtectSystem", "DynamicUser"]
            .iter()
            .all(|p| get(p) == Some("no"))
        && EMPTY.iter().all(|p| get(p) == Some(""));
    let object = format!(
        "/org/freedesktop/systemd1/unit/{}_2eservice",
        unit.replace('-', "_2d")
    );
    let exec = output(
        "/usr/bin/busctl",
        &[
            "--system",
            "--auto-start=no",
            "--timeout=3s",
            "get-property",
            "org.freedesktop.systemd1",
            &object,
            "org.freedesktop.systemd1.Service",
            "ExecStartEx",
            "ExecConditionEx",
            "ExecStartPreEx",
            "ExecStartPostEx",
            "ExecReloadEx",
            "ExecStopEx",
            "ExecStopPostEx",
        ],
    )?;
    let mut commands = exec.lines();
    let command = commands
        .next()
        .is_some_and(|line| correct_exec(line, &unit))
        && commands.eq(["a(sasasttttuii) 0"; 6]);
    let result = get("Result").unwrap_or("unknown");
    let code = get("ExecMainCode").and_then(|v| v.parse::<i32>().ok());
    let status = get("ExecMainStatus").and_then(|v| v.parse::<i32>().ok());
    println!(
        "unit={service} command={command} profile={profile} last_result={result} exit_code={} exit_status={}",
        code.unwrap_or(-1),
        status.unwrap_or(-1)
    );
    Ok(profile && command)
}

pub(crate) fn inspect() -> u8 {
    let mut mask = 0;
    for (i, mode) in MODES.iter().enumerate() {
        match inspect_unit(mode) {
            Ok(true) => mask |= 1 << i,
            Ok(false) => {}
            Err(_) => println!("unit=systemd-{mode}.service inspection=unverified"),
        }
    }
    mask
}

pub(crate) fn protected_cgroup(unit: &str) -> io::Result<bool> {
    let s = output(
        "/usr/bin/systemctl",
        &[
            "--system",
            "show",
            "--property=ProtectControlGroups",
            "--value",
            unit,
        ],
    )?;
    Ok(s.trim_end() == "yes")
}

pub(crate) fn power_idle() -> io::Result<bool> {
    let mut idle = true;
    for unit in MODES
        .iter()
        .map(|m| format!("systemd-{m}.service"))
        .chain(MODES.iter().map(|m| format!("{m}.target")))
        .chain(std::iter::once("sleep.target".into()))
    {
        let s = output(
            "/usr/bin/systemctl",
            &[
                "--system",
                "show",
                "--all",
                "--property=LoadState,ActiveState,Job,MainPID,ControlPID,ControlGroup",
                &unit,
            ],
        )?;
        let p: BTreeMap<_, _> = s.lines().filter_map(|s| s.split_once('=')).collect();
        let field = |key| p.get(key).copied();
        let mut quiet = field("LoadState") == Some("loaded")
            && matches!(field("ActiveState"), Some("inactive" | "failed"))
            && field("Job") == Some("");
        if unit.ends_with(".service") {
            let cg = format!("/system.slice/{unit}");
            quiet &= field("MainPID") == Some("0")
                && field("ControlPID") == Some("0")
                && matches!(field("ControlGroup"), Some(g) if g.is_empty() || g == cg)
                && protected_cgroup(&unit)?;
        }
        println!("unit={unit} idle={quiet}");
        idle &= quiet;
    }
    let flags = output(
        "/usr/bin/busctl",
        &[
            "--system",
            "--auto-start=no",
            "--timeout=3s",
            "get-property",
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "PreparingForSleep",
        ],
    )?;
    Ok(idle && flags.trim_end() == "b false")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_executable_argv_count_flags_and_mode() {
        let good = format!(
            "a(sasasttttuii) 1 \"{BIN}\" 3 \"{BIN}\" \"coordinated-sleep\" \"systemd-suspend\" 0 1 2 3 4 5 1 0"
        );
        assert!(correct_exec(&good, "systemd-suspend"));
        for bad in [
            good.replace(") 1 ", ") 2 "),
            good.replace(" 3 \"", " 2 \""),
            good.replace("sleep\" \"systemd", "sleep systemd"),
            good.replace(" 0 1 2", " 1 \"ignore-failure\" 1 2"),
            good.replace("systemd-suspend", "systemd-hibernate"),
        ] {
            assert!(!correct_exec(&bad, "systemd-suspend"));
        }
    }
}
