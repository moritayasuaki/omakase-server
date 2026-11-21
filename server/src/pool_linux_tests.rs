use super::*;
use crate::pool_locks::with_snapshot;
use rustix::net::sockopt::{set_socket_linger, set_socket_send_buffer_size, socket_cookie};
use rustix::time::{ClockId, clock_gettime};
use std::{fs, os::fd::AsRawFd, panic::catch_unwind, path::PathBuf};

#[test]
fn mutex_handoff_publishes_the_whole_health_observation() {
    let pool = Pool::new(
        "app.example",
        "/ready",
        &["127.0.0.1:1".parse().unwrap()],
        &[],
    );
    let member = &pool.members[0];
    let (start, read) = mpsc::channel();
    let (contended, proceed) = mpsc::channel();
    thread::scope(|scope| {
        let observer = scope.spawn(move || {
            read.recv_timeout(WAIT).unwrap();
            assert!(matches!(
                member.health.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
            contended.send(()).unwrap();
            with_snapshot(&pool.retired, &member.health, |retired, h| {
                (*retired, h.revision, h.at, h.status)
            })
            .unwrap()
        });
        let mut h = member.health.lock().unwrap();
        start.send(()).unwrap();
        proceed.recv_timeout(WAIT).unwrap();
        // All channel handshakes precede this publication. Its visibility to
        // the observer is carried by releasing and reacquiring this mutex.
        *h = publish_health(*h, h.revision, 421, 204);
        drop(h);
        assert_eq!(observer.join().unwrap(), (false, 1, 421, 204));
    });
}

#[test]
fn callback_unwind_drops_both_guards_and_poison_skips_the_callback() {
    let generation = Mutex::new(false);
    let health = Mutex::new(204u16);
    let unwind = catch_unwind(|| with_snapshot(&generation, &health, |_, _| panic!("fixture")));
    assert!(unwind.is_err());
    assert!(matches!(
        generation.try_lock(),
        Err(TryLockError::Poisoned(_))
    ));
    assert!(matches!(health.try_lock(), Err(TryLockError::Poisoned(_))));
    assert_eq!(
        with_snapshot(&generation, &health, |_, _| unreachable!()),
        None::<()>
    );
    let live = Mutex::new(false);
    assert_eq!(
        with_snapshot(&live, &health, |_, _| unreachable!()),
        None::<()>
    );
    assert!(live.try_lock().is_ok());
}

#[test]
fn reset_after_partial_write_preserves_errno_and_spends_the_grant() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool = Pool::new("app.example", "/ready", &[addr], &[]);
    assert!(probe(&pool, &listener, 204));
    let mut client = TcpStream::connect(addr).unwrap();
    client.set_nonblocking(true).unwrap();
    set_socket_send_buffer_size(&client, 32768).unwrap();
    let cookie = socket_cookie(&client).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    set_socket_linger(&peer, Some(Duration::ZERO)).unwrap();
    let bytes = vec![0x45; 4 << 20];
    let deadline = Instant::now() + WAIT;
    let mut sent = false;
    let first = futures_lite::future::block_on(pool.write_first(
        0,
        &mut client,
        &bytes,
        deadline,
        &mut sent,
    ))
    .unwrap()
    .unwrap();
    assert!(sent && first > 0 && first < bytes.len());
    let mut received = [0; 128];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(received, [0x45; 128]);
    drop(peer);
    let error = futures_lite::future::block_on(async_http::write_all_from(
        &mut client,
        &bytes,
        first,
        deadline,
    ))
    .unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
    ));
    assert_eq!(socket_cookie(&client).unwrap(), cookie);
    assert_eq!(
        futures_lite::future::block_on(pool.start(0, deadline, WAIT, &bytes, &mut sent))
            .unwrap_err()
            .0,
        503
    );
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    println!(
        "RESET first={first} offered={} errno={} same_cookie=true alternate_dials=0",
        bytes.len(),
        error.raw_os_error().unwrap()
    );
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(
        std::env::var_os("PATHWARD_POOL_LAB").expect("requires the isolated guest driver"),
    )
}

fn nanos(clock: ClockId) -> u128 {
    let t = clock_gettime(clock);
    t.tv_sec as u128 * 1_000_000_000 + t.tv_nsec as u128
}

// Bracket the std Instant read with two direct reads of the kernel clock.
fn sample(pool: &Pool) -> (u128, u128, u128, u128) {
    let lo = nanos(ClockId::Monotonic);
    let tick = u128::from(pool.now());
    let hi = nanos(ClockId::Monotonic);
    (lo, tick, hi, nanos(ClockId::Boottime))
}

#[test]
#[ignore = "guest supervisor performs a real suspend and RTC wake"]
fn suspended_pool_samples_match_the_kernel_clock() {
    let dir = fixture_dir();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let pool = Pool::new(
        "app.example",
        "/ready",
        &[listener.local_addr().unwrap()],
        &[],
    );
    assert!(probe(&pool, &listener, 204));
    let h = *pool.members[0].health.lock().unwrap();
    let before = sample(&pool);
    fs::write(dir.join("sampled"), b"ready").unwrap();
    let limit = Instant::now() + WAIT;
    while !dir.join("resumed").exists() {
        assert!(Instant::now() < limit);
        thread::sleep(Duration::from_millis(5));
    }
    let after = sample(&pool);
    let tick = after.1 - before.1;
    let lower = after.0 - before.2;
    let upper = after.2 - before.0;
    let boot = after.3 - before.3;
    assert!((lower..=upper).contains(&tick));
    assert!(boot > upper + 5_000_000_000);
    assert!(fresh_health(h, u64::try_from(after.1).unwrap()));
    println!(
        "SUSPEND mono_lower_ns={lower} instant_ns={tick} mono_upper_ns={upper} boottime_ns={boot} same_generation=true fresh_after_resume=true"
    );
}

#[test]
#[ignore = "guest supervisor stops and resumes a thread in a blocking send"]
fn interrupted_send_preserves_the_same_socket_and_unsent_byte() {
    let dir = fixture_dir();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    let cookie = socket_cookie(&socket).unwrap();
    set_socket_send_buffer_size(&socket, 32768).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut filled = 0;
    let mut last = Instant::now();
    while last.elapsed() < Duration::from_millis(250) {
        match async_http::write_report(socket.write(&[0x76; 16384])).unwrap() {
            Some(n) => {
                assert!(n > 0);
                filled += n;
                assert!(filled < 32 << 20);
                last = Instant::now();
            }
            None => thread::sleep(Duration::from_millis(2)),
        }
    }
    // A timed blocking send makes EINTR observable with STOP/CONT on Linux.
    socket.set_nonblocking(false).unwrap();
    socket.set_write_timeout(Some(WAIT)).unwrap();
    let thread_path = fs::read_link("/proc/thread-self").unwrap();
    let tid = thread_path.file_name().unwrap().to_str().unwrap();
    fs::write(
        dir.join("sending.tmp"),
        format!("{tid} {}\n", socket.as_raw_fd()),
    )
    .unwrap();
    fs::rename(dir.join("sending.tmp"), dir.join("sending")).unwrap();
    let error = socket.write(b"!").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    let errno = error.raw_os_error().unwrap();
    let (first, cause) = first_write_report(async_http::write_report(Err(error)));
    assert_eq!(first, FirstIo::Wait);
    assert!(cause.is_none());
    socket.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(WAIT)).unwrap();
    thread::scope(|scope| {
        let reader = scope.spawn(move || {
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).unwrap();
            bytes
        });
        futures_lite::future::block_on(async_http::write_all(
            &mut socket,
            b"!",
            Instant::now() + WAIT,
        ))
        .unwrap();
        assert_eq!(socket_cookie(&socket).unwrap(), cookie);
        drop(socket);
        let bytes = reader.join().unwrap();
        assert_eq!(bytes.len(), filled + 1);
        assert!(bytes[..filled].iter().all(|b| *b == 0x76));
        assert_eq!(bytes[filled], b'!');
    });
    println!("INTERRUPT prefill={filled} errno={errno} same_cookie=true marker_bytes=1");
}
