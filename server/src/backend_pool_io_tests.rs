use super::*;
use std::{io::Read, net::TcpListener, sync::mpsc, thread};

const HEAD: &[u8] = b"POST /write HTTP/1.1\r\nHost: app.example\r\nContent-Length: 0\r\n\r\n";
const WAIT: Duration = Duration::from_secs(15);

#[path = "backend_pool_platform_tests.rs"]
mod platform;

fn accept_probe(listener: &TcpListener) -> TcpStream {
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(WAIT)).unwrap();
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        peer.read_exact(&mut byte).unwrap();
        request.extend(byte);
        assert!(request.len() <= 256);
    }
    assert!(request.starts_with(b"GET /ready HTTP/1.1\r\n"));
    peer
}

fn probe(pool: &Pool, listener: &TcpListener, status: u16) -> bool {
    thread::scope(|s| {
        s.spawn(|| {
            let mut peer = accept_probe(listener);
            write!(peer, "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n").unwrap();
        });
        futures_lite::future::block_on(pool.ready(&pool.members[0], Instant::now() + WAIT))
    })
}

fn rendezvous() -> (
    impl Fn() + Send + Sync,
    mpsc::Receiver<()>,
    mpsc::Sender<()>,
) {
    let (hit, signal) = mpsc::channel();
    let (go, resume) = mpsc::channel();
    let resume = Mutex::new(resume);
    (
        move || {
            hit.send(()).unwrap();
            resume.lock().unwrap().recv_timeout(WAIT).unwrap();
        },
        signal,
        go,
    )
}

fn pause_on(pool: &Pool, point: WritePoint) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (pause, signal, go) = rendezvous();
    assert!(
        pool.at_write
            .set(Box::new(move |event| {
                if event == point {
                    pause();
                }
            }))
            .is_ok()
    );
    (signal, go)
}

fn wait_for_expiry(pool: &Pool) {
    let end = Instant::now() + WAIT;
    while pool.members[0].cached(pool.now()).is_some() {
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn real_negative_probe_after_dial_prevents_the_first_write() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool = Pool::new("app.example", "/ready", &[addr], &[]);
    assert!(probe(&pool, &listener, 204));
    let (hit, release) = pause_on(&pool, WritePoint::Connected);
    let mut socket = TcpStream::connect(addr).unwrap();
    socket.set_nonblocking(true).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    thread::scope(|s| {
        let exchange = s.spawn(|| {
            let mut sent = false;
            let result = futures_lite::future::block_on(pool.write_first(
                0,
                &mut socket,
                HEAD,
                Instant::now() + WAIT,
                &mut sent,
            ));
            (result.unwrap(), sent)
        });
        hit.recv_timeout(WAIT).unwrap();
        wait_for_expiry(&pool);
        assert!(!probe(&pool, &listener, 503));
        assert_eq!(pool.members[0].health.lock().unwrap().status, 503);
        release.send(()).unwrap();
        assert_eq!(exchange.join().unwrap(), (None, false));
    });
    drop(socket);
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    println!(
        "health changed after dial: real probes 204 then 503, peer received zero request bytes"
    );
}

#[test]
fn delayed_successful_probe_cannot_overwrite_a_newer_real_connect_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool = Pool::new("app.example", "/ready", &[addr], &[]);
    assert!(probe(&pool, &listener, 204));
    let (pause_dial, dial, release_dial) = rendezvous();
    let (pause_probe, parsed, release_probe) = rendezvous();
    assert!(
        pool.at_write
            .set(Box::new(move |point| match point {
                WritePoint::BeforeDial => pause_dial(),
                WritePoint::ProbeResponse(200) => pause_probe(),
                _ => (),
            }))
            .is_ok()
    );
    thread::scope(|s| {
        let request = s.spawn(|| {
            let mut sent = false;
            let result = futures_lite::future::block_on(pool.start(
                0,
                Instant::now() + WAIT,
                Duration::from_secs(1),
                HEAD,
                &mut sent,
            ));
            (result.unwrap_err().0, sent)
        });
        dial.recv_timeout(WAIT).unwrap();
        wait_for_expiry(&pool);
        let check = s.spawn(|| {
            futures_lite::future::block_on(pool.ready(&pool.members[0], Instant::now() + WAIT))
        });
        let mut peer = accept_probe(&listener);
        drop(listener);
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        parsed.recv_timeout(WAIT).unwrap();
        release_dial.send(()).unwrap();
        assert_eq!(request.join().unwrap(), (503, false));
        let down = *pool.members[0].health.lock().unwrap();
        assert_eq!(down.status, 0);
        release_probe.send(()).unwrap();
        assert!(!check.join().unwrap());
        let last = *pool.members[0].health.lock().unwrap();
        assert_eq!((last.revision, last.status), (down.revision, 0));
    });
    println!(
        "parsed HTTP 200 overlapped a refused TCP connect: newer unhealthy revision retained; no dispatch"
    );
}

#[test]
fn full_tcp_send_buffer_rechecks_drain_before_retrying() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool = Pool::new("app.example", "/ready", &[addr], &[]);
    assert!(probe(&pool, &listener, 204));
    let mut socket = TcpStream::connect(addr).unwrap();
    socket.set_nonblocking(true).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    // The peer deliberately does not read. Wait for the TCP window to settle,
    // counting the exact prefill independently of application request bytes.
    let mut filled = 0;
    let mut quiet = Instant::now();
    while quiet.elapsed() < Duration::from_millis(200) {
        match socket.write(&[b'x'; 16384]) {
            Ok(n) => {
                assert!(n > 0);
                filled += n;
                assert!(filled < 32 << 20);
                quiet = Instant::now();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            other => panic!("filling send buffer: {other:?}"),
        }
    }
    let (hit, release) = pause_on(&pool, WritePoint::Waiting);
    thread::scope(|s| {
        let exchange = s.spawn(|| {
            let mut sent = false;
            let result = futures_lite::future::block_on(pool.write_first(
                0,
                &mut socket,
                HEAD,
                Instant::now() + WAIT,
                &mut sent,
            ));
            (result.unwrap(), sent)
        });
        hit.recv_timeout(WAIT).unwrap();
        assert!(pool.retired.try_lock().is_ok());
        assert!(pool.members[0].health.try_lock().is_ok());
        pool.retire();
        release.send(()).unwrap();
        assert_eq!(exchange.join().unwrap(), (None, false));
    });
    drop(socket);
    peer.set_read_timeout(Some(WAIT)).unwrap();
    let mut received = Vec::new();
    peer.read_to_end(&mut received).unwrap();
    assert_eq!(received.len(), filled);
    assert!(received.iter().all(|b| *b == b'x'));
    println!("real TCP WouldBlock then retirement: {filled} prefill bytes, zero request bytes");
}
