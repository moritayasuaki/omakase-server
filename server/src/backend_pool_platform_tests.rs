use super::*;
use crate::http::Transport;
use std::sync::TryLockError;

// Observe the real nonblocking TcpStream without synthesizing a write result.
struct ObservedSocket {
    stream: TcpStream,
    left: usize,
    writes: usize,
    waits: usize,
    on_wait: Option<mpsc::Sender<()>>,
}

impl Read for ObservedSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for ObservedSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        assert_eq!(buf.len(), self.left);
        let result = self.stream.write(buf);
        match &result {
            Ok(n) => {
                self.left -= n;
                self.writes += 1;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.waits += 1;
                if let Some(notify) = self.on_wait.take() {
                    notify.send(()).unwrap();
                }
            }
            _ => (),
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl Transport for ObservedSocket {
    fn deadline(&mut self, d: Instant) -> io::Result<()> {
        self.stream.deadline(d)
    }
    fn local_port(&self) -> io::Result<u16> {
        self.stream.local_port()
    }
}

#[test]
fn partial_write_and_would_block_preserve_the_exact_stream_across_retirement() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool = Pool::new("app.example", "/ready", &[addr], &[]);
    assert!(probe(&pool, &listener, 204));
    let mut socket = TcpStream::connect(addr).unwrap();
    socket.set_nonblocking(true).unwrap();
    let (mut peer, client) = listener.accept().unwrap();
    assert_eq!(socket.local_addr().unwrap(), client);
    assert_eq!(socket.peer_addr().unwrap(), addr);
    peer.set_read_timeout(Some(WAIT)).unwrap();
    let (written, release) = pause_on(&pool, WritePoint::Written);
    let (notify, backpressure) = mpsc::channel();

    // A transport fixture larger than the loopback send window. Position-dependent
    // bytes also detect any accidental repetition of an entire buffer-sized chunk.
    let mut state = 0x12345678u32;
    let payload: Vec<u8> = (0..16 << 20)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    thread::scope(|scope| {
        let bytes = payload.as_slice();
        let pool = &pool;
        let writer = scope.spawn(move || {
            let deadline = Instant::now() + WAIT;
            let mut sent = false;
            let first = futures_lite::future::block_on(pool.write_first(
                0,
                &mut socket,
                bytes,
                deadline,
                &mut sent,
            ))
            .unwrap()
            .unwrap();
            assert!(sent && first > 0 && first < bytes.len());
            let mut observed = ObservedSocket {
                stream: socket,
                left: bytes.len() - first,
                writes: 0,
                waits: 0,
                on_wait: Some(notify),
            };
            futures_lite::future::block_on(async_http::write_all_from(
                &mut observed,
                bytes,
                first,
                deadline,
            ))
            .unwrap();
            assert_eq!(observed.left, 0);
            assert_eq!(observed.stream.peer_addr().unwrap(), addr);
            assert_eq!(observed.stream.local_addr().unwrap(), client);
            (first, observed.writes, observed.waits)
        });
        written.recv_timeout(WAIT).unwrap();
        // The hook is inside the first-write critical section, after the syscall.
        assert!(matches!(
            pool.retired.try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        assert!(matches!(
            pool.members[0].health.try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        release.send(()).unwrap();
        backpressure.recv_timeout(WAIT).unwrap();
        assert_eq!(pool.members[0].health.try_lock().unwrap().status, 204);
        pool.retire();
        assert!(*pool.retired.try_lock().unwrap());
        let mut received = Vec::new();
        peer.read_to_end(&mut received).unwrap();
        let (first, writes, waits) = writer.join().unwrap();
        assert!(writes > 0 && waits > 0);
        assert!(received == payload, "peer byte stream differed");
        println!(
            "TCP bytes={} first={first} continuation_writes={writes} would_block={waits} peer_exact=true both_locks_contended=true",
            payload.len()
        );
    });
}

#[test]
fn ordered_monotonic_samples_and_real_health_expiry() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let pool = Pool::new(
        "app.example",
        "/ready",
        &[listener.local_addr().unwrap()],
        &[],
    );
    assert!(probe(&pool, &listener, 204));
    let health = *pool.members[0].health.lock().unwrap();
    let samples = Mutex::new((health.at, 0));
    thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..1024 {
                    let mut last = samples.lock().unwrap();
                    let now = pool.now();
                    assert!(now >= last.0 && now < u64::MAX);
                    *last = (now, last.1 + 1);
                }
            });
        }
    });
    let (_, count) = *samples.lock().unwrap();
    assert_eq!(count, 4096);
    assert!(fresh_health(health, health.at));
    wait_for_expiry(&pool);
    let elapsed = pool.now() - health.at;
    assert!(elapsed >= 5_000_000_000);
    assert!(!fresh_health(health, pool.now()));
    println!("CLOCK ordered_samples={count} threads=4 expired_age_ns={elapsed}");
}
