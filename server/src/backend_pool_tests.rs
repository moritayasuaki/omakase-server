//! Loopback staging fixtures use normal server admission, reload and proxy I/O.
use super::{exchange, read_request, with_config};
use crate::backend_pool::WritePoint;
use omakase_config::ParsedConfig;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    StopBeforeDispatch,
    DropAfterWrite,
    HoldResponse,
}

#[derive(Default)]
struct Control {
    stop: AtomicBool,
    unhealthy: AtomicBool,
    release: AtomicBool,
    probes: AtomicUsize,
    writes: AtomicUsize,
    empty_connections: AtomicUsize,
}

struct Replica {
    addr: SocketAddr,
    ledger: PathBuf,
    state: Arc<Control>,
    worker: Option<thread::JoinHandle<()>>,
}

fn reply(socket: &mut TcpStream, code: u16, body: &str) {
    write!(
        socket,
        "HTTP/1.1 {code} Result\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
}

impl Replica {
    fn start(name: &'static str, fault: Fault) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let ledger = std::env::temp_dir().join(format!(
            "omakase-pool-{}-{}-{name}",
            std::process::id(),
            addr.port()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&ledger)
            .unwrap();
        let state = Arc::new(Control::default());
        let control = state.clone();
        let worker = thread::spawn(move || {
            while !control.stop.load(Ordering::Acquire) {
                let (mut socket, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                if socket.peek(&mut [0]).unwrap() == 0 {
                    control.empty_connections.fetch_add(1, Ordering::Release);
                    continue;
                }
                let bytes = read_request(&socket);
                let (head, body) = std::str::from_utf8(&bytes)
                    .unwrap()
                    .split_once("\r\n\r\n")
                    .unwrap();
                if head.starts_with("GET /ready HTTP/1.1\r\n") {
                    assert_eq!(
                        head,
                        "GET /ready HTTP/1.1\r\nHost: app.example\r\nVia: 1.1 omakase\r\nConnection: close\r\nContent-Length: 0"
                    );
                    assert!(body.is_empty());
                    control.probes.fetch_add(1, Ordering::Release);
                    if fault == Fault::StopBeforeDispatch {
                        // The probe succeeds, but a subsequent application connect must fail.
                        drop(listener);
                        reply(&mut socket, 204, "");
                        return;
                    }
                    reply(
                        &mut socket,
                        if control.unhealthy.load(Ordering::Acquire) {
                            503
                        } else {
                            204
                        },
                        "",
                    );
                    continue;
                }
                if head.starts_with("POST ") {
                    writeln!(file, "{body}").unwrap();
                    file.sync_data().unwrap();
                    control.writes.fetch_add(1, Ordering::Release);
                    if fault == Fault::DropAfterWrite {
                        continue;
                    }
                    if fault == Fault::HoldResponse {
                        while !control.release.load(Ordering::Acquire)
                            && !control.stop.load(Ordering::Acquire)
                        {
                            thread::sleep(Duration::from_millis(2));
                        }
                    }
                }
                reply(&mut socket, 200, name);
            }
        });
        Self {
            addr,
            ledger,
            state,
            worker: Some(worker),
        }
    }
    fn entries(&self) -> String {
        fs::read_to_string(&self.ledger).unwrap()
    }
}
impl Drop for Replica {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::Release);
        let result = self.worker.take().unwrap().join();
        fs::remove_file(&self.ledger).unwrap();
        if !thread::panicking() {
            result.unwrap();
        }
    }
}

fn config(a: &Replica, b: &Replica, extra: &str) -> ParsedConfig {
    ParsedConfig::parse(&format!("site \"app.example\" {{\ntls \"auto\"\n{extra}proxy-pool \"/api\" \"/ready\" \"{},{}\"\ndeny \"/api/private\"\n}}\n", a.addr,b.addr)).unwrap()
}
fn request(front: SocketAddr, method: &str, path: &str, body: &str) -> Vec<u8> {
    exchange(front, format!("{method} {path} HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\nCookie: user=fixture\r\nContent-Length: {}\r\n\r\n{body}",body.len()).as_bytes())
}
fn wait_for(mut condition: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(15);
    while !condition() {
        assert!(Instant::now() < end, "fixture timed out");
        thread::sleep(Duration::from_millis(10));
    }
}
fn check(reply: &[u8], status: u16, body: &str) {
    assert!(
        reply.starts_with(format!("HTTP/1.1 {status} ").as_bytes()),
        "{}",
        String::from_utf8_lossy(reply)
    );
    if !body.is_empty() {
        assert!(reply.ends_with(body.as_bytes()));
    }
}

#[test]
fn refused_before_send_switches_and_records_one_write() {
    let a = Replica::start("A", Fault::StopBeforeDispatch);
    let b = Replica::start("B", Fault::None);
    with_config(&config(&a, &b, ""), |front, _| {
        wait_for(|| {
            a.state.probes.load(Ordering::Acquire) > 0 && b.state.probes.load(Ordering::Acquire) > 0
        });
        check(&request(front, "POST", "/api/moves", "move-42"), 200, "B");
        assert_eq!(
            (a.entries(), b.entries()),
            (String::new(), "move-42\n".into())
        );
        println!("pre-send refusal: HTTP 200 from B, durable writes A=0 B=1");
    });
}

#[test]
fn lost_response_after_durable_write_does_not_replay() {
    let a = Replica::start("A", Fault::DropAfterWrite);
    let b = Replica::start("B", Fault::None);
    with_config(&config(&a, &b, ""), |front, _| {
        wait_for(|| b.state.probes.load(Ordering::Acquire) > 0);
        check(&request(front, "POST", "/api/moves", "move-42"), 502, "");
        check(&request(front, "GET", "/api/moves", ""), 200, "B");
        assert_eq!(
            (a.entries(), b.entries()),
            ("move-42\n".into(), String::new())
        );
        println!("post-write disconnect: HTTP 502, durable writes A=1 B=0; B still serves reads");
    });
}

#[test]
fn drain_preserves_dispatched_work_and_excludes_new_writes() {
    let a = Replica::start("A", Fault::HoldResponse);
    let b = Replica::start("B", Fault::None);
    with_config(&config(&a, &b, ""), |front, server| {
        thread::scope(|s| {
            let old = server.state.read().unwrap().snapshot.clone();
            let first = s.spawn(|| request(front, "POST", "/api/moves", "first"));
            wait_for(|| a.state.writes.load(Ordering::Acquire) == 1);
            let drain = |members: &str| {
                let parsed = config(&a, &b, &format!("proxy-drain \"/api\" \"{members}\"\n"));
                server
                    .reload(&parsed.compile().unwrap(), &AtomicBool::new(false))
                    .unwrap();
            };
            drain(&a.addr.to_string());
            let old_pool = old.sites[0].proxy_routes[0].pool.as_ref().unwrap();
            let mut sent = false;
            let stale = futures_lite::future::block_on(old_pool.start(
                front.port(),
                Instant::now() + Duration::from_secs(1),
                Duration::from_secs(1),
                b"GET /api HTTP/1.1\r\n\r\n",
                &mut sent,
            ));
            assert_eq!(stale.unwrap_err().0, 503);
            assert!(!sent);
            check(&request(front, "POST", "/api/moves", "second"), 200, "B");
            a.state.release.store(true, Ordering::Release);
            check(&first.join().unwrap(), 200, "A");
            drain(&format!("{},{}", a.addr, b.addr));
            check(&request(front, "POST", "/api/moves", "third"), 503, "");
            check(&request(front, "GET", "/api/private/x", ""), 404, "");
            check(&request(front, "GET", "/api-other", ""), 404, "");
            drain(&b.addr.to_string());
            check(&request(front, "POST", "/api/moves", "fourth"), 200, "A");
            assert_eq!(
                (a.entries(), b.entries()),
                ("first\nfourth\n".into(), "second\n".into())
            );
        })
    });
}

#[test]
fn longest_route_owns_its_members_and_an_empty_pool_never_falls_through() {
    let a = Replica::start("A", Fault::None);
    let b = Replica::start("B", Fault::None);
    let other = Replica::start("default", Fault::None);
    let extra = format!(
        "reverse-proxy \"{}\"\nproxy-pool \"/api/nested\" \"/ready\" \"{}\"\n",
        other.addr, b.addr
    );
    with_config(&config(&a, &b, &extra), |front, server| {
        check(&request(front, "GET", "/api/list", ""), 200, "A");
        check(&request(front, "GET", "/api/list", ""), 200, "B");
        check(&request(front, "GET", "/api/nested/list", ""), 200, "B");
        check(&request(front, "GET", "/else", ""), 200, "default");
        let drained = config(
            &a,
            &b,
            &format!("{extra}proxy-drain \"/api/nested\" \"{}\"\n", b.addr),
        );
        server
            .reload(&drained.compile().unwrap(), &AtomicBool::new(false))
            .unwrap();
        check(&request(front, "POST", "/api/nested/item", "none"), 503, "");
        assert_eq!(
            (a.entries(), b.entries(), other.entries()),
            (String::new(), String::new(), String::new())
        );
    });
}

#[test]
fn unhealthy_members_are_skipped_and_recover_while_idle() {
    let a = Replica::start("A", Fault::None);
    let b = Replica::start("B", Fault::None);
    a.state.unhealthy.store(true, Ordering::Release);
    b.state.unhealthy.store(true, Ordering::Release);
    with_config(&config(&a, &b, ""), |front, _| {
        check(&request(front, "POST", "/api/moves", "discard"), 503, "");
        b.state.unhealthy.store(false, Ordering::Release);
        wait_for(|| b.state.probes.load(Ordering::Acquire) >= 2);
        check(&request(front, "POST", "/api/moves", "recovered"), 200, "B");
        assert_eq!(
            (a.entries(), b.entries()),
            (String::new(), "recovered\n".into())
        );
    });
}

fn race_reload(first: WritePoint) {
    let a = Replica::start("A", Fault::None);
    let b = Replica::start("B", Fault::None);
    let wait = Duration::from_secs(10);
    with_config(&config(&a, &b, ""), |front, server| {
        let snapshot = server.state.read().unwrap().snapshot.clone();
        let pool = snapshot.sites[0].proxy_routes[0].pool.as_ref().unwrap();
        let (at_boundary, reached) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let (retiring, entering) = mpsc::channel();
        let resume = Mutex::new(resume);
        assert!(
            pool.at_write
                .set(Box::new(move |point| {
                    if point == first {
                        at_boundary.send(()).unwrap();
                        resume.lock().unwrap().recv_timeout(wait).unwrap();
                    } else if point == WritePoint::Retiring {
                        retiring.send(()).unwrap();
                    }
                }))
                .is_ok()
        );
        thread::scope(|scope| {
            let old = scope.spawn(|| request(front, "POST", "/api/moves", "old"));
            reached.recv_timeout(wait).unwrap();
            let changed = config(&a, &b, &format!("proxy-drain \"/api\" \"{}\"\n", a.addr));
            let (switched, done) = mpsc::channel();
            scope.spawn(move || {
                server
                    .reload(&changed.compile().unwrap(), &AtomicBool::new(false))
                    .unwrap();
                switched.send(()).unwrap();
            });
            entering.recv_timeout(wait).unwrap();
            if first == WritePoint::Connected {
                done.recv_timeout(wait).unwrap();
                release.send(()).unwrap();
                check(&old.join().unwrap(), 503, "");
                wait_for(|| a.state.empty_connections.load(Ordering::Acquire) == 1);
                assert_eq!(a.entries(), "");
            } else {
                assert!(matches!(done.try_recv(), Err(mpsc::TryRecvError::Empty)));
                release.send(()).unwrap();
                done.recv_timeout(wait).unwrap();
                check(&old.join().unwrap(), 200, "A");
                assert_eq!(a.entries(), "old\n");
            }
            check(&request(front, "POST", "/api/moves", "new"), 200, "B");
            assert_eq!(b.entries(), "new\n");
        });
    });
}

#[test]
fn drain_after_dial_before_first_write_leaves_old_socket_empty() {
    race_reload(WritePoint::Connected);
    println!("retirement first: old socket EOF with zero bytes, HTTP 503; new POST committed on B");
}

#[test]
fn drain_contending_with_first_socket_write_preserves_only_its_exchange() {
    race_reload(WritePoint::Written);
    println!(
        "first write first: retirement contended on the write lock; old POST committed once on A, new POST once on B"
    );
}
