//! Explicit, loopback-only browser interoperability fixture (never in the server binary).
use crate::{Server, http, tls};
use std::{
    io::{self, Write},
    net::{TcpListener, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[test]
#[ignore = "manual browser interoperability fixture; runs for at most 60 seconds"]
fn firefox_loopback_fixture() {
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    backend.set_nonblocking(true).unwrap();
    let config = pathward_config::ParsedConfig::parse(&format!(
        "site \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{}\"\nencode \"gzip,zstd\"\n}}",
        backend.local_addr().unwrap()
    ))
    .unwrap();
    let server = Server::new(&config.compile().unwrap()).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["app.example".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pem = format!("{}{}", key.serialize_pem(), cert.pem());
    let names = vec!["app.example".into()];
    let identity = Arc::new(tls::Identity::new(
        names.clone(),
        Some(tls::Certificate::parse(pem.as_bytes(), &names).unwrap()),
    ));
    let tls = tls::TlsServer::new(identity).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let udp = UdpSocket::bind(address).unwrap();
    println!("BROWSER_FIXTURE_PORT={}", address.port());
    io::stdout().flush().unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let origin = scope.spawn(|| {
            while !stop.load(Ordering::Acquire) {
                let (mut socket, _) = match backend.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => { std::thread::sleep(Duration::from_millis(5)); continue; }
                    Err(e) => panic!("{e}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
                let head = match http::read_head(&mut socket, Instant::now() + Duration::from_secs(3)) {
                    Ok(head) => head,
                    // Closing a browser also cancels speculative/unfinished requests.
                    Err(e) if matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => continue,
                    Err(e) => panic!("{e}"),
                };
                assert!(!String::from_utf8_lossy(&head).to_ascii_lowercase().contains("\r\nte:"));
                let body = if head.starts_with(b"GET /pixel.svg ") {
                    "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\"/>".to_owned()
                } else {
                    format!("<!doctype html><title>PathWard compatibility fixture</title><h1>Firefox transport OK</h1><img src=\"/pixel.svg\">{}", "<!-- bounded test -->".repeat(100))
                };
                let mime = if head.starts_with(b"GET /pixel.svg ") { "image/svg+xml" } else { "text/html; charset=utf-8" };
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = socket.write_all(response.as_bytes());
            }
        });
        let timer = scope.spawn(|| {
            std::thread::sleep(Duration::from_secs(60));
            stop.store(true, Ordering::Release);
        });
        server
            .serve_tls_http3(listener, None, udp, &stop, &tls)
            .unwrap();
        timer.join().unwrap();
        origin.join().unwrap();
    });
}

#[test]
#[ignore = "controlled-loopback transfer experiment; run scripts/transport_benchmark.mjs"]
fn transport_benchmark_fixture() {
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    backend.set_nonblocking(true).unwrap();
    let policy = format!(
        "capacity \"shared-nat\"\nsite \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{}\"\n\
         proxy-limit \"connections\" \"32\"\nproxy-limit \"response-body\" \"1MiB\"\n\
         proxy-timeout \"total\" \"60s\"\n}}",
        backend.local_addr().unwrap()
    );
    let parsed = pathward_config::ParsedConfig::parse(&policy).unwrap();
    let config = parsed.compile().unwrap();
    let server = Server::new(&config).unwrap();
    let names = vec!["app.example".to_owned()];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(names.clone())
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pem = format!("{}{}", key.serialize_pem(), cert.pem());
    let group = tls::Certificate::parse(pem.as_bytes(), &names).unwrap();
    let mut tls = tls::TlsServer::new(Arc::new(tls::Identity::new(names, Some(group)))).unwrap();
    tls.set_quic_send_window(
        tls::QuicSendWindow::parse(&std::env::var("PATHWARD_TEST_SEND_WINDOW").unwrap()).unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let udp = UdpSocket::bind(address).unwrap();
    let stop = AtomicBool::new(false);
    let monitor = TcpListener::bind("127.0.0.1:0").unwrap();
    println!(
        "BENCH_PORT={}\nMONITOR_PORT={}\n{}",
        address.port(),
        monitor.local_addr().unwrap().port(),
        cert.pem()
    );
    io::stdout().flush().unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| crate::control::monitor(monitor, &server, None, &stop, &stop).unwrap());
        scope.spawn(|| {
            let blob: Vec<_> = (0..818_100usize).map(|n| (n % 251) as u8).collect();
            while !stop.load(Ordering::Acquire) {
                let (mut socket, _) = match backend.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let Ok(head) = http::read_head(&mut socket, Instant::now() + Duration::from_secs(3)) else {
                    continue;
                };
                let bytes = if head.starts_with(b"GET /asset ") { blob.as_slice() } else { b"ready" };
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                let _ = socket.write_all(header.as_bytes()).and_then(|()| socket.write_all(bytes));
            }
        });
        let stop_ref = &stop;
        scope.spawn(move || {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            stop_ref.store(true, Ordering::Release);
        });
        server
            .serve_tls_http3(listener, None, udp, &stop, &tls)
            .unwrap();
    });
}
