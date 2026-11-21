//! Cooperative operations over nonblocking transports; each wait yields its task.
use crate::http::{self, Transport};
use std::{
    io,
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

pub async fn pause() {
    async_io::Timer::after(Duration::from_millis(2)).await;
}
fn retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
pub async fn operation<T>(
    deadline: Instant,
    mut op: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    loop {
        http::remaining(deadline)?;
        match op() {
            Err(e) if retryable(&e) => pause().await,
            result => return result,
        }
    }
}
pub async fn read(s: &mut impl Transport, b: &mut [u8], d: Instant) -> io::Result<usize> {
    s.deadline(d)?;
    operation(d, || s.read(b)).await
}
pub async fn read_head(s: &mut impl Transport, d: Instant) -> io::Result<Vec<u8>> {
    if let Some(head) = s.buffered_head() {
        http::remaining(d)?;
        if head.len() > http::MAX_HEAD_BYTES || !head.windows(4).any(|w| w == b"\r\n\r\n") {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok(head);
    }
    let mut data = Vec::with_capacity(http::MAX_HEAD_BYTES);
    let mut chunk = [0; 1024];
    loop {
        let count = chunk.len().min(http::MAX_HEAD_BYTES - data.len());
        if count == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let n = read(s, &mut chunk[..count], d).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let start = data.len().saturating_sub(3);
        data.extend_from_slice(&chunk[..n]);
        if data[start..].windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(data);
        }
    }
}
pub async fn write_all(s: &mut impl Transport, bytes: &[u8], d: Instant) -> io::Result<()> {
    write_all_from(s, bytes, 0, d).await
}

pub async fn write_all_from(
    s: &mut impl Transport,
    original: &[u8],
    accepted: usize,
    d: Instant,
) -> io::Result<()> {
    use pathward::upstream::{remaining_after_write, write_suffix};
    let mut bytes = write_suffix(original, accepted).ok_or(io::ErrorKind::InvalidData)?;
    s.deadline(d)?;
    while !bytes.is_empty() {
        http::remaining(d)?;
        let count = match s.write(bytes) {
            Ok(n) => Some(n),
            Err(e) if retryable(&e) => None,
            Err(e) => return Err(e),
        };
        bytes = remaining_after_write(bytes, count).ok_or_else(|| {
            if count == Some(0) {
                io::ErrorKind::WriteZero
            } else {
                io::ErrorKind::InvalidData
            }
        })?;
        if count.is_none() {
            pause().await;
        }
    }
    operation(d, || s.flush()).await
}
pub async fn connect(address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let socket =
        futures_lite::future::race(async_io::Async::<TcpStream>::connect(address), async {
            async_io::Timer::after(timeout).await;
            Err(io::ErrorKind::TimedOut.into())
        })
        .await?
        .into_inner()?;
    // Requests, WebSocket frames and SSE records should not acquire a delayed
    // ACK dependency merely because the caller writes them in small chunks.
    socket.set_nodelay(true)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}
