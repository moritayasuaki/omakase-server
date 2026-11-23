//! Test transport for one QMP Unix connection over an isolated guest serial port.
use std::{
    env,
    fs::OpenOptions,
    io::{self, Write},
    net::Shutdown,
    os::unix::net::UnixListener,
    thread,
};

fn main() -> io::Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let [socket, port] = args.as_slice() else {
        return Err(io::Error::other("expected fixture socket and virtio port"));
    };
    let listener = UnixListener::bind(socket)?;
    let (mut client, _) = listener.accept()?;
    let mut serial = OpenOptions::new().read(true).write(true).open(port)?;
    serial.write_all(b"OPEN\n")?;
    let mut to_client = client.try_clone()?;
    let mut from_host = serial.try_clone()?;
    thread::spawn(move || {
        let _ = io::copy(&mut from_host, &mut to_client);
        let _ = to_client.shutdown(Shutdown::Both);
    });
    io::copy(&mut client, &mut serial)?;
    Ok(())
}
