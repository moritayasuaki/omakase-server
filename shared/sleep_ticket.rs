//! Canonical wire identity shared by the host and the hypervisor witness.
use std::fmt::Write;

pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(s, "{byte:02x}").expect("writing a String");
    }
    s
}

pub fn decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let mut bytes = [0; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(bytes)
}

pub fn uuid(s: &str) -> bool {
    s.len() == 36
        && s != "00000000-0000-0000-0000-000000000000"
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

pub fn terminal_message(vm: &str, ticket: &str) -> String {
    format!("PathWard hypervisor sleep completed v1\n{vm}\n{ticket}\n")
}

pub fn observed_terminal_message(vm: &str, ticket: &str) -> String {
    format!("PathWard independently observed QEMU resume v2\n{vm}\n{ticket}\n")
}
