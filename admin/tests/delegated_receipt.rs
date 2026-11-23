#[path = "../../shared/sleep_ticket.rs"]
mod sleep_ticket;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use sleep_ticket::{decode, encode, observed_terminal_message, terminal_message, uuid};
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, process::Command};

#[test]
fn a_valid_signature_cannot_cross_vms_or_tickets() {
    let signer = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let key = UnparsedPublicKey::new(&ED25519, signer.public_key().as_ref());
    let vm = "00000000-0000-4000-8000-000000000001";
    let other_vm = "00000000-0000-4000-8000-000000000002";
    assert!(uuid(vm) && uuid(other_vm));
    let id = encode(&[1; 32]);
    let other_id = encode(&[2; 32]);
    assert_eq!(decode(&id), Some([1; 32]));
    let signed = terminal_message(vm, &id);
    let signature = signer.sign(signed.as_bytes());
    assert!(key.verify(signed.as_bytes(), signature.as_ref()).is_ok());
    for different in [
        terminal_message(other_vm, &id),
        terminal_message(vm, &other_id),
        observed_terminal_message(vm, &id),
    ] {
        assert!(
            key.verify(different.as_bytes(), signature.as_ref())
                .is_err()
        );
    }
    let independent = signer.sign(observed_terminal_message(vm, &id).as_bytes());
    for other in [
        observed_terminal_message(other_vm, &id),
        observed_terminal_message(vm, &other_id),
        signed,
    ] {
        assert!(key.verify(other.as_bytes(), independent.as_ref()).is_err());
    }
}

#[test]
fn lookup_preserves_the_original_receipt_and_refuses_a_spent_legacy_ticket() {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut nonce = [0; 16];
    SystemRandom::new().fill(&mut nonce).unwrap();
    let dir = std::env::temp_dir().join(format!("omakase-qmp-{}", encode(&nonce)));
    let vm = "00000000-0000-4000-8000-000000000001";
    let id = encode(&[1; 32]);
    let old = encode(&[2; 32]);
    let witness = env!("CARGO_BIN_EXE_omakase-qmp-sleep");
    let run = |mode: &str, args: &[&str]| {
        Command::new(witness)
            .arg(mode)
            .arg(&dir)
            .args(args)
            .output()
            .unwrap()
    };
    let record = |name: String, bytes: &[u8]| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(name))
            .unwrap()
            .write_all(bytes)
            .unwrap();
    };
    assert!(run("keygen", &[vm]).status.success());
    record(format!("{old}.started"), b"started\n");
    let retry = run("observe", &["unused-qmp-socket", &old]);
    assert!(!retry.status.success());
    assert!(String::from_utf8_lossy(&retry.stderr).contains("already spent"));
    assert!(!dir.join("active").exists());
    assert!(!run("reconcile", &[&old]).status.success());
    let key = dir.join("provider.pk8");
    let signer = Ed25519KeyPair::from_pkcs8(&fs::read(&key).unwrap()).unwrap();
    let signed = signer.sign(observed_terminal_message(vm, &id).as_bytes());
    fs::remove_file(key).unwrap();
    record(format!("{id}.terminal"), signed.as_ref());
    record(format!("{old}.terminal"), signed.as_ref());
    assert!(!run("reconcile", &[&old]).status.success());
    let expected = format!("COMPLETED {id} {}\n", encode(signed.as_ref()));
    for _ in 0..2 {
        let result = run("reconcile", &[&id]);
        assert!(result.status.success());
        assert_eq!(result.stdout, expected.as_bytes());
    }
    fs::remove_dir_all(dir).unwrap();
}
