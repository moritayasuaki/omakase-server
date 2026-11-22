#[path = "../../shared/sleep_ticket.rs"]
mod sleep_ticket;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use sleep_ticket::{decode, encode, terminal_message, uuid};

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
    ] {
        assert!(
            key.verify(different.as_bytes(), signature.as_ref())
                .is_err()
        );
    }
}
