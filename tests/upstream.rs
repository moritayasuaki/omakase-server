use pathward::upstream::{PoolHealth, fresh_health, publish_probe};

#[test]
fn probe_age_starts_at_launch_and_expires_at_five_seconds() {
    let cold = PoolHealth::default();
    let start = 100;
    let expiry = start + 5_000_000_000;
    let last_valid = publish_probe(cold, 0, start, expiry - 1, 204);
    assert_eq!((last_valid.revision, last_valid.at), (1, start));
    assert!(fresh_health(last_valid, expiry - 1));
    assert!(!fresh_health(last_valid, expiry));
    for (begin, end) in [
        (start, expiry),
        (start, start - 1),
        (start, u64::MAX),
        (u64::MAX, start),
    ] {
        assert_eq!(publish_probe(cold, 0, begin, end, 204).revision, 0);
    }
    let rechecked = publish_probe(last_valid, 1, expiry, expiry + 1, 204);
    assert_eq!((rechecked.revision, rechecked.at), (2, expiry));
    assert!(fresh_health(rechecked, expiry + 1));
}
