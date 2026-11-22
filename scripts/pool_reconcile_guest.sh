# Sourced only inside the pinned disk-rollback guest.
exec 8<>/dev/virtio-ports/org.pathward.delegations
read -r vm public < "$seed/provider"
delegate() { "$server" sleep-delegate "$@"; }
deny() { if "$@" > "$peer/rejected" 2>&1; then cat "$peer/rejected"; return 1; fi; }
blocked() {
    n=$(closed_count)
    count=$(application_count)
    test "$(post)" = 503
    test "$(closed_count)" = "$((n+1))"
    test "$(application_count)" = "$count"
    grep -Fxq 'HEALTH 204' "$peer/events"
}
delivered() {
    count=$(application_count)
    test "$(post)" = 200
    test "$(application_count)" = "$((count+1))"
}
restore_local() {
    localdir=/var/lib/pathward-sleep-delegates
    (
        flock -x 9
        cp "$1" "$localdir/state.restore"
        mv "$localdir/state.restore" "$localdir/state"
    ) 9<"$localdir"
}
printf 'phase\n' >&8
read -r phase <&8
if test "$phase" = baseline; then
    "$first"
    cp /var/lib/pathward-sleep-delegates/state "$guard/lab-prior-enrollment"
    delegate enroll-recoverable "$vm" "$public" | grep -Fx PROVISIONED
    delegate status | grep -Fx 'service=- hypervisor=- guard=-'
    delivered
    echo RECONCILE_BASELINE
elif test "$phase" = submit; then
    delegate status | grep -Fx 'service=- hypervisor=- guard=-'
    id=$(delegate hypervisor-begin)
    cp /var/lib/pathward-sleep-delegates/state "$guard/lab-prior-guest-record"
    blocked
    printf 'lose %s\n' "$id" >&8
    read -r answer observed <&8
    test "$answer" = OBSERVED
    test "$observed" = "$id"
    blocked
    delegate status | grep -Fx "service=- hypervisor=$id guard=$id"
    echo 'RECONCILE_WITHHELD http=503 delivered=0'
    echo RECONCILE_SUBMITTED
elif test "$phase" = restored; then
    printf 'original\n' >&8
    read -r id <&8
    delegate status | grep -Fx "service=- hypervisor=- guard=$id"
    blocked
    restore_local "$guard/lab-prior-enrollment"
    deny delegate status
    count=$(application_count)
    test "$(post)" = 503
    test "$(application_count)" = "$count"
    delegate enroll-recoverable "$vm" "$public" | grep -Fx PROVISIONED
    delegate status | grep -Fx "service=- hypervisor=- guard=$id"
    blocked
    echo 'RECONCILE_GUEST_DOWNGRADE legacy_record_closed=true reenrollment_preserves_original=true'
    deny delegate hypervisor-begin
    deny delegate hypervisor-confirm "$id" "$(printf '%0128d' 0)"
    delegate enroll-recoverable "$vm" "$public" | grep -Fx ALREADY_PROVISIONED
    blocked
    printf 'receipt %s\n' "$id" >&8
    read -r answer tid sig <&8
    test "$answer" = COMPLETED
    test "$tid" = "$id"
    delegate hypervisor-confirm "$id" "$sig" | grep -Fx HYPERVISOR_CONFIRMED
    delivered
    echo 'RECONCILE_GUEST_ROLLBACK local_idle=true independent_pending=true before_http=503 before_delivered=0 confirmed_http=200 confirmed_delivered=1'
    lost=$(delegate hypervisor-begin)
    deny delegate hypervisor-confirm "$lost" "$sig"
    # Restore an actual older local record while leaving the new guard intact.
    restore_local "$guard/lab-prior-guest-record"
    delegate status | grep -Fx "service=- hypervisor=$id guard=$lost"
    blocked
    delegate hypervisor-confirm "$id" "$sig" | grep -Fx LOCAL_HISTORY_CONFIRMED
    delegate status | grep -Fx "service=- hypervisor=- guard=$lost"
    blocked
    echo 'RECONCILE_STALE_GUEST old_receipt_repairs_local=true newer_guard_pending=true http=503 delivered=0'
    printf 'ambiguous %s\n' "$lost" >&8
    read -r answer tid <&8
    test "$answer" = UNCONFIRMED
    test "$tid" = "$lost"
    blocked
    echo 'RECONCILE_OBSERVER_LOSS running=true completion_unknown=true http=503 delivered=0'
    echo POOL_RECONCILIATION_PASSED
else
    exit 1
fi
