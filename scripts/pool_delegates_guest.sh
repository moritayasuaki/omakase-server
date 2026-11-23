# Sourced in two boots of the isolated guest. The private host key stays outside it.
delegate() { "$server" sleep-delegate "$@"; }
deny() {
    if "$@" > "$state/denied.log" 2>&1; then cat "$state/denied.log"; return 1; fi
}
blocked() {
    local count http
    count=$(closed_count)
    http=$(post)
    test "$http" = 503 || { echo "Expected closed POST, got $http"; return 1; }
    grep -Fxq 'HEALTH 204' "$peer/events"
    test "$(closed_count)" = "$((count+1))" || { cat "$peer/events"; return 1; }
    test "$(application_count)" = "$baseline"
}
delivered() {
    local http
    http=$(post)
    test "$http" = 200 || { echo "Expected delivered POST, got $http"; cat "$peer/events"; return 1; }
    test "$(application_count)" = "$((baseline+1))"
}
await_exit() {
    for _ in $(seq 1 500); do test ! -e "/proc/$1" && return 0; sleep 0.03; done
    return 1
}
port=/dev/virtio-ports/org.pathward.delegations
exec 8<>"$port"
pause_vm() {
    printf 'pause %s\n' "$1" >&8
    read -r msg tid <&8
    test "$msg" = WITNESSED
    test "$1" = "$tid"
}
receipt() {
    printf 'receipt %s\n' "$1" >&8
    read -r msg tid sig <&8
    test "$msg" = COMPLETED
    test "$1" = "$tid"
    test "$shasize" = "$(echo -n "$sig" | wc -c)"
}
shasize=128
read -r vm public < "$seed/provider"
printf 204 > "$peer/status"
baseline=$(application_count)
if "$first"; then
    delegate enroll "$vm" "$public" | grep -Fx PROVISIONED
    delivered
    baseline=$(application_count)
    deny delegate service-start
    delegate status | grep -Fx 'service=- hypervisor=-'
    install -Dm0644 "$seed/delegated.service" /etc/systemd/system/pathward-delegated-sleep@.service
    cat > /usr/local/libexec/pathward-delegated-sleep <<'SH'
#!/bin/sh
set -eu
dir=/var/lib/pathward-cold-lab
/bin/sh -c 'while test ! -e "$1/leaf-release.$2"; do sleep 0.03; done' sh "$dir" "$1" &
echo "$!" > "$dir/leaf.$1"
while test ! -e "$dir/main-release.$1"; do sleep 0.03; done
SH
    chmod 0755 /usr/local/libexec/pathward-delegated-sleep
    cat > "$state/delegating-hook" <<'SH'
#!/bin/sh
set -eu
dir=/var/lib/pathward-cold-lab
server=/usr/local/libexec/pathward-server
"$server" sleep-delegate service-start > "$dir/service-id"
"$server" sleep-delegate hypervisor-begin > "$dir/hv-id"
SH
    chmod 0700 "$state/delegating-hook"
    dropin=/etc/systemd/system/pathward-delegated-sleep@.service.d
    mkdir -p "$dropin"
    printf '[Service]\nExecStopPost=/bin/true\n' > "$dropin/lifecycle-test.conf"
    systemctl daemon-reload
    deny delegate service-start
    delegate status | grep -Fx 'service=- hypervisor=-'
    rm "$dropin/lifecycle-test.conf"
    systemctl daemon-reload
    echo 'DELEGATED_PROFILE missing_unit_denied=true extra_stop_work_denied=true slots_empty=true'
    mount --bind "$state/delegating-hook" /usr/lib/systemd/systemd-sleep
    systemctl start systemd-suspend.service || { journalctl -u systemd-suspend.service -n 30; exit 1; }
    umount /usr/lib/systemd/systemd-sleep
    service=$(cat "$state/service-id")
    hv=$(cat "$state/hv-id")
    test "$(cat "$fence")" = A
    delegate status | grep -Fx "service=$service hypervisor=$hv"
    deny delegate service-start
    deny delegate hypervisor-begin
    deny "$server" recover-pool-fence --control-dir "$state/control"
    deny delegate service-check "$service"
    blocked
    echo 'DELEGATED_HOOK_EXIT base_awake=true two_owners=true http=503 applications=0'
    unit="pathward-delegated-sleep@$service.service"
    touch "$state/main-release.$service"
    for _ in $(seq 1 400); do test "$(systemctl show "$unit" -p SubState --value)" != exited || break; sleep 0.03; done
    test "$(systemctl show "$unit" -p SubState --value)" = exited
    test "$(systemctl show "$unit" -p MainPID --value)" = 0
    leaf=$(cat "$state/leaf.$service")
    kill -0 "$leaf"
    grep -Fx 'populated 1' "/sys/fs/cgroup/system.slice/$unit/cgroup.events"
    deny delegate service-check "$service"
    blocked
    echo 'DELEGATED_DESCENDANT exit_status=0 main_pid=0 populated=1 http=503 applications=0'
    touch "$state/leaf-release.$service"
    await_exit "$leaf"
    delegate service-check "$service" | grep -Fx SERVICE_CONFIRMED
    blocked
    pause_vm "$hv"
    deny delegate hypervisor-confirm "$hv" "$(printf '%0128d' 0)"
    blocked
    echo 'DELEGATED_HYPERVISOR qmp_resumed=true signed_receipt_withheld=true http=503 applications=0'
    echo DELEGATED_FIRST_POWEROFF
else
    old=$(cat "$state/hv-id")
    delegate status | grep -Fx "service=- hypervisor=$old"
    blocked
    deny delegate init-local
    deny diag
    receipt "$old"
    old_sig=$sig
    delegate hypervisor-confirm "$old" "$old_sig" | grep -Fx HYPERVISOR_CONFIRMED
    delivered
    echo 'DELEGATED_COLD_BOOT same_ticket=true withheld_http=503 withheld_applications=0 confirmed_http=200 confirmed_applications=1'
    baseline=$(application_count)
    race=$(mktemp -d)
    chown nobody:nogroup "$race"
    OMAKASE_POOL_LAB="$race" run "$bin" delegated_registration_waits_for_first_write --ignored --nocapture > "$race/report" 2>&1 & writer=$!
    for _ in $(seq 1 500); do test ! -e "$race/sampled" || break; kill -0 "$writer"; sleep 0.02; done
    test -e "$race/sampled"
    "$server" sleep-delegate hypervisor-begin > "$race/ticket" & registrar=$!
    # The pinned x86_64 guest reports flock as syscall 73. Verify its fd too.
    for _ in $(seq 1 400); do
        set -- $(cat "/proc/$registrar/syscall")
        if test "${1-}" = 73 && test "$(readlink "/proc/$registrar/fd/$(( $2 ))")" = /var/lib/pathward-sleep-delegates; then break; fi
        sleep 0.02
    done
    test "${1-}" = 73
    test "$(readlink "/proc/$registrar/fd/$(( $2 ))")" = /var/lib/pathward-sleep-delegates
    touch "$race/send"
    for _ in $(seq 1 400); do test ! -e "$race/written" || break; kill -0 "$writer"; sleep 0.02; done
    test -e "$race/written"
    test ! -s "$race/ticket"
    kill -0 "$registrar"
    touch "$race/release"
    wait "$writer" || { cat "$race/report"; exit 1; }
    wait "$registrar"
    grep -F 'DELEGATE_RACE_PEER bytes=62' "$race/report"
    hv=$(cat "$race/ticket")
    test "$hv" != "$old"
    service=$(delegate service-start)
    deny delegate hypervisor-confirm "$old" "$old_sig"
    deny delegate hypervisor-confirm "$hv" "$old_sig"
    pause_vm "$hv"
    receipt "$hv"
    delegate hypervisor-confirm "$hv" "$sig" | grep -Fx HYPERVISOR_CONFIRMED
    blocked
    for _ in $(seq 1 400); do test ! -s "$state/leaf.$service" || break; sleep 0.03; done
    leaf=$(cat "$state/leaf.$service")
    touch "$state/main-release.$service" "$state/leaf-release.$service"
    await_exit "$leaf"
    for _ in $(seq 1 200); do test "$(systemctl show "pathward-delegated-sleep@$service.service" -p SubState --value)" != exited || break; sleep 0.03; done
    delegate service-check "$service" | grep -Fx SERVICE_CONFIRMED
    delivered
    echo 'DELEGATED_REPLAY old_ticket_denied=true old_signature_denied=true other_owner_http=503 confirmed_http=200 applications=1'
    baseline=$(application_count)
    mv /var/lib/pathward-sleep-delegates /var/lib/pathward-sleep-delegates.offline
    test "$(post)" = 503
    test "$(application_count)" = "$baseline"
    deny delegate enroll "$vm" "$public"
    mv /var/lib/pathward-sleep-delegates.offline /var/lib/pathward-sleep-delegates
    diag | grep -Fx READY
    echo 'DELEGATED_STORAGE missing_ledger_http=503 applications=0 refused_reinitialization=true'
    lost=$(delegate hypervisor-begin)
    printf 'lose-witness %s\n' "$lost" >&8
    read -r msg tid <&8
    test "$msg" = UNCONFIRMED
    test "$tid" = "$lost"
    deny delegate hypervisor-confirm "$lost" "$old_sig"
    delegate status | grep -Fx "service=- hypervisor=$lost"
    blocked
    echo 'DELEGATED_WITNESS_LOSS console_resumed=true receipt_unavailable=true resubmission_denied=true http=503 applications=0'
    echo POOL_DELEGATED_PASSED
fi
