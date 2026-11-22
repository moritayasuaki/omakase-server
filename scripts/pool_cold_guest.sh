# Two separate boots of the same disposable disk. The daemon and backend
# run as nobody and communicate only on guest loopback.
set -eu
state=/var/lib/pathward-cold-lab
peer=/run/pathward-cold-peer
server=/usr/local/libexec/pathward-server
fence=/run/pathward-sleep.gate
boot=$(cat /proc/sys/kernel/random/boot_id)
first=false
if test ! -f "$state/first-boot"; then
    first=true
    install -d -m0755 "$state"
    install -d -o nobody -g nogroup -m0700 "$state/control"
    install -Dm0755 "$seed/pathward-server" "$server"
    cat > "$state/pool.kdl" <<'KDL'
site "app.example" {
  tls "auto"
  proxy-pool "/api" "/ready" "127.0.0.1:43065"
}
KDL
    cat > "$state/owner.kdl" <<'KDL'
site "app.example" {
  tls "auto"
  // proxy-pool
  reverse-proxy "127.0.0.1:43065"
  proxy-resource "/rooms" "12" "127.0.0.1:43065"
}
KDL
    run "$server" pool-preflight "$state/owner.kdl" | grep -Fx NOT_REQUIRED
    run "$server" init "$state/control" "$state/pool.kdl"
    for mode in suspend hibernate hybrid-sleep suspend-then-hibernate; do
        install -Dm0644 "$seed/sleep.conf" "/etc/systemd/system/systemd-$mode.service.d/50-pathward.conf"
    done
    sed 's/ root pathward / root nogroup /' "$seed/sleep.tmpfiles" > /etc/tmpfiles.d/pathward-sleep.conf
    systemd-tmpfiles --create /etc/tmpfiles.d/pathward-sleep.conf
    run "$bin" pool_preflight:: --test-threads=1 | grep -E 'test result: ok\. [1-9][0-9]* passed; 0 failed'
    cat > /etc/systemd/system/pathward-cold-app.service <<UNIT
[Service]
User=nobody
Group=nogroup
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=$state/control
ExecStart=$server serve-http $state/control/.config 127.0.0.1:43064 --control-dir $state/control --monitor 127.0.0.1:43066
UNIT
    # cloud-init's runcmd runs only on the first boot. Re-enter the same
    # verified read-only seed once on a fresh kernel after the first poweroff.
    cat > "$state/second.sh" <<'SH'
#!/bin/sh
mkdir -p /mnt/pool-lab
report=/var/lib/pathward-cold-lab/second.log
if mount -o ro /dev/sr0 /mnt/pool-lab && /bin/sh /mnt/pool-lab/run > "$report" 2>&1; then
    result=0
else
    result=$?
fi
cat "$report" > /dev/ttyS0
echo "COLD_GUEST_EXIT=$result" > /dev/ttyS0
systemctl --no-block poweroff
SH
    cat > /etc/systemd/system/pathward-cold-second.service <<UNIT
[Unit]
After=local-fs.target systemd-tmpfiles-setup.service
[Service]
Type=oneshot
ExecStart=/bin/sh $state/second.sh
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable pathward-cold-second.service
    # No login or network interface is used in the second QEMU process.
    # A serial getty can hang up existing console file descriptors at startup.
    systemctl mask serial-getty@ttyS0.service systemd-networkd-wait-online.service
    printf '%s\n' "$boot" > "$state/first-boot"
    touch /run/pathward-first-boot-only
else
    test "$boot" != "$(cat "$state/first-boot")"
    test ! -e /run/pathward-first-boot-only
    test "$(cat "$fence")" = A
    echo "NEW_BOOT different_id=true old_run_gone=true tmpfiles_awake=true"
fi

install -d -o nobody -g nogroup -m0700 "$peer"
if "$first"; then printf 204 > "$peer/status"; else printf 503 > "$peer/status"; fi
PATHWARD_POOL_LAB="$peer" run "$bin" cold_boot_http_peer --ignored --test-threads=1 --nocapture &
worker=$!
for _ in $(seq 1 400); do test ! -f "$peer/listening" || break; kill -0 "$worker"; sleep 0.02; done
test -f "$peer/listening"
systemctl start pathward-cold-app.service
get() { curl --noproxy '*' -fsS --max-time 3 "http://127.0.0.1:43066/$1"; }
for _ in $(seq 1 300); do if get readyz >/dev/null 2>&1; then break; fi; sleep 0.02; done
get readyz | grep -Fx ready
post() { curl --noproxy '*' -sS --max-time 3 -H 'Host: app.example' -H 'Content-Length: 0' -X POST -o /dev/null -w '%{http_code}' http://127.0.0.1:43064/api/write; }
diag() { "$server" pool-preflight "$state/control/.config" --control-dir "$state/control"; }
closed_count() { get metrics | awk '$1=="pathward_pool_fence_rejections_total{reason=\"closed\"}"{print $2}'; }
application_count() { awk '$1=="APP"{n++} END{print n+0}' "$peer/events"; }
diag > "$peer/report" || { cat "$peer/report"; exit 1; }
grep -Fx READY "$peer/report"
if "$first"; then
    test "$(post)" = 200
    test "$(application_count)" = 1
    test "$(closed_count)" = 0
    chmod 0600 "$fence"
    if diag > "$peer/report"; then exit 1; fi
    grep -F 'host_fence=awake service_fence=permission same_inode=false' "$peer/report"
    chmod 0640 "$fence"
    invalid_unit=/etc/systemd/system/systemd-hibernate.service.d/90-wrong.conf
    printf '[Service]\nExecStart=\nExecStart=/usr/lib/systemd/systemd-sleep hibernate\n' > "$invalid_unit"
    systemctl daemon-reload
    if diag > "$peer/report"; then exit 1; fi
    grep -F 'unit=systemd-hibernate.service command=false' "$peer/report"
    rm "$invalid_unit"
    systemctl daemon-reload
    diag | grep -Fx READY
    # A valid awake marker on a different inode must give BLOCKED even if the
    # copied mode and contents look identical to the service.
    install -m0644 "$fence" "$state/other-fence"
    unshare --mount --propagation private /bin/sh -eu -c '
        mount --bind "$1" /run/pathward-sleep.gate
        exec setpriv --reuid=nobody --regid=nogroup --clear-groups "$2" pool-fence-witness
    ' sh "$state/other-fence" "$server" > "$peer/other-view"
    if "$server" pool-preflight "$state/pool.kdl" --service-stdin < "$peer/other-view" > "$peer/report"; then exit 1; fi
    grep -F 'host_fence=awake service_fence=awake same_inode=false' "$peer/report"
    test "$(closed_count)" = 0 && test "$(application_count)" = 1

    # Only this disposable guest sees the inert replacement for the sleep
    # backend. The real systemd unit runs and records the supervisor's death.
    cat > "$state/hold-sleep" <<'SH'
#!/bin/sh
echo "$$" > /run/pathward-cold-sleeper
exec /bin/sleep 120
SH
    chmod 0755 "$state/hold-sleep"
    mount --bind "$state/hold-sleep" /usr/lib/systemd/systemd-sleep
    systemctl start --no-block systemd-suspend.service
    for _ in $(seq 1 400); do test ! -s /run/pathward-cold-sleeper || break; sleep 0.02; done
    test -s /run/pathward-cold-sleeper
    supervisor=$(systemctl show systemd-suspend.service -p MainPID --value)
    test "$supervisor" -gt 1 && test "$(readlink "/proc/$supervisor/exe")" = "$server"
    if diag > "$peer/report"; then exit 1; fi
    grep -F 'host_fence=busy service_fence=busy same_inode=true' "$peer/report"
    test "$(closed_count)" = 0
    kill -KILL "$supervisor"
    for _ in $(seq 1 400); do systemctl is-failed --quiet systemd-suspend.service && break; sleep 0.02; done
    systemctl is-failed --quiet systemd-suspend.service
    test "$(cat "$fence")" = S
    test "$(post)" = 503
    test "$(closed_count)" = 1
    if diag > "$peer/report"; then exit 1; fi
    grep -Fx BLOCKED "$peer/report"
    grep -F 'host_fence=closed service_fence=closed same_inode=true' "$peer/report"
    grep -F 'unit=systemd-suspend.service command=true profile=true last_result=signal exit_code=2 exit_status=9' "$peer/report"
    test "$(application_count)" = 1
    test "$(cat "$fence")" = S
    echo 'ORPHAN_503 http=503 closed_counter_delta=1 extra_applications=0 unit_signal=9'
    sync
    echo POOL_COLD_FIRST_POWEROFF
else
    test "$(closed_count)" = 0
    test "$(post)" = 503
    grep -q '^HEALTH 503$' "$peer/events"
    test "$(application_count)" = 0
    test "$(closed_count)" = 0
    printf 204 > "$peer/status"
    status=503
    for _ in $(seq 1 100); do
        status=$(post)
        test "$status" = 503 || break
        sleep 0.1
    done
    test "$status" = 200
    awk '$1=="HEALTH" && $2==204 {good=1} $1=="APP" {if (!good || $2<1) exit 1; n++} END {if(n!=1) exit 1}' "$peer/events"
    bytes=$(awk '$1=="APP" {print $2}' "$peer/events")
    echo "COLD_DISPATCH failed_probe_http=503 before_204_applications=0 before_204_bytes=0 after_204_http=200 applications=1 application_bytes=$bytes"
    echo POOL_COLD_RECOVERY_PASSED
fi
