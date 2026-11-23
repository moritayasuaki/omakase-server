# This fixture runs on the separate, NIC-less Linux machine hosting the
# original submitter. Its entire root disk is restored before the third boot.
set -eu
seed=/mnt/pool-lab
base=/var/lib/pathward-witness-lab
mountpoint=/mnt/omakase-witness-authority
disk=/dev/disk/by-id/virtio-pw-witness-journal
test "$(cat /sys/class/block/vdb/serial)" = pw-witness-journal
exec 8<>/dev/virtio-ports/org.pathward.witness.lab
printf 'phase\n' >&8
read -r phase id vm <&8
mkdir -p -m0700 "$base" "$mountpoint"
install -m0755 "$seed/linux-witness" "$base/witness"
install -m0755 "$seed/linux-relay" "$base/relay"
bin=$base/witness
auth=$mountpoint/authority
mirror=$base/mirror
if test "$phase" = baseline; then
    test -z "$(lsblk -nro FSTYPE "$disk")"
    mkfs.ext4 -q "$disk"
    mount "$disk" "$mountpoint"
    mkdir -m0700 "$mirror"
    "$bin" keygen "$auth" "$vm" > "$mountpoint/public"
    printf 'KEY %s\n' "$(cat "$mountpoint/public")" >&8
    cat > "$base/next" <<'SH'
#!/bin/sh
set -eu
mount -o ro /dev/sr0 /mnt/pool-lab
if /bin/sh /mnt/pool-lab/run >/var/lib/pathward-witness-lab/result 2>&1; then code=0; else code=$?; fi
cat /var/lib/pathward-witness-lab/result >/dev/ttyS0
echo "WITNESS_EXIT=$code" >/dev/ttyS0
systemctl --no-block poweroff
SH
    cat > /etc/systemd/system/pathward-witness-lab.service <<UNIT
[Unit]
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/bin/sh $base/next
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable omakase-witness-lab
    systemctl mask systemd-networkd-wait-online.service serial-getty@ttyS0.service
    echo WITNESS_BASELINE
elif test "$phase" = submit; then
    mount "$disk" "$mountpoint"
    run=/run/pathward-witness-lab
    mkdir -m0700 "$run"
    for which in command events; do
        "$base/relay" "$run/$which" "/dev/virtio-ports/org.pathward.qmp.$which" &
    done
    for i in $(seq 1 300); do test ! -S "$run/events" || break; sleep 0.03; done
    "$bin" observe "$auth" "$run/events" "$id" > "$run/observed" & observer=$!
    for i in $(seq 1 500); do grep -qx "ARMED $id" "$run/observed" && break; kill -0 "$observer"; sleep 0.03; done
    grep -qx "ARMED $id" "$run/observed"
    mkfifo "$run/input"
    exec 7<>"$run/input"
    "$bin" pause-once "$mirror" "$auth" "$run/command" "$id" <&7 > "$run/worker" & worker=$!
    for i in $(seq 1 500); do grep -qx "PAUSED $id" "$run/worker" && break; kill -0 "$worker"; sleep 0.03; done
    grep -qx "PAUSED $id" "$run/worker"
    kill -KILL "$worker"
    wait "$worker" || test "$?" = 137
    test -f "$mirror/$id.started"
    if "$bin" reconcile "$auth" "$id"; then exit 1; fi
    printf 'resume\n' >&8
    wait "$observer"
    grep -qx "OBSERVED $id" "$run/observed"
    echo WITNESS_COMPLETED_BEFORE_RESTORE
elif test "$phase" = restored; then
    mount "$disk" "$mountpoint"
    test ! -e "$mirror/$id.started"
    test ! -e "$mirror/$id.resumed"
    if "$bin" pause-once "$mirror" "$auth" /run/nonexistent-monitor "$id"; then exit 1; fi
    # Redelivery reads only the stored signature and public key.
    mv "$auth/provider.pk8" "$mountpoint/offline-signing-key"
    receipt=$("$bin" reconcile "$auth" "$id")
    test "$receipt" = "$("$bin" reconcile "$auth" "$id")"
    printf '%s\n' "$receipt" >&8
    mv "$mountpoint/offline-signing-key" "$auth/provider.pk8"
    echo 'WITNESS_ROOT_RESTORED local_claim_absent=true signed_original_recovered=true'
else
    exit 1
fi
