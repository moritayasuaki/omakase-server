# Sourced inside the first, NIC-less boot after an actual coordinator crash.
recover() { "$server" recover-pool-fence --control-dir "$state/control"; }
expect_recovered() {
    recover > "$state/recovery-report" 2>&1 || { cat "$state/recovery-report"; return 1; }
    grep -Fx RECOVERED_AWAKE "$state/recovery-report"
}
expect_closed() {
    if recover > "$state/recovery-report" 2>&1; then cat "$state/recovery-report"; return 1; fi
    test "$(cat "$fence")" = S
    test "$(post)" = 503
    test "$(application_count)" = "$before_apps"
}
inode=$(stat -c '%d:%i' "$fence")
daemon=$(systemctl show pathward-cold-app.service --property MainPID --value)
before_apps=$(application_count)
expect_recovered
test "$(post)" = 200
test "$(application_count)" = "$((before_apps + 1))"
recover | grep -Fx ALREADY_AWAKE

# Keep descendants alive even after the main PID disappears. Only this guest
# uses KillMode=process. Its descendants still belong to the managed subtree.
printf '[Service]\nKillMode=process\n' > /etc/systemd/system/systemd-suspend.service.d/90-survivors.conf
systemctl daemon-reload
cat > "$state/hold-sleep" <<'SH'
#!/bin/sh
dir=/var/lib/pathward-cold-lab
/bin/sh "$dir/parent.sh" &
echo "$$" > /run/pathward-direct-pid
SH
cat > "$state/parent.sh" <<'SH'
#!/bin/sh
/bin/sh /var/lib/pathward-cold-lab/leaf.sh &
echo "$$" > /run/pathward-parent-pid
while test ! -f /run/pathward-release-parent; do sleep 0.05; done
SH
cat > "$state/leaf.sh" <<'SH'
#!/bin/sh
echo "$$" > /run/pathward-leaf-pid
while test ! -f /run/pathward-release-leaf; do sleep 0.05; done
SH
systemctl start --no-block systemd-suspend.service
for _ in $(seq 1 600); do test ! -s /run/pathward-leaf-pid || break; sleep 0.02; done
leaf=$(cat /run/pathward-leaf-pid)
parent=$(cat /run/pathward-parent-pid)
direct=$(cat /run/pathward-direct-pid)
supervisor=$(systemctl show systemd-suspend.service -p MainPID --value)
test "$supervisor" -gt 1
test "$(readlink "/proc/$supervisor/exe")" = "$server"
for _ in $(seq 1 400); do test -e "/proc/$direct" || break; sleep 0.02; done
test ! -e "/proc/$direct"
kill -0 "$parent"
kill -0 "$leaf"
before_apps=$(application_count)
expect_closed
echo 'ONLINE_ACTIVE direct_exited=true subreaper_alive=true http=503 extra_applications=0'

cg=/sys/fs/cgroup/system.slice/systemd-suspend.service
mkdir "$cg/lab-leaf"
echo "$leaf" > "$cg/lab-leaf/cgroup.procs"
kill -KILL "$supervisor"
for _ in $(seq 1 400); do systemctl is-failed --quiet systemd-suspend.service && break; sleep 0.02; done
test "$(systemctl show systemd-suspend.service -p MainPID --value)" = 0
kill -0 "$parent"
kill -0 "$leaf"
expect_closed
grep -Fx 'unit=systemd-suspend.service descendant_cgroup_empty=false' "$state/recovery-report"
touch /run/pathward-release-parent
for _ in $(seq 1 500); do test -e "/proc/$parent" || break; sleep 0.02; done
test ! -e "/proc/$parent"
for _ in $(seq 1 300); do test -n "$(cat "$cg/cgroup.procs")" || break; sleep 0.02; done
test -z "$(cat "$cg/cgroup.procs")"
kill -0 "$leaf"
grep -Fx 'populated 1' "$cg/cgroup.events"
expect_closed
grep -Fx 'unit=systemd-suspend.service idle=true' "$state/recovery-report"
grep -Fx 'unit=systemd-suspend.service descendant_cgroup_empty=false' "$state/recovery-report"
echo 'ONLINE_ORPHAN main_pid=0 immediate_cgroup_empty=true descendant_alive=true http=503 extra_applications=0'
touch /run/pathward-release-leaf
for _ in $(seq 1 500); do test -e "/proc/$leaf" || break; sleep 0.02; done
test ! -e "/proc/$leaf"
# Keep the hibernate start job queued before its ExecStart. Every sleep
# cgroup is empty here, so a population-only recovery would be premature.
barrier=pathward-test-power-barrier.service
printf '[Service]\nType=oneshot\nExecStart=/bin/sleep 120\n' > "/etc/systemd/system/$barrier"
pending=/etc/systemd/system/systemd-hibernate.service.d/90-pending.conf
printf '[Unit]\nRequires=%s\nAfter=%s\n' "$barrier" "$barrier" > "$pending"
systemctl daemon-reload
systemctl start --no-block systemd-hibernate.service
for _ in $(seq 1 300); do
    test "$(systemctl show "$barrier" -p MainPID --value)" -gt 0 && break
    sleep 0.02
done
test -n "$(systemctl show systemd-hibernate.service -p Job --value)"
test "$(systemctl show systemd-hibernate.service -p MainPID --value)" = 0
expect_closed
grep -Fx 'unit=systemd-hibernate.service idle=false' "$state/recovery-report"
grep -Fx 'unit=systemd-hibernate.service descendant_cgroup_empty=true' "$state/recovery-report"
systemctl stop --no-block systemd-hibernate.service
systemctl stop "$barrier"
rm "$pending" "/etc/systemd/system/$barrier"
systemctl daemon-reload
echo 'ONLINE_QUEUED main_pid=0 cgroup_empty=true pending_job=true http=503 extra_applications=0'
if "$server" recover-pool-fence --control-dir "$state/no-control" > "$state/recovery-report" 2>&1; then exit 1; fi
test "$(readlink "/proc/$daemon/ns/mnt")" != "$(readlink /proc/self/ns/mnt)"
nsenter --target "$daemon" --mount -- mount --bind "$state/other-fence" "$fence"
if recover > "$state/recovery-report" 2>&1; then exit 1; fi
test "$(cat "$fence")" = S
nsenter --target "$daemon" --mount -- umount "$fence"
echo 'ONLINE_WITNESS missing_control_denied=true foreign_inode_denied=true'
test "$(cat "$fence")" = S
test "$(post)" = 503
test "$(application_count)" = "$before_apps"

# Two independent administrator processes contend for exactly one transition.
recover > "$state/race1" 2>&1 & one=$!
recover > "$state/race2" 2>&1 & two=$!
wait "$one" || true
wait "$two" || true
test "$(grep -hx RECOVERED_AWAKE "$state/race1" "$state/race2" | wc -l)" -eq 1 || { cat "$state/race1" "$state/race2"; exit 1; }
recover | grep -Fx ALREADY_AWAKE
test "$(post)" = 200
test "$(application_count)" = "$((before_apps + 1))"
test "$(stat -c '%d:%i' "$fence")" = "$inode"
test "$(cat /proc/sys/kernel/random/boot_id)" = "$boot"
test "$(systemctl show pathward-cold-app.service -p MainPID --value)" = "$daemon"
echo 'ONLINE_REOPEN one_recovery=true same_boot=true same_server=true same_inode=true http=200 extra_applications=1'

# Inject the written prefix Q + idle left by interruption just before A.
printf Q > "$fence"
expect_recovered
# A legacy writer can leave a bare S with a previous idle receipt. It must
# stay closed even when all systemd services and all four groups are empty.
printf S > "$fence"
before_apps=$(application_count)
expect_closed
echo 'ONLINE_RETRY quiescent_prefix_recovered=true legacy_s_refused=true'
echo ONLINE_RECOVERY_PASSED
