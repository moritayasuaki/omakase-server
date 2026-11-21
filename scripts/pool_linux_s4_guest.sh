#!/bin/sh
# Runs only on the fresh, pinned, NIC-less lab guest, with an extra disposable swap disk.
set -eu
bin=$1
test "$(id -u)" = 0
test "$(cat /sys/devices/virtual/dmi/id/product_name)" = PathWardPoolLab
test "$(ls /sys/class/net)" = lo
test "$(cat /sys/class/block/vdb/serial)" = PathWardS4Swap
test "$(getconf PAGESIZE)" = 4096
grep -qw disk /sys/power/state
grep -qw platform /sys/power/disk
test -z "$(lsblk -nro FSTYPE /dev/vdb)"
mkswap -L PathWardS4 /dev/vdb
swapon /dev/vdb
cat /sys/class/block/vdb/dev > /sys/power/resume
echo platform > /sys/power/disk
grep -F '[platform]' /sys/power/disk
# The pinned kernel has built-in virtio block and early software resume.
# Boot it from the private overlay with no mountable root on a failed restore.
kernel=/boot/vmlinuz-$(uname -r)
boot_uuid=$(findmnt -n -o UUID -T "$kernel")
test -n "$boot_uuid"
case "$(findmnt -n -o TARGET -T "$kernel")" in
    /boot) kernel_path=/vmlinuz-$(uname -r) ;;
    /) kernel_path=$kernel ;;
    *) exit 1 ;;
esac
mkswap --version
cat > /boot/grub/grub.cfg <<GRUB
set default=0
set timeout=0
menuentry 'PathWard S4 restore' {
    search --no-floppy --fs-uuid --set=root $boot_uuid
    linux $kernel_path resume=/dev/vdb resumewait root=/dev/pathward-no-root ro console=ttyS0 panic=-1
}
GRUB
sync

wait_sample() {
    for _ in $(seq 1 500); do
        test ! -s "$1/sampled" || return 0
        kill -0 "$2" || return 1
        sleep 0.02
    done
    return 1
}
worker() {
    PATHWARD_POOL_LAB=$1 exec setpriv --reuid=nobody --regid=nogroup --clear-groups \
        "$bin" "$2" --ignored --exact --test-threads=1 --nocapture
}
prefix=backend_pool::io_tests::platform::linux::
boot_id=$(cat /proc/sys/kernel/random/boot_id)
for trial in 1 2; do
    pre=$(mktemp -d)
    post=$(mktemp -d)
    chown nobody:nogroup "$pre" "$post"
    worker "$pre" "${prefix}suspended_pool_samples_expire_and_require_a_successful_recheck" &
    pre_pid=$!
    worker "$post" "${prefix}hibernated_after_clock_read_exposes_the_socket_boundary" &
    post_pid=$!
    wait_sample "$pre" "$pre_pid"
    wait_sample "$post" "$post_pid"
    printf '\nS4_HIBERNATE trial=%s\n' "$trial"
    echo disk > /sys/power/state
    test "$(cat /proc/sys/kernel/random/boot_id)" = "$boot_id"
    kill -0 "$pre_pid" "$post_pid"
    echo "S4_CONTINUITY trial=$trial same_boot_id=true both_workers_alive=true"
    touch "$pre/resumed" "$post/resumed"
    wait "$pre_pid"
    wait "$post_pid"
    echo "S4_RESTORED trial=$trial"
done
echo POOL_LINUX_S4_PASSED
