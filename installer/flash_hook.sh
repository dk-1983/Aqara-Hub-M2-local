#!/bin/sh
# Deliberate separate operation: never called by the application installer.
set -eu
umask 077
rmdir() { [ -d "$1" ] && [ ! -L "$1" ] && [ -z "$(ls -A "$1")" ] && rm -r "$1"; }
fail() { echo "ERROR: $*" >&2; exit 1; }
MODE=${1:-check}
case "$MODE" in check|apply-with-backup-and-uart) ;; *) fail 'Usage: sh flash_hook.sh [check|apply-with-backup-and-uart]' ;; esac
[ "$(awk '/^Uid:/ {print $2}' /proc/self/status)" = 0 ] || fail 'Root required.'
if [ "$MODE" != check ]; then
    mkdir /var/run/4vrs-flash-lock 2>/dev/null || fail 'Another flash operation is active, or its stale lock needs inspection.'
    trap 'rmdir /var/run/4vrs-flash-lock 2>/dev/null || :' EXIT
    trap 'exit 1' HUP INT TERM
fi
cd "$(dirname "$0")"
[ "$(/bin/getprop persist.sys.model)" = lumi.gateway.agl001 ] || fail 'Unsupported model.'
grep -q RTL8197F /proc/cpuinfo || fail 'Unsupported CPU.'
grep -q '^ro.sys.fw_ver=4.1.6$' /etc/build.prop || fail 'Unsupported firmware.'
grep -q '^ro.sys.build_num=0018$' /etc/build.prop || fail 'Unsupported build.'
[ "$(sha256sum /bin/fw_update | awk '{print $1}')" = 94c2946ad26c44a9d4581c4e461f4665c5ff0006e009b74d12889b712a593917 ] || fail 'Unexamined factory updater.'
grep -Fq '/data/aqara-panel/autostart.sh' /etc/init.d/rcS && fail 'Startup hook already present; no rootfs update needed.'
# Do not source an editable environment file as shell code.
value() { sed -n "s/^$1=//p" hook.env; }
source_sha=$(value SOURCE_SHA)
image_sha=$(value IMAGE_SHA)
blocks=$(value IMAGE_BLOCKS)
package_sha=$(value PACKAGE_SHA)
for hash in "$source_sha" "$image_sha" "$package_sha"; do
    [ "${#hash}" = 64 ] || fail 'Invalid hash metadata.'
    case "$hash" in *[!0-9a-f]*) fail 'Invalid hash metadata.' ;; esac
done
[ "$source_sha" = 9e59e35714a076d062ebc53ddb3b3e78f892584efd6cac9c44e37851bb86c6ef ] || fail 'Unexamined source image.'
case "$blocks" in ''|*[!0-9]*) fail 'Invalid image size.' ;; esac
[ "$blocks" -gt 0 ] && [ "$blocks" -lt 4096 ] || fail 'Image exceeds partition.'
[ "$(sha256sum rootfs-hook-update.bin | awk '{print $1}')" = "$package_sha" ] || fail 'Corrupt upload.'
[ "$(wc -c < rootfs-hook-update.bin)" -eq $((blocks * 4096 + 18)) ] || fail 'Invalid package size.'
# Support only the exact partition map examined on the test hub.
awk '/^mtd5: 01000000 00020000 "rootfs_1"$/ {ok=1} END {exit !ok}' /proc/mtd || fail 'Unexpected rootfs bank 0.'
awk '/^mtd7: 01000000 00020000 "rootfs_2"$/ {ok=1} END {exit !ok}' /proc/mtd || fail 'Unexpected rootfs bank 1.'
boot=$(/bin/boot_ctrl show)
echo "$boot"
echo "$boot" | awk '/^root_sum_check:[[:space:]]*off[[:space:]]*$/ {ok=1} END {exit !ok}' || fail 'Unexamined root checksum policy.'
echo "$boot" | awk '/^priv_mode:[[:space:]]*on[[:space:]]*$/ {ok=1} END {exit !ok}' || fail 'Unexamined boot policy.'
# Both boot selections must agree with current, with no invalid bank / failure count.
# fw_update can write BOTH banks if a bank is invalid: refuse that state entirely.
echo "$boot" | awk '/^rootfs:[[:space:]]*[01][[:space:]]+[01][[:space:]]*$/ {ok=1} END {exit !ok}' || fail 'Unrecognized boot metadata.'
selected=$(echo "$boot" | awk '/^rootfs:/ {print $2}')
current=$(echo "$boot" | awk '/^rootfs:/ {print $3}')
[ "$selected" = "$current" ] || fail 'Pending boot selection; reboot and inspect first.'
for bank in 0 1; do
    echo "$boot" | awk -v key="rootfs_$bank:" '$1==key && NF==4 && $2==0 && $3 ~ /^[0-9a-fA-F]+$/ && $4>0 && $4<=16777216 {ok=1} END {exit !ok}' || fail 'Invalid rootfs bank; updater may overwrite both.'
done
if [ "$current" = 0 ]; then active=/dev/mtdblock5; target=/dev/mtdblock7; next=1; else active=/dev/mtdblock7; target=/dev/mtdblock5; next=0; fi
grep -q "root=$active " /proc/cmdline || fail 'Boot metadata disagrees with running rootfs.'
[ "$(sha256sum "$active" | awk '{print $1}')" = "$source_sha" ] || fail 'Live rootfs differs from the verified source backup.'
echo "Verified. Active: $active; updater target: $target. No reboot is automatic."
[ "$MODE" != check ] || exit 0
echo 'Operator confirms: all MTD backups are off-device and verified; UART recovery is available.'
[ "$(/bin/boot_ctrl show)" = "$boot" ] || fail 'Boot metadata changed during validation; retry inspection.'
/bin/boot_ctrl show > /var/tmp/4vrs-boot-before.txt
/bin/fw_update rootfs-hook-update.bin > /var/tmp/4vrs-flash.log 2>&1 || fail 'Updater failed; keep power on and inspect /var/tmp/4vrs-flash.log.'
cat /var/tmp/4vrs-flash.log
# Factory updater may return zero on failure. Independent readback is mandatory.
grep -q Success /var/tmp/4vrs-flash.log || fail 'No success marker; do not reboot.'
[ "$(dd if="$target" bs=4096 count="$blocks" 2>/dev/null | sha256sum | awk '{print $1}')" = "$image_sha" ] || fail 'Readback mismatch; do not reboot.'
[ "$(sha256sum "$active" | awk '{print $1}')" = "$source_sha" ] || fail 'Original bank changed; do not reboot.'
after=$(/bin/boot_ctrl show)
echo "$after"
echo "$after" | awk -v selected="$next" -v current="$current" '$1=="rootfs:" && $2==selected && $3==current {ok=1} END {exit !ok}' || fail 'Unexpected boot selection; do not reboot.'
[ "$(echo "$boot" | grep '^kernel')" = "$(echo "$after" | grep '^kernel')" ] || fail 'Kernel metadata changed; do not reboot.'
sync
echo 'Rootfs readback verified. Save the UART output. Then run sync; reboot and verify the new bank before installing the application.'
