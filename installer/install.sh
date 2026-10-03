#!/bin/sh
# Run from an already authenticated root UART shell. No network listener is opened.
set -eu
umask 077
# This factory BusyBox omits the rmdir and id applets.
rmdir() { [ -d "$1" ] && [ ! -L "$1" ] && [ -z "$(ls -A "$1")" ] && rm -r "$1"; }
BASE=/data/aqara-panel
SELF=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODE=${1:-check}
fail() { echo "ERROR: $*" >&2; exit 1; }
case "$MODE" in check|install) ;; *) fail 'Usage: sh install.sh [check|install] [hub-ip-for-first-identity]' ;; esac
[ "$(awk '/^Uid:/ {print $2}' /proc/self/status)" = 0 ] || fail 'Root UART access is required.'
[ "$(/bin/getprop persist.sys.model)" = lumi.gateway.agl001 ] || fail 'Unsupported effective model.'
grep -q 'RTL8197F' /proc/cpuinfo || fail 'Unsupported CPU.'
grep -q '^ro.sys.fw_ver=4.1.6$' /etc/build.prop || fail 'Unsupported factory firmware.'
grep -q '^ro.sys.build_num=0018$' /etc/build.prop || fail 'Unsupported factory build.'
grep -q ' /data ubifs ' /proc/mounts || fail '/data is not mounted as UBIFS.'
for tool in sha256sum cp mv readlink wget; do [ -x "/bin/$tool" ] || fail "Missing $tool"; done
[ "$SELF" != "$BASE" ] || fail 'Extract the bundle into a separate staging directory.'
cd "$SELF"
[ -s SHA256SUMS ] && [ -f panel ] && [ -f autostart.sh ] || fail 'Incomplete bundle.'
# Factory SHA256 utility does not implement -c (unlike desktop coreutils).
verified=' '
while read -r expected name extra; do
    [ -z "$extra" ] && [ "${#expected}" = 64 ] || fail 'Invalid checksum line.'
    case "$expected" in *[!0-9a-f]*) fail 'Invalid checksum.' ;; esac
    case "$name" in panel|autostart.sh|install.sh|INSTALLER.md|LICENSE|THIRD_PARTY.md|manifest.json|licenses/go.txt|licenses/go-x-net.txt|licenses/go-x-sync.txt|licenses/gorilla-websocket.txt|licenses/paho.txt) ;; *) fail 'Unexpected checksum path.' ;; esac
    case "$verified" in *" $name "*) fail 'Duplicate checksum entry.' ;; esac
    [ "$(sha256sum "$name" | awk '{print $1}')" = "$expected" ] || fail "Bundle checksum mismatch: $name"
    verified="$verified$name "
done < SHA256SUMS
for required in panel autostart.sh install.sh manifest.json; do
    case "$verified" in *" $required "*) ;; *) fail "Missing checksum: $required" ;; esac
done
hook=no
grep -Fq '/bin/sh /data/aqara-panel/autostart.sh' /etc/init.d/rcS && hook=yes
echo "Model verified; rootfs startup hook: $hook"
[ ! -L "$BASE" ] || fail 'Application directory must not be a symlink.'
if [ -d "$BASE" ]; then
    for name in panel autostart.sh auth.sha256 config.json devices.json panel.pid autostart.disabled install-backup install-incomplete; do
        [ ! -L "$BASE/$name" ] || fail "Unexpected symlink: $name"
    done
fi
# Existing runtime data stays in place; one complete application backup is retained.
required=$(du -sk "$SELF" | awk '{print $1}')
if [ -f "$BASE/panel" ]; then
    required=$((required + $(du -k "$BASE/panel" | awk '{print $1}')))
fi
required=$((required + 2048))
free=$(df -Pk /data | awk 'END {print $4}')
[ "$free" -ge "$required" ] || fail "Need $required KiB free on /data (available $free). Remove only verified off-device backups or the uploaded archive."
echo "Space verified: $free KiB free, reserve $required KiB"
[ "$MODE" = install ] || exit 0
[ "$hook" = yes ] || fail 'Install the verified rootfs hook first; see INSTALLER.md. No files changed.'
[ ! -e "$BASE/autostart.disabled" ] || fail 'Autostart was deliberately disabled; resolve this before installing.'
[ ! -e "$BASE/install-incomplete" ] || fail 'Previous transaction is incomplete; inspect it before retrying.'
[ ! -e "$BASE/install-backup" ] || fail 'Archive the previous install-backup off-device before another update.'
ip=${2:-}
if [ ! -f "$BASE/auth.sha256" ]; then
    [ ! -e "$BASE" ] || fail 'Existing directory has no auth.sha256; refusing to replace a partial identity.'
    # The IP is certificate metadata, never a shell command.
    echo "$ip" | awk -F. 'NF!=4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || length($i)>3 || $i>255) exit 1}' || fail 'Supply the hub IPv4 for initial provisioning.'
fi
LOCK=/var/run/4vrs-installer
mkdir "$LOCK" 2>/dev/null || fail 'Another installation is running (or its lock needs inspection).'
stage="$BASE/install-incomplete"
stopped=no
success=no
stop_service() {
    if [ -f /var/run/aqara-panel-supervisor/pid ]; then
        pid=$(cat /var/run/aqara-panel-supervisor/pid)
        case "$pid" in ''|*[!0-9]*) return 1 ;; esac
        if kill -0 "$pid" 2>/dev/null; then
            tr '\000' '\n' < "/proc/$pid/cmdline" | grep -Fxq "$BASE/autostart.sh" || return 1
            kill "$pid" || return 1
            count=0
            while kill -0 "$pid" 2>/dev/null; do
                count=$((count + 1)); [ "$count" -lt 20 ] || return 1
                sleep 1
            done
        fi
    fi
    for proc in /proc/[0-9]*/exe; do
        [ "$(readlink "$proc" 2>/dev/null)" = "$BASE/panel" ] || continue
        pid=${proc#/proc/}; pid=${pid%/exe}
        kill "$pid" || return 1
        count=0
        while [ "$(readlink "$proc" 2>/dev/null)" = "$BASE/panel" ]; do
            count=$((count + 1)); [ "$count" -lt 20 ] || return 1
            sleep 1
        done
    done
    # Older supervisors used an absent rmdir applet and can leave an empty lock.
    if [ -d /var/run/aqara-panel-supervisor ] && [ ! -e /var/run/aqara-panel-supervisor/pid ]; then
        rmdir /var/run/aqara-panel-supervisor || return 1
    fi
}
cleanup() {
    if [ "$stopped" = yes ] && [ "$success" != yes ]; then
        echo 'Installation did not complete; restoring previous application.' >&2
        touch "$BASE/autostart.disabled"
        if ! stop_service; then
            echo 'Could not safely stop the service; disabled marker retained. Inspect UART.' >&2
        elif [ -f "$BASE/install-backup/panel" ] && [ -f "$BASE/install-backup/autostart.sh" ]; then
            for name in panel autostart.sh; do
                cp -p "$BASE/install-backup/$name" "$BASE/$name.rollback" && mv "$BASE/$name.rollback" "$BASE/$name" || return
            done
            rm -f "$BASE/autostart.disabled"
            /bin/sh "$BASE/autostart.sh" </dev/null >/dev/null 2>&1 &
        else
            echo 'First install stopped. Files kept for inspection; autostart remains disabled.' >&2
        fi
    fi
    rmdir "$LOCK" 2>/dev/null || :
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir -p "$BASE"
chmod 700 "$BASE"
mkdir "$stage"
cp "$SELF/panel" "$stage/panel"
cp "$SELF/autostart.sh" "$stage/autostart.sh"
chmod 700 "$stage/panel" "$stage/autostart.sh"
[ "$(sha256sum "$stage/panel" | awk '{print $1}')" = "$(sha256sum "$SELF/panel" | awk '{print $1}')" ] || fail 'Staged executable mismatch.'
if [ ! -f "$BASE/auth.sha256" ]; then
    "$stage/panel" -data "$stage/identity" -init "$ip"
    for name in auth.sha256 panel-password.txt server.crt server.key; do
        cp "$stage/identity/$name" "$BASE/$name"
        chmod 600 "$BASE/$name"
    done
fi
if [ -f "$BASE/panel" ]; then
    mkdir "$BASE/install-backup"
    cp -p "$BASE/panel" "$BASE/install-backup/panel"
    [ ! -f "$BASE/autostart.sh" ] || cp -p "$BASE/autostart.sh" "$BASE/install-backup/autostart.sh"
    # Private configuration backup is local only; installer never reads its contents.
    for name in auth.sha256 config.json devices.json; do
        [ ! -f "$BASE/$name" ] || cp -p "$BASE/$name" "$BASE/install-backup/$name"
    done
fi
touch "$BASE/autostart.disabled"
stopped=yes
stop_service || fail 'Cannot safely stop the current service; inspect process identities.'
mv "$stage/panel" "$BASE/panel"
mv "$stage/autostart.sh" "$BASE/autostart.sh"
cp "$SELF/manifest.json" "$BASE/release.json"
rm -f "$BASE/autostart.disabled"
/bin/sh "$BASE/autostart.sh" </dev/null >/dev/null 2>&1 &
count=0
while :; do
    sleep 2
    pid=$(cat /var/run/aqara-panel.pid 2>/dev/null || :)
    if [ -n "$pid" ] && [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$BASE/panel" ]; then
        # Basic auth must protect the HTTP endpoint; do not expose credentials to wget.
        response=$(wget -O /dev/null -T 3 http://127.0.0.1/api/status 2>&1 || :)
        if echo "$response" | grep -q '401 Unauthorized'; then break; fi
    fi
    count=$((count + 1)); [ "$count" -lt 15 ] || fail 'Panel HTTP startup check failed.'
done
sync
success=yes
# Only our known transaction files are removed, never user data or arbitrary trees.
if [ -d "$stage/identity" ]; then
    rm -f "$stage/identity/auth.sha256" "$stage/identity/panel-password.txt" "$stage/identity/server.crt" "$stage/identity/server.key"
    rmdir "$stage/identity"
fi
rmdir "$stage"
echo 'Installed; HTTP authentication responds. Configure MQTT and verify discovery in HA.'
echo 'Initial password (first install only): /data/aqara-panel/panel-password.txt'
echo 'Root/UART password, paired devices and existing MQTT settings were not changed.'
