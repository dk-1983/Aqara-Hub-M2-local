#!/bin/sh
# Trusted worker embedded in the RUNNING panel, never taken from an uploaded archive.
set -eu
umask 077
rmdir() { [ -d "$1" ] && [ ! -L "$1" ] && [ -z "$(ls -A "$1")" ] && rm -r "$1"; }
BASE=/data/aqara-panel
STAGE=$BASE/.web-update
BACKUP=$BASE/web-previous
LOCK=/var/run/aqara-panel-supervisor
result() {
    printf '{"status":"%s","message":"%s"}\n' "$1" "$2" > "$BASE/update-result.json.new"
    mv "$BASE/update-result.json.new" "$BASE/update-result.json"
}
stop_service() {
    if [ -f "$LOCK/pid" ]; then
        pid=$(cat "$LOCK/pid")
        case "$pid" in ''|*[!0-9]*) return 1 ;; esac
        if kill -0 "$pid" 2>/dev/null; then
            tr '\000' '\n' < "/proc/$pid/cmdline" | grep -Fxq "$BASE/autostart.sh" || return 1
            kill "$pid" || return 1
            n=0
            while kill -0 "$pid" 2>/dev/null; do n=$((n+1)); [ "$n" -lt 20 ] || return 1; sleep 1; done
        fi
    fi
    for proc in /proc/[0-9]*/exe; do
        [ "$(readlink "$proc" 2>/dev/null)" = "$BASE/panel" ] || continue
        pid=${proc#/proc/}; pid=${pid%/exe}
        kill "$pid" || return 1
        n=0
        while [ "$(readlink "$proc" 2>/dev/null)" = "$BASE/panel" ]; do n=$((n+1)); [ "$n" -lt 20 ] || return 1; sleep 1; done
    done
}
clear_stage() {
    rm -f "$STAGE/panel" "$STAGE/autostart.sh" "$STAGE/pending.json" "$STAGE/worker.pid" "$STAGE/transaction" "$STAGE/worker.sh"
    rmdir "$STAGE"
}
restore() {
    touch "$BASE/autostart.disabled"
    stop_service || { result recovery_required 'Cannot safely stop service; UART inspection required'; return 1; }
    if [ -f "$BACKUP/armed" ]; then
        # A power cut can occur between the two rename operations.
        for name in panel autostart.sh; do
            [ ! -f "$BACKUP/$name" ] || mv -f "$BACKUP/$name" "$BASE/$name"
        done
        rm -f "$BACKUP/armed"
    fi
    [ -x "$BASE/panel" ] && [ -f "$BASE/autostart.sh" ] || return 1
    result rolled_back 'Previous application restored; settings preserved'
    clear_stage
    sync
    rm -f "$BASE/autostart.disabled"
    if [ "${1:-}" != boot ]; then /bin/sh "$BASE/autostart.sh" </dev/null >/dev/null 2>&1 & fi
}
if [ "${1:-}" = --recover ]; then restore boot; exit $?; fi
echo $$ > "$STAGE/worker.pid"
finished=no
trap 'if [ "$finished" != yes ]; then restore || :; fi' EXIT
trap 'exit 1' HUP INT TERM
sleep 2
result applying 'Installing application; settings preserved'
touch "$BASE/autostart.disabled"
stop_service
# Retain exactly one previous release; uploaded files are already hash-verified.
mkdir -p "$BACKUP"
rm -f "$BACKUP/panel" "$BACKUP/autostart.sh"
touch "$BACKUP/armed"
sync
mv "$BASE/panel" "$BACKUP/panel"
mv "$BASE/autostart.sh" "$BACKUP/autostart.sh"
mv "$STAGE/panel" "$BASE/panel"
mv "$STAGE/autostart.sh" "$BASE/autostart.sh"
chmod 700 "$BASE/panel" "$BASE/autostart.sh"
sync
rm -f "$BASE/autostart.disabled"
/bin/sh "$BASE/autostart.sh" </dev/null >/dev/null 2>&1 &
# Require an authenticated HTTP endpoint and the same live process for 15 seconds.
good=0
lastpid=
n=0
while [ "$n" -lt 30 ]; do
    sleep 2
    n=$((n+1))
    pid=$(cat /var/run/aqara-panel.pid 2>/dev/null || :)
    response=$(wget -O /dev/null -T 2 http://127.0.0.1/api/status 2>&1 || :)
    if [ -n "$pid" ] && [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$BASE/panel" ] && echo "$response" | grep -q '401 Unauthorized'; then
        if [ "$pid" = "$lastpid" ]; then good=$((good+1)); else good=1; fi
        [ "$good" -lt 8 ] || break
    else good=0; fi
    lastpid=$pid
done
[ "$good" -ge 8 ] || exit 1
# Commit on disk before clearing transaction: boot recovery sees the committed marker.
rm -f "$BACKUP/armed"
sync
result success 'Application updated; settings preserved'
finished=yes
clear_stage
sync
