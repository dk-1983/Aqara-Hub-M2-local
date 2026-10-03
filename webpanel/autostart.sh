#!/bin/sh
# Optional /data service. Runtime files and logs stay in RAM.
BASE=/data/aqara-panel
LOCK=/var/run/aqara-panel-supervisor
umask 077
rmdir() { [ -d "$1" ] && [ ! -L "$1" ] && [ -z "$(ls -A "$1")" ] && rm -r "$1"; }
if [ -f "$BASE/.web-update/transaction" ]; then
    owner=$(cat "$BASE/.web-update/worker.pid" 2>/dev/null)
    active=no
    case "$owner" in ''|*[!0-9]*) ;; *)
        if [ -r "/proc/$owner/cmdline" ] && tr '\000' '\n' < "/proc/$owner/cmdline" | grep -Fxq "$BASE/.web-update/worker.sh"; then active=yes; fi ;;
    esac
    if [ "$active" != yes ]; then
        /bin/sh "$BASE/.web-update/worker.sh" --recover || exit 1
    fi
fi
[ ! -e "$BASE/autostart.disabled" ] || exit 0
[ -x "$BASE/panel" ] || exit 1
mkdir -p /var/run
# Atomic singleton; stale locks are removed only when their owner is gone.
if ! mkdir "$LOCK" 2>/dev/null; then
    owner=$(cat "$LOCK/pid" 2>/dev/null)
    case "$owner" in ''|*[!0-9]*) exit 1 ;; esac
    if kill -0 "$owner" 2>/dev/null; then exit 0; fi
    rm -f "$LOCK/pid"
    rmdir "$LOCK" 2>/dev/null || exit 1
    mkdir "$LOCK" 2>/dev/null || exit 1
fi
echo $$ > "$LOCK/pid"
child=
cleanup() {
    if [ -n "$child" ]; then kill "$child" 2>/dev/null; wait "$child" 2>/dev/null; fi
    rm -f "$LOCK/pid" /var/run/aqara-panel.pid
    rmdir "$LOCK" 2>/dev/null
}
trap 'exit 0' TERM INT HUP
trap cleanup EXIT
export GOMEMLIMIT=12MiB GOGC=50
# Avoid racing an already running manually launched panel.
for proc in /proc/[0-9]*/exe; do
    [ "$(readlink "$proc" 2>/dev/null)" != "$BASE/panel" ] || exit 0
done
delay=5
while [ ! -e "$BASE/autostart.disabled" ]; do
    started=$(cut -d. -f1 /proc/uptime)
    "$BASE/panel" -data "$BASE" -listen :80 >/dev/null 2>&1 &
    child=$!
    echo "$child" > /var/run/aqara-panel.pid
    # Compatibility with existing local maintenance scripts.
    echo "$child" > "$BASE/panel.pid"
    wait "$child"
    result=$?
    child=
    ended=$(cut -d. -f1 /proc/uptime)
    printf 'last_exit=%s uptime=%s retry_delay=%s\n' "$result" "$ended" "$delay" > /var/run/aqara-panel-supervisor.status
    [ ! -e "$BASE/autostart.disabled" ] || break
    [ $((ended - started)) -lt 60 ] || delay=5
    sleep "$delay"
    [ "$delay" -ge 60 ] || delay=$((delay * 2))
    [ "$delay" -le 60 ] || delay=60
done
