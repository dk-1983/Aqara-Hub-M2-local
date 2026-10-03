"""Linux sandbox lifecycle test; no hub, root privileges or port 80 needed.

Run with a native Linux build of webpanel: python3 installer/test_lifecycle.py /path/to/panel
Only hardware checks and absolute runtime paths are redirected into a temporary tree.
The real installer stages files, starts/stops the real panel and handles rollback.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def run(panel):
    with tempfile.TemporaryDirectory(prefix="4vrs-installer-test-") as tmp:
        home = Path(tmp)
        base = home / "data/aqara-panel"
        bundle = home / "bundle"
        runtime = home / "run"
        fixture = home / "fixture"
        for path in (base.parent, bundle, runtime, fixture):
            path.mkdir(parents=True)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        (fixture / "cpu").write_text("system type: RTL8197F\n")
        (fixture / "model").write_text("lumi.gateway.agl001\n")
        (fixture / "getprop").write_text(f'#!/bin/sh\ncat "{fixture}/model"\n')
        (fixture / "getprop").chmod(0o700)
        (fixture / "mounts").write_text(f"ubi0 {base.parent} ubifs rw 0 0\n")
        (fixture / "prop").write_text("ro.sys.fw_ver=4.1.6\nro.sys.build_num=0018\n")
        (fixture / "rcS").write_text(f"/bin/sh {base}/autostart.sh\n")
        substitutions = {
            "/data/aqara-panel": str(base), "/var/run": str(runtime),
            "/bin/getprop": str(fixture / "getprop"), "/proc/cpuinfo": str(fixture / "cpu"),
            "/etc/build.prop": str(fixture / "prop"), "/proc/mounts": str(fixture / "mounts"),
            "/etc/init.d/rcS": str(fixture / "rcS"), "\"$(awk '/^Uid:/ {print $2}' /proc/self/status)\"": '"0"' ,
            " /data ubifs ": f" {base.parent} ubifs ", "df -Pk /data": f'df -Pk "{base.parent}"',
            "http://127.0.0.1/api/status": f"http://127.0.0.1:{port}/api/status",
            "-listen :80": f"-listen 127.0.0.1:{port}",
        }
        for source, target in (("installer/install.sh", "install.sh"), ("webpanel/autostart.sh", "autostart.sh")):
            text = (ROOT / source).read_text(encoding="utf-8")
            for before, after in substitutions.items():
                text = text.replace(before, after)
            (bundle / target).write_text(text)
        shutil.copyfile(panel, bundle / "panel")
        (bundle / "panel").chmod(0o700)
        (bundle / "manifest.json").write_text('{"test":true}\n')

        def checksums():
            (bundle / "SHA256SUMS").write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in sorted(bundle.iterdir()) if p.name != "SHA256SUMS"))

        def install(mode="install", expected=0):
            result = subprocess.run(["sh", str(bundle / "install.sh"), mode, "127.0.0.1"], capture_output=True, text=True, timeout=100)
            if (result.returncode == 0) != (expected == 0):
                raise AssertionError(result.stdout + result.stderr)
            return result.stdout + result.stderr

        def status():
            password = (base / "panel-password.txt").read_text()
            token = base64.b64encode(("admin:" + password).encode()).decode()
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/status", headers={"Authorization": "Basic " + token})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=4) as response:
                return json.load(response)

        checksums()
        try:
            install("check")
            assert not base.exists(), "Check mode mutated application directory"
            (fixture / "model").write_text("unsupported\n")
            assert "Unsupported" in install("check", 1)
            (fixture / "model").write_text("lumi.gateway.agl001\n")
            (bundle / "manifest.json").write_text("corrupted\n")
            assert "checksum" in install("check", 1)
            (bundle / "manifest.json").write_text('{"test":true}\n')
            checksums()
            install()
            status()
            original_auth = (base / "auth.sha256").read_bytes()
            config = b'{"host":"127.0.0.1","port":1883,"prefix":"test/local","client_id":"test-local","enabled":false,"username":"test","password":"test-only"}'
            (base / "config.json").write_bytes(config)
            (base / "root-password.txt").write_text("test-copy-only")
            install()
            assert (base / "auth.sha256").read_bytes() == original_auth
            assert (base / "config.json").read_bytes() == config
            assert (base / "root-password.txt").read_text() == "test-copy-only"
            status()
            assert "install-backup" in install(expected=1)
            (base / "install-backup").rename(home / "archived-backup")
            # A checksum-valid but non-starting executable must trigger application rollback.
            (bundle / "panel").write_text("#!/bin/sh\nexit 12\n")
            checksums()
            result = install(expected=1)
            assert "restoring previous" in result
            for attempt in range(20):
                try:
                    status()
                    break
                except OSError:
                    time.sleep(0.5)
            else:
                raise AssertionError("Rollback did not restore HTTP")
            assert (base / "auth.sha256").read_bytes() == original_auth
            assert (base / "config.json").read_bytes() == config
            assert (base / "install-incomplete").is_dir()
            print("PASS: dry run, incompatible model, corrupted package, first install, update, credential/config preservation, backup guard, failed-start rollback")
        finally:
            if base.exists():
                (base / "autostart.disabled").touch()
            pidfile = runtime / "aqara-panel-supervisor/pid"
            if pidfile.exists():
                pid = int(pidfile.read_text())
                try:
                    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
                    if str(base / "autostart.sh").encode() in cmdline.split(b"\0"):
                        os.kill(pid, signal.SIGTERM)
                except (FileNotFoundError, ProcessLookupError):
                    pass
            time.sleep(2)


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve())
