"""Build a clean application bundle, never a copy of a configured hub."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_elf(path):
    header = path.read_bytes()[:20]
    if len(header) != 20 or header[:6] != b"\x7fELF\x01\x01" or struct.unpack_from("<H", header, 18)[0] != 8:
        raise ValueError("Expected a 32-bit little-endian MIPS ELF executable")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    env = os.environ.copy()
    for key in ("GOOS", "GOARCH", "GOMIPS", "CGO_ENABLED"):
        env.pop(key, None)
    go = str(Path(args.go).resolve()) if Path(args.go).exists() else args.go
    import sys
    subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "installer", "-v"], cwd=ROOT, check=True)
    for command in (["test", "./..."], ["vet", "./..."]):
        subprocess.run([go, *command], cwd=ROOT / "webpanel", env=env, check=True)
    version = re.search(r'const addonVersion = "([0-9.]+)"', (ROOT / "webpanel/devices.go").read_text(encoding="utf-8"))[1]
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output / ("4vrs-m2-" + version + ".tar")
    if output.exists():
        raise SystemExit(f"Refusing to overwrite {output}")
    with tempfile.TemporaryDirectory(prefix="4vrs-release-") as tmp:
        bundle = Path(tmp) / "4vrs-m2"
        bundle.mkdir()
        env.update({"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "mipsle", "GOMIPS": "softfloat"})
        subprocess.run([go, "build", "-trimpath", "-ldflags", "-s -w", "-o", str(bundle / "panel"), "."], cwd=ROOT / "webpanel", env=env, check=True)
        verify_elf(bundle / "panel")
        # An explicit allowlist prevents accidental inclusion of identities or captures.
        for source, target in (("webpanel/autostart.sh", "autostart.sh"), ("installer/install.sh", "install.sh"), ("installer/README.md", "INSTALLER.md"), ("LICENSE", "LICENSE"), ("THIRD_PARTY.md", "THIRD_PARTY.md")):
            content = (ROOT / source).read_bytes().replace(b"\r\n", b"\n")
            (bundle / target).write_bytes(content)
        shutil.copytree(ROOT / "licenses", bundle / "licenses")
        manifest = {"format": 1, "version": version, "platform": "linux/mipsle/softfloat", "model": "lumi.gateway.agl001", "factory_firmware": "4.1.6_0018.0650", "contains_credentials": False, "contains_rootfs": False}
        (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
        files = sorted(p for p in bundle.rglob("*") if p.is_file())
        (bundle / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.relative_to(bundle).as_posix()}\n" for p in files), encoding="ascii", newline="\n")
        with tarfile.open(output, "w", format=tarfile.USTAR_FORMAT) as archive:
            for path in sorted(bundle.rglob("*")):
                if not path.is_file():
                    continue
                info = archive.gettarinfo(str(path), "4vrs-m2/" + path.relative_to(bundle).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                info.mode = 0o700 if path.name in ("panel", "install.sh", "autostart.sh") else 0o600
                with path.open("rb") as stream:
                    archive.addfile(info, stream)
    output.with_suffix(".tar.sha256").write_text(f"{sha(output)}  {output.name}\n", encoding="ascii", newline="\n")
    print(output)
    print("SHA256", sha(output))


if __name__ == "__main__":
    main()
