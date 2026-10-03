"""Patch a verified private HM2-G01 rootfs backup; never access a live hub."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

SOURCE_SHA = "9e59e35714a076d062ebc53ddb3b3e78f892584efd6cac9c44e37851bb86c6ef"
PARTITION_BYTES = 16777216
MARKER = b"# START OF DATA - DO NOT MODIFY\n#\n"
HOOK = b'''\n# 4VRS: optional local panel; never block factory startup.
if [ -f /data/aqara-panel/autostart.sh ] && [ ! -e /data/aqara-panel/autostart.disabled ]; then
    /bin/sh /data/aqara-panel/autostart.sh </dev/null >/dev/null 2>&1 &
fi
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_pseudo(raw):
    header, data = raw.split(MARKER, 1)
    entries = {}
    for line in header.splitlines():
        if not line or line.startswith(b"#"):
            continue
        match = re.fullmatch(rb"(.*?) ([A-Z]) (.*)", line)
        if not match:
            raise ValueError("Unsupported pseudo-file entry")
        path, kind, fields = match.groups()
        if path in entries:
            raise ValueError("Duplicate pseudo-file path")
        if kind == b"R":
            parts = fields.split()
            if len(parts) != 6:
                raise ValueError("Unsupported regular-file metadata")
            size, offset = map(int, parts[-2:])
            if min(size, offset) < 0 or offset + size > len(data):
                raise ValueError("Invalid file data bounds")
            entries[path] = (kind, b" ".join(parts[:4]), data[offset:offset + size])
        else:
            entries[path] = (kind, fields)
    return header, data, entries


def patch_pseudo(raw):
    header, data, entries = parse_pseudo(raw)
    kind, metadata, original = entries[b"etc/init.d/rcS"]
    if b"/data/aqara-panel" in original or not original.rstrip().endswith(b"fw_manager.sh -r"):
        raise ValueError("Unexpected rcS; refusing to patch")
    replacement = original + HOOK
    line = b"etc/init.d/rcS R " + metadata + b" " + str(len(replacement)).encode() + b" " + str(len(data)).encode()
    lines = [line if entry.startswith(b"etc/init.d/rcS R ") else entry for entry in header.splitlines()]
    return b"\n".join(lines) + b"\n" + MARKER + data + replacement


def verify_only_hook(before, after):
    _, _, a = parse_pseudo(before)
    _, _, b = parse_pseudo(after)
    if a.keys() != b.keys():
        raise ValueError("Filesystem entries changed")
    changed = [path for path in a if a[path] != b[path]]
    target = b"etc/init.d/rcS"
    if changed != [target] or a[target][:2] != b[target][:2] or b[target][2] != a[target][2] + HOOK:
        raise ValueError("Unexpected filesystem change")
    return len(a)


def package_image(image):
    if len(image) % 2 or len(image) + 2 >= PARTITION_BYTES or image[:4] != b"hsqs":
        raise ValueError("Invalid SquashFS size or magic")
    checksum = (-sum(word[0] for word in struct.iter_unpack(">H", image))) & 0xffff
    payload = image + struct.pack(">H", checksum)
    return struct.pack(">4sIII", b"r6cr", 0, 0, len(payload)) + payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="full ECC-corrected 16 MiB rootfs partition backup, without OOB")
    parser.add_argument("output", type=Path, help="new private directory (contains vendor firmware)")
    parser.add_argument("--unsquashfs", default="unsquashfs")
    parser.add_argument("--mksquashfs", default="mksquashfs")
    args = parser.parse_args()
    original = args.source.read_bytes()
    if len(original) != PARTITION_BYTES or sha(original) != SOURCE_SHA:
        raise SystemExit("Unsupported rootfs hash. No compatibility overrides: inspect the new firmware first.")
    args.output.mkdir(parents=True, exist_ok=False)
    out = args.output.resolve()
    source = args.source.resolve()
    subprocess.run([args.unsquashfs, "-pf", str(out / "original.pseudo"), str(source)], check=True)
    before = (out / "original.pseudo").read_bytes()
    patched = patch_pseudo(before)
    (out / "patched.pseudo").write_bytes(patched)
    (out / "empty").mkdir()
    image = out / "rootfs-hook.squashfs"
    subprocess.run([args.mksquashfs, str(out / "empty"), str(image), "-pf", str(out / "patched.pseudo"), "-noappend", "-root-uid", "0", "-root-gid", "0", "-root-mode", "775", "-root-time", "1718850806", "-comp", "xz", "-b", "131072", "-always-use-fragments", "-exports", "-no-xattrs", "-mkfs-time", "2191381760", "-processors", "2", "-no-progress"], check=True)
    subprocess.run([args.unsquashfs, "-pf", str(out / "verified.pseudo"), str(image)], check=True)
    entries = verify_only_hook(before, (out / "verified.pseudo").read_bytes())
    payload = image.read_bytes()
    package = package_image(payload)
    (out / "rootfs-hook-update.bin").write_bytes(package)
    report = {"source_sha256": SOURCE_SHA, "squashfs_sha256": sha(payload), "squashfs_bytes": len(payload), "package_sha256": sha(package), "package_bytes": len(package), "entries_compared": entries, "changed_files": ["etc/init.d/rcS"], "flashed": False, "boot_tested": False}
    (out / "verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    # Numeric/hash values only; no device credentials or identifiers.
    (out / "hook.env").write_text(f"SOURCE_SHA={SOURCE_SHA}\nIMAGE_SHA={sha(payload)}\nIMAGE_BLOCKS={len(payload) // 4096}\nPACKAGE_SHA={sha(package)}\n", encoding="ascii")
    if len(payload) % 4096:
        raise ValueError("Unexpected image alignment")
    (out / "flash_hook.sh").write_bytes(Path(__file__).with_name("flash_hook.sh").read_bytes().replace(b"\r\n", b"\n"))
    print(json.dumps(report, indent=2))
    print("Private output only. Nothing has been flashed. Read installer/README.md before proceeding.")


if __name__ == "__main__":
    main()
