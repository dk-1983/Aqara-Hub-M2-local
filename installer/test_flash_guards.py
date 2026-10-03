"""Linux-only fault injection for flash guards; all MTD paths are temporary files."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
import os

from test_installer import hook


@unittest.skipUnless(os.name == "posix", "shell fixture requires Linux/WSL")
class FlashGuards(unittest.TestCase):
    def test_bank_guards_readback_and_selection(self):
        with tempfile.TemporaryDirectory(prefix="4vrs-flash-test-") as tmp:
            root = Path(tmp)
            sha = lambda data: hashlib.sha256(data).hexdigest()
            active = b"original-rootfs-fixture"
            image = b"hsqs" + bytes(4092)
            (root / "mtdblock7").write_bytes(active)
            (root / "mtdblock5").write_bytes(b"fallback")
            (root / "rootfs-hook-update.bin").write_bytes(hook.package_image(image))
            (root / "hook.env").write_text(f"SOURCE_SHA={sha(active)}\nIMAGE_SHA={sha(image)}\nIMAGE_BLOCKS=1\nPACKAGE_SHA={sha(hook.package_image(image))}\n")
            (root / "cpu").write_text("RTL8197F\n")
            (root / "prop").write_text("ro.sys.fw_ver=4.1.6\nro.sys.build_num=0018\n")
            (root / "mtd").write_text('mtd5: 01000000 00020000 "rootfs_1"\nmtd7: 01000000 00020000 "rootfs_2"\n')
            (root / "cmdline").write_text(f"root={root}/mtdblock7 console=ttyS0,38400\n")
            (root / "rcS").write_text("fw_manager.sh -r\n")
            good = "kernel: 1 1\nkernel_0: 0 abcd 1234\nkernel_1: 0 abcd 1234\nrootfs: 1 1\nrootfs_0: 0 abcd 4098\nrootfs_1: 0 abcd 4098\nroot_sum_check: off\npriv_mode: on\n"
            for name, content in {
                "getprop": "#!/bin/sh\necho lumi.gateway.agl001\n",
                "boot_ctrl": f'#!/bin/sh\ncat "{root}/boot"\n',
                "fw_update": f'#!/bin/sh\ntouch "{root}/updater-called"\ndd if="$1" of="{root}/mtdblock5" bs=1 skip=16 count=4096 2>/dev/null\nsed -i "s/rootfs: 1 1/rootfs: 0 1/" "{root}/boot"\necho Success\n',
            }.items():
                (root / name).write_text(content)
                (root / name).chmod(0o700)
            text = Path(__file__).with_name("flash_hook.sh").read_text()
            substitutions = {
                hook.SOURCE_SHA: sha(active),
                "94c2946ad26c44a9d4581c4e461f4665c5ff0006e009b74d12889b712a593917": sha((root / "fw_update").read_bytes()),
                "\"$(awk '/^Uid:/ {print $2}' /proc/self/status)\"": '"0"' ,
                "/bin/getprop": str(root / "getprop"), "/bin/boot_ctrl": str(root / "boot_ctrl"),
                "/bin/fw_update": str(root / "fw_update"), "/proc/cpuinfo": str(root / "cpu"),
                "/etc/build.prop": str(root / "prop"), "/etc/init.d/rcS": str(root / "rcS"),
                "/proc/mtd": str(root / "mtd"), "/proc/cmdline": str(root / "cmdline"),
                "/dev/mtdblock": str(root / "mtdblock"), "/var/tmp/": str(root) + "/",
                "/var/run/4vrs-flash-lock": str(root / "flash-lock"),
            }
            for before, after in substitutions.items():
                text = text.replace(before, after)
            script = root / "flash.sh"
            script.write_text(text)
            def run(mode="check"):
                return subprocess.run(["sh", str(script), mode], capture_output=True, text=True, timeout=20)
            for broken in (
                good.replace("rootfs: 1 1", "rootfs: 0 1"),
                good.replace("rootfs_0: 0 abcd 4098", "rootfs_0: 3 abcd 4098"),
                good.replace("rootfs_1: 0 abcd 4098", "rootfs_1: 0 abcd 0"),
                good.replace("root_sum_check: off", "root_sum_check: on"),
            ):
                (root / "boot").write_text(broken)
                self.assertNotEqual(run("apply-with-backup-and-uart").returncode, 0)
                self.assertFalse((root / "updater-called").exists())
            (root / "boot").write_text(good)
            result = run()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((root / "updater-called").exists())
            result = run("apply-with-backup-and-uart")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((root / "mtdblock5").read_bytes(), image)
            self.assertEqual((root / "mtdblock7").read_bytes(), active)
            # A misleading success message cannot bypass readback failure.
            (root / "boot").write_text(good)
            (root / "mtdblock5").write_bytes(b"corrupted")
            updater = (root / "fw_update").read_text()
            (root / "fw_update").write_text(updater.replace('dd if="$1"', 'false # dd if="$1"'))
            script.write_text(text.replace(sha(updater.encode()), sha((root / "fw_update").read_bytes())))
            result = run("apply-with-backup-and-uart")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Readback mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
