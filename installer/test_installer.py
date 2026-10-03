"""Offline checks. Run: python -m unittest discover -s installer -v"""
import importlib.util
from pathlib import Path
import struct
import re
import tempfile
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


hook = module("build_hook")
release = module("build_release")


def pseudo(content=b"#!/bin/sh\nfw_manager.sh -r\n", other=b"untouched"):
    header = b"/ D 1 775 0 0\netc/init.d/rcS R 1 755 0 0 " + str(len(content)).encode() + b" 0\n"
    header += b"bin/other R 2 700 0 0 " + str(len(other)).encode() + b" " + str(len(content)).encode() + b"\n"
    return header + hook.MARKER + content + other


class BuildTests(unittest.TestCase):
    def test_preserves_all_other_contents_and_metadata(self):
        before = pseudo()
        after = hook.patch_pseudo(before)
        self.assertEqual(hook.verify_only_hook(before, after), 3)
        with self.assertRaises(ValueError):
            hook.verify_only_hook(before, after.replace(b"untouched", b"corrupted"))
        with self.assertRaises(ValueError):
            hook.verify_only_hook(before, after.replace(b"R 2 700", b"R 2 755"))

    def test_double_patch_and_unexpected_startup_rejected(self):
        with self.assertRaises(ValueError):
            hook.patch_pseudo(hook.patch_pseudo(pseudo()))
        with self.assertRaises(ValueError):
            hook.patch_pseudo(pseudo(b"exit 0\n"))

    def test_corrupt_offsets_rejected(self):
        with self.assertRaises(ValueError):
            hook.parse_pseudo(re.sub(rb'(etc/init.d/rcS R 1 755 0 0 )\d+', rb'\g<1>999999', pseudo()))

    def test_update_header_and_checksum(self):
        image = b"hsqs" + bytes(range(256)) * 16 + b"\x00\x00"
        packed = hook.package_image(image)
        self.assertEqual(struct.unpack(">4sIII", packed[:16]), (b"r6cr", 0, 0, len(image) + 2))
        self.assertEqual(sum(x[0] for x in struct.iter_unpack(">H", packed[16:])) & 0xffff, 0)
        self.assertEqual(packed[16:-2], image)
        for wrong in (b"bad!", b"hsqs1", b"hsqs" + bytes(hook.PARTITION_BYTES)):
            with self.assertRaises(ValueError):
                hook.package_image(wrong)

    def test_reject_wrong_architecture(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "panel"
            for header in (b"", b"not an ELF executable", b"\x7fELF\x02\x01" + bytes(14)):
                path.write_bytes(header)
                with self.assertRaises(ValueError):
                    release.verify_elf(path)
            header = bytearray(20)
            header[:6] = b"\x7fELF\x01\x01"
            struct.pack_into("<H", header, 18, 8)
            path.write_bytes(header)
            release.verify_elf(path)


if __name__ == "__main__":
    unittest.main()
