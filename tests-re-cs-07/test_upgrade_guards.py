"""Execute the added RE-CS-07 upgrade guards without accessing block devices.

Only block-device discovery/type checks and the final write helper are mocked.
The archive and backup size checks execute the actual shell code against files.
"""
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "Config/RE-CS-07-NSS/patches/re-cs-07-wired-nss-v25.12.5.patch"
PREFIX = "sysupgrade-jdcloud_re-cs-07"
MIB = 1024 * 1024


def platform_additions(context=False):
    text = PATCH.read_text()
    marker = "diff --git a/target/linux/qualcommax/ipq60xx/base-files/lib/upgrade/platform.sh "
    chunk = text.split(marker, 1)[1].split("\ndiff --git ", 1)[0]
    return "\n".join(line[1:] for line in chunk.splitlines()
                     if (line.startswith("+") or (context and line.startswith(" ")))
                     and not line.startswith("+++"))


def added_functions():
    additions = platform_additions(context=True)
    # All new top-level functions are added whole. Exclude platform_do_upgrade's
    # small case hunk, whose dispatcher is checked separately below.
    return "\n\n".join(re.findall(r"^(?:re_cs_07_\w+|platform_(?:check_image|copy_config))\(\) \{\n.*?^\}", additions, re.M | re.S))


class ZeroReader:
    def read(self, size=-1):
        return bytes(size)


class UpgradeGuardTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="recs07-guards-")
        self.addCleanup(self.work.cleanup)
        self.path = Path(self.work.name)
        for name in ("config", "kernel0", "kernel1", "root0", "root1"):
            (self.path / name).write_bytes(b"\0" * 149)
        self.script = self.path / "guards.sh"
        self.script.write_text(added_functions().replace("[ -b ", "[ -f ")
                               .replace("/sys/class/block/", str(self.path / "sysblock") + "/"))
        self.image = self.path / "image.tar"
        self.make_image()

    def make_image(self, kernel=1024, root=1024, missing=None, prefix=PREFIX, duplicate=None):
        with tarfile.open(self.image, "w") as archive:
            directory = tarfile.TarInfo(prefix + "/")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            for name, size in (("kernel", kernel), ("root", root)):
                if name == missing:
                    continue
                member = tarfile.TarInfo(prefix + "/" + name)
                member.size = size
                archive.addfile(member, ZeroReader())
                if name == duplicate:
                    archive.addfile(member, ZeroReader())

    def run_guard(self, command='re_cs_07_do_upgrade "$IMAGE"', *, slot="0", kernel_cap=6*MIB,
                  root_cap=60*MIB, backup=None, tar_failure=False):
        # A blank slot emulates a short BOOTCONFIG partition. Arbitrary bytes are
        # represented as decimal strings by hexdump, exactly as on the device.
        config = self.path / "config"
        config.write_bytes(bytes(148) + (bytes([int(slot)]) if slot else b""))
        for name, capacity in (("kernel0", kernel_cap), ("kernel1", kernel_cap),
                               ("root0", root_cap), ("root1", root_cap)):
            size = self.path / "sysblock" / name / "size"
            size.parent.mkdir(parents=True, exist_ok=True)
            size.write_text(str(capacity // 512) + "\n")
        prelude = r'''
. "$GUARDS"
board_name() { printf '%s\n' jdcloud,re-cs-07; }
find_mmc_part() {
    case "$1" in
    0:BOOTCONFIG) printf '%s/config\n' "$DEVICE_DIR" ;;
    0:HLOS) printf '%s/kernel0\n' "$DEVICE_DIR" ;;
    0:HLOS_1) printf '%s/kernel1\n' "$DEVICE_DIR" ;;
    rootfs) printf '%s/root0\n' "$DEVICE_DIR" ;;
    rootfs_1) printf '%s/root1\n' "$DEVICE_DIR" ;;
    *) return 1 ;;
    esac
}
hexdump() {
    test "$1:$2:$3:$4:$5:$6:$7" = '-v:-n:1:-s:148:-e:1/1 "%u"' || return 1
    "$PYTHON" -c 'import sys; f=open(sys.argv[1],"rb"); f.seek(148); b=f.read(1); print(b[0] if b else "",end="")' "$8"
}
emmc_do_upgrade() {
    # Make any accidental optional target visible to the test.
    printf '%s|%s|%s|%s|%s|%s\n' "$EMMC_KERN_DEV" "$EMMC_ROOT_DEV" "$CI_DATAPART" "$CI_DTBPART" "$EMMC_DATA_DEV" "$EMMC_DTB_DEV" >> "$WRITE_LOG"
}
emmc_copy_config() { printf 'copy-config\n' >> "$WRITE_LOG"; }
'''
        if tar_failure:
            prelude += '\ntar() { command tar "$@"; test "$1" != xf; }\n'
        env = dict(os.environ, GUARDS=str(self.script), DEVICE_DIR=str(self.path),
                   IMAGE=str(self.image), KERNEL_CAP=str(kernel_cap), ROOT_CAP=str(root_cap),
                   WRITE_LOG=str(self.path / "writes"), PYTHON=os.sys.executable,
                   UPGRADE_BACKUP=str(backup) if backup else "",
                   CI_DATAPART="do-not-write", CI_DTBPART="do-not-write",
                   EMMC_DATA_DEV="do-not-write", EMMC_DTB_DEV="do-not-write")
        result = subprocess.run(["sh", "-c", prelude + "\n" + command], env=env,
                                text=True, capture_output=True)
        log = self.path / "writes"
        return result, log.read_text() if log.exists() else ""

    def assert_rejected(self, **kwargs):
        result, writes = self.run_guard(**kwargs)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(writes, "")

    def test_both_slots_select_only_hlos_and_root(self):
        for slot in ("0", "1"):
            with self.subTest(slot=slot):
                result, writes = self.run_guard(slot=slot)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(writes, f"{self.path}/kernel{slot}|{self.path}/root{slot}||||\n")
                (self.path / "writes").unlink()

    def test_every_invalid_slot_byte_fails_closed(self):
        # Exhaustive selection tests do not need to read the archive.
        for slot in range(2, 256):
            with self.subTest(slot=slot):
                self.assert_rejected(slot=str(slot), command="re_cs_07_select_slot")
        self.assert_rejected(slot="")

    def test_missing_selected_block_devices(self):
        for name in ("config", "kernel0", "root0"):
            with self.subTest(name=name):
                path = self.path / name
                path.unlink()
                # run_guard recreates config bytes, so suppress discovery instead.
                if name == "config":
                    command = 'find_mmc_part() { return 1; }; re_cs_07_do_upgrade "$IMAGE"'
                else:
                    command = 're_cs_07_do_upgrade "$IMAGE"'
                self.assert_rejected(command=command)
                path.write_bytes(bytes(149))

    def test_hlos_oem_and_actual_size_limits(self):
        self.make_image(kernel=6*MIB)
        result, _ = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.path / "writes").unlink()
        self.assert_rejected(kernel_cap=6*MIB-1)
        self.make_image(kernel=6*MIB+1)
        self.assert_rejected(kernel_cap=7*MIB)

    def test_root_alignment_and_overlay_marker_fit(self):
        self.make_image(root=60*MIB-65536)
        result, _ = self.run_guard(root_cap=60*MIB-65536+4096)
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.path / "writes").unlink()
        self.assert_rejected(root_cap=60*MIB-65536+4095)
        self.make_image(root=60*MIB-65536+1)
        self.assert_rejected()
        self.make_image(root=60*MIB)
        self.assert_rejected(root_cap=61*MIB)

    def test_backup_space_is_reserved_after_64k_alignment(self):
        self.make_image(root=65537)
        backup = self.path / "backup.tgz"
        backup.write_bytes(bytes(8192))
        result, _ = self.run_guard(root_cap=131072+8192, backup=backup)
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.path / "writes").unlink()
        self.assert_rejected(root_cap=131072+8191, backup=backup)
        self.assert_rejected(backup=self.path / "missing-backup.tgz")

    def test_tar_failure_cannot_be_hidden_by_successful_byte_count(self):
        self.assert_rejected(tar_failure=True)

    def test_missing_empty_duplicate_and_wrong_board_members(self):
        for kwargs in ({"missing":"kernel"}, {"missing":"root"}, {"kernel":0},
                       {"root":0}, {"duplicate":"kernel"}, {"duplicate":"root"},
                       {"prefix":"sysupgrade-zn_m2"}):
            with self.subTest(kwargs=kwargs):
                self.make_image(**kwargs)
                self.assert_rejected()
        self.image.write_bytes(b"not a TAR")
        self.assert_rejected()

    def test_do_upgrade_rechecks_after_successful_image_check(self):
        result, writes = self.run_guard(command=r'''
platform_check_image "$IMAGE" || exit 99
hexdump() { printf 2; }
re_cs_07_do_upgrade "$IMAGE"
''')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(writes, "")

    def test_do_upgrade_rechecks_changed_backup(self):
        backup = self.path / "backup.tgz"
        backup.write_bytes(bytes(4096))
        result, writes = self.run_guard(backup=backup, root_cap=65536+4096, command=r'''
platform_check_image "$IMAGE" || exit 99
"$PYTHON" -c 'import sys; open(sys.argv[1],"ab").write(b"x")' "$UPGRADE_BACKUP"
re_cs_07_do_upgrade "$IMAGE"
''')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(writes, "")

    def test_platform_config_copy_delegates_to_emmc(self):
        result, writes = self.run_guard(command="platform_copy_config")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(writes, "copy-config\n")

    def test_dispatch_and_ramfs_tools(self):
        additions = platform_additions()
        self.assertIn('jdcloud,re-cs-07)\n\t\tre_cs_07_do_upgrade "$1"', additions)
        for binary in ("hexdump", "tar", "mktemp", "wc", "rm", "grep"):
            self.assertRegex(additions, r"RAMFS_COPY_BIN='[^'\n]*\b" + binary + r"\b")
        self.assertNotRegex(additions, r"CI_DATAPART\s*=")
        self.assertNotRegex(additions, r"mmcblk\d+p(?:22|25|27)\b")
        self.assertNotIn("fw_setenv", added_functions())
        self.assertNotIn("nand_do_upgrade", added_functions())


if __name__ == "__main__":
    unittest.main()
