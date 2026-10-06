"""Fast local tests; never fetch or execute third-party build sources."""
import importlib.util
import json
from pathlib import Path
import re
import copy
import struct
import tempfile
import unittest
from unittest import mock
import zipfile

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "Scripts/zn-m2-nss" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load("builder", "build.py")
images = load("images", "verify-images.py")


class WiredMemoryTests(unittest.TestCase):
    def setUp(self):
        self.nodes = images.FDT(images.fixture_board()).nodes

    def verify(self, nodes):
        return images.verify_board_dtb(images.fixture_fdt(nodes))

    def test_zero_q6_layout(self):
        result = self.verify(self.nodes)["wired_memory"]
        self.assertEqual(result["raw_reclaim_bytes"], 85 * 1024 * 1024)
        self.assertTrue(result["wcss_node_removed"])
        self.assertTrue(result["wifi_node_removed"])
        self.assertEqual(result["q6_bytes"], 0)
        self.assertFalse(result["hardware_boot_validated"])

    def test_old_q6_reservation_is_rejected(self):
        self.nodes["/reserved-memory/memory@4ab00000"] = {
            "reg": struct.pack(">QQ", 0x4ab00000, 0x5500000), "no-map": b""}
        with self.assertRaises(images.VerificationError):
            self.verify(self.nodes)

    def test_wireless_nodes_must_be_removed_even_if_disabled(self):
        for compatible in ("qcom,ipq6018-wcss-pil", "qcom,ipq6018-wifi"):
            for status in (b"okay\0", b"disabled\0"):
                nodes = copy.deepcopy(self.nodes)
                nodes["/soc/wireless"] = {"compatible": compatible.encode()+b"\0", "status": status}
                with self.subTest(compatible=compatible, status=status), self.assertRaises(images.VerificationError):
                    self.verify(nodes)

    def test_each_protected_reservation_is_preserved(self):
        for path in images.FDT(images.fixture_board()).children("/reserved-memory"):
            for mutation in ("size", "mapped", "disabled", "missing"):
                nodes = copy.deepcopy(self.nodes)
                props = nodes[path]
                if mutation == "size":
                    props["reg"] = props["reg"][:-1] + b"\x01"
                elif mutation == "mapped":
                    del props["no-map"]
                elif mutation == "disabled":
                    props["status"] = b"disabled\0"
                else:
                    del nodes[path]
                with self.subTest(path=path, mutation=mutation), self.assertRaises(images.VerificationError):
                    self.verify(nodes)

    def test_extra_reservation_is_rejected(self):
        self.nodes["/reserved-memory/guard@4bb00000"] = {
            "reg": struct.pack(">QQ", 0x4bb00000, 0x300000), "no-map": b""}
        with self.assertRaises(images.VerificationError):
            self.verify(self.nodes)

    def test_dangling_memory_reference_is_rejected(self):
        self.nodes["/soc/other-consumer"] = {"memory-region": struct.pack(">I", 101)}
        with self.assertRaises(images.VerificationError):
            self.verify(self.nodes)

    def test_memreserve_map_cannot_hide_reclaimed_range(self):
        dt = images.FDT(images.fixture_board())
        dt.reservations = [(0x4ab00000, 0x5500000)]
        with self.assertRaises(images.VerificationError):
            images.verify_wired_reserved_memory(dt)


class ProfileTests(unittest.TestCase):
    def test_locks_and_profile(self):
        lock, config = build.validate_inputs()
        self.assertEqual(lock["base"]["commit"], "f0a60eee2fe051741c643ea6118718aae1ef17fb")
        self.assertEqual(config["CONFIG_PACKAGE_dnsmasq-full"], "y")
        self.assertEqual(config["CONFIG_PACKAGE_dnsmasq"], "n")
        self.assertNotIn("CONFIG_PACKAGE_kmod-mtd-rw", config)

    def test_zero_q6_patch_is_locked_after_board_port(self):
        lock, _ = build.validate_inputs()
        files = [patch["file"] for patch in lock["patches"]]
        zero = "Config/ZN-M2-NSS/patches/zn-m2-wired-memory-zero.patch"
        base = "Config/ZN-M2-NSS/patches/zn-m2-wired-nss-v25.12.5.patch"
        self.assertGreater(files.index(zero), files.index(base))
        self.assertEqual(lock["identity"]["version"], "25.12.5-nss-taiyi3-q6zero")
        lock["patches"] = [patch for patch in lock["patches"] if patch["file"] != zero]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sources.lock.json"
            path.write_text(json.dumps(lock))
            with mock.patch.object(build, "LOCK_PATH", path):
                with self.assertRaisesRegex(ValueError, "Missing zero-Q6"):
                    build.validate_inputs()

    def test_duplicate_hyphenated_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            build.read_config("CONFIG_PACKAGE_dnsmasq-full=y\n# CONFIG_PACKAGE_dnsmasq-full is not set\n")

    def test_nonliteral_configuration_rejected(self):
        for line in ("CONFIG_X=$(touch foo)", "source evil", "CONFIG_X=y; exit", "CONFIG_X=Y"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                build.read_config(line)

    def test_generated_config_has_no_duplicate_keys(self):
        lock, _ = build.validate_inputs()
        result = build.read_config(build.generate_config(lock, Path("/tmp/toolchain")))
        self.assertEqual(result["CONFIG_TOOLCHAIN_ROOT"], '"/tmp/toolchain"')
        self.assertEqual(result["CONFIG_VERSION_NUMBER"], json.dumps(lock["identity"]["version"]))
        self.assertEqual(result["CONFIG_PACKAGE_dnsmasq-full"], "y")
        self.assertFalse(any("/workspace/scratch/" in value for value in result.values()))

    def test_unsafe_toolchain_path_rejected(self):
        lock, _ = build.validate_inputs()
        for path in ("/tmp/a b", '/tmp/a"b', "/tmp/a\\b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                build.generate_config(lock, Path(path))

    def test_full_variant_and_profile_survive_defconfig(self):
        lock, _ = build.validate_inputs()
        text = build.generate_config(lock, Path("/tmp/toolchain"))
        text += "CONFIG_PACKAGE_kmod-qca-nss-drv=y\nCONFIG_PACKAGE_kmod-qca-nss-ecm=y\n"
        text += "".join(f"CONFIG_PACKAGE_dnsmasq_full_{name}=y\n" for name in ("dhcp", "dhcpv6", "dnssec", "nftset", "conntrack"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".config"
            path.write_text(text)
            build.verify_config(path.parent)
            path.write_text(text.replace("CONFIG_PACKAGE_dnsmasq-full=y", "# CONFIG_PACKAGE_dnsmasq-full is not set"))
            with self.assertRaisesRegex(ValueError, "changed/dropped"):
                build.verify_config(path.parent)
            path.write_text(text.replace("# CONFIG_PACKAGE_kmod-ath11k is not set", "CONFIG_PACKAGE_kmod-ath11k=y"))
            with self.assertRaises(ValueError):
                build.verify_config(path.parent)

    def test_service_defaults_fail_closed(self):
        configs = {"etc/config/ttyd": b"config ttyd\n option enable '0'\n",
                   "etc/config/upnpd": b"config upnpd config\n option enabled 0\n",
                   "etc/config/sing-box": b"config sing-box main\n option enabled '0'\n",
                   "etc/config/sqm": b"config queue\n option enabled '0'\n"}
        self.assertEqual(len(images.audit_service_defaults(configs.__getitem__)), 4)
        for name in configs:
            changed = dict(configs)
            changed[name] = changed[name].replace(b"0", b"1")
            with self.subTest(name=name), self.assertRaises(images.VerificationError):
                images.audit_service_defaults(changed.__getitem__)

    def test_service_configs_are_extracted_from_actual_squashfs(self):
        command = images.squashfs_extract_command("unsquashfs", Path("/tmp/root"), Path("/tmp/image"))
        extracted = command[command.index("/tmp/image") + 1:]
        for filename, _ in images.SERVICE_CONFIG_OPTIONS:
            self.assertIn(filename, extracted)
        for filename in images.NETWORK_FILES:
            self.assertIn(filename, extracted)
        self.assertIn("etc/apk/keys", extracted)

    def test_trust_keys_bind_staging_to_both_delivered_images(self):
        key = b"-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n"
        keys = images.public_key_fingerprints({"builder.pem": key})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "build_dir/target-test/root-qualcommax/etc/apk/keys"
            root.mkdir(parents=True)
            (root / "builder.pem").write_bytes(key)
            images.compare_apk_trust(Path(directory), {"apk_public_keys": keys}, {"apk_public_keys": keys})
            changed = images.public_key_fingerprints({"builder.pem": key.replace(b"fixture", b"rotated")})
            with self.assertRaisesRegex(images.VerificationError, "trust keys differ"):
                images.compare_apk_trust(Path(directory), {"apk_public_keys": changed}, {"apk_public_keys": keys})
            (root / "builder.pem").write_bytes(key.replace(b"fixture", b"rotated"))
            with self.assertRaises(images.VerificationError):
                images.compare_apk_trust(Path(directory), {"apk_public_keys": keys}, {"apk_public_keys": keys})

    def test_source_export_is_allowlisted(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sources.zip"
            build.source_zip(target)
            with zipfile.ZipFile(target) as archive:
                self.assertIsNone(archive.testzip())
                self.assertIn("Config/ZN-M2-NSS.config", archive.namelist())
                self.assertIn("Scripts/zn-m2-nss/build.py", archive.namelist())
                self.assertIn("Config/ZN-M2-NSS/patches/zn-m2-wired-memory-zero.patch", archive.namelist())
                self.assertFalse(any(".git/" in name or "__pycache__" in name for name in archive.namelist()))


class WorkflowTests(unittest.TestCase):
    def read(self, name):
        return yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)

    def test_new_workflow_is_manual_read_only_and_pinned(self):
        workflow = self.read("ZN-M2-NSS.yml")
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"^actions/[a-z-]+@[0-9a-f]{40}$")
                    if step["uses"].startswith("actions/checkout@"):
                        self.assertEqual(step["with"]["persist-credentials"], "false")
                    if step["uses"].startswith("actions/cache@"):
                        self.assertEqual(step["if"], "inputs.mode == 'build'")
        text = (ROOT / ".github/workflows/ZN-M2-NSS.yml").read_text()
        self.assertNotIn("secrets.", text)
        self.assertNotIn("gh release create", text)
        self.assertNotIn("staging_dir", text)

    def test_destructive_cleaner_is_retired(self):
        cleaner = self.read("Auto-Clean.yml")
        self.assertEqual(set(cleaner["on"]), {"workflow_dispatch"})
        self.assertEqual(set(cleaner["permissions"].values()), {"read"})
        text = (ROOT / ".github/workflows/Auto-Clean.yml").read_text()
        self.assertNotIn("delete-releases", text)
        self.assertNotIn("gh release delete", text)
        self.assertNotIn("gh run delete", text)
        legacy = self.read("QCA-ALL.yml")
        self.assertEqual(set(legacy["on"]), {"workflow_dispatch"})
        self.assertEqual(legacy["permissions"], {"contents": "read"})
        for job in legacy["jobs"].values():
            self.assertNotIn("uses", job)
            for step in job.get("steps", []):
                self.assertNotIn("uses", step)
                self.assertNotIn("secrets", step.get("run", ""))
        self.assertNotIn("WRT-CORE", (ROOT / ".github/workflows/QCA-ALL.yml").read_text())

    def test_legacy_full_variant_is_explicit(self):
        config = build.read_config((ROOT / "Config/GENERAL.txt").read_text())
        self.assertEqual(config["CONFIG_PACKAGE_dnsmasq"], "n")
        self.assertEqual(config["CONFIG_PACKAGE_dnsmasq-full"], "y")


if __name__ == "__main__":
    unittest.main()
