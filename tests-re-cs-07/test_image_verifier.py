"""Synthetic image regressions; no network, firmware execution, or router access."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("recs07_images", ROOT / "Scripts/re-cs-07-nss/verify-images.py")
images = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(images)
W = lambda number: struct.pack(">I", number)
S = lambda value: value.encode() + b"\0"


def metadata():
    return {"supported_devices": ["jdcloud,re-cs-07"], "version": {
        "dist": "OpenWrt", "target": "qualcommax/ipq60xx", "board": "jdcloud_re-cs-07",
        "version": images.EXPECTED_VERSION, "revision": images.EXPECTED_REVISION}}


def fwtool(payload, info=None):
    encoded = json.dumps(metadata() if info is None else info).encode()
    body = payload + b"\0" * 8 + encoded
    return body + struct.pack(">IIB3xI", 0x46577830, images.crc_raw(body), 1, len(encoded) + 24)


def sysupgrade(kernel=b"fit fixture", root=b"root fixture", control=b"BOARD=jdcloud_re-cs-07", extra=()):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        for name, content in (("sysupgrade-jdcloud_re-cs-07/CONTROL", control),
                              ("sysupgrade-jdcloud_re-cs-07/kernel", kernel),
                              ("sysupgrade-jdcloud_re-cs-07/root", root), *extra):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return fwtool(stream.getvalue())


def fit_nodes():
    raw = bytearray(4096)
    raw[56:60] = b"ARM\x64"
    banner = ("Linux version " + images.EXPECTED_KERNEL + " test\0").encode()
    raw[100:100 + len(banner)] = banner
    zipped = gzip.compress(bytes(raw), mtime=0)
    board = images.fixture_board()
    return {"/": {"timestamp": W(images.EXPECTED_EPOCH)}, "/images": {},
        "/images/kernel@1": {"data": zipped, "type": S("kernel"), "arch": S("arm64"),
                             "os": S("linux"), "compression": S("gzip"), "load": W(0x41000000), "entry": W(0x41000000)},
        "/images/kernel@1/hash@1": {"algo": S("sha256"), "value": hashlib.sha256(zipped).digest()},
        "/images/fdt@1": {"data": board, "type": S("flat_dt"), "compression": S("none")},
        "/images/fdt@1/hash@1": {"algo": S("sha256"), "value": hashlib.sha256(board).digest()},
        "/configurations": {"default": S("config@cp03-c4")},
        "/configurations/config@cp03-c4": {"kernel": S("kernel@1"), "fdt": S("fdt@1")}}


class BoardTests(unittest.TestCase):
    def setUp(self):
        self.nodes = images.FDT(images.fixture_board()).nodes

    def verify(self, nodes=None):
        return images.verify_board_dtb(images.fixture_fdt(self.nodes if nodes is None else nodes))

    def test_emmc_board_has_original_q6_and_two_gib_ram(self):
        result = self.verify()
        self.assertEqual(result["physical_ram_bytes_in_dtb"], 2 * 1024 ** 3)
        self.assertEqual(result["wired_memory"]["q6_bytes"], 85 * 1024 ** 2)
        self.assertEqual(result["wired_memory"]["reclaimed_bytes"], 0)
        self.assertEqual(result["ports"]["ethernet0"]["label"], "wan")
        self.assertEqual(result["ports"]["ethernet3"]["phy_address"], 27)
        self.assertTrue(result["emmc"]["non_removable"])
        self.assertNotIn("nand", result)

    def test_zero_q6_and_every_changed_reservation_are_rejected(self):
        for path in images.FDT(images.fixture_board()).children("/reserved-memory"):
            for mutation in ("missing", "size", "mapped", "disabled"):
                nodes = copy.deepcopy(self.nodes)
                if mutation == "missing":
                    del nodes[path]
                elif mutation == "size":
                    nodes[path]["reg"] = nodes[path]["reg"][:-1] + b"\x01"
                elif mutation == "mapped":
                    del nodes[path]["no-map"]
                else:
                    nodes[path]["status"] = S("disabled")
                with self.subTest(path=path, mutation=mutation), self.assertRaises(images.VerificationError):
                    self.verify(nodes)

    def test_enabled_wifi_or_wcss_are_rejected(self):
        for path in ("/soc@0/wifi@c000000", "/soc@0/remoteproc@cd00000"):
            nodes = copy.deepcopy(self.nodes)
            nodes[path]["status"] = S("okay")
            with self.subTest(path=path), self.assertRaises(images.VerificationError):
                self.verify(nodes)

    def test_extra_enabled_ath_consumer_is_rejected(self):
        self.nodes["/soc@0/wireless"] = {"compatible": S("qcom,ath11k"), "status": S("okay")}
        with self.assertRaises(images.VerificationError):
            self.verify()

    def test_wrong_ram_nand_mmc_or_unused_port_is_rejected(self):
        edits = [("/memory@40000000", "reg", struct.pack(">QQ", 0x40000000, 0x40000000)),
                 ("/soc@0/mmc@7804000", "bus-width", W(4)),
                 ("/soc@0/mmc@7804000", "status", S("disabled")),
                 ("/soc@0/dp5", "status", S("okay")),
                 ("/soc@0/ess-switch@3a000000", "switch_lan_bmp", W(0x16)),
                 ("/soc@0/dp1", "label", S("lan3")),
                 ("/soc@0/phy@24", "reg", W(0))]
        for path, prop, value in edits:
            nodes = copy.deepcopy(self.nodes)
            nodes[path][prop] = value
            with self.subTest(path=path, prop=prop), self.assertRaises(images.VerificationError):
                self.verify(nodes)
        self.nodes["/soc@0/nand"] = {"compatible": S("qcom,ipq6018-nand"), "status": S("okay")}
        with self.assertRaises(images.VerificationError):
            self.verify()

    def test_foreign_board_and_dangling_phandles_are_rejected(self):
        for path, prop, value in (("/", "compatible", b"zn,m2\0qcom,ipq6018\0"),
                                  ("/aliases", "label-mac-device", S("/soc@0/dp1")),
                                  ("/soc@0/dp1", "phy-handle", W(999)),
                                  ("/soc@0/remoteproc@cd00000", "memory-region", W(100))):
            nodes = copy.deepcopy(self.nodes)
            nodes[path][prop] = value
            with self.subTest(path=path, prop=prop), self.assertRaises(images.VerificationError):
                self.verify(nodes)


class TarAndFitTests(unittest.TestCase):
    def test_tar_metadata_and_actual_partition_sizes(self):
        kernel, root, report = images.parse_sysupgrade(sysupgrade())
        self.assertEqual((kernel, root), (b"fit fixture", b"root fixture"))
        self.assertEqual(report["emmc_partition_budgets"]["rootfs_footprint_bytes"], 65536 + 4096)
        self.assertEqual(images.verify_emmc_budgets(images.HLOS_SIZE, images.ROOTFS_SIZE - 65536)
                         ["kernel_bytes"], images.HLOS_SIZE)

    def test_budgets_include_alignment_and_overlay_marker(self):
        for kernel, root in ((0, 1), (1, 0), (images.HLOS_SIZE + 1, 1),
                             (1, images.ROOTFS_SIZE), (1, images.ROOTFS_SIZE - 4096),
                             (1, images.ROOTFS_SIZE - 65536 + 1)):
            with self.subTest(kernel=kernel, root=root), self.assertRaises(images.VerificationError):
                images.verify_emmc_budgets(kernel, root)

    def test_oversized_actual_tar_kernel_is_rejected(self):
        with self.assertRaisesRegex(images.VerificationError, "6 MiB"):
            images.parse_sysupgrade(sysupgrade(kernel=b"k" * (images.HLOS_SIZE + 1)))

    def test_tar_foreign_board_paths_duplicates_and_control_are_rejected(self):
        fixtures = [sysupgrade(control=b"BOARD=zn_m2"),
                    sysupgrade(extra=(("../secret", b"x"),)),
                    sysupgrade(extra=(("sysupgrade-zn_m2/root", b"x"),)),
                    sysupgrade(extra=(("sysupgrade-jdcloud_re-cs-07/root", b"duplicate"),))]
        for fixture in fixtures:
            with self.subTest(length=len(fixture)), self.assertRaises(images.VerificationError):
                images.parse_sysupgrade(fixture)

    def test_metadata_crc_valid_wrong_board_or_release_is_rejected(self):
        for key, value in (("board", "zn_m2"), ("revision", "v25.12.5-nss.recs07.1-f0a60eee"),
                           ("version", "25.12.5-nss-recs07.1"), ("target", "qualcommax/ipq807x")):
            info = metadata()
            info["version"][key] = value
            with self.subTest(key=key), self.assertRaises(images.VerificationError):
                images.verify_fwtool(fwtool(b"test", info))

    def test_fit_hashes_config_load_and_entry(self):
        images.verify_fit(images.fixture_fdt(fit_nodes()), images.EXPECTED_KERNEL)
        for path, prop, value in (("/configurations", "default", S("config@cp03-c1")),
                                  ("/images/kernel@1", "load", W(0x42000000)),
                                  ("/images/kernel@1", "entry", W(0x42000000)),
                                  ("/images/fdt@1/hash@1", "value", b"\0" * 32),
                                  ("/images/kernel@1/hash@1", "value", b"\0" * 32)):
            nodes = fit_nodes()
            nodes[path][prop] = value
            with self.subTest(path=path, prop=prop), self.assertRaises(images.VerificationError):
                images.verify_fit(images.fixture_fdt(nodes), images.EXPECTED_KERNEL)

    def test_new_profile_self_test_preserves_network_and_package_audits(self):
        result = images.self_test()
        self.assertEqual(result["result"], "pass")
        self.assertGreaterEqual(result["network_regressions"]["negative_fixtures_rejected"], 24)


class StorageAndTrustTests(unittest.TestCase):
    def setUp(self):
        self.fstab = (ROOT / "Config/RE-CS-07-NSS/files/etc/config/fstab").read_bytes()

    def test_inert_fstab_supports_manual_mounts_only(self):
        result = images.audit_inert_fstab(self.fstab)
        self.assertEqual(result["mount_entries"], 0)
        self.assertEqual(result["swap_entries"], 0)
        self.assertEqual(result["global_options"]["delay_root"], "5")

    def test_automatic_mount_swap_or_old_overlay_entries_are_rejected(self):
        invalid = [self.fstab + b"config mount\n option target '/overlay'\n option uuid 'synthetic-fixture'\n",
                   self.fstab + b"config swap\n option device '/dev/fixture'\n",
                   self.fstab + b" option device '/dev/fixture'\n",
                   self.fstab + b"config global\n",
                   self.fstab + b" option auto_mount '0'\n",
                   self.fstab + b"echo dangerous\n"]
        for option in (b"anon_swap", b"anon_mount", b"auto_swap", b"auto_mount", b"check_fs"):
            invalid.append(self.fstab.replace(option + b" '0'", option + b" '1'"))
        for fixture in invalid:
            with self.subTest(fixture=fixture), self.assertRaises(images.VerificationError):
                images.audit_inert_fstab(fixture)

    def test_extraction_includes_storage_platform_and_service_configs(self):
        command = images.squashfs_extract_command(Path("tool"), Path("output"), Path("image"))
        for path in images.STORAGE_FILES:
            self.assertIn(path, command)
        for path, _ in images.SERVICE_CONFIG_OPTIONS:
            self.assertIn(path, command)

    def test_m2_runtime_files_are_rejected(self):
        images.reject_foreign_payloads(["etc/init.d/re-cs-07-nss"])
        for path in ("etc/init.d/zn-m2-nss", "etc/uci-defaults/99-zz-m2-nss-wired"):
            with self.subTest(path=path), self.assertRaises(images.VerificationError):
                images.reject_foreign_payloads([path])

    def test_services_remain_disabled(self):
        files = {path: ("config service\n option %s '0'\n" % option).encode()
                 for path, option in images.SERVICE_CONFIG_OPTIONS}
        self.assertEqual(len(images.audit_service_defaults(files.__getitem__)), 4)
        for filename, option in images.SERVICE_CONFIG_OPTIONS:
            changed = dict(files)
            changed[filename] = ("config service\n option %s '1'\n" % option).encode()
            with self.subTest(filename=filename), self.assertRaises(images.VerificationError):
                images.audit_service_defaults(changed.__getitem__)

    def test_public_keys_cannot_contain_private_material(self):
        good = b"-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n"
        images.public_key_fingerprints({"fixture.pem": good})
        for files in ({}, {"../escape.pem": good}, {"key": b"-----BEGIN PRIVATE KEY-----\n"},
                      {"key": good + b"PRIVATE KEY"}):
            with self.subTest(files=files), self.assertRaises(images.VerificationError):
                images.public_key_fingerprints(files)

    def test_emmc_guard_and_config_copy_match_reviewed_source(self):
        expected = images.locked_platform_functions()
        names = ("re_cs_07_select_slot", "re_cs_07_partition_bytes", "re_cs_07_tar_member_size",
                 "re_cs_07_check_image", "re_cs_07_do_upgrade", "platform_check_image", "platform_copy_config")
        platform = "REQUIRE_IMAGE_METADATA=1\nRAMFS_COPY_BIN='hexdump tar mktemp wc cat rm grep'\n"
        platform += "\n\n".join(images.shell_function(expected, name) for name in names)
        platform += '\nplatform_do_upgrade() {\n\tcase "$(board_name)" in\n\tjdcloud,re-cs-07)\n\t\tre_cs_07_do_upgrade "$1"\n\t\t;;\n\tesac\n}\n'
        emmc = b"synthetic official-helper fixture"
        with patch.object(images, "EXPECTED_EMMC_HELPER_SHA256", images.sha256(emmc)):
            images.audit_emmc_upgrade(platform.encode(), emmc)
            for old, new in (("6291456", "9999999"), ("62914560", "99999999"),
                             ("sectors * 512", "sectors * 4096"), ("tail_bytes=4096", "tail_bytes=0"),
                             ("unset CI_DATAPART", "# unset CI_DATAPART"),
                             ("emmc_copy_config ;;", ": ;;"),
                             ("REQUIRE_IMAGE_METADATA=1", "REQUIRE_IMAGE_METADATA=0"),
                             ("RAMFS_COPY_BIN='hexdump", "RAMFS_COPY_BIN='")):
                self.assertIn(old, platform)
                with self.subTest(old=old), self.assertRaises(images.VerificationError):
                    images.audit_emmc_upgrade(platform.replace(old, new).encode(), emmc)
            with self.assertRaisesRegex(images.VerificationError, "official base"):
                images.audit_emmc_upgrade(platform.encode(), b"changed generic write helper")

    def test_duplicate_guard_function_is_rejected(self):
        body = "guard() {\n return 0\n}\n"
        self.assertIn("return 0", images.shell_function(body, "guard"))
        with self.assertRaisesRegex(images.VerificationError, "duplicate"):
            images.shell_function(body + body, "guard")


class BuildConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = (ROOT / "Config/RE-CS-07-NSS.config").read_text()
        self.config += '\nCONFIG_KERNEL_DEBUG_FS=y\nCONFIG_NSS_DRV_PPPOE_ENABLE=y\n'
        self.config += "".join("CONFIG_PACKAGE_%s=y\n" % name for name in
                               ("kmod-qca-nss-drv", "kmod-qca-nss-ecm", "kmod-qca-nss-drv-bridge-mgr",
                                "kmod-qca-nss-drv-vlan-mgr", "nss-firmware-ipq60xx"))
        self.config += 'CONFIG_VERSION_NUMBER="%s"\nCONFIG_VERSION_CODE="%s"\n' % (images.EXPECTED_VERSION, images.EXPECTED_REVISION)
        (self.root / ".config").write_text(self.config)
        kernel = self.root / ("build_dir/target-aarch64-test/linux-qualcommax_ipq60xx/linux-%s/.config" % images.EXPECTED_KERNEL)
        kernel.parent.mkdir(parents=True)
        self.kernel = kernel
        self.kernel_text = "".join("CONFIG_%s=y\n" % name for name in
                                   ("PREEMPT_NONE", "PREEMPT_NONE_BUILD", "DEBUG_FS", "NF_CONNTRACK_EVENTS", "IPV6"))
        self.kernel_text += "".join("CONFIG_%s=m\n" % name for name in
                                    ("WIREGUARD", "TUN", "INET_DIAG", "INET_TCP_DIAG", "INET_UDP_DIAG", "INET_RAW_DIAG",
                                     "CRYPTO_LIB_CHACHA", "CRYPTO_LIB_CHACHA20POLY1305", "CRYPTO_LIB_CURVE25519",
                                     "CRYPTO_LIB_POLY1305", "NET_UDP_TUNNEL"))
        kernel.write_text(self.kernel_text)

    def test_current_memory_profile_and_manual_storage_support_pass(self):
        report = images.audit_configs(self.root, images.EXPECTED_KERNEL)
        self.assertIn("1024/MEDIUM", report["memory_profile"])

    def test_old_memory_profiles_recycler_and_missing_block_mount_fail(self):
        for key, value in (("NSS_MEM_PROFILE_MEDIUM", "n"), ("NSS_MEM_PROFILE_HIGH", "y"),
                           ("NSS_MEM_PROFILE_LOW", "y"), ("IPQ_MEM_PROFILE_1024", "n"),
                           ("KERNEL_IPQ_MEM_PROFILE", "256"), ("KERNEL_SKB_RECYCLER", "y"),
                           ("PACKAGE_block-mount", "n"), ("AUTOREMOVE", "n")):
            (self.root / ".config").write_text(self.config + "CONFIG_%s=%s\n" % (key, value))
            with self.subTest(key=key), self.assertRaises(images.VerificationError):
                images.audit_configs(self.root, images.EXPECTED_KERNEL)

    def test_compiled_wifi_or_missing_network_module_fails(self):
        for text in (self.kernel_text + "CONFIG_ATH11K=m\n", self.kernel_text.replace("CONFIG_TUN=m", "CONFIG_TUN=y"),
                     self.kernel_text + "CONFIG_SKB_RECYCLER=y\n"):
            self.kernel.write_text(text)
            with self.subTest(text=text), self.assertRaises(images.VerificationError):
                images.audit_configs(self.root, images.EXPECTED_KERNEL)


if __name__ == "__main__":
    unittest.main()
