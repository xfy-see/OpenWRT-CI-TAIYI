"""Focused offline-bundle tests; no firmware compilation, network, or source execution.

The pipeline fixture mocks the trusted APK executable, not its trust guarantees.
A real completed build can additionally be tested by invoking package-offline.py
with all explicit CLI identity arguments and an output outside the build tree.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "Scripts/re-cs-07-nss/package-offline.py"
SPEC = importlib.util.spec_from_file_location("offline_packaging", SCRIPT)
offline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(offline)

ARCH = offline.ARCH
VERMAGIC = "1234567890abcdef1234567890abcdef"
KVER = "6.12.94"
KERNEL = f"{KVER}~{VERMAGIC}-r1"
RELEASE = {
    "DISTRIB_RELEASE": "25.12.5-nss-recs07.2",
    "DISTRIB_REVISION": "v25.12.5-nss.recs07.2-f0a60eee",
    "DISTRIB_TARGET": offline.TARGET,
    "DISTRIB_ARCH": ARCH,
}


def metadata():
    return [
        {"name": "kernel", "version": KERNEL, "arch": ARCH, "depends": ["libc"]},
        {"name": "libc", "version": "1.2.5-r1", "arch": ARCH},
        {"name": "dnsmasq-full", "version": "2.91-r1", "arch": ARCH,
         "depends": ["libc", "!dnsmasq"], "provides": ["dnsmasq-any"]},
        {"name": "kmod-tun", "version": f"{KVER}-r1", "arch": ARCH,
         "depends": [f"kernel={KERNEL}"]},
        {"name": "luci-app-example", "version": "1.0-r1", "arch": "noarch",
         "depends": ["dnsmasq-any"]},
    ]


def installed_records(packages=None):
    return {
        p["name"]: {"P": p["name"], "V": p["version"], "A": p["arch"],
                    "D": " ".join(p.get("depends", [])), "p": " ".join(p.get("provides", []))}
        for p in packages or metadata()
    }


class ParserAndAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def write(self, content):
        path = self.root / "input"
        path.write_text(content)
        return path

    def test_cli_requires_every_identity_component(self):
        args = ["--build-root", "/build", "--output", "/output", "--version-number",
                RELEASE["DISTRIB_RELEASE"], "--revision", RELEASE["DISTRIB_REVISION"],
                "--kernel-version", KVER, "--output-name", "RE-CS-07-offline"]
        self.assertEqual(offline.argument_parser().parse_args(args).output_name, "RE-CS-07-offline")
        for position in (4, 6, 8, 10):
            with self.subTest(flag=args[position]), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    offline.argument_parser().parse_args(args[:position] + args[position + 2:])

    def test_safe_output_slug_rejects_paths_options_and_shell_text(self):
        self.assertEqual(offline.safe_slug("RE-CS-07_25.12.5-NSS"), "RE-CS-07_25.12.5-NSS")
        for value in ("", ".", "..", "../outside", "/tmp/name", "-option", "bad/name",
                      "bad\\name", "bad name", "x;echo", "x\nnext", "a..b", "x" * 129):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                offline.safe_slug(value)

    def test_identity_tokens_reject_command_and_line_injection(self):
        for value in ("", "hello world", "foo\nbar", "$(touch /tmp/x)", "../other", "a=b"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                offline.identity_value(value)

    def test_release_parser_never_evaluates_shell_and_rejects_duplicates(self):
        parsed = offline.parse_release(self.write("DISTRIB_RELEASE='$(touch x)'\n"))
        self.assertEqual(parsed["DISTRIB_RELEASE"], "$(touch x)")
        self.assertFalse((self.root / "x").exists())
        with self.assertRaisesRegex(RuntimeError, "Duplicate release"):
            offline.parse_release(self.write("DISTRIB_RELEASE=a\nDISTRIB_RELEASE=b\n"))

    def test_installed_parser_rejects_missing_fields_duplicates_and_invalid_names(self):
        good = f"P:libc\nV:1.2.5-r1\nA:{ARCH}\nD:libgcc1\n\n"
        self.assertEqual(offline.parse_installed(self.write(good))["libc"]["D"], "libgcc1")
        for content in ("", good + good, good.replace("V:1.2.5-r1\n", ""),
                        good.replace("P:libc", "P:../libc"), good.replace("P:libc\n", ""),
                        good.replace("V:1.2.5-r1", "V:1.2.5-r1\nV:1.2.6-r1")):
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                offline.parse_installed(self.write(content))

    def test_manifest_parser_rejects_duplicate_or_malformed_entries(self):
        self.assertEqual(offline.parse_manifest(self.write("libc - 1.2.5-r1\n")), {"libc": "1.2.5-r1"})
        for value in ("libc - v1\nlibc - v2\n", "libc:v1\n", "../libc - v1\n"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                offline.parse_manifest(self.write(value))

    def test_selection_contains_all_userspace_and_kmods_but_no_kernel(self):
        installed = installed_records()
        manifest = {p: v["V"] for p, v in installed.items()}
        self.assertEqual(offline.requested_packages(installed, manifest),
                         ["dnsmasq-full", "kmod-tun", "libc", "luci-app-example"])
        manifest.pop("luci-app-example")
        with self.assertRaisesRegex(RuntimeError, "sets/versions differ"):
            offline.requested_packages(installed, manifest)

    def test_selection_rejects_wrong_installed_architecture(self):
        installed = installed_records()
        installed["libc"]["A"] = "x86_64"
        with self.assertRaisesRegex(RuntimeError, "architecture"):
            offline.requested_packages(installed, {p: v["V"] for p, v in installed.items()})

    def test_explicit_identity_and_actual_abi_must_all_agree(self):
        kwargs = dict(version_number=RELEASE["DISTRIB_RELEASE"], revision=RELEASE["DISTRIB_REVISION"],
                      kernel_version=KVER)
        offline.validate_identity(RELEASE, KERNEL, VERMAGIC, **kwargs)
        cases = [(dict(RELEASE, DISTRIB_RELEASE="other"), KERNEL, VERMAGIC),
                 (dict(RELEASE, DISTRIB_REVISION="other"), KERNEL, VERMAGIC),
                 (dict(RELEASE, DISTRIB_TARGET="other"), KERNEL, VERMAGIC),
                 (RELEASE, KERNEL.replace(KVER, "6.12.95"), VERMAGIC),
                 (RELEASE, KVER, VERMAGIC), (RELEASE, KERNEL, "0" * 32)]
        for release, kernel, vermagic in cases:
            with self.subTest(release=release, kernel=kernel, vermagic=vermagic):
                with self.assertRaises(RuntimeError):
                    offline.validate_identity(release, kernel, vermagic, **kwargs)

    def test_solver_must_exactly_match_installed_package_set_and_metadata(self):
        original = metadata()
        offline.validate_selected(original, installed_records())
        candidates = [original[:-1], original + [original[-1]]]
        for field, value in (("version", "9-r1"), ("arch", "x86_64"),
                             ("depends", ["missing"]), ("provides", ["unexpected"])):
            changed = copy.deepcopy(original)
            changed[1][field] = value
            candidates.append(changed)
        for changed in candidates:
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                offline.validate_selected(changed, installed_records())

    def test_closure_audits_virtual_dependencies_and_external_exact_kernel(self):
        selected = {p["name"]: p for p in metadata()}
        edges = offline.validate_edges(Path("apk"), selected, KERNEL)
        kernel_edges = [edge for edge in edges if edge["requires"].startswith("kernel=")]
        self.assertEqual(kernel_edges[0]["status"], "exact_running_firmware_prerequisite")
        self.assertTrue(any(e["requires"] == "dnsmasq-any" and e["satisfied_by"] == ["dnsmasq-full"] for e in edges))
        self.assertTrue(any(e["status"] == "conflict_absent" for e in edges))

    def test_closure_rejects_missing_positive_dependency_conflict_and_wrong_abi(self):
        original = {p["name"]: p for p in metadata()}
        missing = copy.deepcopy(original)
        missing.pop("libc")
        wrong_abi = copy.deepcopy(original)
        wrong_abi["kmod-tun"]["depends"] = ["kernel=wrong"]
        unpinned = copy.deepcopy(original)
        unpinned["kmod-tun"]["depends"] = ["kernel"]
        absent = copy.deepcopy(original)
        absent["kmod-tun"]["depends"] = []
        conflict = copy.deepcopy(original)
        conflict["dnsmasq"] = {"version": "2-r1"}
        for selected in (missing, wrong_abi, unpinned, absent, conflict):
            with self.subTest(selected=selected), self.assertRaises(RuntimeError):
                offline.validate_edges(Path("apk"), selected, KERNEL)

    def test_version_audit_fails_closed_on_unsupported_or_invalid_results(self):
        self.assertTrue(offline.version_matches(Path("apk"), "1-r1", "=", "1-r1"))
        self.assertFalse(offline.version_matches(Path("apk"), "1-r1", "=", "2-r1"))
        self.assertFalse(offline.version_matches(Path("apk"), "", "<", "2-r1"))
        with self.assertRaisesRegex(RuntimeError, "Unsupported version operator"):
            offline.version_matches(Path("apk"), "1-r1", "~", "1")
        with patch.object(offline, "run", return_value=""):
            with self.assertRaisesRegex(RuntimeError, "Invalid APK version"):
                offline.version_matches(Path("apk"), "1-r1", ">=", "1")
        with patch.object(offline, "run", return_value=">\n"):
            self.assertTrue(offline.version_matches(Path("apk"), "2-r1", ">=", "1"))
        for malformed in ("foo=", "foo==1", "foo bar", "foo><1"):
            with self.subTest(malformed=malformed), self.assertRaises(RuntimeError):
                offline.dependency_parts(malformed)

    def test_simulations_must_restore_exactly_every_selected_name_and_version(self):
        selected = {"libc": {"version": "1-r1"}}
        fix = "(1/1) Reinstalling libc (1-r1)\n"
        recovery = "(1/1) Installing libc (1-r1)\n"
        offline.validate_simulations("OK\n", fix, recovery, selected)
        for add, reinstall, missing in ((recovery, fix, recovery), ("", "", recovery),
                                         ("", fix, ""), ("", fix, recovery.replace("1-r1", "2-r1")),
                                         ("", fix + fix, recovery), ("", fix, recovery + "Installing extra (1-r1)\n"),
                                         ("", fix.replace("Reinstalling", "Upgrading"), recovery)):
            with self.subTest(plans=(add, reinstall, missing)), self.assertRaises(RuntimeError):
                offline.validate_simulations(add, reinstall, missing, selected)

    def test_trust_copy_refuses_private_keys_and_symlinks(self):
        source = self.root / "keys"
        source.mkdir()
        (source / "public.pem").write_text("-----BEGIN PRIVATE KEY-----\nsecret\n")
        with self.assertRaisesRegex(RuntimeError, "non-public-key"):
            offline.copy_public_keys(source, self.root / "dest1")
        (source / "public.pem").unlink()
        (source / "public.pem").symlink_to(self.write("-----BEGIN PUBLIC KEY-----\n"))
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            offline.copy_public_keys(source, self.root / "dest2")

    def test_package_sources_reject_escapes_symlinks_wrong_names_and_kernel(self):
        repo = self.root / "bin/repo"
        repo.mkdir(parents=True)
        apk = repo / "libc-1-r1.apk"
        apk.write_bytes(b"fixture")
        index = repo / "packages.adb"
        index.write_bytes(b"fixture index")
        selected = {"libc": {"version": "1-r1", "download-url": str(apk)}}
        self.assertEqual(offline.package_sources(selected, self.root / "bin", [index])["libc"], apk)
        outside = self.root / "outside.apk"
        outside.write_bytes(b"fixture")
        alias = repo / "alias.apk"
        alias.symlink_to(outside)
        for url in (str(outside), str(alias), "https://example.invalid/pkg.apk", str(repo / "../repo/libc-1-r1.apk")):
            bad = {"libc": {"version": "1-r1", "download-url": url}}
            with self.subTest(url=url), self.assertRaises(RuntimeError):
                offline.package_sources(bad, self.root / "bin", [index])
        with self.assertRaisesRegex(RuntimeError, "forbidden"):
            offline.package_sources({"kernel": {"version": "1-r1", "download-url": str(apk)}}, self.root / "bin", [index])


class PipelineContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.build = self.root / "completed-build"
        self.output = self.root / "output"
        self.image = self.build / "build_dir/target-aarch64-test/root-qualcommax"
        for directory in ("etc/apk/keys", "lib/apk/db"):
            (self.image / directory).mkdir(parents=True)
        (self.image / "etc/apk/keys/public.pem").write_text("-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n")
        (self.image / "etc/openwrt_release").write_text("".join(f"{k}='{v}'\n" for k, v in RELEASE.items()))
        (self.image / "etc/apk/world").write_text("dnsmasq-full\nkmod-tun\nluci-app-example\n")
        records = installed_records()
        (self.image / "lib/apk/db/installed").write_text("\n\n".join("\n".join(f"{k}:{v}" for k, v in p.items() if v) for p in records.values()) + "\n\n")
        self.target = self.build / "bin/targets/qualcommax/ipq60xx"
        self.repo = self.target / "packages"
        self.repo.mkdir(parents=True)
        (self.repo / "packages.adb").write_bytes(b"ORIGINAL SIGNED INDEX FIXTURE; DO NOT REBUILD")
        (self.target / "fixture-jdcloud_re-cs-07.manifest").write_text("".join(f"{name} - {p['V']}\n" for name, p in records.items()))
        (self.target / "fixture-jdcloud_re-cs-07-squashfs-sysupgrade.bin").write_bytes(b"completed firmware fixture")
        vermagic = self.image.parent / f"linux-qualcommax_ipq60xx/linux-{KVER}/.vermagic"
        vermagic.parent.mkdir(parents=True)
        vermagic.write_text(VERMAGIC + "\n")
        self.packages = metadata()
        for p in self.packages:
            file = self.repo / f"{p['name']}-{p['version']}.apk"
            file.write_bytes(json.dumps(p, sort_keys=True).encode())
            p["download-url"] = str(file)
        self.calls = []
        self.fail_stage = None

    def args(self, output=None):
        return ["--build-root", str(self.build), "--output", str(output or self.output),
                "--version-number", RELEASE["DISTRIB_RELEASE"], "--revision", RELEASE["DISTRIB_REVISION"],
                "--kernel-version", KVER, "--output-name", "RE-CS-07-exact-offline"]

    def apk_stub(self, args, *, log=None):
        args = [str(arg) for arg in args]
        self.calls.append(args)
        if self.fail_stage and self.fail_stage in args:
            raise RuntimeError("fixture authentication rejected")
        result = ""
        if "query" in args:
            result = json.dumps(self.packages)
        elif "fetch" in args:
            dest = Path(args[args.index("--output") + 1])
            names = args[args.index("--output") + 2:]
            for p in self.packages:
                if p["name"] in names:
                    shutil.copyfile(p["download-url"], dest / Path(p["download-url"]).name)
        elif "adbdump" in args:
            result = json.dumps({"info": json.loads(Path(args[-1]).read_text())})
        elif "fix" in args:
            result = "\n".join(f"({i}/4) Reinstalling {p['name']} ({p['version']})" for i, p in enumerate(self.packages) if p["name"] != "kernel")
        elif "add" in args and "missing-packages-root-copy" in " ".join(args):
            result = "\n".join(f"({i}/4) Installing {p['name']} ({p['version']})" for i, p in enumerate(self.packages) if p["name"] != "kernel")
        if log is not None:
            log.append({"argv": args, "returncode": 0, "stdout": result, "stderr": ""})
        return result

    def generate(self, output=None):
        with patch.object(offline, "run", side_effect=self.apk_stub), contextlib.redirect_stdout(io.StringIO()):
            offline.main(self.args(output))

    def snapshot(self):
        return {str(p.relative_to(self.build)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.build.rglob("*") if p.is_file()}

    def test_complete_pipeline_preserves_indexes_source_and_reproducibility(self):
        before = self.snapshot()
        self.generate()
        self.assertEqual(self.snapshot(), before)
        bundle = self.output / "RE-CS-07-exact-offline"
        report = json.loads((bundle / "DEPENDENCIES.json").read_text())
        self.assertEqual(report["requested_packages"], ["dnsmasq-full", "kmod-tun", "libc", "luci-app-example"])
        self.assertFalse(report["kernel_apk_included"])
        self.assertEqual(len(report["packages"]), 4)
        self.assertEqual((bundle / report["signed_indexes"][0]["file"]).read_bytes(), (self.repo / "packages.adb").read_bytes())
        self.assertEqual((bundle / "package-offline.py").read_bytes(), SCRIPT.read_bytes())
        self.assertFalse(any(p.name.startswith("kernel-") for p in bundle.rglob("*.apk")))
        self.assertFalse(any(p.suffix in {".pem", ".key"} for p in bundle.rglob("*")))
        self.assertTrue((self.output / "SUMMARY.json").is_file())
        self.assertTrue((self.output / "verification-log.json").is_file())
        self.assertNotIn("kernel=", (bundle / "PACKAGE-CONSTRAINTS.txt").read_text())
        preflight = (bundle / "check-offline.sh").read_text()
        self.assertIn("'jdcloud,re-cs-07'", preflight)
        self.assertNotIn("zn,m2", preflight)
        self.assertIn(RELEASE["DISTRIB_REVISION"], preflight)
        for flag in ("--version-number", "--revision", "--kernel-version", "--output-name"):
            self.assertIn(flag, (bundle / "README-中文.md").read_text())
        for line in (bundle / "SHA256SUMS").read_text().splitlines():
            digest, filename = line.split("  ", 1)
            self.assertEqual(offline.sha256(bundle / filename), digest)
        with zipfile.ZipFile(self.output / "RE-CS-07-exact-offline.zip") as z:
            self.assertIsNone(z.testzip())
            self.assertTrue(all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in z.infolist()))
        second = self.root / "second-output"
        self.generate(second)
        self.assertEqual(offline.sha256(self.output / "RE-CS-07-exact-offline.zip"),
                         offline.sha256(second / "RE-CS-07-exact-offline.zip"))

    def test_pipeline_commands_use_trusted_offline_queries_fetches_and_simulations(self):
        self.generate()
        self.assertEqual(sum("fetch" in c for c in self.calls), 2)
        self.assertTrue(any("verify" in c for c in self.calls))
        for command in self.calls:
            self.assertNotIn("--allow-untrusted", command)
            self.assertNotIn("--force", command)
            if any(op in command for op in ("query", "fetch", "add", "fix")):
                self.assertIn("--no-network", command)
                self.assertIn("--cache=no", command)
            if any(op in command for op in ("add", "fix")):
                self.assertIn("--simulate", command)
                self.assertNotIn("--depends", command)
                self.assertNotIn(str(self.image), command)
            if "fetch" in command:
                self.assertNotIn("kernel", command)
        query = next(c for c in self.calls if "query" in c)
        self.assertIn("dnsmasq-full=2.91-r1", query)
        self.assertIn("luci-app-example=1.0-r1", query)

    def test_signature_and_content_authentication_fail_closed(self):
        for stage in ("verify", "fetch"):
            self.fail_stage = stage
            with self.subTest(stage=stage), self.assertRaisesRegex(RuntimeError, "authentication rejected"):
                self.generate(self.root / stage)
            self.assertFalse(list((self.root / stage).glob("*.zip")))

    def test_wrong_index_metadata_and_source_escape_fail_before_fetch(self):
        self.packages[1]["version"] = "2-r1"
        with self.assertRaisesRegex(RuntimeError, "Signed index disagrees"):
            self.generate(self.root / "bad-metadata")
        self.assertFalse(any("fetch" in c for c in self.calls))
        self.packages[1]["version"] = "1.2.5-r1"
        self.packages[1]["download-url"] = str(self.root / "outside.apk")
        with self.assertRaisesRegex(RuntimeError, "escaped"):
            self.generate(self.root / "outside-source")
        self.assertFalse(any("fetch" in c for c in self.calls))

    def test_refuses_existing_output_or_source_overlap(self):
        self.output.mkdir()
        sentinel = self.output / "existing.txt"
        sentinel.write_text("preserve")
        with self.assertRaisesRegex(RuntimeError, "absent or empty"):
            self.generate()
        self.assertEqual(sentinel.read_text(), "preserve")
        with self.assertRaisesRegex(RuntimeError, "must not overlap"):
            self.generate(self.build / "new-output")
        self.assertFalse((self.build / "new-output").exists())

    def test_kernel_changes_are_rejected(self):
        normal_stub = self.apk_stub

        def kernel_mutating_stub(args, *, log=None):
            result = normal_stub(args, log=log)
            if "fix" in args:
                result += f"\nReinstalling kernel ({KERNEL})\n"
            return result

        with patch.object(offline, "run", side_effect=kernel_mutating_stub):
            with self.assertRaisesRegex(RuntimeError, "changes kernel"):
                offline.main(self.args())
        self.assertFalse(list(self.output.glob("*.zip")))

    def test_tar_extension_is_supported_but_ambiguous_images_are_rejected(self):
        binary = self.target / "fixture-jdcloud_re-cs-07-squashfs-sysupgrade.bin"
        archive = binary.with_suffix(".tar")
        binary.rename(archive)
        self.generate()
        report = json.loads((self.output / "RE-CS-07-exact-offline/DEPENDENCIES.json").read_text())
        self.assertEqual(report["firmware_image"]["filename"], archive.name)
        binary.write_bytes(b"another image")
        with self.assertRaisesRegex(RuntimeError, "Expected one completed"):
            self.generate(self.root / "ambiguous")

    def test_m2_named_firmware_is_not_an_input(self):
        binary = self.target / "fixture-jdcloud_re-cs-07-squashfs-sysupgrade.bin"
        binary.rename(self.target / "fixture-zn_m2-squashfs-sysupgrade.bin")
        with self.assertRaisesRegex(RuntimeError, "Expected one completed"):
            self.generate()


if __name__ == "__main__":
    unittest.main()
