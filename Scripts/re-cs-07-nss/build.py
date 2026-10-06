#!/usr/bin/env python3
"""Pinned, single-profile RE-CS-07 build entry point (Python standard library).

validate is local/static. prepare downloads sources/toolchain and executes the
locked OpenWrt feed/configuration tools. build compiles; package verifies the
result and only exports allowlisted files, never private signing keys.
"""
from __future__ import annotations

import argparse
import hashlib
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "Config/RE-CS-07-NSS/sources.lock.json"
PROFILE_PATH = ROOT / "Config/RE-CS-07-NSS.config"
TARGET = "qualcommax/ipq60xx"
ARCH = "aarch64_cortex-a53"
RADIO = re.compile(r"(?:wpad|hostapd|wpa-supplicant|ath\d+k-firmware|ipq-wifi|kmod-(?:ath\d|ath$|mac80211|cfg80211|mt76|mt79|rt2|rtw|rtl8|brcmfmac|brcmsmac))")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_config(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        match = re.fullmatch(r"# (CONFIG_[A-Za-z0-9_+.-]+) is not set", line)
        if match:
            key, value = match[1], "n"
        elif re.fullmatch(r"CONFIG_[A-Za-z0-9_+.-]+=(?:y|m|n|[0-9]+|\"[^\"\n]*\")", line):
            key, value = line.split("=", 1)
        elif not line or line.startswith("#"):
            continue
        else:
            raise ValueError("Invalid Kconfig line: " + line)
        require(key not in values, "Duplicate Kconfig option: " + key)
        values[key] = value
    return values


def validate_inputs():
    lock = json.loads(LOCK_PATH.read_text())
    require(lock.get("schema") == 1, "Unsupported source lock format")
    for source in [lock["base"], *lock["feeds"].values()]:
        require(re.fullmatch(r"[0-9a-f]{40}", source["commit"]), "Source must be pinned to a full commit")
        require(source["repository"].startswith("https://github.com/"), "Unexpected source host/protocol")
    require(lock["base"]["tag"] == "v25.12.5", "Review the board/NSS port before changing release")
    require(lock["kernel"]["version"] == "6.12.94", "Review the board/NSS port before changing Linux")
    for name in ("version", "revision"):
        require(re.fullmatch(r"[A-Za-z0-9._-]+", lock["identity"][name]), "Unsafe firmware identity")
    tc = lock["toolchain"]
    require(tc["url"].startswith("https://downloads.openwrt.org/releases/25.12.5/"), "Unexpected toolchain source")
    require(re.fullmatch(r"[a-f0-9]{64}", tc["sha256"]), "Toolchain SHA256 required")
    require(not Path(tc["directory"]).is_absolute() and ".." not in Path(tc["directory"]).parts, "Unsafe toolchain path")
    for patch in lock["patches"]:
        path = (ROOT / patch["file"]).resolve()
        require(path.is_relative_to(ROOT / "Config/RE-CS-07-NSS/patches"), "Patch escaped allowlist")
        require(digest(path) == patch["sha256"], "Patch hash mismatch: " + patch["file"])
        require(patch["directory"] in {".", "feeds/packages", "feeds/nss_packages"}, "Unexpected patch target")
    require(any(patch["file"] == "Config/RE-CS-07-NSS/patches/re-cs-07-wired-nss-v25.12.5.patch"
                and patch["directory"] == "." for patch in lock["patches"]),
            "Missing RE-CS-07 board/NSS port")
    require(not any("memory-zero" in patch["file"] for patch in lock["patches"]),
            "M2 zero-Q6 layout must not be applied to RE-CS-07")
    files = lock.get("files", [])
    require(len(files) == 1 and files[0]["file"] == "Config/RE-CS-07-NSS/files/etc/config/fstab"
            and files[0]["destination"] == "etc/config/fstab", "Unexpected image overlay files")
    overlay = ROOT / files[0]["file"]
    require(not overlay.is_symlink() and digest(overlay) == files[0]["sha256"], "fstab hash mismatch")
    fstab_lines = [line.split() for line in overlay.read_text().splitlines() if line.strip()]
    require(fstab_lines == [["config", "global"], ["option", "anon_swap", "'0'"],
            ["option", "anon_mount", "'0'"], ["option", "auto_swap", "'0'"],
            ["option", "auto_mount", "'0'"], ["option", "delay_root", "'5'"],
            ["option", "check_fs", "'0'"]], "fstab must not automatically mount old data/overlay")
    config = read_config(PROFILE_PATH.read_text())
    for key in ("TARGET_qualcommax", "TARGET_qualcommax_ipq60xx", "TARGET_qualcommax_ipq60xx_DEVICE_jdcloud_re-cs-07",
                "TARGET_ROOTFS_INITRAMFS", "PACKAGE_dnsmasq-full", "PACKAGE_ip-full", "PACKAGE_luci",
                "PACKAGE_ppp-mod-pppoe", "PACKAGE_kmod-wireguard", "PACKAGE_wireguard-tools",
                "PACKAGE_luci-proto-wireguard", "PACKAGE_kmod-inet-diag", "PACKAGE_kmod-tun",
                "PACKAGE_block-mount", "AUTOREMOVE",
                "IPQ_MEM_PROFILE_1024", "NSS_MEM_PROFILE_MEDIUM", "NSS_FIRMWARE_VERSION_12_5"):
        require(config.get("CONFIG_" + key) == "y", "Missing required profile choice: " + key)
    for key in ("PACKAGE_dnsmasq", "PACKAGE_dnsmasq-dhcpv6", "PACKAGE_ip-tiny", "ALL_KMODS", "KERNEL_SKB_RECYCLER", "KERNEL_SKB_RECYCLER_PREALLOC"):
        require(config.get("CONFIG_" + key, "n") == "n", "Unsafe/conflicting profile choice: " + key)
    require(config.get("CONFIG_KERNEL_IPQ_MEM_PROFILE") == "1024", "Expected ipq60xx 1024 MiB resource profile")
    for key, value in config.items():
        if key.startswith("CONFIG_PACKAGE_") and value in {"y", "m"}:
            require(not RADIO.match(key.removeprefix("CONFIG_PACKAGE_")), "Wireless package selected: " + key)
        if "DEVICE_" in key and value == "y":
            require(key == "CONFIG_TARGET_qualcommax_ipq60xx_DEVICE_jdcloud_re-cs-07", "Only RE-CS-07 is supported by this profile")
    return lock, config


def run(*args, cwd=None, capture=False, log=None):
    command = [str(arg) for arg in args]
    print("+ " + " ".join(command), flush=True)
    if log:
        with Path(log).open("w") as stream:
            result = subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, check=False)
        require(result.returncode == 0, "Command failed; see " + str(log))
        return ""
    result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE if capture else None, check=True)
    return result.stdout.strip() if capture else ""


def environment(lock):
    require(os.geteuid() != 0, "Run OpenWrt preparation/build/packaging as a regular user")
    os.environ.update(LC_ALL="C", TZ="UTC", FAKEROOTDONTTRYCHOWN="1",
                      SOURCE_DATE_EPOCH=str(lock["base"]["source_date_epoch"]))
    # No repository token is needed by source/build tools.
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        os.environ.pop(name, None)
    os.umask(0o022)


def generate_config(lock, toolchain):
    require(not re.search(r"[\s\"\\]", str(toolchain)), "OpenWrt toolchain path must not contain whitespace/quotes/backslashes")
    values = read_config(PROFILE_PATH.read_text())
    generated = {
        "DEVEL": "y", "EXTERNAL_TOOLCHAIN": "y", "EXTERNAL_TOOLCHAIN_LIBC_USE_MUSL": "y",
        "EXTERNAL_GCC_VERSION": json.dumps(lock["toolchain"]["gcc_version"]), "USE_EXTERNAL_LIBC": "y",
        "TARGET_NAME": '"aarch64-openwrt-linux-musl"', "TOOLCHAIN_PREFIX": '"aarch64-openwrt-linux-musl-"',
        "TOOLCHAIN_LIBC": '"musl"', "TOOLCHAIN_BIN_PATH": '"./usr/bin ./bin"',
        "TOOLCHAIN_INC_PATH": '"./usr/include ./include/fortify ./include"', "TOOLCHAIN_LIB_PATH": '"./usr/lib ./lib"',
        "LIBC_FILE_SPEC": '"./lib/ld{*.so*,-linux*.so.*} ./lib/lib{anl,c,cidn,crypt,dl,m,nsl,nss_dns,nss_files,resolv,util}{-*.so,.so.*,.so}"',
        "LIBGCC_FILE_SPEC": '"./lib/libgcc_s.so.*"', "LIBPTHREAD_FILE_SPEC": '"./lib/libpthread{-*.so,.so.*}"',
        "LIBRT_FILE_SPEC": '"./lib/librt{-*.so,.so.*}"', "VERSIONOPT": "y", "IMAGEOPT": "y",
        "VERSION_NUMBER": json.dumps(lock["identity"]["version"]), "VERSION_CODE": json.dumps(lock["identity"]["revision"]),
        "VERSION_DIST": '"OpenWrt"', "VERSION_FILENAMES": "y", "VERSION_CODE_FILENAMES": "n",
        "VERSION_REPO": '"https://downloads.openwrt.org/releases/25.12.5"',
    }
    for key in ("TOOLCHAIN_ROOT", "LIBC_ROOT_DIR", "LIBGCC_ROOT_DIR", "LIBPTHREAD_ROOT_DIR", "LIBRT_ROOT_DIR"):
        generated[key] = json.dumps(str(toolchain))
    for key, value in generated.items():
        key = "CONFIG_" + key
        require(key not in values, "Profile duplicates generated identity/toolchain setting: " + key)
        values[key] = value
    return "".join(f"# {key} is not set\n" if value == "n" else f"{key}={value}\n" for key, value in values.items())


def verify_config(build):
    lock, wanted = validate_inputs()
    actual = read_config((build / ".config").read_text())
    for key, value in wanted.items():
        require(actual.get(key, "n") == value, f"Kconfig changed/dropped requested option {key}: wanted {value}, got {actual.get(key, 'n')}")
    for key, value in actual.items():
        if key.startswith("CONFIG_PACKAGE_") and value in {"y", "m"}:
            require(not RADIO.match(key.removeprefix("CONFIG_PACKAGE_")), "Unexpected radio dependency: " + key)
    for key in ("dhcp", "dhcpv6", "dnssec", "nftset", "conntrack"):
        require(actual.get("CONFIG_PACKAGE_dnsmasq_full_" + key) == "y", "dnsmasq-full lost feature: " + key)
    require(actual.get("CONFIG_PACKAGE_kmod-qca-nss-drv") == "y" and actual.get("CONFIG_PACKAGE_kmod-qca-nss-ecm") == "y", "NSS datapath missing")
    require(actual.get("CONFIG_VERSION_NUMBER") == json.dumps(lock["identity"]["version"]), "Release identity mismatch")
    return actual


def prepare(work):
    lock, _ = validate_inputs()
    environment(lock)
    work.mkdir(parents=True, exist_ok=True)
    require(not re.search(r"[\s\"\\]", str(work)), "OpenWrt build path contains unsupported characters")
    build = work / "openwrt"
    require(not build.exists(), "Refusing to overwrite an existing build; use a new work directory")
    archive = work / "toolchain.tar.zst"
    tc = lock["toolchain"]
    run("curl", "--fail", "--location", "--retry", "3", "--connect-timeout", "30", tc["url"], "--output", archive)
    require(digest(archive) == tc["sha256"], "Official toolchain checksum mismatch")
    run("tar", "--zstd", "-xf", archive, "-C", work)
    toolchain = work / tc["directory"]
    require(toolchain.is_dir(), "Toolchain extraction failed")
    run("git", "init", build)
    run("git", "remote", "add", "origin", lock["base"]["repository"], cwd=build)
    run("git", "fetch", "--depth", "1", "origin", "tag", lock["base"]["tag"], cwd=build)
    run("git", "checkout", "--detach", lock["base"]["tag"], cwd=build)
    require(run("git", "rev-parse", "HEAD", cwd=build, capture=True) == lock["base"]["commit"], "Release tag moved; refusing to build")
    for patch in lock["patches"]:
        if patch["directory"] == ".":
            run("git", "apply", "--check", ROOT / patch["file"], cwd=build)
            run("git", "apply", ROOT / patch["file"], cwd=build)
    (build / "version").write_text(lock["identity"]["revision"] + "\n")
    (build / "version.date").write_text(str(lock["base"]["source_date_epoch"]) + "\n")
    (build / "feeds.conf").write_text("".join(f"src-git {name} {source['repository']}^{source['commit']}\n" for name, source in lock["feeds"].items()))
    (build / "scripts/localmirrors").write_text("https://sources.openwrt.org\n")
    # Only downloaded source archives are cached; never restore kernel/toolchain/staging output.
    (work / "downloads").mkdir(exist_ok=True)
    (build / "dl").symlink_to(work / "downloads", target_is_directory=True)
    run("./scripts/feeds", "update", "-a", cwd=build)
    for name, source in lock["feeds"].items():
        require(run("git", "rev-parse", "HEAD", cwd=build / "feeds" / name, capture=True) == source["commit"], "Feed commit mismatch: " + name)
    patched_feeds = set()
    for patch in lock["patches"]:
        if patch["directory"] != ".":
            dest = build / patch["directory"]
            run("git", "apply", "--check", ROOT / patch["file"], cwd=dest)
            run("git", "apply", ROOT / patch["file"], cwd=dest)
            patched_feeds.add(dest.name)
    for name in sorted(patched_feeds):
        run("./scripts/feeds", "update", "-i", name, cwd=build)
    run("./scripts/feeds", "install", "-a", cwd=build)
    for entry in lock["files"]:
        target = build / "files" / entry["destination"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / entry["file"], target)
    (build / ".config").write_text(generate_config(lock, toolchain))
    run("make", "defconfig", cwd=build)
    verify_config(build)
    provenance(work, complete=False)


def provenance(work, complete):
    lock, _ = validate_inputs()
    build = work / "openwrt"
    out = work / "reports"
    out.mkdir(exist_ok=True)
    shutil.copy2(build / ".config", out / "config.full")
    (out / "config.diff").write_text(run("./scripts/diffconfig.sh", cwd=build, capture=True) + "\n")
    repo_identity = repository_identity()
    data = {"schema": 1, "source_lock": lock, "source_lock_sha256": digest(LOCK_PATH),
            "profile_sha256": digest(PROFILE_PATH), "config_sha256": digest(build / ".config"),
            "configuration_repository": repo_identity,
            "workflow_run": os.environ.get("GITHUB_RUN_ID"), "workflow_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "build_completed": complete, "hardware_tested": False,
            "reproducibility": "Pinned source/config/toolchain. Ephemeral signing keys and hosted runner tool versions may change binary hashes."}
    (out / "provenance.json").write_text(json.dumps(data, indent=2) + "\n")
    (out / "host-tools.txt").write_text(run("uname", "-a", capture=True) + "\n" + run("gcc", "--version", capture=True) + "\n" + run("make", "--version", capture=True) + "\n")


def compile_build(work, jobs):
    lock, _ = validate_inputs()
    environment(lock)
    build = work / "openwrt"
    verify_config(build)
    logs = work / "logs"
    logs.mkdir(exist_ok=True)
    run("make", f"-j{jobs}", "download", cwd=build, log=logs / "download.log")
    try:
        run("make", f"-j{jobs}", "V=s", cwd=build, log=logs / "build.log")
    except ValueError:
        run("make", "-j1", "V=s", cwd=build, log=logs / "build-retry.log")
    provenance(work, complete=True)


def write_checksums(directory):
    files = sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    (directory / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.relative_to(directory)}\n" for path in files))


def repository_identity():
    # The source ZIP is deliberately credential-/Git-directory-free and remains
    # usable outside a checkout. Input hashes are always recorded separately.
    if (ROOT / ".git").exists():
        return {"commit": run("git", "rev-parse", "HEAD", cwd=ROOT, capture=True),
                "dirty": bool(run("git", "status", "--porcelain", cwd=ROOT, capture=True))}
    archived = ROOT / "source-export.json"
    if archived.is_file():
        return {"exported_from": json.loads(archived.read_text()), "working_tree_status": "unavailable in source archive"}
    return {"commit": None, "working_tree_status": "not a Git checkout"}


def source_zip(path):
    names = [PROFILE_PATH, LOCK_PATH, ROOT / ".github/workflows/RE-CS-07-NSS.yml",
             ROOT / ".github/workflows/Auto-Clean.yml", ROOT / ".github/workflows/QCA-ALL.yml",
             ROOT / "Config/GENERAL.txt", ROOT / "docs/RE-CS-07-NSS.md", ROOT / "LICENSE",
             ROOT / "Config/ZN-M2-NSS.config", ROOT / ".github/workflows/ZN-M2-NSS.yml",
             ROOT / "docs/ZN-M2-NSS.md"]
    for directory in (ROOT / "Config/RE-CS-07-NSS", ROOT / "Scripts/re-cs-07-nss", ROOT / "tests-re-cs-07",
                      ROOT / "Config/ZN-M2-NSS", ROOT / "Scripts/zn-m2-nss", ROOT / "tests"):
        names += [p for p in directory.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(set(names)):
            require(not file.is_symlink(), "Source export refuses symlinks")
            data = file.read_bytes()
            require(not re.search(rb"(?m)^-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----$", data), "Private key in source export")
            item = zipfile.ZipInfo(str(file.relative_to(ROOT)), (1980, 1, 1, 0, 0, 0))
            item.external_attr = 0o100644 << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, data)
        item = zipfile.ZipInfo("source-export.json", (1980, 1, 1, 0, 0, 0))
        item.external_attr = 0o100644 << 16
        item.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(item, json.dumps(repository_identity(), indent=2) + "\n")


def package(work):
    lock, _ = validate_inputs()
    environment(lock)
    build = work / "openwrt"
    verify_config(build)
    reports = work / "reports"
    run(sys.executable, ROOT / "Scripts/re-cs-07-nss/verify-images.py", "--images-dir", build / "bin/targets" / TARGET,
        "--build-root", build, "--report", reports / "image-verification.json")
    image_report = json.loads((reports / "image-verification.json").read_text())
    require(not image_report.get("warnings"), "Incomplete image verification; inspect report before publishing")
    name = "RE-CS-07-" + lock["identity"]["version"]
    offline = work / "offline-output"
    run(sys.executable, ROOT / "Scripts/re-cs-07-nss/package-offline.py", "--build-root", build, "--output", offline,
        "--version-number", lock["identity"]["version"], "--revision", lock["identity"]["revision"],
        "--kernel-version", lock["kernel"]["version"], "--output-name", name + "-offline-apks")
    out = work / "artifacts"
    require(not out.exists(), "Refusing to replace existing packaged artifacts")
    out.mkdir()
    images = build / "bin/targets" / TARGET
    image_files = sorted(p for p in images.iterdir() if p.is_file() and
                         (p.suffix in {".bin", ".tar", ".itb", ".manifest", ".json", ".buildinfo"} or p.name.startswith("sha256sums")))
    require(any(p.name.endswith("sysupgrade.bin") or p.name.endswith("sysupgrade.tar") for p in image_files), "No firmware image to package")
    with tarfile.open(out / (name + "-firmware.tar.gz"), "w:gz") as archive:
        for file in image_files:
            archive.add(file, arcname=file.name, recursive=False)
    for file in offline.glob("*.zip"):
        shutil.copy2(file, out / file.name)
    shutil.copy2(offline / "SUMMARY.json", reports / "offline-summary.json")
    shutil.copy2(offline / "verification-log.json", reports / "offline-verification-log.json")
    kernels = list(build.glob("build_dir/target*/linux-qualcommax_ipq60xx/linux-*/.config"))
    require(len(kernels) == 1, "Cannot select final kernel config")
    shutil.copy2(kernels[0], reports / "kernel.config")
    shutil.copy2(ROOT / "docs/RE-CS-07-NSS.md", out / "README_FIRST.md")
    source_zip(out / (name + "-sources.zip"))
    shutil.copytree(reports, out / "reports")
    (out / "logs").mkdir()
    for filename in ("download.log", "build.log", "build-retry.log"):
        source = work / "logs" / filename
        if source.is_file():
            require(not source.is_symlink(), "Build log must not be a symlink")
            with source.open("rb") as src, gzip.open(out / "logs" / (filename + ".gz"), "wb") as dst:
                shutil.copyfileobj(src, dst)
    write_checksums(out)
    print("Verified artifacts: " + str(out))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["validate", "prepare", "verify-config", "build", "package"])
    parser.add_argument("--work-dir", type=Path, default=ROOT / "_work")
    parser.add_argument("--jobs", type=int, choices=(2, 4), default=4)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    if args.command == "validate":
        validate_inputs()
        print("Source locks, patch hashes and profile invariants pass (static validation only)")
    elif args.command == "prepare":
        prepare(work)
    elif args.command == "verify-config":
        verify_config(work / "openwrt")
    elif args.command == "build":
        compile_build(work, args.jobs)
    elif args.command == "package":
        package(work)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
