#!/usr/bin/env python3
"""Assemble an exact-image offline APK closure without building or signing.

Reads a completed OpenWrt build. Only the output directory is written. Original
signed indexes are copied unchanged; APK's solver and fetcher verify the closure
and the signed-index-to-package identity. No private signing key is accessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile

ARCH = "aarch64_cortex-a53"
TARGET = "qualcommax/ipq60xx"
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+_.-]*")


def safe_slug(value: str) -> str:
    """One portable filename component, never a path or command option."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) or ".." in value:
        raise argparse.ArgumentTypeError("output name must be a safe 1-128 character filename slug")
    return value


def identity_value(value: str) -> str:
    if not value or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_~:-]*", value):
        raise argparse.ArgumentTypeError("identity must be a nonempty version/revision token")
    return value


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version-number", type=identity_value, required=True,
                        help="exact DISTRIB_RELEASE in the completed image")
    parser.add_argument("--revision", type=identity_value, required=True,
                        help="exact DISTRIB_REVISION in the completed image")
    parser.add_argument("--kernel-version", type=identity_value, required=True,
                        help="exact Linux version; full ABI is independently checked")
    parser.add_argument("--output-name", type=safe_slug, required=True,
                        help="bundle directory and ZIP stem (without .zip)")
    return parser


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def checked_file(path: Path, root: Path) -> Path:
    """Reject aliases/traversal before APK can read any repository payload."""
    if not path.is_absolute() or path != path.resolve() or not path.is_relative_to(root):
        raise RuntimeError(f"Input escaped the expected read-only source directory: {path}")
    if not path.is_file():
        raise RuntimeError(f"Missing completed build file: {path}")
    return path


def package_sources(selected: dict[str, dict], bindir: Path, indexes: list[Path]) -> dict[str, Path]:
    sources = {}
    for name, pkg in selected.items():
        source = checked_file(Path(pkg["download-url"]), bindir)
        if source.parent / "packages.adb" not in indexes:
            raise RuntimeError(f"Package has unexpected repository: {source}")
        if source.name != f"{name}-{pkg['version']}.apk" or name == "kernel":
            raise RuntimeError(f"Unexpected or forbidden package filename: {source.name}")
        sources[name] = source
    return sources


def run(args: list[str | Path], *, log: list | None = None) -> str:
    args = [str(x) for x in args]
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=False,
                       env={**os.environ, "LC_ALL": "C"})
    if log is not None:
        log.append({"argv": args, "returncode": p.returncode,
                    "stdout": p.stdout, "stderr": p.stderr})
    if p.returncode:
        raise RuntimeError(f"Command failed ({p.returncode}): {shlex.join(args)}\n"
                           f"{p.stdout}{p.stderr}")
    return p.stdout


def parse_release(path: Path) -> dict:
    result = {}
    for line in path.read_text().splitlines():
        if line.startswith("DISTRIB_") and "=" in line:
            key, value = line.split("=", 1)
            if key in result:
                raise RuntimeError(f"Duplicate release field: {key}")
            parts = shlex.split(value)
            if len(parts) != 1:
                raise RuntimeError(f"Malformed release line: {line}")
            result[key] = parts[0]
    return result


def parse_installed(path: Path) -> dict[str, dict]:
    packages = {}
    for block in path.read_text().split("\n\n"):
        values = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":" and line[0] in "PVADp":
                if line[0] in values:
                    raise RuntimeError(f"Duplicate package metadata field: {line}")
                values[line[0]] = line[2:]
        if "P" in values:
            if not PACKAGE_NAME.fullmatch(values["P"]) or not values.get("V") or not values.get("A"):
                raise RuntimeError(f"Incomplete/invalid installed package metadata: {values}")
            identity_value(values["V"])
            if values["P"] in packages:
                raise RuntimeError(f"Duplicate installed package: {values['P']}")
            packages[values["P"]] = values
        elif values:
            raise RuntimeError("Installed package record has no name")
    if not packages:
        raise RuntimeError("Installed package database is empty")
    return packages


def parse_manifest(path: Path) -> dict[str, str]:
    packages = {}
    for line in path.read_text().splitlines():
        if not line:
            continue
        parts = line.split(" - ", 1)
        if len(parts) != 2 or not PACKAGE_NAME.fullmatch(parts[0]) or not parts[1]:
            raise RuntimeError(f"Malformed firmware manifest entry: {line}")
        name, version = parts
        if name in packages:
            raise RuntimeError(f"Duplicate firmware manifest package: {name}")
        packages[name] = version
    return packages


def requested_packages(installed: dict[str, dict], manifest: dict[str, str]) -> list[str]:
    """The actual image determines the complete requested set; kernel stays external."""
    if "kernel" not in installed:
        raise RuntimeError("Final image has no installed kernel ABI record")
    if {name: p["V"] for name, p in installed.items()} != manifest:
        raise RuntimeError("Firmware manifest and installed database package sets/versions differ")
    for name, p in installed.items():
        if p["A"] not in {ARCH, "noarch"}:
            raise RuntimeError(f"Wrong installed package architecture: {name}")
    requested = sorted(set(installed) - {"kernel"})
    if not requested:
        raise RuntimeError("Final image has no userspace or kmod packages")
    return requested


def validate_identity(release: dict, kernel: str, vermagic: str, *,
                      version_number: str, revision: str, kernel_version: str) -> None:
    if release.get("DISTRIB_RELEASE") != version_number:
        raise RuntimeError("Firmware release does not match --version-number")
    if release.get("DISTRIB_REVISION") != revision:
        raise RuntimeError("Firmware revision does not match --revision")
    if release.get("DISTRIB_TARGET") != TARGET or release.get("DISTRIB_ARCH") != ARCH:
        raise RuntimeError("Firmware target/architecture mismatch")
    if not re.fullmatch(re.escape(kernel_version) + r"~[0-9a-f]{32}-r\d+", kernel):
        raise RuntimeError(f"Unexpected actual kernel ABI for --kernel-version: {kernel}")
    if not re.fullmatch(r"[0-9a-f]{32}", vermagic) or kernel.split("~", 1)[1].rsplit("-r", 1)[0] != vermagic:
        raise RuntimeError("Actual built kernel .vermagic and installed ABI do not match")


def validate_selected(solved: list[dict], installed: dict[str, dict]) -> dict[str, dict]:
    selected = {p["name"]: p for p in solved}
    if len(selected) != len(solved) or set(selected) != set(installed):
        raise RuntimeError("Solver-selected closure does not exactly equal the complete installed image")
    for name, pkg in selected.items():
        record = installed[name]
        for field, key in (("version", "V"), ("arch", "A")):
            if pkg[field] != record[key]:
                raise RuntimeError(f"Signed index disagrees with installed image: {name}/{field}")
        for field, key in (("depends", "D"), ("provides", "p")):
            if sorted(pkg.get(field, [])) != sorted(record.get(key, "").split()):
                raise RuntimeError(f"Signed index disagrees with installed image: {name}/{field}")
    return selected


def dependency_parts(dep: str) -> tuple[bool, str, str, str]:
    match = re.fullmatch(r"(!?)([^<>=~\s]+)([<>=~]*)(.*)", dep)
    if not match:
        raise RuntimeError(f"Unsupported dependency syntax: {dep}")
    neg, name, op, version = match.groups()
    if bool(op) != bool(version) or op not in {"", "=", "<", ">", "<=", ">=", "~", "<~", ">~"}:
        raise RuntimeError(f"Unsupported dependency syntax: {dep}")
    return bool(neg), name, op, version


def version_matches(apk: Path, actual: str, op: str, wanted: str) -> bool:
    if not op:
        return True
    if not actual:  # An unversioned virtual provide cannot satisfy a version constraint.
        return False
    if op == "=":
        return actual == wanted
    if op in {"<", ">", "<=", ">="}:
        relation = run([apk, "version", "--test", actual, wanted]).strip()
        if relation not in {"<", "=", ">"}:
            raise RuntimeError(f"Invalid APK version comparison result: {relation!r}")
        return relation in op
    # Fail closed on dependency operators the independent audit cannot verify.
    raise RuntimeError(f"Unsupported version operator for independent audit: {op}")


def validate_edges(apk: Path, selected: dict[str, dict], kernel: str) -> list[dict]:
    providers: dict[str, list[tuple[str, str]]] = {}
    for name, pkg in selected.items():
        providers.setdefault(name, []).append((name, pkg["version"]))
        for provide in pkg.get("provides", []):
            neg, pname, op, version = dependency_parts(provide)
            if neg or op not in {"", "="}:
                raise RuntimeError(f"Unsupported provided capability: {provide}")
            providers.setdefault(pname, []).append((name, version))
    edges = []
    for name, pkg in sorted(selected.items()):
        deps = pkg.get("depends", [])
        if name.startswith("kmod-"):
            kernel_deps = [d for d in deps if dependency_parts(d)[1] == "kernel"]
            if kernel_deps != [f"kernel={kernel}"]:
                raise RuntimeError(f"Wrong/non-exact kernel ABI in {name}: {kernel_deps}")
        for dep in deps:
            neg, dname, op, wanted = dependency_parts(dep)
            matches = [pname for pname, version in providers.get(dname, [])
                       if version_matches(apk, version, op, wanted)]
            if neg:
                if matches:
                    raise RuntimeError(f"Selected package conflict: {name}: {dep}")
                status = "conflict_absent"
            elif not matches:
                raise RuntimeError(f"Dependency closure is incomplete: {name}: {dep}")
            elif dname == "kernel":
                if op != "=" or wanted != kernel:
                    raise RuntimeError(f"Kernel ABI mismatch: {name}: {dep}")
                status = "exact_running_firmware_prerequisite"
            else:
                status = "included_apk"
            edges.append({"from": name, "requires": dep,
                          "satisfied_by": sorted(set(matches)), "status": status})
    return edges


def copy_public_keys(source: Path, dest: Path) -> list[dict]:
    dest.mkdir(parents=True)
    keys = []
    for p in sorted(source.iterdir()):
        if p.is_symlink():
            raise RuntimeError(f"Refusing symlink in image trust directory: {p.name}")
        if not p.is_file():
            continue
        data = p.read_bytes()
        if b"PRIVATE KEY" in data or not data.startswith(b"-----BEGIN PUBLIC KEY-----"):
            raise RuntimeError(f"Refusing non-public-key input in image trust directory: {p.name}")
        shutil.copyfile(p, dest / p.name)
        keys.append({"filename": p.name, "sha256": sha256(p)})
    if not keys:
        raise RuntimeError("Image contains no public APK trust keys")
    return keys


def fresh_apk_root(path: Path, image: Path, *, installed: bool) -> None:
    (path / "etc/apk").mkdir(parents=True)
    (path / "lib/apk/db").mkdir(parents=True)
    copy_public_keys(image / "etc/apk/keys", path / "etc/apk/keys")
    (path / "etc/apk/arch").write_text(ARCH + "\n")
    if installed:
        for item in (image / "lib/apk/db").iterdir():
            if item.is_file():
                shutil.copyfile(item, path / "lib/apk/db" / item.name)
        shutil.copyfile(image / "etc/apk/world", path / "etc/apk/world")
    else:
        (path / "lib/apk/db/installed").write_text("")
        (path / "etc/apk/world").write_text("")


def apk_options(apk: Path, root: Path, repos: Path) -> list:
    return [apk, "--root", root, "--arch", ARCH, "--repositories-file", repos,
            "--no-network", "--cache=no", "--logfile=no"]


def validate_simulations(add_plan: str, fix_plan: str, recovery_plan: str,
                         selected: dict[str, dict]) -> None:
    action = re.compile(r"\b(Installing|Reinstalling|Upgrading|Downgrading|Purging) ([^ ]+) \(([^\n)]*)\)")
    plans = [action.findall(plan) for plan in (add_plan, fix_plan, recovery_plan)]
    if any(name == "kernel" for plan in plans for _, name, _ in plan):
        raise RuntimeError("Simulation unexpectedly changes kernel package")
    if plans[0]:
        raise RuntimeError("Offline add unexpectedly changes the already-complete image")
    expected = {(name, p["version"]) for name, p in selected.items()}
    for plan, verb, label in ((plans[1], "Reinstalling", "reinstall"),
                              (plans[2], "Installing", "missing-package recovery")):
        if (any(operation != verb for operation, _, _ in plan)
                or len(plan) != len(expected)
                or {(name, version) for _, name, version in plan} != expected):
            raise RuntimeError(f"Offline {label} did not exactly restore the complete installed package set")


def write_preflight(bundle: Path, release: dict, kernel: str, kver: str) -> None:
    script = '''#!/bin/sh
# Read-only router preflight; only a temporary repository list is created.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "请以 root 运行检查" >&2; exit 1; }
[ -r /etc/openwrt_release ] || { echo "缺少 OpenWrt 版本信息" >&2; exit 1; }
. /etc/openwrt_release
[ "${DISTRIB_RELEASE:-}" = @RELEASE@ ] || { echo "固件 release 不匹配，停止" >&2; exit 1; }
[ "${DISTRIB_REVISION:-}" = @REVISION@ ] || { echo "固件 revision 不匹配，停止" >&2; exit 1; }
[ "$(cat /tmp/sysinfo/board_name)" = 'jdcloud,re-cs-07' ] || { echo "设备型号不匹配，停止" >&2; exit 1; }
[ "$(uname -r)" = @KVER@ ] || { echo "运行中内核版本不匹配，停止" >&2; exit 1; }
KERNEL=$(awk 'BEGIN { RS=""; FS="\\n" } { p=""; v=""; for (i=1;i<=NF;i++) { if ($i ~ /^P:/) p=substr($i,3); if ($i ~ /^V:/) v=substr($i,3) } if (p=="kernel") print v }' /lib/apk/db/installed)
[ "$KERNEL" = @KERNEL@ ] || { echo "运行固件的 kernel ABI 不匹配，停止" >&2; exit 1; }
(cd "$HERE" && sha256sum -c SHA256SUMS)
TMP=$(mktemp -d /tmp/re-cs-07-offline.XXXXXX)
trap 'rm -f "$TMP/repositories.list"; rmdir "$TMP"' EXIT HUP INT TERM
find "$HERE/repos" -type f -name packages.adb | sort > "$TMP/repositories.list"
while IFS= read -r INDEX; do
    apk --no-network --logfile=no verify "$INDEX"
done < "$TMP/repositories.list"
echo "检查通过；下面仅模拟离线补装，不修改软件包："
set --
while IFS= read -r PACKAGE; do
    set -- "$@" "$PACKAGE"
done < "$HERE/PACKAGE-CONSTRAINTS.txt"
apk --no-network --cache=no --logfile=no --repositories-file "$TMP/repositories.list" add --simulate "$@"
echo "已安装包的离线重装计划（仅模拟）："
set --
while IFS= read -r PACKAGE; do
    set -- "$@" "$PACKAGE"
done < "$HERE/PACKAGES.txt"
apk --no-network --cache=no --logfile=no --repositories-file "$TMP/repositories.list" fix --simulate --reinstall "$@"
echo "未安装或重装任何软件包，也未修改信任密钥、源配置、网络或路由器设置。"
'''
    for key, value in {"RELEASE": release["DISTRIB_RELEASE"],
                       "REVISION": release["DISTRIB_REVISION"],
                       "KERNEL": kernel, "KVER": kver}.items():
        script = script.replace(f"@{key}@", shlex.quote(value))
    (bundle / "check-offline.sh").write_text(script)
    (bundle / "check-offline.sh").chmod(0o755)


def write_readme(bundle: Path, report: dict) -> None:
    release = report["firmware"]
    package_rows = "\n".join(f"- {p['name']} = {p['version']}" for p in report["packages"])
    command = shlex.join([
        "python3", "package-offline.py", "--build-root", "/absolute/path/to/completed-openwrt-build",
        "--output", "/absolute/path/to/new-offline-output",
        "--version-number", release["DISTRIB_RELEASE"],
        "--revision", release["DISTRIB_REVISION"],
        "--kernel-version", report["linux_version"], "--output-name", bundle.name,
    ])
    text = f'''# JDCloud RE-CS-07 NSS 离线 APK 包：{release['DISTRIB_RELEASE']}

本包只用于与它一起发布、身份和完整 kernel ABI 完全匹配的 JDCloud RE-CS-07 镜像。它包含该镜像已安装的全部 userspace 和 kmod 软件包，唯独不携带 kernel 元数据 APK。正常使用已内置的功能无需再安装本包；它用于离线补装或恢复被删除的软件包。

## 必须完全匹配

- 设备：JDCloud RE-CS-07；目标：{TARGET}；架构：{ARCH}
- 固件 release：{release['DISTRIB_RELEASE']}
- 固件 revision：{release['DISTRIB_REVISION']}
- Linux：{report['linux_version']}
- kernel 包完整 ABI 版本：{report['kernel_abi']}
- 对应 sysupgrade 镜像 SHA-256：{report['firmware_image']['sha256']}

仅 Linux 版本号相同还不够，完整 kernel ABI 必须逐字一致。不能用于其他构建或其他机型；APK 文件名末尾的 release 是软件包自身的版本信息。

**没有包含可安装的 kernel APK。** 原始签名索引可能仍列出 kernel 等未携带包；不能用 kernel 元数据 APK “修复” ABI 不匹配，它不会替换正在运行的内核。遇到 ABI 或签名错误请停止，使用对应完整固件与配套包；不要混用其他仓库的 kmod，不要强制安装、改写依赖或绕过签名。

## 内容与验证

- {len(report['packages'])} 个 APK，严格对应最终镜像的全部已安装软件包（kernel 除外）
- 递归解析并核对全部依赖，唯一外部前提为镜像本身的精确 kernel ABI
- `repos/` 保留原构建目录结构和原始签名 `packages.adb`，未重建、裁剪或重新签名
- APK 内容由原始签名索引中的哈希认证；通过本地仓库按包名安装，不要把裸 APK 当作不可信文件安装
- 使用固件已有 `/etc/apk/keys` 信任，不包含私钥，也不导入或替换密钥
- `DEPENDENCIES.json`：完整包集合、依赖边、精确版本、来源、哈希、ABI 和核验结果
- `PACKAGES.txt`：全部可恢复包名；`PACKAGE-CONSTRAINTS.txt`：其精确版本约束，两者都不含 kernel
- `SHA256SUMS`：全部有效载荷文件的 SHA-256（校验文件自身除外）
- `FIRMWARE.manifest`：镜像原始清单，其中 kernel 记录仅用于核对
- `package-offline.py`：可独立运行的只读收集脚本，不编译、不改包、不签名

## 使用前检查（不会安装软件包）

1. 在电脑上核对 ZIP 的独立 SHA-256，然后解压
2. 将整个解压目录放到路由器，例如 `/tmp/{bundle.name}`，保留子目录；空间不足时使用已挂载存储
3. 在路由器本机执行：

```sh
cd /tmp/{bundle.name}
sh ./check-offline.sh
```

脚本检查 release、revision、设备、运行内核、完整 ABI、SHA-256 和原始索引签名，只模拟补装与重装。检查失败请停止。模拟步骤不代表已经安装。

## 确实需要离线恢复时

请先备份配置，确认运行的是同一镜像且上面所有检查通过。优先只恢复需要的软件包；整批重装会执行软件包自身安装脚本，可能影响服务和配置。以下仅是由你手动运行的完整恢复示例；打包过程没有访问路由器。

```sh
cd /tmp/{bundle.name}
BUNDLE=$(pwd)
LIST=$(mktemp /tmp/re-cs-07-offline-repos.XXXXXX)
find "$BUNDLE/repos" -type f -name packages.adb | sort > "$LIST"
set --
while IFS= read -r PACKAGE; do set -- "$@" "$PACKAGE"; done < PACKAGE-CONSTRAINTS.txt
# 补装缺失的软件包，按镜像精确版本约束求解：
apk --no-network --cache=no --repositories-file "$LIST" add "$@"
# 已登记的包如确需恢复文件，可先查看模拟计划：
set --
while IFS= read -r PACKAGE; do set -- "$@" "$PACKAGE"; done < PACKAGES.txt
apk --no-network --cache=no --repositories-file "$LIST" fix --simulate --reinstall "$@"
# 仅在确认模拟计划安全后，自行去掉 --simulate 执行上述重装
rm -f "$LIST"
```

临时 `--repositories-file` 关闭默认远程仓库目录读取，`--no-network` 禁止联网，不修改系统源配置。不要加 `--depends` 重装依赖树，否则可能把 kernel 列入操作。本包不会替你配置 VPN、代理、密钥、防火墙或网络；应用运行需要的额外下载、订阅和配置不属于 APK 依赖闭包保证。

## APK 清单

{package_rows}

## 重新生成

在已完成且已校验的原始源码构建目录之外运行，输出目录必须不存在或为空：

```sh
{command}
```

脚本读取完成的 `bin/`、最终 rootfs、`.vermagic` 和可信 host apk，只向输出目录写入；不运行 make，不读取私钥，不改镜像或依赖。原始索引签名验证后，使用 APK 求解器和独立依赖核对，再从原始和重新定位的仓库验证每个 APK；最后在隔离的安装数据库副本中模拟补装、重装和全部缺失包恢复。

主机验证证明包来源、签名信任、闭包、ABI 一致及离线求解可行；没有在实体路由器安装或运行，不能替代硬件启动、联网和应用功能实测。
'''
    (bundle / "README-中文.md").write_text(text)


def main(argv: list[str] | None = None) -> None:
    args = argument_parser().parse_args(argv)
    build = args.build_root.resolve()
    output = args.output.resolve()
    if any(c in str(build) + str(output) for c in "\r\n"):
        raise RuntimeError("Build and output paths cannot contain newlines")
    if output == build or output.is_relative_to(build) or build.is_relative_to(output):
        raise RuntimeError("Output and read-only source tree must not overlap")
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("Output must be absent or empty; existing artifacts are preserved")
    output.mkdir(parents=True, exist_ok=True)
    apk = build / "staging_dir/host/bin/apk"
    image_roots = sorted((build / "build_dir").glob("target-*/root-qualcommax"))
    if len(image_roots) != 1:
        raise RuntimeError(f"Expected one completed target rootfs, got {len(image_roots)}")
    image = image_roots[0]
    bindir = build / "bin"
    for path in (image / "etc/openwrt_release", image / "etc/apk/world",
                 image / "lib/apk/db/installed"):
        checked_file(path, build)
    release = parse_release(image / "etc/openwrt_release")
    installed = parse_installed(image / "lib/apk/db/installed")
    kernel = installed["kernel"]["V"]
    kver = args.kernel_version
    vermagic_path = image.parent / f"linux-qualcommax_ipq60xx/linux-{kver}/.vermagic"
    checked_file(vermagic_path, build)
    vermagic = vermagic_path.read_text().strip()
    validate_identity(release, kernel, vermagic, version_number=args.version_number,
                      revision=args.revision, kernel_version=kver)
    firmware_images = sorted(p for suffix in ("bin", "tar") for p in
                             (bindir / "targets" / TARGET).glob(f"*jdcloud_re-cs-07-squashfs-sysupgrade.{suffix}"))
    if len(firmware_images) != 1:
        raise RuntimeError(f"Expected one completed JDCloud RE-CS-07 sysupgrade image, got {len(firmware_images)}")
    checked_file(firmware_images[0], bindir)
    firmware_image = {"filename": firmware_images[0].name, "sha256": sha256(firmware_images[0]),
                      "bytes": firmware_images[0].stat().st_size}
    manifests = sorted((bindir / "targets" / TARGET).glob("*jdcloud_re-cs-07.manifest"))
    if len(manifests) != 1:
        raise RuntimeError(f"Expected one JDCloud RE-CS-07 firmware manifest, got {len(manifests)}")
    checked_file(manifests[0], bindir)
    manifest = parse_manifest(manifests[0])
    requested = requested_packages(installed, manifest)
    constraints = [f"{name}={installed[name]['V']}" for name in requested]
    indexes = [bindir / "targets" / TARGET / "packages/packages.adb"]
    indexes += sorted((bindir / "packages" / ARCH).glob("*/packages.adb"))
    if not all(p.is_file() for p in indexes):
        raise RuntimeError("Missing completed signed package indexes")
    for index in indexes:
        checked_file(index, bindir)
    for directory in (image / "lib/apk/db", image / "etc/apk/keys"):
        for path in directory.iterdir():
            if path.is_file() or path.is_symlink():
                checked_file(path, image)
    bundle = output / args.output_name
    bundle.mkdir()
    logs: list[dict] = []
    root_before = {str(p.relative_to(image)): sha256(p) for p in [
        *(p for p in (image / "lib/apk/db").iterdir() if p.is_file()),
        *(p for p in (image / "etc/apk/keys").iterdir() if p.is_file()),
        image / "etc/apk/world", image / "etc/openwrt_release"]}
    index_before = {p: sha256(p) for p in indexes}
    manifest_before = sha256(manifests[0])
    with tempfile.TemporaryDirectory(prefix="verification-", dir=output) as temp:
        temp = Path(temp)
        fresh = temp / "empty-root"
        fresh_apk_root(fresh, image, installed=False)
        trust = [{"filename": p.name, "sha256": sha256(p)}
                 for p in sorted((fresh / "etc/apk/keys").iterdir())]
        source_repos = temp / "source-repositories.list"
        source_repos.write_text("".join(str(p) + "\n" for p in indexes))
        base = apk_options(apk, fresh, source_repos)
        for index in indexes:
            run([apk, "--no-network", "--cache=no", "--logfile=no",
                 "--keys-dir", fresh / "etc/apk/keys", "verify", index], log=logs)
        fields = "name,version,arch,depends,provides,download-url,repositories"
        query = run(base + ["query", "--from", "repositories", "--recursive",
                            "--format", "json", "--fields", fields] + constraints, log=logs)
        solved = json.loads(query)
        selected = validate_selected(solved, installed)
        edges = validate_edges(apk, selected, kernel)
        selected.pop("kernel")  # It is an external running-firmware prerequisite, never an installable workaround.
        sources = package_sources(selected, bindir, indexes)
        fetchdir = temp / "verified-apks"
        fetchdir.mkdir()
        # Non-recursive APK fetch matches package names (not name=version
        # constraints). The solver already selected exact versions; subsequently
        # require the fetched filenames, metadata and content to match exactly.
        fetch_names = sorted(selected)
        run(base + ["fetch", "--output", fetchdir] + fetch_names, log=logs)
        if len(list(fetchdir.glob("*.apk"))) != len(selected):
            raise RuntimeError("Fetched package set does not equal the solver-selected closure")
        packages = []
        used_indexes = set()
        for name, p in sorted(selected.items()):
            version = p["version"]
            if manifest.get(name) != version or installed.get(name, {}).get("V") != version:
                raise RuntimeError(f"Closure package not exactly embedded in final image: {name}={version}")
            if p["arch"] not in {ARCH, "noarch"}:
                raise RuntimeError(f"Wrong architecture: {name}")
            source = sources[name]
            source_rel = source.relative_to(bindir)
            index = source.parent / "packages.adb"
            verified = fetchdir / source.name
            if sha256(source) != sha256(verified):
                raise RuntimeError(f"Verified fetch differs from source: {name}")
            meta = json.loads(run([apk, "adbdump", "--format", "json", verified], log=logs))["info"]
            for field in ("name", "version", "arch", "depends", "provides"):
                if meta.get(field, []) != p.get(field, []):
                    raise RuntimeError(f"APK metadata disagrees with signed index: {name}/{field}")
            dest = bundle / "repos" / source_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(verified, dest)
            used_indexes.add(index)
            packages.append({"name": name, "version": version, "arch": p["arch"],
                             "requested": name in requested, "depends": p.get("depends", []),
                             "provides": p.get("provides", []), "source": str(Path("bin") / source_rel),
                             "file": str(dest.relative_to(bundle)), "bytes": dest.stat().st_size,
                             "sha256": sha256(dest), "signed_index": str(Path("repos") / index.relative_to(bindir))})
        repo_records = []
        for index in sorted(used_indexes):
            dest = bundle / "repos" / index.relative_to(bindir)
            shutil.copyfile(index, dest)
            repo_records.append({"source": str(Path("bin") / index.relative_to(bindir)),
                                 "file": str(dest.relative_to(bundle)), "sha256": sha256(dest),
                                 "signature": "verified with public keys embedded in final image rootfs"})
        bundle_repos = temp / "bundle-repositories.list"
        bundle_repos.write_text("".join(str(bundle / p["file"]) + "\n" for p in repo_records))
        # Fetch everything again from the reduced, relocated offline tree. This
        # validates that no required APK was omitted or placed at a wrong path.
        fetched_bundle = temp / "relocated-verified-apks"
        fetched_bundle.mkdir()
        run(apk_options(apk, fresh, bundle_repos) + ["fetch", "--output", fetched_bundle] + fetch_names, log=logs)
        if len(list(fetched_bundle.glob("*.apk"))) != len(selected):
            raise RuntimeError("Relocated repository fetch differs from the selected closure")
        for p in packages:
            if sha256(fetched_bundle / Path(p["file"]).name) != p["sha256"]:
                raise RuntimeError(f"Relocated verification mismatch: {p['name']}")
        simulation = temp / "installed-root-copy"
        fresh_apk_root(simulation, image, installed=True)
        simbase = apk_options(apk, simulation, bundle_repos)
        add_plan = run(simbase + ["add", "--simulate"] + constraints, log=logs)
        fix_plan = run(simbase + ["fix", "--simulate", "--reinstall"] + requested, log=logs)
        # Also exercise genuinely missing packages. Only a disposable database
        # copy is edited; the exact kernel entry and all non-bundle packages stay.
        recovery = temp / "missing-packages-root-copy"
        fresh_apk_root(recovery, image, installed=True)
        recovery_db = recovery / "lib/apk/db/installed"
        blocks = recovery_db.read_text().split("\n\n")
        retained = [b for b in blocks if not any(
            line.startswith("P:") and line[2:] in selected for line in b.splitlines())]
        recovery_db.write_text("\n\n".join(retained))
        recovery_plan = run(apk_options(apk, recovery, bundle_repos) + ["add", "--simulate"] + constraints, log=logs)
        validate_simulations(add_plan, fix_plan, recovery_plan, selected)
        shutil.copyfile(manifests[0], bundle / "FIRMWARE.manifest")
        shutil.copyfile(Path(__file__), bundle / "package-offline.py")
        (bundle / "package-offline.py").chmod(0o755)
        (bundle / "PACKAGES.txt").write_text("\n".join(requested) + "\n")
        (bundle / "PACKAGE-CONSTRAINTS.txt").write_text("\n".join(constraints) + "\n")
        report = {"schema": 2, "firmware": release, "linux_version": kver,
                  "kernel_abi": kernel, "kernel_apk_included": False,
                  "kernel_vermagic": vermagic, "firmware_image": firmware_image,
                  "selection": "all_installed_packages_except_kernel",
                  "requested_packages": requested, "package_constraints": constraints,
                  "packages": packages,
                  "dependency_edges": edges, "signed_indexes": repo_records,
                  "embedded_public_key_fingerprints": trust,
                  "image_manifest_sha256": sha256(manifests[0]),
                  "verification": {"solver": "apk query --recursive against same-build signed indexes",
                                   "dependency_closure": "all positive dependency edges resolved; kernel exact prerequisite only",
                                   "kernel_abi": "all kmod kernel dependencies equal final rootfs and firmware manifest",
                                   "package_authentication": "apk fetch against original signed indexes; repeated from relocated bundle",
                                   "offline_simulation": "add, fix --reinstall, and full missing-closure recovery passed using copied installed databases",
                                   "source_unchanged": True, "hardware_tested": False},
                  "simulation_add": add_plan, "simulation_fix": fix_plan,
                  "simulation_missing_closure_recovery": recovery_plan}
        (bundle / "DEPENDENCIES.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        write_preflight(bundle, release, kernel, kver)
        write_readme(bundle, report)
    for rel, digest in root_before.items():
        if sha256(image / rel) != digest:
            raise RuntimeError(f"Source image changed during collection: {rel}")
    if sha256(firmware_images[0]) != firmware_image["sha256"] or vermagic_path.read_text().strip() != vermagic:
        raise RuntimeError("Firmware or actual kernel ABI changed during collection")
    if sha256(manifests[0]) != manifest_before or any(sha256(p) != digest for p, digest in index_before.items()):
        raise RuntimeError("Original manifest or signed indexes changed during collection")
    if any(p.name.startswith("kernel-") for p in bundle.rglob("*.apk")):
        raise RuntimeError("Kernel meta APK must never be included")
    files = sorted(p for p in bundle.rglob("*") if p.is_file())
    (bundle / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.relative_to(bundle)}\n" for p in files))
    run(["sh", "-n", bundle / "check-offline.sh"], log=logs)
    zip_name = args.output_name + ".zip"
    zip_path = output / zip_name
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(p for p in bundle.rglob("*") if p.is_file()):
            zi = zipfile.ZipInfo(str(Path(args.output_name) / p.relative_to(bundle)), (1980, 1, 1, 0, 0, 0))
            zi.create_system = 3
            zi.external_attr = (0o100755 if p.suffix in {".sh", ".py"} else 0o100644) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, p.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with zipfile.ZipFile(zip_path) as z:
        bad = z.testzip()
        if bad:
            raise RuntimeError(f"ZIP CRC failed: {bad}")
    digest = sha256(zip_path)
    (output / (zip_name + ".sha256")).write_text(f"{digest}  {zip_name}\n")
    (output / "verification-log.json").write_text(json.dumps(logs, indent=2, ensure_ascii=False) + "\n")
    summary = {"zip": str(zip_path), "sha256": digest, "zip_bytes": zip_path.stat().st_size,
               "apk_count": len(packages), "apk_bytes": sum(p["bytes"] for p in packages),
               "kernel_abi": kernel, "signed_index_count": len(repo_records),
               "zip_crc": "passed", "source_image_database_unchanged": True}
    (output / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
