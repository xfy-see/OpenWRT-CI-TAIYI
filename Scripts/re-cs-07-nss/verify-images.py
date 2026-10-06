#!/usr/bin/env python3
"""Offline structural verifier for the custom JDCloud RE-CS-07 wired NSS images.

Python 3.9+, standard library only for firmware binary verification. Optional
filesystem extraction uses an explicitly supplied unsquashfs or the official
host tool in --build-root. No router is contacted, no firmware is executed, and
no build is started. All image inputs are read-only. Extraction/report outputs
are the only writes. CRCs and FIT hashes establish integrity, not authenticity.

Example:
  python3 verify-nss-images.py --images-dir ../../_work/openwrt/bin/targets/qualcommax/ipq60xx \
    --build-root ../../_work/openwrt --report verification.json

Use --sysupgrade, --initramfs and --manifest to select explicit files.
--self-test exercises the parsers with synthetic data, without reading images.
"""

import argparse
import collections
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib


HLOS_SIZE = 6 * 1024 * 1024
ROOTFS_SIZE = 60 * 1024 * 1024
ROOTFS_ALIGNMENT = 64 * 1024
ROOTFS_OVERLAY_MARKER = 4096
MAX_IMAGE_SIZE = 256 * 1024 * 1024
MAX_INFLATED_KERNEL = 512 * 1024 * 1024
# Share identity and commit pins with the workflow; do not maintain a second list.
ROOT = Path(__file__).resolve().parents[2]
LOCK = json.loads((ROOT / "Config/RE-CS-07-NSS/sources.lock.json").read_text())
EXPECTED_KERNEL = LOCK["kernel"]["version"]
EXPECTED_VERSION = LOCK["identity"]["version"]
EXPECTED_REVISION = LOCK["identity"]["revision"]
EXPECTED_EPOCH = LOCK["base"]["source_date_epoch"]
EXPECTED_BASE_COMMIT = LOCK["base"]["commit"]
# Pinned 12.5-210-CP.R firmware payload (from the locked NSS feed).
EXPECTED_NSS_FIRMWARE_SHA256 = "3c7708960681859a24d964895dff166f2336de8ccaae4ba9e7e39f272561ccee"
EXPECTED_EMMC_HELPER_SHA256 = "d4503632578285896b1e9ddaa64d12c163ebcf391cbd5399218d91b6333cd1f6"
EXPECTED_FEEDS = {name: value["commit"] for name, value in LOCK["feeds"].items()}
CAVEAT = ("Offline structural checks only. No router flashing, boot test, physical "
          "RAM-capacity verification, port/MAC test, throughput test, or on-device "
          "NSS/ECM acceleration/stability test was performed by this verifier. "
          "WireGuard availability is software support; NSS WireGuard offload is not claimed.")


class VerificationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def u32(data, offset=0):
    require(offset >= 0 and offset + 4 <= len(data), "Truncated 32-bit field")
    return struct.unpack_from(">I", data, offset)[0]


def cell_value(data):
    require(len(data) in (4, 8), "Expected a 32/64-bit DT cell value")
    return int.from_bytes(data, "big")


def strings(data):
    require(data.endswith(b"\0"), "DT string property lacks NUL terminator")
    return data[:-1].decode("utf-8", "strict").split("\0")


def one_string(data):
    value = strings(data)
    require(len(value) == 1, "Expected exactly one DT string")
    return value[0]


def crc_raw(data):
    # fwtool: reflected CRC32, initial 0xffffffff, no final xor.
    return zlib.crc32(data) ^ 0xFFFFFFFF


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_image(path):
    path = Path(path)
    require(path.is_file(), "Missing image: %s" % path)
    require(0 < path.stat().st_size <= MAX_IMAGE_SIZE,
            "Empty or unexpectedly large image: %s" % path)
    return path.read_bytes()


class FDT:
    """Bounded flattened device-tree parser, also used for FIT containers."""

    def __init__(self, data):
        require(len(data) >= 40, "FDT header is truncated")
        fields = struct.unpack_from(">10I", data)
        magic, total, off_struct, off_strings, off_resv, version, last, _, nstr, nstruct = fields
        require(magic == 0xD00DFEED, "Invalid FDT magic")
        require(40 <= total <= len(data), "Invalid FDT total size")
        require(version >= 17 and last <= 17, "Unsupported FDT version")
        require(off_struct % 4 == 0 and off_resv % 8 == 0, "Misaligned FDT blocks")
        for start, size in ((off_struct, nstruct), (off_strings, nstr)):
            require(start >= 40 and start + size <= total, "FDT block out of bounds")
        require(off_struct + nstruct <= off_strings or off_strings + nstr <= off_struct,
                "FDT structure and strings overlap")
        self.data = data[:total]
        self.total = total
        self.nodes = {}
        self.reservations = []
        pos = off_resv
        while True:
            require(pos + 16 <= total, "Unterminated FDT memory-reservation map")
            address, size = struct.unpack_from(">QQ", data, pos)
            pos += 16
            if address == 0 and size == 0:
                break
            self.reservations.append((address, size))
        string_block = data[off_strings:off_strings + nstr]
        stack = []
        pos = off_struct
        end = off_struct + nstruct
        finished = False
        while pos + 4 <= end:
            token = u32(data, pos)
            pos += 4
            if token == 1:  # FDT_BEGIN_NODE
                nul = data.find(b"\0", pos, end)
                require(nul >= pos, "Unterminated FDT node name")
                name = data[pos:nul].decode("utf-8", "strict")
                require("/" not in name, "Slash in FDT node name")
                require(bool(stack) or not name, "FDT root node name must be empty")
                stack.append(name)
                path = "/" + "/".join(stack[1:])
                require(path not in self.nodes, "Duplicate FDT node: " + path)
                self.nodes[path] = {}
                pos = (nul + 4) & ~3
            elif token == 2:  # FDT_END_NODE
                require(bool(stack), "Unbalanced FDT end node")
                stack.pop()
            elif token == 3:  # FDT_PROP
                require(bool(stack) and pos + 8 <= end, "FDT property outside node")
                length, nameoff = struct.unpack_from(">II", data, pos)
                pos += 8
                require(nameoff < len(string_block), "FDT property name offset out of range")
                nul = string_block.find(b"\0", nameoff)
                require(nul >= nameoff, "Unterminated FDT property name")
                name = string_block[nameoff:nul].decode("ascii", "strict")
                require(pos + length <= end, "FDT property data out of bounds")
                path = "/" + "/".join(stack[1:])
                require(name not in self.nodes[path], "Duplicate FDT property: " + path + "/" + name)
                self.nodes[path][name] = data[pos:pos + length]
                pos = (pos + length + 3) & ~3
            elif token == 4:  # FDT_NOP
                continue
            elif token == 9:  # FDT_END
                require(not stack, "Unclosed FDT node")
                finished = True
                break
            else:
                raise VerificationError("Unknown FDT token %d" % token)
        require(finished and "/" in self.nodes, "FDT structure is incomplete")
        self.phandles = {}
        for path, props in self.nodes.items():
            values = [cell_value(props[k]) for k in ("phandle", "linux,phandle") if k in props]
            if values:
                require(len(set(values)) == 1 and values[0] not in (0, 0xFFFFFFFF),
                        "Invalid/inconsistent phandle at " + path)
                require(values[0] not in self.phandles, "Duplicate phandle")
                self.phandles[values[0]] = path

    def prop(self, path, name):
        require(path in self.nodes and name in self.nodes[path],
                "Missing FDT property: %s/%s" % (path, name))
        return self.nodes[path][name]

    def text(self, path, name):
        return one_string(self.prop(path, name))

    def children(self, path):
        prefix = path.rstrip("/") + "/"
        return [p for p in self.nodes if p.startswith(prefix) and "/" not in p[len(prefix):]]

    def compatible(self, value):
        return [p for p, v in self.nodes.items()
                if "compatible" in v and value in strings(v["compatible"])]

    def enabled(self, path):
        return self.nodes[path].get("status", b"okay\0") in (b"okay\0", b"ok\0")

    def resolve(self, value):
        phandle = cell_value(value)
        require(phandle in self.phandles, "Unresolved FDT phandle %#x" % phandle)
        return self.phandles[phandle]


def verify_wired_reserved_memory(dt):
    """Retain the original Q6 carveout while disabling every wireless consumer."""
    expected = {
        "/reserved-memory/memory@60000": (0x60000, 0x6000),
        "/reserved-memory/memory@40000000": (0x40000000, 0x1000000),
        "/reserved-memory/bootloader@4a100000": (0x4a100000, 0x400000),
        "/reserved-memory/sbl@4a500000": (0x4a500000, 0x100000),
        "/reserved-memory/memory@4a600000": (0x4a600000, 0x400000),
        "/reserved-memory/memory@4aa00000": (0x4aa00000, 0x100000),
        "/reserved-memory/memory@4ab00000": (0x4ab00000, 0x5500000),
    }
    require(not dt.reservations, "Unexpected FDT memreserve entries")
    for prop in ("#address-cells", "#size-cells"):
        require(cell_value(dt.prop("/reserved-memory", prop)) == 2,
                "RE-CS-07 reserved-memory cell widths changed")
    require(set(dt.children("/reserved-memory")) == set(expected),
            "RE-CS-07 protected reserved-memory nodes changed")
    regions = []
    for path, (address, size) in expected.items():
        require(dt.prop(path, "reg") == struct.pack(">QQ", address, size),
                "RE-CS-07 protected reserved-memory layout changed: " + path)
        require("no-map" in dt.nodes[path] and dt.enabled(path),
                "Protected reservation is mapped or disabled: " + path)
        regions.append((address, address + size, path))
    regions.sort()
    require(all(left[1] <= right[0] for left, right in zip(regions, regions[1:])),
            "Reserved-memory regions overlap")
    wcss = dt.compatible("qcom,ipq6018-wcss-pil")
    wifi = dt.compatible("qcom,ipq6018-wifi")
    require(len(wcss) == 1 and not dt.enabled(wcss[0]), "WCSS must remain present and disabled")
    require(len(wifi) == 1 and not dt.enabled(wifi[0]), "SoC Wi-Fi must remain present and disabled")
    require(dt.resolve(dt.prop(wcss[0], "memory-region")) == "/reserved-memory/memory@4ab00000",
            "WCSS must retain its original Q6 memory reference")
    memory_references = 0
    for path, props in dt.nodes.items():
        compatible = strings(props["compatible"]) if "compatible" in props else []
        if "qcom,rproc" in props or any(re.search(r"(?:ath[0-9]+k|wifi|wcss-pil)", value) for value in compatible):
            require(not dt.enabled(path), "Wireless consumer is enabled: " + path)
        if "qcom,rproc" in props:
            require(dt.resolve(props["qcom,rproc"]) == wcss[0], "Unexpected wireless remoteproc reference")
        if "memory-region" not in props:
            continue
        data = props["memory-region"]
        require(len(data) > 0 and len(data) % 4 == 0, "Malformed memory-region phandles: " + path)
        for i in range(0, len(data), 4):
            target = dt.resolve(data[i:i + 4])
            require(target in expected, "Unexpected reserved-memory consumer: " + path)
            memory_references += 1
    return {"q6_bytes": 0x5500000, "q6_reservation_retained": True,
            "wcss_disabled": True, "wifi_disabled": True,
            "protected_reservations_unchanged": True,
            "memory_region_references_verified": memory_references,
            "reclaimed_bytes": 0, "hardware_boot_validated": False}


def verify_board_dtb(data):
    dt = FDT(data)
    require(dt.text("/", "model") == "JDCloud RE-CS-07", "DTB model is not JDCloud RE-CS-07")
    require(strings(dt.prop("/", "compatible")) == ["jdcloud,re-cs-07", "qcom,ipq6018"],
            "Unexpected DTB compatible list")
    expected = {"ethernet0": (1, "wan", 24), "ethernet1": (2, "lan1", 25),
                "ethernet2": (3, "lan2", 26), "ethernet3": (4, "lan3", 27)}
    aliases = dt.nodes.get("/aliases", {})
    actual = {k for k in aliases if re.fullmatch(r"ethernet\d+", k)}
    require(actual == set(expected), "Ethernet aliases differ: %s" % sorted(actual))
    require(aliases.get("label-mac-device") == aliases["ethernet1"], "Label MAC must refer to LAN1/dp2")
    ports = {}
    for alias, (portid, label, phyid) in expected.items():
        path = one_string(aliases[alias])
        require(path in dt.nodes and dt.enabled(path), "Missing/disabled dataplane port " + path)
        require(cell_value(dt.prop(path, "qcom,id")) == portid, "Wrong dataplane port ID")
        require(dt.text(path, "label") == label, "Wrong port label for " + alias)
        phy = dt.resolve(dt.prop(path, "phy-handle"))
        require(cell_value(dt.prop(phy, "reg")) == phyid, "Wrong PHY address for " + alias)
        require(dt.enabled(phy), "Port PHY is disabled")
        ports[alias] = {"path": path, "label": label, "port_id": portid, "phy_address": phyid}
    unused = [path for path, props in dt.nodes.items()
              if props.get("qcom,id") == struct.pack(">I", 5) and path.rsplit("/", 1)[-1] == "dp5"]
    require(len(unused) == 1 and not dt.enabled(unused[0]), "Unused dp5 must remain disabled")
    wifi = dt.compatible("qcom,ipq6018-wifi")
    require(len(wifi) == 1 and not dt.enabled(wifi[0]), "IPQ6018 Wi-Fi must be disabled")
    nss = dt.compatible("qcom,nss")
    require(len(nss) == 1 and dt.enabled(nss[0]), "Expected one enabled NSS core")
    require(cell_value(dt.prop(nss[0], "qcom,id")) == 0, "NSS core ID is not zero")
    require(cell_value(dt.prop(nss[0], "qcom,load-addr")) == 0x40000000, "Wrong NSS load address")
    for name in ("qcom,wlanredirect-enabled", "qcom,wlan-dataplane-offload-enabled"):
        require(name not in dt.nodes[nss[0]], "Wired-only DTB still enables " + name)
    common = dt.compatible("qcom,nss-common")
    require(len(common) == 1, "Expected exactly one NSS common node")
    memory = dt.resolve(dt.prop(common[0], "memory-region"))
    require(memory.startswith("/reserved-memory/"), "NSS phandle does not refer to reserved memory")
    ac = cell_value(dt.prop("/reserved-memory", "#address-cells"))
    sc = cell_value(dt.prop("/reserved-memory", "#size-cells"))
    require(ac in (1, 2) and sc in (1, 2), "Unsupported reserved-memory cell widths")
    reg = dt.prop(memory, "reg")
    require(len(reg) == (ac + sc) * 4, "Unexpected NSS memory reg tuples")
    address = int.from_bytes(reg[:ac * 4], "big")
    size = int.from_bytes(reg[ac * 4:], "big")
    require((address, size) == (0x40000000, 0x01000000), "NSS reservation must be 16 MiB at 0x40000000")
    require("no-map" in dt.nodes[memory], "NSS reserved memory lacks no-map")
    wired_memory = verify_wired_reserved_memory(dt)
    require(dt.prop("/memory@40000000", "reg") == struct.pack(">QQ", 0x40000000, 0x80000000),
            "RE-CS-07 device tree must describe 2 GiB physical RAM")
    mmc = dt.compatible("qcom,ipq6018-sdhci")
    require(len(mmc) == 1 and dt.enabled(mmc[0]), "Expected one enabled eMMC controller")
    require(cell_value(dt.prop(mmc[0], "bus-width")) == 8 and "non-removable" in dt.nodes[mmc[0]],
            "eMMC must use an 8-bit non-removable bus")
    nand = dt.compatible("qcom,ipq6018-nand")
    require(all(not dt.enabled(path) for path in nand), "RE-CS-07 may not enable NAND storage")
    switch = dt.compatible("qcom,ess-switch-ipq60xx")
    require(len(switch) == 1 and dt.enabled(switch[0]), "Expected one enabled IPQ60xx switch")
    for name, value in (("switch_lan_bmp", 0x1c), ("switch_wan_bmp", 0x2)):
        require(cell_value(dt.prop(switch[0], name)) == value, "Switch port bitmap differs: " + name)
    switch_ports = {}
    for portid, phyid in ((1, 24), (2, 25), (3, 26), (4, 27)):
        path = switch[0] + "/qcom,port_phyinfo/port@%d" % portid
        require(cell_value(dt.prop(path, "port_id")) == portid and cell_value(dt.prop(path, "phy_address")) == phyid,
                "Switch port/PHY map differs: " + path)
        switch_ports[str(portid)] = phyid
    return {"model": "JDCloud RE-CS-07", "compatible": ["jdcloud,re-cs-07", "qcom,ipq6018"],
            "ports": ports, "wifi_disabled": True, "nss_node": nss[0],
            "nss_reserved_memory": {"path": memory, "address": hex(address), "bytes": size},
            "wired_memory": wired_memory,
            "emmc": {"controller": mmc[0], "bus_width": 8, "non_removable": True},
            "physical_ram_bytes_in_dtb": 0x80000000,
            "switch": {"lan_bitmap": "0x1c", "wan_bitmap": "0x2", "port_phy_map": switch_ports},
            "sha256": sha256(dt.data)}


def inflate_gzip(data):
    require(data[:2] == b"\x1f\x8b", "Kernel payload is not gzip")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    result = decoder.decompress(data, MAX_INFLATED_KERNEL + 1)
    require(len(result) <= MAX_INFLATED_KERNEL and decoder.eof, "Truncated/oversized gzip kernel")
    require(not decoder.unused_data, "Unexpected bytes after gzip kernel")
    return result


def verify_fit(data, kernel_version, epoch=EXPECTED_EPOCH):
    fit = FDT(data)
    require(cell_value(fit.prop("/", "timestamp")) == epoch, "FIT SOURCE_DATE_EPOCH timestamp differs")
    default = fit.text("/configurations", "default")
    require(default == "config@cp03-c4", "Unexpected FIT default configuration: " + default)
    config = "/configurations/" + default
    kernel_node = "/images/" + fit.text(config, "kernel")
    dtb_node = "/images/" + fit.text(config, "fdt")
    payloads, image_reports = {}, {}
    for path in fit.children("/images"):
        props = fit.nodes[path]
        if "data" in props:
            payload = props["data"]
        else:
            length = cell_value(fit.prop(path, "data-size"))
            if "data-position" in props:
                offset = cell_value(props["data-position"])
            else:
                offset = ((fit.total + 3) & ~3) + cell_value(fit.prop(path, "data-offset"))
            require(offset >= fit.total and offset + length <= len(data), "FIT external image out of bounds")
            payload = data[offset:offset + length]
        hashes = []
        for child in fit.children(path):
            if not child.rsplit("/", 1)[1].startswith("hash"):
                continue
            algo = fit.text(child, "algo")
            expected = fit.prop(child, "value")
            if algo == "crc32":
                digest = struct.pack(">I", zlib.crc32(payload))
            else:
                require(algo in ("sha1", "sha256", "sha384", "sha512", "md5"),
                        "Unsupported FIT hash algorithm: " + algo)
                digest = hashlib.new(algo, payload).digest()
            require(digest == expected, "FIT %s hash mismatch: %s" % (algo, path))
            hashes.append(algo)
        require(bool(hashes), "FIT image has no verified hash: " + path)
        payloads[path] = payload
        image_reports[path] = {"bytes": len(payload), "hashes": hashes, "sha256": sha256(payload)}
    require(kernel_node in payloads and dtb_node in payloads, "FIT references absent kernel/DTB")
    for prop, expected in (("type", "kernel"), ("arch", "arm64"), ("os", "linux"), ("compression", "gzip")):
        require(fit.text(kernel_node, prop) == expected, "Unexpected FIT kernel " + prop)
    for prop in ("load", "entry"):
        require(cell_value(fit.prop(kernel_node, prop)) == 0x41000000, "FIT kernel %s address differs" % prop)
    require(fit.text(dtb_node, "type") == "flat_dt", "FIT DTB type differs")
    require(fit.text(dtb_node, "compression") == "none", "FIT DTB unexpectedly compressed")
    kernel = inflate_gzip(payloads[kernel_node])
    require(len(kernel) >= 64 and kernel[56:60] == b"ARM\x64", "Decompressed kernel lacks ARM64 Image magic")
    banner = re.search(rb"Linux version ([^\x00\n]{1,240})", kernel)
    require(banner is not None, "Kernel version banner missing")
    version = banner.group(1).decode("ascii", "replace")
    require(re.match(re.escape(kernel_version) + r"(?:\s|[-+])", version), "Unexpected kernel version: " + version)
    board = verify_board_dtb(payloads[dtb_node])
    return {"configuration": default, "load": "0x41000000", "entry": "0x41000000",
            "kernel_version_banner": version, "kernel_uncompressed_bytes": len(kernel),
            "kernel_image_size_field": struct.unpack_from("<Q", kernel, 16)[0],
            "timestamp": epoch, "images": image_reports, "dtb": board}, kernel, payloads[dtb_node]


def verify_fwtool(data, version_number=EXPECTED_VERSION, revision=EXPECTED_REVISION):
    end, metadata, trailers = len(data), None, []
    for _ in range(8):
        if end < 16 or data[end - 16:end - 12] != b"FWx0":
            break
        magic, checksum, kind, size = struct.unpack_from(">IIB3xI", data, end - 16)
        require(16 <= size <= end, "Invalid fwtool trailer size")
        require(data[end - 7:end - 4] == b"\0\0\0", "Nonzero fwtool trailer padding")
        require(crc_raw(data[:end - 16]) == checksum, "fwtool trailer CRC mismatch")
        start = end - size
        if kind == 1:
            require(metadata is None and size >= 24, "Duplicate/short fwtool metadata")
            require(data[start:start + 8] == b"\0" * 8, "Unsupported fwtool metadata header")
            metadata = json.loads(data[start + 8:end - 16].decode("utf-8"))
        else:
            require(kind == 0, "Unknown fwtool trailer type")
        trailers.append({"type": "metadata" if kind == 1 else "signature", "bytes": size,
                         "crc32": "%08x" % checksum})
        end = start
    require(metadata is not None, "fwtool metadata not found")
    require(isinstance(metadata, dict), "fwtool metadata must be an object")
    supported = metadata.get("new_supported_devices", metadata.get("supported_devices", []))
    require(isinstance(supported, list), "fwtool supported_devices must be an array")
    require(supported == ["jdcloud,re-cs-07"], "fwtool metadata must support only jdcloud,re-cs-07")
    version = metadata.get("version", {})
    require(isinstance(version, dict), "fwtool version must be an object")
    require(version.get("target") == "qualcommax/ipq60xx", "fwtool target differs")
    require(version.get("board") == "jdcloud_re-cs-07", "fwtool board differs")
    require(str(version.get("version", "")).startswith("25.12"), "fwtool release is not 25.12")
    require(version.get("dist") == "OpenWrt", "fwtool distribution differs")
    require(version.get("version") == version_number, "fwtool custom release differs")
    require(version.get("revision") == revision, "fwtool custom revision differs")
    return data[:end], {"metadata": metadata, "trailers": trailers,
                       "signature_authenticity_checked": False}


def parse_sysupgrade(data, version_number=EXPECTED_VERSION, revision=EXPECTED_REVISION):
    archive, metadata = verify_fwtool(data, version_number, revision)
    entries = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        members = tar.getmembers()
        require(0 < len(members) <= 12, "Unexpected sysupgrade member count")
        names = set()
        for member in members:
            name = member.name.rstrip("/")
            require(name not in names, "Duplicate sysupgrade tar member")
            names.add(name)
            parts = PurePosixPath(name).parts
            require(parts and parts[0] == "sysupgrade-jdcloud_re-cs-07" and ".." not in parts,
                    "Unexpected sysupgrade tar path: " + name)
            require(member.isdir() or member.isfile(), "Non-regular sysupgrade tar member")
            if member.isfile():
                require(member.size <= MAX_IMAGE_SIZE, "Oversized tar member")
                entries[name] = tar.extractfile(member).read()
    prefix = "sysupgrade-jdcloud_re-cs-07/"
    require(set(entries) == {prefix + "CONTROL", prefix + "kernel", prefix + "root"},
            "Unexpected/missing sysupgrade payload members")
    require(entries[prefix + "CONTROL"].strip() == b"BOARD=jdcloud_re-cs-07", "Sysupgrade CONTROL board differs")
    metadata["emmc_partition_budgets"] = verify_emmc_budgets(
        len(entries[prefix + "kernel"]), len(entries[prefix + "root"]))
    return entries[prefix + "kernel"], entries[prefix + "root"], metadata


def verify_emmc_budgets(kernel_bytes, rootfs_bytes):
    """Match emmc.sh's 64 KiB overlay alignment plus its 4 KiB marker write."""
    require(0 < kernel_bytes <= HLOS_SIZE, "TAR kernel exceeds the 6 MiB eMMC HLOS partition")
    require(rootfs_bytes > 0, "TAR rootfs is empty")
    aligned = (rootfs_bytes + ROOTFS_ALIGNMENT - 1) // ROOTFS_ALIGNMENT * ROOTFS_ALIGNMENT
    footprint = aligned + ROOTFS_OVERLAY_MARKER
    require(footprint <= ROOTFS_SIZE,
            "TAR rootfs plus aligned overlay marker exceeds the 60 MiB eMMC rootfs partition")
    return {"kernel_bytes": kernel_bytes, "hlos_limit_bytes": HLOS_SIZE,
            "rootfs_bytes": rootfs_bytes, "rootfs_aligned_bytes": aligned,
            "overlay_marker_bytes": ROOTFS_OVERLAY_MARKER, "rootfs_footprint_bytes": footprint,
            "rootfs_limit_bytes": ROOTFS_SIZE, "actual_partition_capacity_checked_on_device": False}


def squashfs_info(data):
    require(len(data) >= 96 and data[:4] == b"hsqs", "Rootfs is not little-endian SquashFS")
    major, minor = struct.unpack_from("<HH", data, 28)
    require((major, minor) == (4, 0), "Unsupported SquashFS version")
    used = struct.unpack_from("<Q", data, 40)[0]
    require(96 <= used <= len(data), "SquashFS bytes_used exceeds payload")
    return {"bytes_used": used, "padded_bytes": len(data), "sha256_used_bytes": sha256(data[:used]),
            "creation_timestamp": struct.unpack_from("<I", data, 8)[0],
            "compression_id": struct.unpack_from("<H", data, 20)[0],
            "block_size": struct.unpack_from("<I", data, 12)[0]}


def verify_manifest(path, kernel_version):
    packages = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split(" - ", 1)
        name = parts[0].strip()
        require(name and name not in packages, "Invalid/duplicate manifest package")
        packages[name] = parts[1].strip() if len(parts) == 2 else ""
    required = {"kmod-qca-nss-dp", "kmod-qca-ssdk", "kmod-qca-nss-drv", "kmod-qca-nss-ecm",
                "kmod-qca-nss-drv-bridge-mgr", "kmod-qca-nss-drv-vlan-mgr", "nss-firmware-ipq60xx",
                "luci-base", "luci-mod-admin-full", "ppp", "ppp-mod-pppoe", "kmod-pppoe",
                "kmod-wireguard", "wireguard-tools", "luci-proto-wireguard", "kmod-tun", "kmod-inet-diag",
                "kmod-crypto-lib-chacha20", "kmod-crypto-lib-chacha20poly1305", "kmod-crypto-lib-curve25519",
                "kmod-crypto-lib-poly1305", "kmod-udptunnel4", "kmod-udptunnel6", "ucode", "luci-lib-uqr", "resolveip"}
    # Verify the current compact profile survived both Kconfig and image assembly.
    selected = set(re.findall(r"^CONFIG_PACKAGE_([^=\n]+)=y$",
                              (ROOT / "Config/RE-CS-07-NSS.config").read_text(), re.M))
    required |= selected
    require("dnsmasq" not in packages and "dnsmasq-dhcpv6" not in packages,
            "Base dnsmasq conflicts with the requested full variant")
    require(required.issubset(packages), "Required manifest packages missing: " + ", ".join(sorted(required - packages.keys())))
    forbidden = [p for p in packages if re.match(r"(?:wpad|hostapd|wpa-supplicant|ath\d+k-firmware|ipq-wifi|kmod-(?:ath\d|ath$|mac80211|cfg80211|mt76|mt79|rt2|rtw|rtl8|brcmfmac|brcmsmac))", p)]
    require(not forbidden, "Radio packages in wired-only manifest: " + ", ".join(forbidden))
    require(re.match(re.escape(kernel_version) + r"(?:[~+.-]|$)", packages.get("kernel", "")),
            "Manifest kernel version differs")
    require(packages["nss-firmware-ipq60xx"] == "2025.05.01-r1", "Manifest NSS firmware package version differs")
    require(packages.get("base-files") == "1~f0a60eee", "Manifest base-files package is stale or has the wrong source revision")
    for name, expected in (("wireguard-tools", "1.0.20250521-r1"),
                           ("luci-proto-wireguard", "26.180.75667~128a781"),
                           ("kmod-wireguard", kernel_version + "-r1"),
                           ("kmod-tun", kernel_version + "-r1"),
                           ("kmod-inet-diag", kernel_version + "-r1")):
        require(packages.get(name) == expected, "Requested network package version differs: " + name)
    return {"package_count": len(packages), "required_packages": {p: packages[p] for p in sorted(required)},
            "radio_packages_absent": True, "kernel": packages["kernel"],
            "package_versions": packages}


def load_config(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        match = re.fullmatch(r"# (CONFIG_\w+) is not set", line)
        if match:
            values[match.group(1)] = "n"
        elif line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def audit_configs(build_root, kernel_version, version_number=EXPECTED_VERSION, revision=EXPECTED_REVISION):
    config_path = build_root / ".config"
    config = load_config(config_path)
    enabled = ("TARGET_qualcommax_ipq60xx_DEVICE_jdcloud_re-cs-07", "PACKAGE_kmod-qca-nss-drv", "PACKAGE_kmod-qca-nss-ecm",
               "PACKAGE_kmod-qca-nss-drv-bridge-mgr", "PACKAGE_kmod-qca-nss-drv-vlan-mgr", "PACKAGE_nss-firmware-ipq60xx",
               "NSS_FIRMWARE_VERSION_12_5", "NSS_MEM_PROFILE_MEDIUM", "IPQ_MEM_PROFILE_1024", "KERNEL_PREEMPT_NONE",
               "KERNEL_PREEMPT_NONE_BUILD", "KERNEL_DEBUG_FS", "NSS_DRV_PPPOE_ENABLE",
               "PACKAGE_kmod-wireguard", "PACKAGE_wireguard-tools", "PACKAGE_luci-proto-wireguard",
               "PACKAGE_kmod-tun", "PACKAGE_kmod-inet-diag", "PACKAGE_block-mount", "AUTOREMOVE")
    disabled = ("NSS_FIRMWARE_VERSION_11_4", "NSS_FIRMWARE_VERSION_12_1", "NSS_FIRMWARE_VERSION_12_2",
                "NSS_MEM_PROFILE_LOW", "NSS_MEM_PROFILE_HIGH", "IPQ_MEM_PROFILE_256", "IPQ_MEM_PROFILE_512",
                "KERNEL_SKB_RECYCLER", "KERNEL_SKB_RECYCLER_PREALLOC", "KERNEL_PREEMPT", "NSS_DRV_WIFIOFFLOAD_ENABLE")
    for name in enabled:
        require(config.get("CONFIG_" + name) == "y", "Build config must enable " + name)
    for name in disabled:
        require(config.get("CONFIG_" + name, "n") == "n", "Build config must disable " + name)
    require(config.get("CONFIG_KERNEL_IPQ_MEM_PROFILE") == "1024", "Kernel IPQ memory profile is not 1024")
    for key, value in (("CONFIG_VERSION_NUMBER", version_number), ("CONFIG_VERSION_CODE", revision)):
        require(config.get(key) == json.dumps(value), "Custom release config differs: " + key)
    kernel_configs = list(build_root.glob("build_dir/target*/linux-qualcommax_ipq60xx/linux-%s/.config" % kernel_version))
    require(len(kernel_configs) == 1, "Cannot select exactly one built kernel .config")
    kernel = load_config(kernel_configs[0])
    for name in ("PREEMPT_NONE", "PREEMPT_NONE_BUILD", "DEBUG_FS", "NF_CONNTRACK_EVENTS"):
        require(kernel.get("CONFIG_" + name) == "y", "Built kernel must enable " + name)
    for name in ("PREEMPT", "SKB_RECYCLER", "SKB_RECYCLER_PREALLOC", "ATH11K", "MAC80211", "CFG80211"):
        require(kernel.get("CONFIG_" + name, "n") == "n", "Built kernel must disable " + name)
    network_configs = ("WIREGUARD", "TUN", "INET_DIAG", "INET_TCP_DIAG", "INET_UDP_DIAG", "INET_RAW_DIAG",
                       "CRYPTO_LIB_CHACHA", "CRYPTO_LIB_CHACHA20POLY1305", "CRYPTO_LIB_CURVE25519",
                       "CRYPTO_LIB_POLY1305", "NET_UDP_TUNNEL")
    for name in network_configs:
        require(kernel.get("CONFIG_" + name) == "m", "Built kernel must provide a module for " + name)
    require(kernel.get("CONFIG_IPV6") == "y", "IPv6 is required for the delivered IPv6 UDP-tunnel support")
    require(kernel.get("CONFIG_INET_DIAG_DESTROY", "n") == "n", "INET_DIAG_DESTROY unexpectedly enabled")
    require(kernel.get("CONFIG_WIREGUARD_DEBUG", "n") == "n", "WIREGUARD_DEBUG unexpectedly enabled")
    return {"build_config": str(config_path),
            "requested_network_module_configs": {name: kernel["CONFIG_" + name] for name in network_configs}, "kernel_config": str(kernel_configs[0]),
            "memory_profile": "1024/MEDIUM for the 2 GiB board; physical RAM capacity is not verified", "nss_firmware": "12.5", "preemption": "NONE",
            "skb_recycler_and_preallocation_disabled": True, "wifi_disabled": True,
            "nf_conntrack_events": kernel.get("CONFIG_NF_CONNTRACK_EVENTS", "n")}


def audit_build_pins(build_root, revision=EXPECTED_REVISION, epoch=EXPECTED_EPOCH):
    def git(path, *args):
        result = subprocess.run(["git", "-C", str(path), *args], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30, check=False)
        require(result.returncode == 0, "Cannot inspect source Git state: " + str(path))
        return result.stdout.decode("utf-8", "strict").strip()

    require(git(build_root, "rev-parse", "HEAD") == EXPECTED_BASE_COMMIT,
            "OpenWrt checkout is not the exact official v25.12.5 base commit")
    require(git(build_root, "rev-parse", "v25.12.5^{commit}") == EXPECTED_BASE_COMMIT,
            "OpenWrt v25.12.5 tag does not resolve to the expected base")
    require(git(build_root, "show", "-s", "--format=%ct", "HEAD") == str(epoch),
            "OpenWrt base commit timestamp differs from expected SOURCE_DATE_EPOCH")
    require((build_root / "version").read_text().strip() == revision, "version file differs")
    require((build_root / "version.date").read_text().strip() == str(epoch), "version.date differs")
    kernel = (build_root / "target/linux/generic/kernel-6.12").read_text()
    require(re.search(r"^LINUX_VERSION-6\.12\s*=\s*\.94$", kernel, re.M), "Kernel source pin differs")
    require(re.search(r"^LINUX_KERNEL_HASH-6\.12\.94\s*=\s*e998a232b9418db3301cb58468e291a4f41d6ab8306029b30d991f56251dc8d2$",
                      kernel, re.M), "Kernel archive hash differs")
    configured = {}
    for line in (build_root / "feeds.conf").read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            parts = line.split()
            require(len(parts) == 3 and parts[0] == "src-git" and "^" in parts[2],
                    "Feed configuration is not pinned: " + line)
            require(parts[1] not in configured, "Duplicate configured feed")
            configured[parts[1]] = parts[2].rsplit("^", 1)[1]
    require(configured == EXPECTED_FEEDS, "Configured feed pins differ")
    feeds = {}
    for name, expected in EXPECTED_FEEDS.items():
        path = build_root / "feeds" / name
        require(git(path, "rev-parse", "HEAD") == expected, "Checked out feed commit differs: " + name)
        feeds[name] = {"commit": expected, "tracked_modifications": git(path, "status", "--porcelain", "--untracked-files=no")}
    ecm = (build_root / "feeds/nss_packages/qca-nss-ecm/Makefile").read_text()
    require("CONFIG_NF_CONNTRACK_EVENTS=y" in ecm, "NSS feed does not retain conntrack-events build fix")
    return {"base_commit": EXPECTED_BASE_COMMIT, "base_tag": "v25.12.5", "source_date_epoch": epoch,
            "custom_revision": revision, "feeds": feeds,
            "base_tracked_modifications": git(build_root, "status", "--porcelain", "--untracked-files=no"),
            "scope_note": "Git commit pins identify the bases; the local board/NSS port and conntrack-events modification are intentional and must accompany reproduction sources."}


def parse_assignments(data):
    """Parse release-file literals without sourcing or executing shell content."""
    result = {}
    for line in data.decode("utf-8", "strict").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        require(separator and re.fullmatch(r"[A-Z][A-Z0-9_]*", key), "Malformed release assignment")
        require(key not in result, "Duplicate release assignment: " + key)
        parts = shlex.split(value, comments=False, posix=True)
        require(len(parts) <= 1, "Nonliteral release assignment: " + key)
        result[key] = parts[0] if parts else ""
    return result


def audit_release_identity(read, version_number=EXPECTED_VERSION, revision=EXPECTED_REVISION, epoch=EXPECTED_EPOCH):
    openwrt = parse_assignments(read("etc/openwrt_release"))
    os_release = parse_assignments(read("usr/lib/os-release"))
    for key, value in (("DISTRIB_ID", "OpenWrt"), ("DISTRIB_RELEASE", version_number),
                       ("DISTRIB_REVISION", revision), ("DISTRIB_TARGET", "qualcommax/ipq60xx"),
                       ("DISTRIB_ARCH", "aarch64_cortex-a53")):
        require(openwrt.get(key) == value, "Installed release identity differs: " + key)
    for key, value in (("NAME", "OpenWrt"), ("VERSION", version_number),
                       ("BUILD_ID", revision), ("OPENWRT_BOARD", "qualcommax/ipq60xx"),
                       ("OPENWRT_ARCH", "aarch64_cortex-a53"), ("OPENWRT_BUILD_DATE", str(epoch))):
        require(os_release.get(key) == value, "Installed os-release identity differs: " + key)
    require(read("etc/openwrt_version").decode("utf-8").strip() == revision,
            "Installed openwrt_version differs")
    return {"version_number": version_number, "revision": revision, "source_date_epoch": epoch,
            "openwrt_release": openwrt, "os_release": os_release}


def parse_apk_database(data):
    packages = {}
    for entry in data.decode("utf-8", "strict").split("\n\n"):
        if not entry.strip():
            continue
        header = {}
        for line in entry.splitlines():
            if line.startswith(("P:", "V:")):
                key, value = line.split(":", 1)
                require(key not in header, "Duplicate APK package header")
                header[key] = value
        require(header.get("P") and header.get("V"), "APK database entry lacks package/version")
        require(header["P"] not in packages, "Duplicate installed APK package")
        packages[header["P"]] = header["V"]
    require(packages, "Installed APK database is empty")
    return packages


def audit_package_versions(data, manifest):
    installed = parse_apk_database(data)
    require(installed == manifest["package_versions"], "Installed APK package versions differ from manifest: " +
            ", ".join(sorted(name for name in installed.keys() | manifest["package_versions"].keys()
                             if installed.get(name) != manifest["package_versions"].get(name))))
    kmod_dependencies = {}
    for entry in data.decode("utf-8").split("\n\n"):
        fields = {line[:1]: line[2:] for line in entry.splitlines() if line.startswith(("P:", "D:"))}
        name = fields.get("P", "")
        if name.startswith("kmod-"):
            dependencies = fields.get("D", "").split()
            kernel_dependencies = [dep for dep in dependencies if dep.startswith("kernel")]
            require(kernel_dependencies == ["kernel=" + installed["kernel"]],
                    "Installed APK database has stale/different kernel ABI: " + name)
            kmod_dependencies[name] = kernel_dependencies[0]
    return {"package_count": len(installed), "matches_manifest": True,
            "installed_kmod_kernel_dependencies": kmod_dependencies,
            "installed_database_sha256": sha256(data)}


def audit_image_metadata(directory, inputs, blobs, kernel_version, version_number, revision, epoch):
    profiles = json.loads((directory / "profiles.json").read_text())
    for key, value in (("version_number", version_number), ("version_code", revision),
                       ("source_date_epoch", epoch), ("target", "qualcommax/ipq60xx"),
                       ("arch_packages", "aarch64_cortex-a53")):
        require(profiles.get(key) == value, "profiles.json identity differs: " + key)
    require(profiles.get("linux_kernel", {}).get("version") == kernel_version,
            "profiles.json kernel version differs")
    profile = profiles.get("profiles", {}).get("jdcloud_re-cs-07", {})
    require(profile.get("supported_devices") == ["jdcloud,re-cs-07"], "profiles.json supported device differs")
    limits = profile.get("file_size_limits", {})
    require(limits.get("kernel") == HLOS_SIZE, "profiles.json HLOS size limit differs")
    require(limits.get("image") in (None, ROOTFS_SIZE), "profiles.json unexpected combined-image limit")
    records = {entry["name"]: entry for entry in profile.get("images", [])}
    require(len(records) == 2, "Expected exactly two image records in profiles.json")
    for name in ("sysupgrade", "initramfs"):
        record = records.get(inputs[name].name, {})
        require(record.get("sha256") == sha256(blobs[name]) and record.get("size") == len(blobs[name]),
                "profiles.json image digest/size differs: " + name)
    require((directory / "version.buildinfo").read_text().strip() == revision,
            "version.buildinfo custom revision differs")
    sums = {}
    for line in (directory / "sha256sums").read_text().splitlines():
        checksum, name = line.split(None, 1)
        require(re.fullmatch(r"[a-f0-9]{64}", checksum), "Malformed sha256sums digest")
        name = name.lstrip("*")
        require(name not in sums, "Duplicate sha256sums file")
        sums[name] = checksum
    for name, path in inputs.items():
        require(sums.get(path.name) == sha256(blobs[name]), "sha256sums image/manifest mismatch: " + path.name)
    return {"version_number": version_number, "version_code": revision, "source_date_epoch": epoch,
            "linux_kernel": profiles["linux_kernel"], "two_image_sizes_and_hashes_match": True,
            "image_and_manifest_sha256sums_match": True}


def safe_root_path(root, relative):
    """Resolve rootfs absolute/relative symlinks without accessing the host root."""
    pending = list(PurePosixPath("/" + str(relative).lstrip("/")).parts[1:])
    done, links = [], 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            require(bool(done), "Rootfs symlink escapes image root")
            done.pop()
            continue
        candidate = root.joinpath(*done, part)
        if candidate.is_symlink():
            links += 1
            require(links < 32, "Rootfs symlink loop")
            target = os.readlink(candidate)
            if target.startswith("/"):
                done = []
            pending = list(PurePosixPath(target).parts) + pending
            if pending and pending[0] == "/":
                pending.pop(0)
        else:
            done.append(part)
    return root.joinpath(*done)


def undefined_elf_symbols(data):
    """Read actual ELF64 little-endian symbol-table references, without nm."""
    require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01", "Not little-endian ELF64")
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size, count = struct.unpack_from("<HH", data, 58)
    require(entry_size == 64 and count > 0, "Unsupported ELF section table")
    require(section_offset + entry_size * count <= len(data), "ELF section table out of bounds")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, section_offset + index * entry_size)
                for index in range(count)]
    result = set()
    symbol_tables = 0
    for section in sections:
        if section[1] != 2:  # SHT_SYMTAB
            continue
        symbol_tables += 1
        offset, size, link, symbol_size = section[4], section[5], section[6], section[9]
        require(symbol_size == 24 and size % 24 == 0 and offset + size <= len(data), "Malformed ELF symbol table")
        require(link < count and sections[link][1] == 3, "ELF symbol string-table link is invalid")
        string_section = sections[link]
        begin, length = string_section[4], string_section[5]
        require(begin + length <= len(data), "ELF symbol strings out of bounds")
        names = data[begin:begin + length]
        for index in range(size // 24):
            name_offset, info, _, section_index, _, _ = struct.unpack_from("<IBBHQQ", data, offset + index * 24)
            if section_index != 0 or info >> 4 not in (1, 2):
                continue
            require(name_offset < len(names), "ELF symbol name out of bounds")
            end = names.find(b"\0", name_offset)
            require(end >= name_offset, "Unterminated ELF symbol name")
            result.add(names[name_offset:end].decode("ascii", "strict"))
    require(symbol_tables > 0, "ELF module has no readable symbol table")
    return result


def elf64_sections(data):
    """Read bounded AArch64 ELF section contents without executing target code."""
    require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01", "Not little-endian ELF64")
    require(struct.unpack_from("<H", data, 18)[0] == 183, "ELF is not AArch64")
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, names_index = struct.unpack_from("<HHH", data, 58)
    require(size == 64 and 0 < names_index < count and offset + size * count <= len(data),
            "Invalid ELF64 section-header table")
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * size) for i in range(count)]
    strings_header = headers[names_index]
    require(strings_header[1] == 3 and strings_header[4] + strings_header[5] <= len(data),
            "Invalid ELF64 section-name table")
    names = data[strings_header[4]:strings_header[4] + strings_header[5]]
    result = {}
    for header in headers:
        require(header[0] < len(names), "ELF64 section name is out of bounds")
        end = names.find(b"\0", header[0])
        require(end >= 0, "Unterminated ELF64 section name")
        name = names[header[0]:end].decode("ascii", "strict")
        if header[1] == 8:  # SHT_NOBITS has no bytes in the file.
            continue
        require(header[4] + header[5] <= len(data), "ELF64 section data is out of bounds")
        require(not name or name not in result, "Duplicate ELF64 section name: " + name)
        result[name] = data[header[4]:header[4] + header[5]]
    return result


def module_info(data, filename, kernel_version):
    require(len(data) >= 64, "Truncated ELF module: " + filename)
    require(struct.unpack_from("<H", data, 16)[0] == 1, "Kernel module is not relocatable ELF: " + filename)
    sections = elf64_sections(data)
    require(".modinfo" in sections, "Kernel module has no .modinfo: " + filename)
    fields = collections.defaultdict(list)
    for entry in sections[".modinfo"].split(b"\0"):
        if entry:
            key, separator, value = entry.partition(b"=")
            require(separator, "Malformed .modinfo field: " + filename)
            fields[key.decode("ascii")].append(value.decode("ascii"))
    for key in ("name", "depends", "vermagic"):
        require(len(fields[key]) == 1, "Missing/duplicate module %s: %s" % (key, filename))
    name = fields["name"][0]
    require(name == filename[:-3].replace("-", "_"), "ELF module name does not match filename: " + filename)
    expected_vermagic = kernel_version + " SMP mod_unload aarch64"
    require(fields["vermagic"][0].strip() == expected_vermagic, "Module kernel vermagic differs: " + filename)
    raw_depends = fields["depends"][0].split(",") if fields["depends"][0] else []
    depends = [name.replace("-", "_") for name in raw_depends]
    require(len(depends) == len(set(depends)) and all(re.fullmatch(r"[A-Za-z0-9_-]+", d) for d in raw_depends),
            "Malformed/duplicate module dependencies: " + filename)
    return {"name": name, "depends": depends, "vermagic": fields["vermagic"][0], "sha256": sha256(data)}


def audit_module_tree(entries, kernel_version=EXPECTED_KERNEL):
    """Resolve every shipped module's actual .modinfo dependencies in that image."""
    paths = {name: entry for name, entry in entries.items()
             if name.startswith("lib/modules/") and name.endswith(".ko")}
    require(paths, "Delivered module tree is empty")
    modules, hashes = {}, {}
    for path, entry in sorted(paths.items()):
        require(stat.S_ISREG(entry["mode"]), "Nonregular module in image: " + path)
        require(path.startswith("lib/modules/" + kernel_version + "/"), "Wrong kernel module directory: " + path)
        filename = path.rsplit("/", 1)[-1]
        info = module_info(entry["data"], filename, kernel_version)
        require(info["name"] not in modules, "Duplicate delivered module name: " + info["name"])
        info["path"] = path
        modules[info["name"]] = info
        hashes[path] = info["sha256"]
    for name, info in modules.items():
        require(set(info["depends"]) <= modules.keys(), "Unresolved dependencies for %s: %s" %
                (name, ", ".join(sorted(set(info["depends"]) - modules.keys()))))
    required = ("wireguard", "tun", "inet_diag", "tcp_diag", "udp_diag", "raw_diag")
    require(set(required) <= modules.keys(), "Requested network modules are missing from delivered image")
    for name in ("tcp_diag", "udp_diag", "raw_diag"):
        require("inet_diag" in modules[name]["depends"], name + " is not linked to inet_diag")
    require({"udp_tunnel", "ip6_udp_tunnel", "libcurve25519_generic", "libchacha20poly1305"} <=
            set(modules["wireguard"]["depends"]), "WireGuard dependency set is incomplete")
    visiting, visited = set(), set()
    def visit(name):
        require(name not in visiting, "Circular module dependency: " + name)
        if name in visited:
            return
        visiting.add(name)
        for dependency in modules[name]["depends"]:
            visit(dependency)
        visiting.remove(name)
        visited.add(name)
    for name in modules:
        visit(name)
    return {"module_count": len(modules), "all_dependencies_resolve": True,
            "common_vermagic": kernel_version + " SMP mod_unload aarch64",
            "requested_modules": {name: modules[name] for name in required},
            "all_modules": modules, "all_module_sha256": hashes}


NETWORK_FILES = (
    "usr/bin/wg", "usr/bin/wireguard_watchdog", "lib/netifd/proto/wireguard.sh",
    "www/luci-static/resources/protocol/wireguard.js",
    "www/luci-static/resources/view/wireguard/status.js",
    "usr/share/luci/menu.d/luci-proto-wireguard.json",
    "usr/share/rpcd/acl.d/luci-wireguard.json", "usr/share/rpcd/ucode/luci.wireguard",
    "etc/modules.d/30-tun", "etc/modules.d/31-inet-diag", "etc/modules.d/wireguard",
)


def audit_wg_elf(data):
    """Use program headers: OpenWrt sstrip legitimately removes section tables."""
    require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01", "wg is not little-endian ELF64")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    require(kind in (2, 3) and machine == 183 and version == 1, "wg is not an AArch64 ELF executable")
    entry, offset = struct.unpack_from("<QQ", data, 24)
    size, count = struct.unpack_from("<HH", data, 54)
    require(size == 56 and 0 < count <= 128 and offset + size * count <= len(data),
            "wg has an invalid program-header table")
    programs = [struct.unpack_from("<IIQQQQQQ", data, offset + size * i) for i in range(count)]
    for header in programs:
        require(header[2] + header[5] <= len(data), "wg program segment extends outside file")
        if header[0] == 1:
            require(header[6] >= header[5], "wg load segment has invalid memory/file sizes")
    loads = [header for header in programs if header[0] == 1]
    require(any(h[1] & 1 and h[3] <= entry < h[3] + h[6] for h in loads),
            "wg entry point is outside executable load segments")
    interpreters = [data[h[2]:h[2] + h[5]] for h in programs if h[0] == 3]
    require(interpreters == [b"/lib/ld-musl-aarch64.so.1\0"], "wg ELF dynamic interpreter differs")
    dynamics = [h for h in programs if h[0] == 2]
    require(len(dynamics) == 1 and dynamics[0][5] % 16 == 0, "wg dynamic table is missing/invalid")
    dynamic = dynamics[0]
    tags = collections.defaultdict(list)
    for position in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = struct.unpack_from("<qQ", data, position)
        tags[tag].append(value)
        if tag == 0:
            break
    require(0 in tags and len(tags[5]) == len(tags[10]) == 1, "wg dynamic strings are invalid")
    address, length = tags[5][0], tags[10][0]
    segments = [h for h in loads if h[3] <= address and address + length <= h[3] + h[5]]
    require(len(segments) == 1, "wg dynamic string table does not map to file bytes")
    begin = segments[0][2] + address - segments[0][3]
    names, libraries = data[begin:begin + length], []
    for string_offset in tags[1]:
        require(string_offset < len(names), "wg library string is out of bounds")
        end = names.find(b"\0", string_offset)
        require(end >= string_offset, "wg library string is unterminated")
        libraries.append(names[string_offset:end].decode("ascii"))
    require(set(libraries) == {"libgcc_s.so.1", "libc.so"}, "wg dynamic library dependencies differ")
    require(b"1.0.20250521" in data, "wg executable does not identify the pinned upstream version")
    return {"architecture": "AArch64", "elf_type": kind, "load_segment_count": len(loads),
            "entry_in_executable_segment": True, "interpreter": "/lib/ld-musl-aarch64.so.1",
            "dynamic_libraries": libraries, "upstream_version": "1.0.20250521",
            "section_table_present": struct.unpack_from("<Q", data, 40)[0] != 0}


def audit_network_support(entries, kernel_version=EXPECTED_KERNEL):
    modules = audit_module_tree(entries, kernel_version)
    def read(name):
        item = entries.get(name, {})
        require(stat.S_ISREG(item.get("mode", 0)) and item.get("data"),
                "Requested network file missing/empty/nonregular: " + name)
        return item["data"]
    for name in NETWORK_FILES:
        read(name)
    for name in ("usr/bin/wg", "usr/bin/wireguard_watchdog", "lib/netifd/proto/wireguard.sh"):
        require(entries[name]["mode"] & stat.S_IXUSR, "Network executable lacks execute bit: " + name)
    wg = read("usr/bin/wg")
    wg_elf = audit_wg_elf(wg)
    netifd = read("lib/netifd/proto/wireguard.sh").decode("utf-8")
    for marker in ("proto_wireguard_init_config", "proto_wireguard_setup", "proto_wireguard_teardown", "add_protocol wireguard"):
        require(marker in netifd, "WireGuard netifd protocol is incomplete: " + marker)
    require(read("usr/bin/wireguard_watchdog").startswith(b"#!/bin/sh"), "WireGuard watchdog is not a shell script")
    protocol = read("www/luci-static/resources/protocol/wireguard.js")
    require(b"registerProtocol" in protocol and b"wireguard" in protocol, "LuCI WireGuard protocol registration is absent")
    status = read("www/luci-static/resources/view/wireguard/status.js")
    require(b"getWgInstances" in status, "LuCI WireGuard status view is incomplete")
    menu = json.loads(read("usr/share/luci/menu.d/luci-proto-wireguard.json"))
    require(menu.get("admin/status/wireguard", {}).get("action", {}).get("path") == "wireguard/status",
            "LuCI WireGuard status menu target differs")
    acl = json.loads(read("usr/share/rpcd/acl.d/luci-wireguard.json"))
    read_rpc = acl.get("luci-proto-wireguard", {}).get("read", {}).get("ubus", {}).get("luci.wireguard", [])
    require("getWgInstances" in read_rpc, "LuCI WireGuard RPC ACL is incomplete")
    rpc = read("usr/share/rpcd/ucode/luci.wireguard")
    for marker in (b"getWgInstances", b"generateKeyPair", b"generatePsk"):
        require(marker in rpc, "LuCI WireGuard RPC implementation is incomplete")
    for path, expected in (("etc/modules.d/30-tun", {"tun"}),
                           ("etc/modules.d/31-inet-diag", {"inet_diag", "tcp_diag", "udp_diag", "raw_diag"}),
                           ("etc/modules.d/wireguard", {"wireguard"})):
        loaded = {line.split()[0] for line in read(path).decode().splitlines() if line.strip() and not line.startswith("#")}
        require(loaded == expected, "Network module autoload list differs: " + path)
    return {"module_tree": modules, "file_sha256": {name: sha256(read(name)) for name in NETWORK_FILES},
            "wg_aarch64_elf_executable": True, "wg_elf": wg_elf, "netifd_protocol_present": True,
            "wg_execution_test": "Not performed: static offline checks only; target executable is never run by this verifier",
            "luci_protocol_status_rpc_and_acl_present": True, "autoload_lists_verified": True,
            "wireguard_scope": "Standard Linux software WireGuard; NSS WireGuard offload is not claimed"}


def audit_kmod_apks(build_root, manifest, module_tree, kernel_version=EXPECTED_KERNEL):
    """Check every built kmod APK ABI and every installed module's package payload hash."""
    kernels = list(build_root.glob("build_dir/target*/linux-qualcommax_ipq60xx/linux-%s" % kernel_version))
    require(len(kernels) == 1, "Cannot select built kernel for APK ABI audit")
    kernel = kernels[0]
    config_set = (kernel / ".config.set").read_bytes()
    enabled_lines = sorted(line for line in config_set.splitlines() if re.search(rb"=[ym]", line))
    abi = hashlib.md5(b"\n".join(enabled_lines) + b"\n").hexdigest()
    require((kernel / ".vermagic").read_text().strip() == abi, "Kernel ABI does not match config-derived OpenWrt hash")
    expected_kernel = kernel_version + "~" + abi + "-r1"
    require(manifest["kernel"] == expected_kernel, "Manifest kernel package ABI differs from current build")
    tool = build_root / "staging_dir/host/bin/apk"
    require(tool.is_file() and os.access(tool, os.X_OK), "Built APK inspector is unavailable")
    paths = sorted((build_root / "bin/targets/qualcommax/ipq60xx/packages").glob("kmod-*.apk"))
    require(paths, "No built kmod APKs found")
    result = subprocess.run([str(tool), "--network=no", "--allow-untrusted", "verify", *map(str, paths)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False)
    require(result.returncode == 0, "Kmod APK integrity check failed: " + result.stderr.decode("utf-8", "replace")[-2000:])
    records, installed_payloads = {}, {}
    for path in paths:
        result = subprocess.run([str(tool), "--network=no", "adbdump", "--format", "json", str(path)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        require(result.returncode == 0, "Cannot read kmod APK metadata: " + path.name)
        data = json.loads(result.stdout)
        info = data.get("info", {})
        name = info.get("name", "")
        require(name.startswith("kmod-") and name not in records, "Duplicate/invalid kmod APK package: " + name)
        require(info.get("arch") == "aarch64_cortex-a53", "Wrong kmod APK architecture: " + name)
        abi_dependencies = [value for value in info.get("depends", []) if value.startswith("kernel")]
        require(abi_dependencies == ["kernel=" + expected_kernel], "Stale/different kernel ABI in APK: " + name)
        installed = name in manifest["package_versions"]
        if installed:
            require(info.get("version") == manifest["package_versions"][name], "Installed kmod/APK version mismatch: " + name)
        module_payloads = {}
        for directory in data.get("paths", []):
            for file in directory.get("files", []):
                filename = str(PurePosixPath(directory.get("name", "")) / file["name"])
                if filename.startswith("lib/modules/") and filename.endswith(".ko"):
                    require(filename.startswith("lib/modules/" + kernel_version + "/"), "Wrong module path in APK: " + filename)
                    module_payloads[filename] = file.get("hash")
                    if installed:
                        require(filename not in installed_payloads, "Two installed APKs own the same module: " + filename)
                        require(module_tree["all_module_sha256"].get(filename) == file.get("hash"),
                                "Installed module does not match verified APK payload: " + filename)
                        installed_payloads[filename] = file["hash"]
        records[name] = {"file": path.name, "sha256": sha256(path.read_bytes()), "version": info.get("version"),
                         "kernel_dependency": abi_dependencies[0], "installed": installed, "module_payloads": module_payloads}
    installed_kmods = {name for name in manifest["package_versions"] if name.startswith("kmod-")}
    require(installed_kmods <= records.keys(), "Installed kmod APK missing from build output")
    require(installed_payloads == module_tree["all_module_sha256"], "Delivered module tree has missing/extra APK payloads")
    return {"kernel_abi": abi, "kernel_package": expected_kernel, "derived_from_this_build": True,
            "config_derived_abi_matches": True, "all_kmod_apk_integrity_verified": True,
            "apk_count": len(records), "installed_kmod_count": len(installed_kmods),
            "installed_module_payload_count": len(installed_payloads), "packages": records,
            "note": "APK content hashes are verified; --allow-untrusted does not authenticate a public release signature"}


SERVICE_CONFIG_OPTIONS = (("etc/config/ttyd", "enable"), ("etc/config/upnpd", "enabled"),
                          ("etc/config/sing-box", "enabled"), ("etc/config/sqm", "enabled"))
STORAGE_FILES = ("etc/config/fstab", "sbin/block", "lib/upgrade/platform.sh", "lib/upgrade/emmc.sh")


def squashfs_extract_command(tool, dest, image):
    return [str(tool), "-no-progress", "-no-xattrs", "-processors", "1", "-dest", str(dest), str(image),
            "lib/modules", "lib/firmware", "etc/init.d", "etc/rc.d", "etc/uci-defaults",
            "etc/openwrt_release", "etc/openwrt_version", "usr/lib/os-release", "lib/apk/db/installed", "etc/apk/keys",
            *NETWORK_FILES, *STORAGE_FILES, *(filename for filename, _ in SERVICE_CONFIG_OPTIONS)]


def public_key_fingerprints(files):
    require(files, "No APK public trust keys in image")
    result = {}
    for name, data in sorted(files.items()):
        require(PurePosixPath(name).name == name and name not in {".", ".."}, "Invalid APK public-key filename")
        require(data.startswith(b"-----BEGIN PUBLIC KEY-----\n") and b"PRIVATE KEY" not in data,
                "APK trust file is not a public key: " + name)
        result[name] = sha256(data)
    return result


def root_public_key_fingerprints(root):
    directory = safe_root_path(root, "etc/apk/keys")
    files = {}
    for path in directory.iterdir():
        require(path.is_file() and not path.is_symlink(), "Nonregular APK trust key")
        files[path.name] = path.read_bytes()
    return public_key_fingerprints(files)


def compare_apk_trust(build_root, filesystem, archive):
    roots = list(build_root.glob("build_dir/target*/root-qualcommax"))
    require(len(roots) == 1, "Cannot select exactly one staged package root")
    staged = root_public_key_fingerprints(roots[0])
    require(filesystem["apk_public_keys"] == archive["apk_public_keys"] == staged,
            "SquashFS, initramfs and staged package-index trust keys differ")
    return {"apk_public_keys": staged, "actual_images_and_staging_match": True}


def audit_service_defaults(read):
    # These packages are preinstalled, but no new terminal, proxy, UPnP or SQM
    # service is enabled by this firmware profile.
    checked = {}
    for filename, option in SERVICE_CONFIG_OPTIONS:
        data = read(filename).decode("utf-8")
        choices = re.findall(r"^\s*option\s+" + option + r"\s+['\"]?([01])['\"]?\s*(?:#.*)?$", data, re.M)
        require(choices and all(value == "0" for value in choices),
                "Preinstalled service must remain disabled by default: " + filename)
        checked[filename] = "disabled"
    return checked


def audit_inert_fstab(data):
    """Only one global section is allowed; old data/overlay must never auto-mount."""
    expected = {"anon_swap": "0", "anon_mount": "0", "auto_swap": "0",
                "auto_mount": "0", "delay_root": "5", "check_fs": "0"}
    sections, options = 0, {}
    for line in data.decode("utf-8", "strict").splitlines():
        fields = shlex.split(line, comments=True)
        if not fields:
            continue
        if fields == ["config", "global"]:
            sections += 1
            require(sections == 1, "fstab must have exactly one global section")
        else:
            require(sections == 1 and len(fields) == 3 and fields[0] == "option",
                    "fstab may not contain mount/swap/device/UUID sections or commands")
            key, value = fields[1:]
            require(key not in options, "Duplicate fstab option: " + key)
            options[key] = value
    require(sections == 1 and options == expected,
            "fstab global options must disable anonymous and automatic mount/swap")
    return {"global_options": options, "mount_entries": 0, "swap_entries": 0,
            "automatic_data_and_overlay_mounts_disabled": True}


def audit_storage_support(read):
    result = audit_inert_fstab(read("etc/config/fstab"))
    block = read("sbin/block")
    require(len(block) >= 20 and block[:6] == b"\x7fELF\x02\x01"
            and struct.unpack_from("<H", block, 18)[0] == 183,
            "Manual block-mount utility is missing or not AArch64 ELF")
    result["manual_block_mount_available"] = True
    result["emmc_upgrade"] = audit_emmc_upgrade(read("lib/upgrade/platform.sh"), read("lib/upgrade/emmc.sh"))
    return result


def shell_function(script, name):
    functions = re.findall(r"^" + re.escape(name) + r"\(\) \{\n.*?^\}\s*$", script, re.M | re.S)
    require(len(functions) == 1, "Missing/duplicate shell function: " + name)
    return functions[0].rstrip()


def locked_platform_functions():
    """Read the reviewed implementation from the hash-pinned board patch."""
    path = "Config/RE-CS-07-NSS/patches/re-cs-07-wired-nss-v25.12.5.patch"
    records = [entry for entry in LOCK["patches"] if entry["file"] == path]
    require(len(records) == 1, "Missing/duplicate board patch lock")
    data = (ROOT / path).read_bytes()
    require(sha256(data) == records[0]["sha256"], "Board patch does not match its source lock")
    target = "target/linux/qualcommax/ipq60xx/base-files/lib/upgrade/platform.sh"
    diff = data.decode("utf-8").split("diff --git a/" + target + " b/" + target + "\n", 1)
    require(len(diff) == 2, "Board patch has no eMMC upgrade implementation")
    section = diff[1].split("\ndiff --git ", 1)[0]
    # Keep new-side hunk content, including unchanged function braces/signatures.
    return "\n".join(line[1:] for line in section.splitlines()
                     if line.startswith(" ") or line.startswith("+") and not line.startswith("+++")) + "\n"


def audit_emmc_upgrade(platform_data, emmc_data):
    require(sha256(emmc_data) == EXPECTED_EMMC_HELPER_SHA256,
            "Generic eMMC upgrade helper differs from the pinned official base")
    actual = platform_data.decode("utf-8", "strict")
    expected = locked_platform_functions()
    names = ("re_cs_07_select_slot", "re_cs_07_partition_bytes", "re_cs_07_tar_member_size", "re_cs_07_check_image",
             "re_cs_07_do_upgrade", "platform_check_image", "platform_copy_config")
    for name in names:
        require(shell_function(actual, name) == shell_function(expected, name),
                "Delivered eMMC slot/capacity/config-preservation guard differs: " + name)
    upgrade = shell_function(actual, "platform_do_upgrade")
    require(re.search(r'case "\$\(board_name\)" in\s+jdcloud,re-cs-07\)\s+re_cs_07_do_upgrade "\$1"\s+;;', upgrade),
            "RE-CS-07 sysupgrade must route through its checked eMMC wrapper")
    require(re.search(r"^REQUIRE_IMAGE_METADATA=1$", actual, re.M), "Sysupgrade must require firmware metadata")
    copied = re.search(r"^RAMFS_COPY_BIN='([^']+)'$", actual, re.M)
    require(copied is not None and {"hexdump", "tar", "mktemp", "wc", "cat", "rm", "grep"}.issubset(copied[1].split()),
            "Upgrade ramfs lacks tools needed for eMMC capacity checks")
    return {"slot_and_capacity_guards_match_locked_patch": True,
            "generic_helper_sha256": sha256(emmc_data), "configuration_copy_hook_verified": True,
            "checks_current_slot_before_writing": True, "hardware_upgrade_tested": False}


def reject_foreign_payloads(paths):
    forbidden = [str(path) for path in paths if re.search(r"(?:zn[-_,]m2|99-zz-m2-nss|taiyi)", str(path), re.I)]
    require(not forbidden, "Foreign-board payloads in RE-CS-07 image: " + ", ".join(forbidden))


def audit_rootfs(root, label, version_number=EXPECTED_VERSION, revision=EXPECTED_REVISION,
                 epoch=EXPECTED_EPOCH, manifest=None):
    def read(relative):
        path = safe_root_path(root, relative)
        require(path.is_file(), "Missing rootfs file: " + relative)
        return path.read_bytes()

    reject_foreign_payloads(path.relative_to(root) for path in root.rglob("*"))
    modules = list((root / "lib/modules").rglob("*.ko"))
    names = {p.name: p for p in modules}
    required = ("ecm.ko", "qca-nss-drv.ko", "qca-nss-dp.ko", "qca-ssdk.ko", "qca-nss-bridge-mgr.ko", "qca-nss-vlan.ko")
    module_report = {}
    ecm_notifiers = []
    for name in required:
        require(name in names, "Missing rootfs kernel module: " + name)
        module = safe_root_path(root, names[name].relative_to(root)).read_bytes()
        require(len(module) >= 20 and module[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", module, 18)[0] == 183,
                "Kernel module is not little-endian AArch64 ELF: " + name)
        module_report[name] = sha256(module)
        if name == "ecm.ko":
            undefined = undefined_elf_symbols(module)
            require("nf_conntrack_register_notifier" in undefined,
                    "Installed ecm.ko does not reference nf_conntrack_register_notifier; event notifier code may be compiled out")
            ecm_notifiers = sorted(name for name in undefined if "conntrack" in name and "notifier" in name)
    forbidden = [p.name for p in modules if re.match(r"(?:ath\d|mac80211|cfg80211|mt76|mt79|rtw|brcmfmac)", p.name)]
    require(not forbidden, "Radio modules installed: " + ", ".join(forbidden))
    firmware = read("lib/firmware/qca-nss0-retail.bin")
    require(len(firmware) >= 65536, "NSS firmware blob is implausibly short")
    require(sha256(firmware) == EXPECTED_NSS_FIRMWARE_SHA256, "Installed NSS firmware is not the pinned 12.5-210-CP.R blob")
    script = read("etc/init.d/re-cs-07-nss").decode("utf-8")
    require(script.startswith("#!/bin/sh /etc/rc.common\n"), "Wrong NSS wrapper init shebang")
    require(re.search(r"^START=27$", script, re.M), "NSS wrapper start ordering differs")
    for text in ('"$(board_name)" = "jdcloud,re-cs-07"', "/sys/module/ecm", "/etc/init.d/qca-nss-ecm start", "logger"):
        require(text in script, "NSS wrapper lacks board guard/start/failure handling: " + text)
    require(safe_root_path(root, "etc/init.d/re-cs-07-nss").stat().st_mode & stat.S_IXUSR,
            "NSS wrapper is not executable")
    link = root / "etc/rc.d/S27re-cs-07-nss"
    require(link.is_symlink(), "Missing S27re-cs-07-nss startup symlink")
    require(safe_root_path(root, "etc/rc.d/S27re-cs-07-nss") == safe_root_path(root, "etc/init.d/re-cs-07-nss"),
            "NSS startup symlink target differs")
    upstream = read("etc/init.d/qca-nss-ecm").decode("utf-8")
    require("modprobe ecm" in upstream, "Installed ECM service does not load ECM")
    defaults = read("etc/uci-defaults/99-zz-re-cs-07-nss-wired").decode("utf-8")
    require('"$(board_name)" = "jdcloud,re-cs-07"' in defaults, "NSS defaults lack board guard")
    for key in ("network.globals.packet_steering", "firewall.@defaults[0].flow_offloading", "firewall.@defaults[0].flow_offloading_hw"):
        require(re.search(r"uci\s+-q\s+set\s+" + re.escape(key) + r"=['\"]?0['\"]?(?:\s|$)", defaults),
                "NSS defaults do not disable " + key)
    require(not re.search(r"(?:^EOF\s*$|cat\s*>|\bsysupgrade\s|\bmtd\s+(?:write|erase))", defaults, re.M),
            "Unexpected embedded commands in NSS defaults")
    apk_public_keys = root_public_key_fingerprints(root)
    service_defaults = audit_service_defaults(read)
    storage = audit_storage_support(read)
    release = audit_release_identity(read, version_number, revision, epoch)
    packages = audit_package_versions(read("lib/apk/db/installed"), manifest) if manifest else None
    entries = {}
    for path in modules:
        require(stat.S_ISREG(path.lstat().st_mode), "Nonregular rootfs module: " + str(path.relative_to(root)))
        entries[str(path.relative_to(root))] = {"mode": path.lstat().st_mode, "data": read(str(path.relative_to(root)))}
    for name in NETWORK_FILES:
        path = safe_root_path(root, name)
        require(path.is_file(), "Missing requested network file: " + name)
        entries[name] = {"mode": path.stat().st_mode, "data": path.read_bytes()}
    network = audit_network_support(entries)
    return {"source": label, "module_sha256": module_report, "ecm_notifier_undefined_symbols": ecm_notifiers,
            "nss_firmware_bytes": len(firmware),
            "nss_firmware_sha256": sha256(firmware), "startup_symlink": os.readlink(link),
            "safe_offload_defaults": True, "radio_modules_absent": True,
            "release_identity": release, "installed_packages": packages, "network_support": network,
            "preinstalled_service_defaults": service_defaults, "storage_support": storage,
            "apk_public_keys": apk_public_keys}


def parse_newc(data):
    entries, pos = {}, 0
    while pos + 110 <= len(data):
        require(data[pos:pos + 6] in (b"070701", b"070702"), "Invalid initramfs newc magic")
        with_crc = data[pos:pos + 6] == b"070702"
        fields = [int(data[pos + 6 + index * 8:pos + 14 + index * 8], 16) for index in range(13)]
        mode, size, namesize, checksum = fields[1], fields[6], fields[11], fields[12]
        require(0 < namesize <= 4096 and pos + 110 + namesize <= len(data), "Invalid newc filename extent")
        filename = data[pos + 110:pos + 110 + namesize]
        require(filename.endswith(b"\0"), "Unterminated newc filename")
        name = filename[:-1].decode("utf-8", "strict")
        begin = (pos + 110 + namesize + 3) & ~3
        require(begin + size <= len(data), "Truncated newc file payload")
        content = data[begin:begin + size]
        pos = (begin + size + 3) & ~3
        if name == "TRAILER!!!":
            require(all(byte == 0 for byte in data[pos:]), "Unexpected data after newc trailer")
            return entries
        if with_crc:
            require(sum(content) & 0xFFFFFFFF == checksum, "newc file checksum mismatch")
        name = name.lstrip("/")
        while name.startswith("./"):
            name = name[2:]
        require(".." not in PurePosixPath(name).parts, "Traversal component in newc filename")
        require(name not in entries, "Duplicate newc member: " + name)
        entries[name] = {"mode": mode, "data": content}
    raise VerificationError("Initramfs newc archive has no complete trailer")


def audit_embedded_initramfs(kernel, build_root, kernel_version, version_number=EXPECTED_VERSION,
                             revision=EXPECTED_REVISION, epoch=EXPECTED_EPOCH, manifest=None):
    archives = list(build_root.glob("build_dir/target*/linux-qualcommax_ipq60xx/linux-%s/usr/initramfs_inc_data" % kernel_version))
    require(len(archives) == 1, "Cannot select exactly one built initramfs compressed archive")
    compressed = read_image(archives[0])
    require(compressed[:4] == b"\x28\xb5\x2f\xfd", "Expected zstd-compressed initramfs archive")
    offset = kernel.find(compressed)
    require(offset >= 0 and kernel.find(compressed, offset + 1) == -1,
            "Built initramfs compressed bytes are not uniquely embedded in delivered kernel")
    tool = build_root / "staging_dir/host/bin/zstd"
    require(tool.is_file() and os.access(tool, os.X_OK), "Official built zstd is unavailable for initramfs audit")
    result = subprocess.run([str(tool), "-q", "-d", "-c"], input=compressed,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    require(result.returncode == 0, "Embedded initramfs zstd decode failed: " + result.stderr.decode("utf-8", "replace")[-1000:])
    require(len(result.stdout) <= MAX_IMAGE_SIZE, "Decompressed initramfs exceeds audit size limit")
    entries = parse_newc(result.stdout)
    reject_foreign_payloads(entries)
    def read(relative):
        entry = entries.get(relative, {})
        require(stat.S_ISREG(entry.get("mode", 0)), "Missing/nonregular initramfs release/package file: " + relative)
        return entry["data"]
    require("init" in entries, "Embedded initramfs lacks /init")
    require(stat.S_ISREG(entries["init"]["mode"]) or stat.S_ISLNK(entries["init"]["mode"]), "Invalid /init entry type")
    files = {name.rsplit("/", 1)[-1]: item for name, item in entries.items() if name.startswith("lib/modules/") and name.endswith(".ko")}
    module_report = {}
    for name in ("ecm.ko", "qca-nss-drv.ko", "qca-nss-dp.ko", "qca-ssdk.ko", "qca-nss-bridge-mgr.ko", "qca-nss-vlan.ko"):
        require(name in files and files[name]["data"], "Embedded initramfs lacks module " + name)
        module_report[name] = sha256(files[name]["data"])
    ecm = files["ecm.ko"]["data"]
    require("nf_conntrack_register_notifier" in undefined_elf_symbols(ecm), "Embedded initramfs ECM notifier code is absent")
    forbidden = [name for name in files if re.match(r"(?:ath\d|mac80211|cfg80211|mt76|mt79|rtw|brcmfmac)", name)]
    require(not forbidden, "Embedded initramfs includes radio modules")
    blob = entries.get("lib/firmware/qca-nss0-retail.bin", {}).get("data", b"")
    require(len(blob) >= 65536, "Embedded initramfs lacks NSS firmware")
    require(sha256(blob) == EXPECTED_NSS_FIRMWARE_SHA256, "Initramfs NSS firmware is not the pinned 12.5-210-CP.R blob")
    link = entries.get("etc/rc.d/S27re-cs-07-nss", {})
    # Linux gen_init_cpio stores symlink payloads as strlen(target) + 1;
    # generic newc writers may omit that terminal NUL. Accept both forms.
    require(stat.S_ISLNK(link.get("mode", 0)) and link.get("data") in
            (b"../init.d/re-cs-07-nss", b"../init.d/re-cs-07-nss\0"),
            "Embedded initramfs NSS startup link is missing/incorrect")
    script = entries.get("etc/init.d/re-cs-07-nss", {})
    require(script.get("mode", 0) & stat.S_IXUSR and b"/etc/init.d/qca-nss-ecm start" in script.get("data", b""),
            "Embedded initramfs NSS startup wrapper is missing")
    trust_files = {}
    for path, item in entries.items():
        if path.startswith("etc/apk/keys/"):
            require(stat.S_ISREG(item["mode"]), "Nonregular initramfs APK trust key")
            trust_files[path.removeprefix("etc/apk/keys/")] = item["data"]
    apk_public_keys = public_key_fingerprints(trust_files)
    service_defaults = audit_service_defaults(read)
    storage = audit_storage_support(read)
    release = audit_release_identity(read, version_number, revision, epoch)
    packages = audit_package_versions(read("lib/apk/db/installed"), manifest) if manifest else None
    network = audit_network_support(entries, kernel_version)
    return {"compressed_archive_sha256": sha256(compressed), "compressed_archive_bytes": len(compressed),
            "compressed_archive_kernel_offset": offset, "cpio_sha256": sha256(result.stdout),
            "cpio_bytes": len(result.stdout), "cpio_entries": len(entries), "init_entry_present": True,
            "nss_startup_link_verified": True, "ecm_notifier_reference_verified": True,
            "ecm_module_sha256": sha256(ecm), "nss_firmware_sha256": sha256(blob),
            "radio_modules_absent": True, "module_sha256": module_report,
            "release_identity": release, "installed_packages": packages, "network_support": network,
            "preinstalled_service_defaults": service_defaults, "storage_support": storage,
            "apk_public_keys": apk_public_keys}


def select_input(explicit, directory, patterns, description):
    if explicit:
        return Path(explicit).resolve()
    require(directory is not None, "Supply --%s or --images-dir" % description)
    matches = set()
    for pattern in patterns:
        matches.update(p.resolve() for p in directory.glob(pattern) if p.is_file())
    require(len(matches) == 1, "Need exactly one %s input; found %s" % (description, sorted(map(str, matches))))
    return matches.pop()


class Report:
    def __init__(self):
        self.data = {"schema_version": 1, "result": "pending", "checks": [], "warnings": [], "caveat": CAVEAT}

    def stage(self, name, function):
        try:
            value = function()
            self.data["checks"].append({"check": name, "result": "pass"})
            return value
        except (VerificationError, OSError, ValueError, KeyError, struct.error, tarfile.TarError, zlib.error, subprocess.SubprocessError) as error:
            self.data["checks"].append({"check": name, "result": "fail", "error": str(error)})
            return None

    def finish(self):
        self.data["result"] = "fail" if any(c["result"] == "fail" for c in self.data["checks"]) else "pass"
        return self.data


def verify(args):
    report = Report()
    directory = Path(args.images_dir).resolve() if args.images_dir else None
    inputs = report.stage("input_selection", lambda: {
        "sysupgrade": select_input(args.sysupgrade, directory, ["*jdcloud_re-cs-07*sysupgrade.bin", "*jdcloud_re-cs-07*sysupgrade.tar"], "sysupgrade"),
        "initramfs": select_input(args.initramfs, directory, ["*jdcloud_re-cs-07*initramfs*.itb", "*jdcloud_re-cs-07*initramfs*.bin"], "initramfs"),
        "manifest": select_input(args.manifest, directory, ["*jdcloud_re-cs-07*.manifest"], "manifest")})
    if inputs is None:
        return report.finish()
    report.data["inputs"] = {key: str(path) for key, path in inputs.items()}
    blobs = {}
    report.data["file_sha256"] = {}
    for key, path in inputs.items():
        blob = report.stage("read_" + key, lambda p=path: read_image(p))
        if blob is not None:
            blobs[key] = blob
            report.data["file_sha256"][key] = sha256(blob)
    report.data["expected_identity"] = {"version_number": args.version_number, "revision": args.revision,
                                        "kernel_version": args.kernel_version, "source_date_epoch": args.source_date_epoch}
    extracted = report.stage("sysupgrade_tar_and_fwtool", lambda: parse_sysupgrade(blobs["sysupgrade"], args.version_number, args.revision)) if "sysupgrade" in blobs else None
    sysfit = None
    if extracted:
        kernel_fit, rootfs, metadata = extracted
        report.data["fwtool"] = metadata
        sysfit = report.stage("sysupgrade_fit_and_dtb", lambda: verify_fit(kernel_fit, args.kernel_version, args.source_date_epoch))
        if sysfit:
            report.data["sysupgrade_fit"] = sysfit[0]
        def check_squashfs():
            sq = squashfs_info(rootfs)
            require(sq["creation_timestamp"] == args.source_date_epoch, "SquashFS SOURCE_DATE_EPOCH timestamp differs")
            return sq
        sq = report.stage("sysupgrade_squashfs", check_squashfs)
        if sq:
            report.data["squashfs"] = sq
    else:
        rootfs = None
    initfit = report.stage("initramfs_fit_and_dtb", lambda: verify_fit(blobs["initramfs"], args.kernel_version, args.source_date_epoch)) if "initramfs" in blobs else None
    if initfit:
        report.data["initramfs_fit"] = initfit[0]
        if sysfit:
            report.stage("sysupgrade_initramfs_dtb_identity", lambda: require(sysfit[2] == initfit[2], "Initramfs and sysupgrade embedded DTBs differ"))
            report.stage("distinct_initramfs_kernel", lambda: require(sysfit[1] != initfit[1], "Initramfs kernel is identical to non-initramfs kernel"))
    manifest = report.stage("package_manifest", lambda: verify_manifest(inputs["manifest"], args.kernel_version))
    if manifest:
        report.data["manifest"] = manifest
    if directory and all(name in blobs for name in inputs):
        metadata = report.stage("image_metadata_identity_and_checksums", lambda: audit_image_metadata(
            directory, inputs, blobs, args.kernel_version, args.version_number, args.revision, args.source_date_epoch))
        if metadata:
            report.data["image_metadata"] = metadata
    build_root = Path(args.build_root).resolve() if args.build_root else None
    if build_root:
        configs = report.stage("actual_build_and_kernel_configs", lambda: audit_configs(build_root, args.kernel_version, args.version_number, args.revision))
        if configs:
            report.data["configs"] = configs
        pins = report.stage("official_release_base_and_feed_pins", lambda: audit_build_pins(build_root, args.revision, args.source_date_epoch))
        if pins:
            report.data["build_pins"] = pins
    tool = Path(args.unsquashfs).resolve() if args.unsquashfs else None
    if tool is None and build_root:
        candidate = build_root / "staging_dir/host/bin/unsquashfs4"
        if candidate.is_file():
            tool = candidate
    if rootfs is not None and tool is not None:
        def extract_audit():
            require(tool.is_file() and os.access(tool, os.X_OK), "unsquashfs tool is not executable")
            with tempfile.TemporaryDirectory(prefix="re-cs-07-nss-verify-") as temporary:
                directory = Path(temporary)
                image = directory / "root.squashfs"
                image.write_bytes(rootfs)
                dest = directory / "root"
                command = squashfs_extract_command(tool, dest, image)
                completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False)
                require(completed.returncode == 0, "unsquashfs extraction failed: " + completed.stderr.decode("utf-8", "replace")[-1800:])
                return audit_rootfs(dest, "extracted from verified sysupgrade rootfs", args.version_number,
                                    args.revision, args.source_date_epoch, manifest)
        fs = report.stage("filesystem_from_actual_squashfs", extract_audit)
        if fs:
            report.data["filesystem"] = fs
    elif args.rootfs_dir:
        fs = report.stage("provided_rootfs_directory", lambda: audit_rootfs(Path(args.rootfs_dir).resolve(),
            "provided build rootfs; not tied byte-for-byte to image", args.version_number,
            args.revision, args.source_date_epoch, manifest))
        if fs:
            report.data["filesystem"] = fs
        report.data["warnings"].append("Filesystem audit used the supplied directory, not a decoded firmware image.")
    else:
        report.data["warnings"].append("Filesystem audit skipped: supply --build-root with its built unsquashfs4 or --unsquashfs. Manifest checks do not prove installed files/startup links.")
    if initfit and build_root:
        archive = report.stage("actual_embedded_initramfs_contents", lambda: audit_embedded_initramfs(initfit[1], build_root,
            args.kernel_version, args.version_number, args.revision, args.source_date_epoch, manifest))
        if archive:
            report.data["embedded_initramfs"] = archive
            filesystem = report.data.get("filesystem")
            if filesystem:
                trust = report.stage("actual_image_and_staged_apk_public_key_identity", lambda: compare_apk_trust(build_root, filesystem, archive))
                if trust:
                    report.data["apk_trust_identity"] = trust
                def compare_installed():
                    require(archive["ecm_module_sha256"] == filesystem["module_sha256"]["ecm.ko"],
                            "Initramfs and SquashFS ECM module bytes differ")
                    require(archive["module_sha256"] == filesystem["module_sha256"],
                            "Initramfs and SquashFS NSS module bytes differ")
                    require(archive["nss_firmware_sha256"] == filesystem["nss_firmware_sha256"],
                            "Initramfs and SquashFS NSS firmware bytes differ")
                report.stage("initramfs_squashfs_nss_identity", compare_installed)
                def compare_network():
                    require(archive["network_support"] == filesystem["network_support"],
                            "Initramfs and SquashFS full module tree/network-support contents differ")
                    return {"all_module_count": archive["network_support"]["module_tree"]["module_count"],
                            "network_file_count": len(NETWORK_FILES), "byte_identical": True}
                identity = report.stage("initramfs_squashfs_all_modules_and_wireguard_identity", compare_network)
                if identity:
                    report.data["network_identity"] = identity
    elif initfit:
        report.data["warnings"].append("Initramfs FIT, gzip kernel, ARM64 header and DTB were verified; supply --build-root to decode and verify its embedded CPIO contents.")
    filesystem = report.data.get("filesystem")
    if build_root and manifest and filesystem:
        apks = report.stage("every_kmod_apk_kernel_abi_and_delivered_payloads", lambda: audit_kmod_apks(
            build_root, manifest, filesystem["network_support"]["module_tree"], args.kernel_version))
        if apks:
            report.data["kmod_apk_audit"] = apks
    else:
        report.data["warnings"].append("Every-kmod-APK ABI/payload audit needs --build-root, a valid manifest and decoded rootfs.")
    return report.finish()


def fixture_fdt(nodes):
    """Small synthetic FDT emitter for parser tests; not a firmware builder."""
    names, block, name_offsets = bytearray(), bytearray(), {}

    def word(value):
        block.extend(struct.pack(">I", value))

    def node(path):
        word(1)
        block.extend(path.rsplit("/", 1)[-1].encode() + b"\0" if path != "/" else b"\0")
        block.extend(b"\0" * (-len(block) % 4))
        for key, value in nodes[path].items():
            if key not in name_offsets:
                name_offsets[key] = len(names)
                names.extend(key.encode() + b"\0")
            word(3)
            word(len(value))
            word(name_offsets[key])
            block.extend(value)
            block.extend(b"\0" * (-len(block) % 4))
        prefix = path.rstrip("/") + "/"
        for child in nodes:
            if child != path and child.startswith(prefix) and "/" not in child[len(prefix):]:
                node(child)
        word(2)

    node("/")
    word(9)
    header = struct.pack(">10I", 0xD00DFEED, 56 + len(block) + len(names), 56,
                         56 + len(block), 40, 17, 16, 0, len(names), len(block))
    return header + b"\0" * 16 + block + names


def fixture_board():
    w = lambda value: struct.pack(">I", value)
    s = lambda value: value.encode() + b"\0"
    nodes = {"/": {"model": s("JDCloud RE-CS-07"), "compatible": b"jdcloud,re-cs-07\0qcom,ipq6018\0"},
             "/aliases": {}, "/chosen": {},
             "/memory@40000000": {"device_type": s("memory"), "reg": struct.pack(">QQ", 0x40000000, 0x80000000)},
             "/soc@0": {}, "/soc@0/nss-common": {"compatible": s("qcom,nss-common"), "memory-region": w(100)},
             "/soc@0/nss@40000000": {"compatible": s("qcom,nss"), "qcom,id": w(0), "qcom,load-addr": w(0x40000000)},
             "/soc@0/mmc@7804000": {"compatible": s("qcom,ipq6018-sdhci"), "status": s("okay"),
                                      "bus-width": w(8), "non-removable": b""},
             "/soc@0/wifi@c000000": {"compatible": s("qcom,ipq6018-wifi"), "status": s("disabled"), "qcom,rproc": w(102)},
             "/soc@0/remoteproc@cd00000": {"compatible": s("qcom,ipq6018-wcss-pil"), "status": s("disabled"),
                                            "memory-region": w(101), "phandle": w(102)},
             "/soc@0/ess-switch@3a000000": {"compatible": s("qcom,ess-switch-ipq60xx"), "status": s("okay"),
                                            "switch_lan_bmp": w(0x1c), "switch_wan_bmp": w(0x2)},
             "/soc@0/ess-switch@3a000000/qcom,port_phyinfo": {},
             "/reserved-memory": {"#address-cells": w(2), "#size-cells": w(2)},
             "/reserved-memory/memory@40000000": {"reg": struct.pack(">QQ", 0x40000000, 0x1000000), "no-map": b"", "phandle": w(100)},
             "/reserved-memory/memory@4ab00000": {"reg": struct.pack(">QQ", 0x4ab00000, 0x5500000), "no-map": b"", "phandle": w(101)}}
    for name, address, size in (("memory@60000", 0x60000, 0x6000),
                                ("bootloader@4a100000", 0x4a100000, 0x400000),
                                ("sbl@4a500000", 0x4a500000, 0x100000),
                                ("memory@4a600000", 0x4a600000, 0x400000),
                                ("memory@4aa00000", 0x4aa00000, 0x100000)):
        nodes["/reserved-memory/" + name] = {"reg": struct.pack(">QQ", address, size), "no-map": b""}
    for alias, port, label, phy in ((0, 1, "wan", 24), (1, 2, "lan1", 25), (2, 3, "lan2", 26), (3, 4, "lan3", 27)):
        path = "/soc@0/dp%d" % port
        nodes["/aliases"]["ethernet%d" % alias] = s(path)
        nodes[path] = {"qcom,id": w(port), "label": s(label), "phy-handle": w(phy + 1), "status": s("okay")}
        nodes["/soc@0/phy@%d" % phy] = {"reg": w(phy), "phandle": w(phy + 1)}
        nodes["/soc@0/ess-switch@3a000000/qcom,port_phyinfo/port@%d" % port] = {"port_id": w(port), "phy_address": w(phy)}
    nodes["/aliases"]["label-mac-device"] = s("/soc@0/dp2")
    nodes["/soc@0/dp5"] = {"qcom,id": w(5), "status": s("disabled")}
    return fixture_fdt(nodes)


def fixture_module(name, depends="", version=EXPECTED_KERNEL):
    """Synthetic ELF for dependency-parser tests, never a loadable test module."""
    names = b"\0.shstrtab\0.modinfo\0"
    metadata = ("name=%s\0depends=%s\0vermagic=%s SMP mod_unload aarch64\0" % (name, depends, version)).encode()
    result = bytearray(64)
    result[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HHI", result, 16, 1, 183, 1)
    result.extend(names + metadata)
    table = (len(result) + 7) & ~7
    result.extend(b"\0" * (table - len(result)))
    struct.pack_into("<Q", result, 40, table)
    struct.pack_into("<HHH", result, 58, 64, 3, 1)
    result.extend(b"\0" * 64)
    result.extend(struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, 64, len(names), 0, 0, 1, 0))
    result.extend(struct.pack("<IIQQQQIIQQ", 11, 1, 0, 0, 64 + len(names), len(metadata), 0, 0, 1, 0))
    return bytes(result)


def test_network_audits():
    dependencies = {"wireguard": "udp_tunnel,ip6_udp_tunnel,libcurve25519_generic,libchacha20poly1305",
                    "tun": "", "inet_diag": "", "tcp_diag": "inet_diag", "udp_diag": "inet_diag",
                    "raw_diag": "inet_diag", "udp_tunnel": "", "ip6_udp_tunnel": "",
                    "libcurve25519_generic": "", "libchacha20poly1305": ""}
    entries = {"lib/modules/%s/%s.ko" % (EXPECTED_KERNEL, name):
               {"mode": stat.S_IFREG | 0o644, "data": fixture_module(name, depends)}
               for name, depends in dependencies.items()}
    result = audit_module_tree(entries)
    require(result["module_count"] == len(dependencies), "All-module audit fixture failed")
    normalized = module_info(fixture_module("tun", "qca-nss-drv"), "tun.ko", EXPECTED_KERNEL)
    require(normalized["depends"] == ["qca_nss_drv"], "Linux hyphen/underscore dependency normalization failed")
    failures = 0
    def reject(function, label):
        nonlocal failures
        try:
            function()
        except (VerificationError, ValueError, struct.error):
            failures += 1
        else:
            raise VerificationError("Network regression failed to reject " + label)
    reject(lambda: module_info(b"broken", "tun.ko", EXPECTED_KERNEL), "truncated module")
    reject(lambda: module_info(fixture_module("tun", version="6.12.93"), "tun.ko", EXPECTED_KERNEL), "stale vermagic")
    reject(lambda: module_info(fixture_module("wrong"), "tun.ko", EXPECTED_KERNEL), "mismatched module name")
    wrong_arch = bytearray(fixture_module("tun"))
    struct.pack_into("<H", wrong_arch, 18, 62)
    reject(lambda: module_info(wrong_arch, "tun.ko", EXPECTED_KERNEL), "wrong architecture")
    reject(lambda: module_info(fixture_module("tun", "bad/name"), "tun.ko", EXPECTED_KERNEL), "invalid dependency")
    tun_path = "lib/modules/%s/tun.ko" % EXPECTED_KERNEL
    reject(lambda: audit_module_tree({k: v for k, v in entries.items() if k != tun_path}), "missing requested module")
    broken = dict(entries)
    broken[tun_path] = {"mode": stat.S_IFREG | 0o644, "data": fixture_module("tun", "nonexistent")}
    reject(lambda: audit_module_tree(broken), "unresolved module dependency")
    broken[tun_path] = {"mode": stat.S_IFREG | 0o644, "data": fixture_module("tun", "tun")}
    reject(lambda: audit_module_tree(broken), "circular module dependency")
    wg = bytearray(768)
    wg[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HHI", wg, 16, 2, 183, 1)
    struct.pack_into("<QQ", wg, 24, 0x400200, 64)
    struct.pack_into("<HH", wg, 54, 56, 3)
    interpreter = b"/lib/ld-musl-aarch64.so.1\0"
    names = b"libgcc_s.so.1\0libc.so\0"
    wg[256:256 + len(interpreter)] = interpreter
    wg[448:448 + len(names)] = names
    wg_version = b"1.0.20250521\0"
    wg[512:512 + len(wg_version)] = wg_version
    for i, header in enumerate(((1, 5, 0, 0x400000, 0x400000, len(wg), len(wg), 4096),
                                (3, 4, 256, 0x400100, 0x400100, len(interpreter), len(interpreter), 1),
                                (2, 6, 320, 0x400140, 0x400140, 80, 80, 8))):
        struct.pack_into("<IIQQQQQQ", wg, 64 + 56 * i, *header)
    for i, item in enumerate(((5, 0x4001c0), (10, len(names)), (1, 0), (1, 14), (0, 0))):
        struct.pack_into("<qQ", wg, 320 + 16 * i, *item)
    audit_wg_elf(wg)
    for offset, fmt, value, label in ((18, "<H", 62, "wg wrong architecture"),
                                      (24, "<Q", 0, "wg invalid entry"),
                                      (32, "<Q", 99999, "wg invalid program table"),
                                      (56, "<H", 0, "wg missing program headers")):
        invalid_wg = bytearray(wg)
        struct.pack_into(fmt, invalid_wg, offset, value)
        reject(lambda d=invalid_wg: audit_wg_elf(d), label)
    fixtures = {
        "usr/bin/wg": bytes(wg), "usr/bin/wireguard_watchdog": b"#!/bin/sh\n",
        "lib/netifd/proto/wireguard.sh": b"proto_wireguard_init_config proto_wireguard_setup proto_wireguard_teardown add_protocol wireguard",
        "www/luci-static/resources/protocol/wireguard.js": b"registerProtocol('wireguard')",
        "www/luci-static/resources/view/wireguard/status.js": b"getWgInstances",
        "usr/share/luci/menu.d/luci-proto-wireguard.json": b'{"admin/status/wireguard":{"action":{"path":"wireguard/status"}}}',
        "usr/share/rpcd/acl.d/luci-wireguard.json": b'{"luci-proto-wireguard":{"read":{"ubus":{"luci.wireguard":["getWgInstances"]}}}}',
        "usr/share/rpcd/ucode/luci.wireguard": b"getWgInstances generateKeyPair generatePsk",
        "etc/modules.d/30-tun": b"tun\n", "etc/modules.d/31-inet-diag": b"inet_diag\ntcp_diag\nudp_diag\nraw_diag\n",
        "etc/modules.d/wireguard": b"wireguard\n"}
    entries.update({name: {"mode": stat.S_IFREG | 0o755, "data": value} for name, value in fixtures.items()})
    audit_network_support(entries)
    for name in NETWORK_FILES:
        incomplete = {k: v for k, v in entries.items() if k != name}
        reject(lambda e=incomplete: audit_network_support(e), "missing " + name)
    wrong_abi = ("P:kernel\nV:6.12.94~new-r1\n\nP:kmod-tun\nV:6.12.94-r1\nD:kernel=6.12.94~old-r1\n\n").encode()
    reject(lambda: audit_package_versions(wrong_abi, {"package_versions": parse_apk_database(wrong_abi)}),
           "installed stale kmod ABI")
    return {"positive_fixtures": 3, "negative_fixtures_rejected": failures}


def self_test():
    require(crc_raw(b"123456789") == 0x340BC6D9, "Raw CRC32 test vector failed")
    raw = bytearray(4096)
    raw[56:60] = b"ARM\x64"
    raw[100:130] = b"Linux version 6.12.94 test\0".ljust(30, b"\0")
    require(inflate_gzip(gzip.compress(bytes(raw), mtime=0)) == raw, "gzip roundtrip failed")
    sq = bytearray(1024)
    sq[:4] = b"hsqs"
    struct.pack_into("<HH", sq, 28, 4, 0)
    struct.pack_into("<Q", sq, 40, 96)
    require(squashfs_info(sq)["bytes_used"] == 96, "SquashFS parser self-test failed")
    verify_emmc_budgets(HLOS_SIZE, ROOTFS_SIZE - ROOTFS_ALIGNMENT)
    for kernel_size, root_size in ((HLOS_SIZE + 1, 96), (1, ROOTFS_SIZE),
                                  (1, ROOTFS_SIZE - ROOTFS_ALIGNMENT + 1), (0, 96), (1, 0)):
        try:
            verify_emmc_budgets(kernel_size, root_size)
        except VerificationError:
            pass
        else:
            raise VerificationError("eMMC partition overflow/empty payload was not rejected")
    metadata = {"supported_devices": ["jdcloud,re-cs-07"], "version": {"dist": "OpenWrt", "target": "qualcommax/ipq60xx",
                "board": "jdcloud_re-cs-07", "version": EXPECTED_VERSION, "revision": EXPECTED_REVISION}}
    payload = b"test firmware" + b"\0" * 8 + json.dumps(metadata).encode()
    size = 8 + len(json.dumps(metadata).encode()) + 16
    fixture = payload + struct.pack(">IIB3xI", 0x46577830, crc_raw(payload), 1, size)
    content, result = verify_fwtool(fixture)
    require(content == b"test firmware" and result["metadata"] == metadata, "fwtool fixture failed")
    corrupt = bytearray(fixture)
    corrupt[0] ^= 1
    try:
        verify_fwtool(corrupt)
    except VerificationError:
        pass
    else:
        raise VerificationError("fwtool corruption was not rejected")
    for key, incorrect in (("version", "25.12-SNAPSHOT"), ("revision", "r0-stale"), ("dist", "Wrong")):
        invalid = json.loads(json.dumps(metadata))
        invalid["version"][key] = incorrect
        encoded = json.dumps(invalid).encode()
        payload = b"test firmware" + b"\0" * 8 + encoded
        wrong_identity = payload + struct.pack(">IIB3xI", 0x46577830, crc_raw(payload), 1, 8 + len(encoded) + 16)
        try:
            verify_fwtool(wrong_identity)
        except VerificationError:
            pass
        else:
            raise VerificationError("CRC-valid fwtool wrong " + key + " was not rejected")
    board = fixture_board()
    verify_board_dtb(board)
    w = lambda value: struct.pack(">I", value)
    s = lambda value: value.encode() + b"\0"
    zipped = gzip.compress(bytes(raw), mtime=0)
    fit_nodes = {"/": {"timestamp": w(EXPECTED_EPOCH)}, "/images": {},
                 "/images/kernel@1": {"data": zipped, "type": s("kernel"), "arch": s("arm64"),
                                      "os": s("linux"), "compression": s("gzip"), "load": w(0x41000000), "entry": w(0x41000000)},
                 "/images/kernel@1/hash@1": {"algo": s("sha256"), "value": hashlib.sha256(zipped).digest()},
                 "/images/fdt@1": {"data": board, "type": s("flat_dt"), "compression": s("none")},
                 "/images/fdt@1/hash@1": {"algo": s("sha256"), "value": hashlib.sha256(board).digest()},
                 "/configurations": {"default": s("config@cp03-c4")},
                 "/configurations/config@cp03-c4": {"kernel": s("kernel@1"), "fdt": s("fdt@1")}}
    fit = fixture_fdt(fit_nodes)
    verify_fit(fit, EXPECTED_KERNEL)
    broken_fit = bytearray(fit)
    broken_fit[fit.find(zipped) + 15] ^= 1
    try:
        verify_fit(broken_fit, EXPECTED_KERNEL)
    except VerificationError:
        pass
    else:
        raise VerificationError("FIT corruption was not rejected")
    elf = bytearray(64)
    elf[:6] = b"\x7fELF\x02\x01"
    names = b"\0nf_conntrack_register_notifier\0"
    symbols = b"\0" * 24 + struct.pack("<IBBHQQ", 1, 0x10, 0, 0, 0, 0)
    sections_at = (64 + len(names) + len(symbols) + 7) & ~7
    struct.pack_into("<Q", elf, 40, sections_at)
    struct.pack_into("<HH", elf, 58, 64, 3)
    elf.extend(names + symbols)
    elf.extend(b"\0" * (sections_at - len(elf)))
    elf.extend(b"\0" * 64)
    elf.extend(struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, 64, len(names), 0, 0, 1, 0))
    elf.extend(struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, 64 + len(names), len(symbols), 1, 0, 8, 24))
    require(undefined_elf_symbols(elf) == {"nf_conntrack_register_notifier"}, "ELF notifier-symbol self-test failed")
    cpio = bytearray()
    for name, mode, content in (("init", stat.S_IFREG | 0o755, b"#!/bin/sh\n"),
                                 ("etc/rc.d/S27re-cs-07-nss", stat.S_IFLNK | 0o777, b"../init.d/re-cs-07-nss\0"),
                                 ("TRAILER!!!", 0, b"")):
        encoded = name.encode() + b"\0"
        values = (1, mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(encoded), 0)
        cpio.extend(b"070701" + "".join("%08x" % value for value in values).encode() + encoded)
        cpio.extend(b"\0" * (-len(cpio) % 4))
        cpio.extend(content)
        cpio.extend(b"\0" * (-len(cpio) % 4))
    cpio.extend(b"\0" * (-len(cpio) % 512))
    parsed = parse_newc(cpio)
    require(parsed["etc/rc.d/S27re-cs-07-nss"]["data"] == b"../init.d/re-cs-07-nss\0",
            "Linux newc NUL-terminated symlink fixture failed")
    release_files = {
        "etc/openwrt_release": ("DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='%s'\nDISTRIB_REVISION='%s'\n"
                                "DISTRIB_TARGET='qualcommax/ipq60xx'\nDISTRIB_ARCH='aarch64_cortex-a53'\n" %
                                (EXPECTED_VERSION, EXPECTED_REVISION)).encode(),
        "etc/openwrt_version": (EXPECTED_REVISION + "\n").encode(),
        "usr/lib/os-release": ("NAME=OpenWrt\nVERSION='%s'\nBUILD_ID='%s'\nOPENWRT_BOARD=qualcommax/ipq60xx\n"
                               "OPENWRT_ARCH=aarch64_cortex-a53\nOPENWRT_BUILD_DATE='%s'\n" %
                               (EXPECTED_VERSION, EXPECTED_REVISION, EXPECTED_EPOCH)).encode(),
    }
    audit_release_identity(release_files.__getitem__)
    release_files["etc/openwrt_version"] = b"r0-stale\n"
    try:
        audit_release_identity(release_files.__getitem__)
    except VerificationError:
        pass
    else:
        raise VerificationError("Stale installed release identity was not rejected")
    apk = b"P:base-files\nV:1~test\nF:etc\nR:openwrt_release\n\nP:kernel\nV:6.12.94-r1\n\n"
    expected_packages = {"package_versions": {"base-files": "1~test", "kernel": "6.12.94-r1"}}
    audit_package_versions(apk, expected_packages)
    for invalid in (apk.replace(b"6.12.94-r1", b"6.12.108-r1"), apk + apk):
        try:
            audit_package_versions(invalid, expected_packages)
        except VerificationError:
            pass
        else:
            raise VerificationError("Incorrect/duplicate installed APK package version was not rejected")
    network = test_network_audits()
    return {"result": "pass", "self_test": "CRC32, gzip, SquashFS, exact fwtool custom identity, complete FIT/board DTB, eMMC TAR partition budgets, ELF notifier reference, Linux newc symlink, release-file identity, installed APK versions and corruption/stale-identity rejection", "network_regressions": network, "caveat": CAVEAT}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--images-dir")
    for flag in ("sysupgrade", "initramfs", "manifest", "build-root", "rootfs-dir", "unsquashfs", "report"):
        parser.add_argument("--" + flag)
    parser.add_argument("--kernel-version", default=EXPECTED_KERNEL)
    parser.add_argument("--version-number", default=EXPECTED_VERSION)
    parser.add_argument("--revision", default=EXPECTED_REVISION)
    parser.add_argument("--source-date-epoch", type=int, default=EXPECTED_EPOCH)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        result = self_test() if args.self_test else verify(args)
    except (VerificationError, OSError, ValueError, subprocess.SubprocessError) as error:
        result = {"result": "fail", "error": str(error), "caveat": CAVEAT}
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.report:
        Path(args.report).write_text(text + "\n")
    return 0 if result["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
