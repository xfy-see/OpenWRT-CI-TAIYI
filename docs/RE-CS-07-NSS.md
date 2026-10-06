# JDCloud RE-CS-07 · official release base + wired NSS

The independent **RE-CS-07-NSS** workflow builds JDCloud RE-CS-07 (`jdcloud,re-cs-07`) from pinned official OpenWrt v25.12.5 / Linux 6.12.94, with the reviewed qosmio NSS 12.5 port. It does not change the ZN M2 workflow. This is a custom build, not an official OpenWrt binary.

## Run the workflow

Open Actions → RE-CS-07-NSS → Run workflow on `main`:

- `mode=build`: compile firmware and packages together, verify images and signed offline packages, then upload the complete artifact
- `mode=config`: fetch pinned sources and resolve/check Kconfig; this does **not** prove the firmware compiles
- `jobs=4` is the default for the public repository's standard Ubuntu 24.04 runner; choose 2 for lower peak memory

The workflow is manual, has read-only repository permissions, uses commit-pinned official Actions, does not retain checkout credentials, and caches only verified source downloads. It never publishes Releases or flashes hardware. Failed runs upload diagnostic reports/logs without private signing keys.

## Board and software profile

The official board description specifies IPQ6010, 2 GiB RAM, 8 GB eMMC, three LAN ports and one WAN port. This build uses the supported IPQ 1024 MiB / NSS MEDIUM resource profile; that setting is not a physical RAM capacity limit. It retains the RE-CS-07 reserved-memory layout and does not import the ZN M2 zero-Q6 experiment.

The requested official main DTS is pinned in `Config/RE-CS-07-NSS/sources.lock.json`. Its board wiring is backported to the locked release's NSS network bindings because current main uses a different PPE/DSA datapath. WAN uses PHY 24 and LAN1–3 use PHY 25–27. Wi-Fi is disabled. NSS wireless offload and SKB recycling/preallocation are disabled.

The profile includes dnsmasq-full, LuCI, WireGuard, inet-diag, tun, PPPoE and the established common application/tool set. Ttyd, UPnP, sing-box and SQM remain disabled until configured. `block-mount` is included for later manual disk mounting.

## Differences from the legacy GENERAL profile

Compatible official-feed packages from `Config/GENERAL.txt` are explicitly selected; Kconfig dependencies are resolved and verified. This does not import every downstream package from the old VIKINGYFY workflow. Existing agreed exclusions remain explicit:

- `autocore`, `automount`, `cpufreq`: downstream UI/automount/frequency customizations are not imported; official `block-mount` provides manual mounting support with inert defaults
- `kmod-nft-fullcone`: unavailable in the locked official/NSS set; standard nft NAT is not Full Cone NAT
- `kmod-usb-net-qmi-wwan-fibocom` / `-quectel`: generic official QMI remains; vendor-specific patches are not promised
- `kmod-usb-xhci`: official `kmod-usb3` provides xHCI support instead of this absent standalone package name
- `sqm-scripts-nss`: not included; official SQM remains without a claim of NSS traffic shaping
- `kmod-mtd-rw`: intentionally excluded; it is not needed for the eMMC upgrade path

LuCI base libraries are selected by dependencies. The fixed official sing-box recipe is retained. No personal proxy, VPN, LAN-address or password configuration is copied. A full resolved `.config` and package manifest are exported so the exact installed set can be inspected.

## eMMC images and upgrade limits

The sysupgrade image is a TAR containing separate FIT `kernel` and SquashFS `root` members. FIT configuration is `config@cp03-c4`; load/entry are `0x41000000`. The kernel must fit a 6 MiB HLOS partition; rootfs plus its 64 KiB alignment and reset/backup tail must fit a 60 MiB rootfs partition. The image verifier checks delivered sizes, and the board upgrade helper checks actual selected device capacities at runtime.

The upgrade helper reads the board BOOTCONFIG slot byte, accepts only 0 or 1, and selects `0:HLOS`/`rootfs` or their `_1` counterparts. It checks the selected block devices, TAR extraction status, kernel size and rootfs tail capacity before writes. It does not target bootloader, calibration, separate data or external-overlay partitions. The first upgrade still runs the **currently installed OS's** upgrade scripts, so safeguards in this new image cannot validate that first write.

No factory concatenated image is generated. The larger initramfs FIT is for a compatible RAM boot/recovery flow and must never be written to a 6 MiB HLOS partition.

## Existing data and custom U-Boot

The default fstab contains only global settings with automatic mounts/swaps disabled. It contains no device UUIDs and does not automatically reuse an old external overlay or data mount. Clean installation is required when moving from the previously inspected custom firmware; restoring old fstab or its whole extroot upper layer can override the new defaults. Separate existing data partitions are not formatted by this profile's upgrade path. Back up configuration and data independently and establish recovery access before any real upgrade.

The inspected `chenxin527/uboot-qsdk12.5-build` source supports the expected FIT and recent versions accept an OpenWrt sysupgrade TAR. Its web updater writes the **primary** HLOS/rootfs pair and resets the firmware slot to primary; this differs from the running OS's BOOTCONFIG-selected sysupgrade. A repository name alone does not identify the version installed on a router. This workflow does not verify installed U-Boot, actual partition/slot state, hardware boot or recovery. A permissive `sysupgrade -T` on an old custom system is not proof of those conditions.

## Outputs and verification

A successful full run exports firmware, the same build's offline APK archive, a source/configuration ZIP, full and reduced Kconfig, kernel config, source provenance, compressed download/build logs, image verification, package/index signature verification and SHA256 checksums. Private signing keys are excluded. Keep each run's image, package archive and checksum files together; even matching kernel ABI strings do not authorize mixing packages between different boards or builds.

The verifier inspects both the delivered initramfs and sysupgrade filesystem, actual FIT/DTB properties, eMMC size limits, module and package ABI, package trust keys, release identity, wired service defaults and the inert fstab. Source locks do not guarantee identical binary hashes: ephemeral signing keys and runner tools can change output bytes.

Revision `recs07.2` is the reconstructed repository publication. The earlier `recs07.1` cloud build passed offline checks, but that result must not be described as a successful GitHub build of this revision. Only the exact run's result establishes its compilation status; physical boot, ports, PPPoE, NSS performance and stability remain untested until separately checked on the device.

## Local build

Use a regular user on Linux x86_64 with the dependencies listed in the workflow:

```sh
python3 Scripts/re-cs-07-nss/build.py validate
python3 -m unittest discover -s tests-re-cs-07 -v
python3 Scripts/re-cs-07-nss/verify-images.py --self-test
python3 Scripts/re-cs-07-nss/build.py prepare
python3 Scripts/re-cs-07-nss/build.py build --jobs 4
python3 Scripts/re-cs-07-nss/build.py package
```

Use a fresh work directory for each source/profile change. The build refuses to overwrite existing preparation or packaged artifacts. The source ZIP is self-contained for its profile tests and build commands, without Git history, personal diagnostics or credentials. It includes unchanged M2 source/configuration as regression-test dependencies; the RE-CS-07 firmware and package artifacts remain single-board.

## Sources

- Requested DTS: https://github.com/openwrt/openwrt/blob/main/target/linux/qualcommax/dts/ipq6010-re-cs-07.dts
- Pinned board source: https://github.com/openwrt/openwrt/blob/c459c71c4a778eac007f7e541cc9831fadde2a3c/target/linux/qualcommax/dts/ipq6010-re-cs-07.dts
- Original official board support: https://github.com/openwrt/openwrt/commit/1c582f7c73939504b6985b2c00c8b7e9b33168ef
- Inspected U-Boot web update path: https://github.com/chenxin527/uboot-qsdk12.5-build/blob/9ce315735ac88fd0a7c7697bc527a8616ed0a972/u-boot-2016/board/qca/arm/common/failsafe.c#L669-L723
- All base/feed/toolchain and patch checksums: `Config/RE-CS-07-NSS/sources.lock.json`
