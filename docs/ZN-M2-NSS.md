# ZN M2：固定 release 底座的无 Wi-Fi NSS 构建

推荐入口是 Actions → **ZN-M2-NSS**。它仅支持 ZN M2，不用于京东云太乙。
源码基于官方 OpenWrt v25.12.5（Linux 6.12.94），加上独立的 M2 板级与 NSS 适配。
这不是官方发布的 M2 二进制固件，也不能把其他官方或 NSS 固件的模块混装进来。

## 日常只改一个配置文件

- `Config/ZN-M2-NSS.config`：设备、256 MB / LOW NSS 内存方案、预装软件包
- `Config/ZN-M2-NSS/sources.lock.json`：源码、feeds、工具链校验值、版本标识和补丁哈希
- `Config/ZN-M2-NSS/patches/`：板级/NSS 适配、conntrack events 修复、ttyd 默认关闭
- `Scripts/zn-m2-nss/`：准备、编译、镜像验证和同构建离线包打包

配置只写有意选择的功能，让 Kconfig 自动选择依赖；不再拼接旧 GENERAL、PRIVATE 或 PACKAGE 覆盖项。
所有显式选项必须在 `make defconfig` 后保留，否则立即失败。包改名或 feed 缺包不能静默跳过。
不要把生成的完整 `.config` 复制回来：其中有工具链绝对路径和自动生成的依赖。
更改底座、内核或 feeds 需要重新审查补丁及兼容性；更改要发布的功能组合时同步更新 lock 中的版本标识。

`dnsmasq-full=y`、`dnsmasq=n`、`dnsmasq-dhcpv6=n`，避免互斥变体共存。
保留上游 full 默认的 DHCP/DHCPv6、DNSSEC、nftset 和 conntrack 编译功能，不写 DNS 上游、DHCP 网段或用户网络配置。
`ip-full` 替换 `ip-tiny`。LuCI、PPPoE、软件 WireGuard / LuCI、tun、inet-diag 和常用 USB/NFT 模块预装。
不启用 ALL_KMODS；新增任何内核模块，即使只编译为可下载包，也可能改变 ABI，必须和固件一起重建。

## 与旧 TAiYI 配置的明确差异

保留官方 feeds 中的 sing-box、ttyd、UPnP、WoL、常用诊断/分区工具、LuCI 协议及兼容组件。
sing-box 使用固定官方 feeds 的 1.12.17 配方，不执行旧 Packages.sh 无条件拉取的大量主题/代理仓库。
ttyd 明确默认关闭；sing-box、UPnP、SQM 保持默认关闭，用户自行配置后开启。

以下名字不在本次锁定的官方/NSS feeds 中，不代表它们都为 ImmortalWrt 独占：

- autocore、automount、cpufreq：不引入这些下游 UI/自动挂载/调频定制
- kmod-nft-fullcone：不包含 Full Cone NAT 扩展；标准 nft NAT 不等于 Full Cone NAT
- kmod-usb-net-qmi-wwan-fibocom / -quectel：保留通用 QMI，未承诺厂商专用修正
- kmod-usb-xhci：没有这个独立名字，已有官方 kmod-usb3 提供 xHCI 支持
- sqm-scripts-nss：不额外引入 qosmio 的 NSS SQM 扩展；官方 SQM UI/脚本仍可用，但不宣称 NSS 整形

另外不预装 kmod-mtd-rw（解除闪存分区写保护的工具模块）。LuCI 基础库等由依赖关系选择。
不复制历史 LAN 地址、Wi-Fi 口令、VPN 密钥、代理配置或私人扩展。
NSS 启动/内存/packet-steering 与软件 flow-offload 的互斥设置来自已审查的板级补丁。

## 手动运行

1. 先选择 `mode=config`：下载锁定源码与官方工具链、应用补丁、解析最终配置，上传检查结果
2. 再选择 `mode=build`：在同一源码树同时构建固件、内核和所有预装包，完成离线验证后上传完整包
3. 并行数默认 2，资源允许时可选 4；编译失败会保存日志，并单线程详细重试一次

只缓存下载的源码归档，不复用内核、目标 staging 或未知 feeds 的二进制缓存。
新入口只有 `contents: read` 权限，Actions 固定到完整提交，不需要 PAT 或新增 secret。
它不会发布 Release、修改分支、删除历史或刷机。成功完整构建的 artifact 保留 30 天；请及时下载留存。
配置检查通过、Python 测试通过，都不等于 GitHub 完整编译通过。

旧 `QCA-ALL` 已退役为手动、只读的说明任务，不再执行旧核心或外部构建代码。京东云太乙尚未迁移，不能使用此 ZN M2 镜像。
旧 Auto-Clean 的每日清空 Release/标签/运行记录行为已经退役，改成手动只读盘点，也不会触发 QCA-ALL。
旧设备配置和 `WRT-CORE` / `Scripts` 保留作参考，新入口不会调用它们。旧 core 本身不具备手动/定时触发；原有 Cache-Clean 缓存维护任务未纳入本次固件流程。

## 完整 artifact 中包含什么

- `*-firmware.tar.gz`：sysupgrade、factory、initramfs、manifest、profiles/buildinfo、原始校验文件
- `*-offline-apks.zip`：当前固件所有已安装软件包（不含 kernel 元包）、原始签名 packages.adb 索引、依赖清单、只读预检脚本
- `*-sources.zip`：精确 profile、source lock、补丁、构建/验证脚本和许可说明；上游对应源码由固定提交与配方中的校验值定位
- `reports/`：最终完整配置、diffconfig、内核配置、镜像/模块验证、离线包验证及构建来源记录
- `SHA256SUMS`：该交付集合的 SHA-256 校验值

离线包的索引签名使用本次固件内嵌的公钥验证。私钥不读取、不上传；不同构建的临时签名密钥不通用。
离线包只适用于同一次构建的 release/revision、内核版本与完整 ABI。
每个 kmod 的精确 kernel 依赖、安装后的模块内容及两种镜像中的模块树均需一致。
kernel APK 不作为“修复 ABI”的安装包分发，禁止强制忽略依赖。
镜像保留上游软件源；官方目标仓库的 kmod ABI 与本固件不同，补装/恢复请用该次构建的离线包，而不是强装官方 kmod。
这套工作流不承诺随时在线安装未编译过的任意模块，也未建立公共软件源。

源代码、配置、工具链版本及补丁可以追溯，但托管 runner、宿主工具版本与每次生成的签名密钥仍可令输出字节变化。
因此不宣称不同运行之间的固件 SHA-256 必定相同。

## 本地检查与复现

使用 Python 3.11+；静态测试额外需要 PyYAML。Linux 完整构建依赖见 workflow 的 apt 安装列表。

```sh
python3 Scripts/zn-m2-nss/build.py validate
python3 -m unittest discover -s tests -v
python3 Scripts/zn-m2-nss/verify-images.py --self-test

# 以下才会下载并执行锁定的上游构建代码，目录不能已有 openwrt 子目录：
python3 Scripts/zn-m2-nss/build.py prepare --work-dir /absolute/path/to/new-build
python3 Scripts/zn-m2-nss/build.py build --work-dir /absolute/path/to/new-build --jobs 2
python3 Scripts/zn-m2-nss/build.py package --work-dir /absolute/path/to/new-build
```

构建脚本必须以普通用户运行。只有 workflow 安装 Ubuntu 官方依赖时使用 sudo，不以 root 执行远程 shell 脚本。
所有验证均为主机离线检查：没有实体硬件启动、端口/MAC、PPPoE、吞吐或长期稳定性测试；WireGuard 是标准软件支持，不宣称 NSS WireGuard offload。
首次刷入和恢复方式应先核对具体硬件/分区/引导环境，不能把构建成功视作可以跳过备份或救援准备。
