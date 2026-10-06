# OpenWRT-CI-TAIYI

## ZN M2 固定 release / NSS 构建

当前 M2 配置为 **25.12.5-nss-taiyi3-q6zero 零 Q6 保留实验版**。
Wi-Fi/WCSS 节点及其 Q6 预留一并移除，NSS 的 16 MiB 和其他保留区不变。
**尚未完成实机验证；编译通过不等于可直接刷入。** 下次手动运行 ZN-M2-NSS 会使用此布局。

Actions → **ZN-M2-NSS** 是新的固件打包入口：

- 官方 OpenWrt v25.12.5 / Linux 6.12.94 源码底座，加固定的 M2 / NSS 适配
- 256 MB / LOW 内存方案，无 Wi-Fi，dnsmasq-full
- LuCI、PPPoE、软件 WireGuard / LuCI、常用 kmod 和兼容的 TAiYI 工具
- 同次构建交付固件、配套离线 APK / 原始签名索引、配置、补丁、来源和校验值
- 仅手动运行，上传 Actions artifact，不自动发布 Release 或刷机

日常只改 `Config/ZN-M2-NSS.config`；版本和源码锁在 `Config/ZN-M2-NSS/sources.lock.json`。
可先运行 `config` 检查，再运行 `build`；完整构建也会先检查配置。
[使用方法、软件包差异及验证范围](docs/ZN-M2-NSS.md)。

这是自定义固件，不是官方 M2 二进制发行版。模块必须来自同一次构建，不可与其他官方/NSS 固件混装。
本入口仅用于 **ZN M2**，不能给京东云太乙刷入。

## 已简化的旧入口

- `QCA-ALL`：退役为手动说明任务，只有只读权限，不再调用旧核心、下载移动分支或执行外部脚本
- `Auto-Clean`：手动只读盘点，不再自动删除 Release、标签、artifact 或运行记录
- `WRT-CORE.yml`、旧 `Config/` 与 `Scripts/`：保留作历史参考，新入口不会调用；京东云太乙尚未迁移
- `Cache-Clean`：原有缓存维护任务保留，与固件/Release 保留无关

旧 GENERAL 也已显式以 dnsmasq-full 替换 dnsmasq。不会复制私人代理、VPN、网络或口令配置。
构建成功只证明编译和主机离线验证通过；实体硬件启动、端口、NSS 性能与长期稳定性仍需实测。
