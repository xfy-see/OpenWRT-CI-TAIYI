# OpenWRT-CI-TAIYI

基于 [VIKINGYFY/OpenWRT-CI](https://github.com/VIKINGYFY/OpenWRT-CI) 的云编译配置，保留京东云太乙和中兴 M2 的无 Wi-Fi 定制。

本次适配基线为上游提交 [`8acf77a`](https://github.com/VIKINGYFY/OpenWRT-CI/commit/8acf77aaa55c43fbccaaae498a3dcc6097446a63)（2026-09-10）。编译时仍拉取所选源码分支的最新提交，具体提交记录在 Release 中。

## 默认构建

| 工作流 | 配置 | 源码与分支 | 默认设置 |
| --- | --- | --- | --- |
| QCA-ALL | IPQ60XX-WIFI-NO | VIKINGYFY/immortalwrt `main` | Bootstrap，192.168.100.1 |

QCA-ALL 只选择 `jdcloud_re-cs-07`（太乙）和 `zn_m2`（中兴 M2），关闭 ath11k 无线驱动及固件，并应用无 Wi-Fi 的 Q6 内存配置。保留 sing-box、ttyd、UPnP、WOL、WireGuard 和 NSS SQM，继续关闭 HomeProxy、Samba、Tailscale 等原有精简项。

只保留这一套 IPQ60XX 无 Wi-Fi 固件构建。每次为太乙和中兴 M2 分别生成完整固件，插件组合与此前成功发布的版本相同。

默认主机名为 `OWRT`，工作流中的登录密码提示为“无”。Auto-Clean 每天北京时间 06:00 运行，成功完成后仅触发 QCA-ALL；实际开始时间受 GitHub Actions 调度影响。固件页面显示编译开始时间。

## 手动编译和配置检查

在 Actions 中运行 `QCA-ALL` 可构建太乙/M2 固件，固定使用 `IPQ60XX-WIFI-NO`、`VIKINGYFY/immortalwrt`、`main`。默认执行完整编译；勾选 `TEST` 时只生成同一套设备及插件的配置文件。

`PACKAGE` 输入填写 Kconfig 行，多行用字面量 `\n` 分隔，例如：

```text
CONFIG_PACKAGE_luci-app-ttyd=y\nCONFIG_PACKAGE_luci-app-samba4=n
```

`TEST=true` 会跳过缓存读写、下载和编译固件，仍执行源码、feeds、软件包准备及 `make defconfig`，并发布配置文件。因此配置检查通过不代表完整固件编译已经通过。

## 配置与脚本

- `.github/workflows/`：编译入口、共用核心和清理任务。
- `Config/IPQ60XX-WIFI-NO.txt`：太乙/M2 无 Wi-Fi 设备配置。
- `Config/GENERAL.txt`：两台设备共用的插件及编译设置。
- `Scripts/Packages.sh`：跟随上游的软件包来源。sing-box 使用 VIKINGYFY/packages 配套版本和校验值，不再单独改写版本。
- `Scripts/Handles.sh`：软件包兼容修复及 HomeProxy 资源准备。
- `Scripts/Settings.sh`：默认网络、主题、无 Wi-Fi DTS 及扩展配置。
- `PkgConfig/`：现有软件包配置文件，工作流不会自动将其嵌入固件。

可选扩展入口为 `Scripts/PRIVATE.sh` 和 `Config/PRIVATE.txt`。Kconfig 应用顺序是设备配置 → GENERAL → 默认主题 → PRIVATE → PACKAGE；后面的配置可覆盖前面的同名选项。

构建缓存按源码仓库、分支和目标平台隔离，编译成功后保存新缓存，确认新缓存存在后再清理旧缓存。完整编译失败时以单线程 `V=s` 重试，便于定位错误。
