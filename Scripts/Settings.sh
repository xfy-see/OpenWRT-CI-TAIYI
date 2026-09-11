#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 VIKINGYFY

#移除luci-app-attendedsysupgrade
find ./feeds/luci/collections/ -type f -name "Makefile" -exec sed -i "/attendedsysupgrade/d" {} +
#修改默认主题
find ./feeds/luci/collections/ -type f -name "Makefile" -exec sed -i "s/luci-theme-bootstrap/luci-theme-$WRT_THEME/g" {} +
#修改immortalwrt.lan关联IP
find ./feeds/luci/modules/luci-mod-system/ -type f -name "flash.js" -exec sed -i "s/192\.168\.[0-9]*\.[0-9]*/$WRT_IP/g" {} +
#添加编译日期标识
find ./feeds/luci/modules/luci-mod-status/ -type f -name "10_system.js" -exec sed -i "s/(\(luciversion || ''\))/(\1) + (' \/ $WRT_MARK-$WRT_DATE')/g" {} +

WIFI_SH_FOUND=false
WIFI_UC="./package/network/config/wifi-scripts/files/lib/wifi/mac80211.uc"
while IFS= read -r -d '' WIFI_SH; do
	WIFI_SH_FOUND=true
	#修改WIFI名称
	sed -i "s/BASE_SSID='.*'/BASE_SSID='$WRT_SSID'/g" "$WIFI_SH"
	#修改WIFI密码
	sed -i "s/BASE_WORD='.*'/BASE_WORD='$WRT_WORD'/g" "$WIFI_SH"
done < <(find ./target/linux/{mediatek/filogic,qualcommax}/base-files/etc/uci-defaults/ -type f -name "*set-wireless.sh" -print0 2>/dev/null)
if [ "$WIFI_SH_FOUND" = false ] && [ -f "$WIFI_UC" ]; then
	#修改WIFI名称
	sed -i "s/ssid='.*'/ssid='$WRT_SSID'/g" "$WIFI_UC"
	#修改WIFI密码
	sed -i "s/key='.*'/key='$WRT_WORD'/g" "$WIFI_UC"
fi

CFG_FILE="./package/base-files/files/bin/config_generate"
#修改默认IP地址
sed -i "s/192\.168\.[0-9]*\.[0-9]*/$WRT_IP/g" "$CFG_FILE"
#修改默认主机名
sed -i "s/hostname='.*'/hostname='$WRT_NAME'/g" "$CFG_FILE"

#配置文件修改
echo "CONFIG_PACKAGE_luci=y" >> ./.config
echo "CONFIG_LUCI_LANG_zh_Hans=y" >> ./.config
echo "CONFIG_PACKAGE_luci-theme-$WRT_THEME=y" >> ./.config
# bootstrap 等内置主题没有独立设置插件。
if [ -n "$(find ./package ./feeds/luci -type d -name "luci-app-$WRT_THEME-config" -print -quit)" ]; then
	echo "CONFIG_PACKAGE_luci-app-$WRT_THEME-config=y" >> ./.config
fi

#引入私有扩展配置
if [ -f "$GITHUB_WORKSPACE/Config/PRIVATE.txt" ]; then
	echo "Applying private configurations from PRIVATE.txt..."
	cat "$GITHUB_WORKSPACE/Config/PRIVATE.txt" >> ./.config
fi

#手动调整的插件
if [ -n "$WRT_PACKAGE" ]; then
	echo -e "$WRT_PACKAGE" >> ./.config
fi

#无WIFI配置标志
WIFI_DISABLED=false
if [[ "${WRT_CONFIG,,}" == *"wifi"* && "${WRT_CONFIG,,}" == *"no"* ]]; then
	WIFI_DISABLED=true
elif [[ "${WRT_TARGET^^}" == *"QUALCOMMAX"* ]]; then
	# TEST 等自定义配置不一定在文件名中标记 WIFI；按覆盖后的最终值判断。
	ATH11K_STATE=$(awk -F= '
		/^CONFIG_PACKAGE_kmod-ath11k=/ { state = $2 }
		/^# CONFIG_PACKAGE_kmod-ath11k is not set$/ { state = "n" }
		END { print state }
	' ./.config)
	if [ "$ATH11K_STATE" = n ]; then
		WIFI_DISABLED=true
	fi
fi
if [ "$WIFI_DISABLED" = true ]; then
	echo "WRT_WIFI=wifi-no" >> "$GITHUB_ENV"
fi

#高通平台调整
if [[ "${WRT_TARGET^^}" == *"QUALCOMMAX"* ]]; then
	#无WIFI配置调整Q6大小
	if [ "$WIFI_DISABLED" = true ]; then
		DTS_PATH="./target/linux/qualcommax/dts"
		if [ ! -d "$DTS_PATH" ]; then
			DTS_PATH="./target/linux/qualcommax/files/arch/arm64/boot/dts/qcom"
		fi
		if [ -d "$DTS_PATH" ]; then
			find "$DTS_PATH" -type f ! -iname '*nowifi*' -exec sed -i -E 's/ipq(6018|8074)\.dtsi/ipq\1-nowifi.dtsi/g' {} +
			echo "qualcommax set up nowifi successfully!"
		else
			echo "Qualcommax DTS directory not found; unable to apply the no-WIFI memory layout." >&2
			exit 1
		fi
	fi
fi
