#!/bin/bash
# ============================================================================
#  一键注入脚本 (电脑端)
#  将 libUnrealMemoryTools.so 与 injector 推送到设备，并注入指定游戏进程。
#
#  用法:
#    ./inject.sh <游戏包名> [so本地路径]
#
#  示例:
#    ./inject.sh com.tencent.tmgp.pubgm
#    ./inject.sh com.epicgames.portal /path/to/libUnrealMemoryTools.so
# ============================================================================

set -e

if [ -z "$1" ]; then
    echo "用法: $0 <游戏包名> [so本地路径]"
    exit 1
fi

PKG="$1"
SO_LOCAL="${2:-libUnrealMemoryTools.so}"
SO_REMOTE="/data/local/tmp/libUnrealMemoryTools.so"
INJ_REMOTE="/data/local/tmp/injector"

echo "[*] 推送 libUnrealMemoryTools.so -> $SO_REMOTE"
adb push "$SO_LOCAL" "$SO_REMOTE"

echo "[*] 推送 injector -> $INJ_REMOTE"
adb push injector "$INJ_REMOTE"
adb shell chmod 755 "$INJ_REMOTE"

echo "[*] 注入包名: $PKG"
adb shell su -c "$INJ_REMOTE -n $PKG -l $SO_REMOTE"

echo "[*] 监听 UnrealMemoryTools 日志 (Ctrl+C 退出)"
adb logcat -s UnrealMemoryTools
