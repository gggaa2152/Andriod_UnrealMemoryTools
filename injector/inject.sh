#!/bin/bash
# ============================================================================
#  一键注入脚本 (电脑端)
#  将 libUnrealMemoryTools.so 与 injector 推送到设备 /data/1/，并注入进程。
#
#  用法:
#    ./inject.sh                 (自动扫描并注入第一个虚幻游戏进程)
#    ./inject.sh <游戏包名>      (按包名注入)
#    ./inject.sh <游戏包名> <so本地路径>
#
#  示例:
#    ./inject.sh
#    ./inject.sh com.tencent.tmgp.pubgm
# ============================================================================

set -e

PKG="$1"
SO_LOCAL="${2:-libUnrealMemoryTools.so}"
SO_REMOTE="/data/1/libUnrealMemoryTools.so"
INJ_REMOTE="/data/1/injector"

# /data/1 通常需 root 才能写入，先推到 tmp 再 su 拷贝过去
echo "[*] 推送 libUnrealMemoryTools.so -> $SO_REMOTE"
adb push "$SO_LOCAL" /data/local/tmp/libUnrealMemoryTools.so
adb shell su -c "mkdir -p /data/1 && cp /data/local/tmp/libUnrealMemoryTools.so $SO_REMOTE && chmod 755 $SO_REMOTE"

echo "[*] 推送 injector -> $INJ_REMOTE"
adb push injector /data/local/tmp/injector
adb shell su -c "cp /data/local/tmp/injector $INJ_REMOTE && chmod 755 $INJ_REMOTE"

if [ -n "$PKG" ]; then
    echo "[*] 注入包名: $PKG"
    adb shell su -c "$INJ_REMOTE -n $PKG -l $SO_REMOTE"
else
    echo "[*] 自动扫描并注入虚幻游戏进程"
    adb shell su -c "$INJ_REMOTE -l $SO_REMOTE"
fi

echo "[*] 监听 UnrealMemoryTools 日志 (Ctrl+C 退出)"
adb logcat -s UnrealMemoryTools
