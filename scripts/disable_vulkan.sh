#!/system/bin/sh
# 禁用某款 UE4 游戏的 Vulkan，强行回退 OpenGL

PKG=$1
if [ -z "$PKG" ]; then
  echo "用法: sh disable_vulkan.sh <游戏包名>"
  echo "例如: sh disable_vulkan.sh com.tencent.tmgp.dfm"
  exit 1
fi

DIR="/sdcard/Android/data/$PKG/files/UE4Game"
if [ ! -d "$DIR" ]; then
  echo "未找到UE4目录: $DIR (请确保游戏已安装并至少运行过一次)"
  exit 1
fi

echo "正在扫描 $PKG 的 UE4 配置文件..."
find "$DIR" -name "Engine.ini" -o -name "GameUserSettings.ini" | while read ini_file; do
  echo "正在修改配置: $ini_file"
  if ! grep -q "DisableVulkanSupport" "$ini_file"; then
    echo "" >> "$ini_file"
    echo "[SystemSettings]" >> "$ini_file"
    echo "r.Vulkan.Enable=0" >> "$ini_file"
    echo "r.Android.DisableVulkanSupport=1" >> "$ini_file"
    echo "-> 成功写入禁用 Vulkan 代码！"
  else
    echo "-> 该文件已经禁用了 Vulkan，无需重复写入。"
  fi
done

echo "完成！以后进游戏默认就是 OpenGL，你可以随时中途注入了！"
