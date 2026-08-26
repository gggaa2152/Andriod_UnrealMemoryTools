// ============================================================================
//  EGL Overlay - 游戏画面内叠加 ImGui 菜单（绕过悬浮窗权限）
// ----------------------------------------------------------------------------
//  原理：
//    1. GOT/PLT hook 游戏进程内所有模块对 eglSwapBuffers 的调用（改 .got 槽，
//       不写 .text，干净且不易被反作弊扫描到）；
//    2. 在游戏渲染线程 swap 前，复用游戏当前 GL context 渲染 ImGui 菜单；
//    3. hook libandroid.so 的 AInputQueue_getEvent，把游戏触摸事件喂给 ImGui
//       （菜单打开时吃掉事件，避免游戏误操作）。
// ============================================================================
#pragma once

#include <EGL/egl.h>

struct AInputEvent;

namespace OverlayUI
{
    // 安装 hook；成功返回 true（菜单会叠加在游戏画面上）
    bool Install();

    bool IsActive();

    extern int g_touchMode; // 1: 顺时针横屏90° (口在右)  2: 逆时针横屏270° (口在左)  0: 1:1直通
}  // namespace OverlayUI
