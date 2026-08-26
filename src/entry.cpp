// ============================================================================
//  UnrealMemoryTools - Hook 注入模式入口
// ----------------------------------------------------------------------------
//  本文件将工具从「独立可执行文件」改造为「共享动态库 (.so)」：
//    - 通过 __attribute__((constructor)) 在 dlopen 加载瞬间自动执行
//    - 等待目标 UE 动态库 (libUE4.so / libUnreal.so) 加载完成
//    - 在独立线程中拉起原有 Vulkan 悬浮窗 UI 与 Dump 管线
//
//  注入方式（任选其一）：
//    A. 注入器 (ptrace 注入 / Zygisk / magisk 模块 dlopen)
//    B. Frida 测试: frida -U -f <pkg> -l load.js
//       其中 load.js: Process.loadLibrary("/data/local/tmp/libUnrealMemoryTools.so")
// ============================================================================

#include <android/log.h>
#include <thread>
#include <chrono>
#include <cstring>
#include <fstream>
#include <string>
#include <unistd.h>

#define LOG_TAG "UnrealMemoryTools"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 原 standalone 主流程（已由 executable.cpp 提供）
extern int ExecutableMain();

namespace
{
    // 当前进程是否已加载 UE 核心库
    bool HasUnrealLibLoaded()
    {
        std::ifstream maps("/proc/self/maps");
        if (!maps.is_open())
            return false;

        std::string line;
        while (std::getline(maps, line))
        {
            if (line.find("libUE4.so") != std::string::npos ||
                line.find("libUnreal.so") != std::string::npos)
                return true;
        }
        return false;
    }

    // 等待 UE 库加载，最长 5 分钟（注入通常发生在游戏启动早期）
    void WaitUnrealLib()
    {
        constexpr int kMaxTries = 600;   // 600 * 500ms = 300s
        for (int i = 0; i < kMaxTries; ++i)
        {
            if (HasUnrealLibLoaded())
            {
                LOGI("检测到 Unreal Engine 动态库已加载。");
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        LOGE("等待超时：未检测到 libUE4.so / libUnreal.so。");
    }

    void HookWorker()
    {
        WaitUnrealLib();
        LOGI("启动注入式悬浮窗 UI (Vulkan + ImGui)...");

        // 拉起原 Vulkan 悬浮窗渲染循环（自动探测当前进程 = 自身）
        ExecutableMain();
    }
}  // namespace

// ============ 动态库加载入口 ============
__attribute__((constructor))
void UnrealMemoryTools_OnLoad()
{
    LOGI("UnrealMemoryTools (Hook 模式) 已注入，pid=%d", getpid());

    static bool started = false;
    if (started)
        return;
    started = true;

    std::thread(HookWorker).detach();
}
