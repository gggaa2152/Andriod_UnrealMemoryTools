// ============================================================================
//  UnrealMemoryTools - Hook 注入模式入口
// ----------------------------------------------------------------------------
//  本文件将工具从「独立可执行文件」改造为「共享动态库 (.so)」：
//    - 通过 __attribute__((constructor)) 在 dlopen 加载瞬间自动执行
//    - 安装崩溃信号捕获器（向 logcat 和 /data/1/crash.log 写入调用现场）
//    - 等待目标 UE 动态库 (libUE4.so / libUnreal.so / libShadowTrackerExtra.so)
//    - 尝试启动 UI 悬浮窗，若 UI 受限则自动在后台执行 UE 内存探针与 SDK Dump
// ============================================================================

#include <android/log.h>
#include <thread>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <ucontext.h>

#define LOG_TAG "UnrealMemoryTools"

// 注入模式下游戏进程的 log 被 logd 过滤，logcat 抓不到。
// 因此所有日志同时追加写入 /data/1/unrealmt.log（目录 777 权限，游戏进程可写）。
static void UnrealLogToFile(const char *fmt, ...)
{
    if (!fmt)
        return;
    char buf[4096] = {0};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int fd = open("/data/1/unrealmt.log", O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0)
        return;
    char line[4224] = {0};
    int n = snprintf(line, sizeof(line), "I: %s\n", buf);
    if (n > (int)sizeof(line))
        n = (int)sizeof(line);
    write(fd, line, (size_t)n);
    close(fd);
}

#define LOGI(...) do { __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); UnrealLogToFile(__VA_ARGS__); } while (0)
#define LOGE(...) do { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); UnrealLogToFile(__VA_ARGS__); } while (0)

// 原主流程（由 executable.cpp 提供）
extern int ExecutableMain();

namespace
{
    // ============ 全局崩溃捕获器 ============
    void CrashHandler(int sig, siginfo_t *info, void *ucontext)
    {
        uintptr_t pc = 0, lr = 0, sp = 0;
#if defined(__aarch64__)
        auto *ctx = static_cast<ucontext_t *>(ucontext);
        if (ctx)
        {
            pc = ctx->uc_mcontext.pc;
            lr = ctx->uc_mcontext.regs[30];
            sp = ctx->uc_mcontext.sp;
        }
#endif
        LOGE("!!! 捕获到致命信号 sig=%d si_code=%d fault_addr=%p pc=0x%lx lr=0x%lx sp=0x%lx !!!",
             sig, info ? info->si_code : 0, info ? info->si_addr : nullptr,
             (unsigned long)pc, (unsigned long)lr, (unsigned long)sp);

        // 写入 /data/1/crash.log
        int fd = open("/data/1/crash.log", O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd >= 0)
        {
            char buf[512];
            int len = snprintf(buf, sizeof(buf),
                               "UnrealMemoryTools Crash Log\n"
                               "Signal: %d (code=%d)\n"
                               "Fault Address: %p\n"
                               "PC: 0x%lx\n"
                               "LR: 0x%lx\n"
                               "SP: 0x%lx\n"
                               "PID: %d\n",
                               sig, info ? info->si_code : 0,
                               info ? info->si_addr : nullptr,
                               (unsigned long)pc, (unsigned long)lr,
                               (unsigned long)sp, getpid());
            write(fd, buf, len);

            // 追加 maps 中命中的地址
            std::ifstream maps("/proc/self/maps");
            if (maps.is_open())
            {
                std::string line;
                while (std::getline(maps, line))
                {
                    if (line.find("libUnrealMemoryTools.so") != std::string::npos ||
                        line.find("libUE4.so") != std::string::npos ||
                        line.find("libShadowTrackerExtra.so") != std::string::npos)
                    {
                        write(fd, line.c_str(), line.length());
                        write(fd, "\n", 1);
                    }
                }
            }
            close(fd);
        }

        // 恢复默认处理并重新抛出，让系统生成 tombstone
        signal(sig, SIG_DFL);
        raise(sig);
    }

    void InstallCrashHandler()
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = CrashHandler;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;

        sigaction(SIGSEGV, &sa, nullptr);
        sigaction(SIGABRT, &sa, nullptr);
        sigaction(SIGBUS, &sa, nullptr);
        sigaction(SIGFPE, &sa, nullptr);
        sigaction(SIGILL, &sa, nullptr);
    }

    // 当前进程是否已加载 UE 核心库
    bool HasUnrealLibLoaded()
    {
        std::ifstream maps("/proc/self/maps");
        if (!maps.is_open())
            return false;

        static const std::vector<std::string> knownLibs = {
            "libUE4.so",
            "libUnreal.so",
            "libShadowTrackerExtra.so",
            "libgcloud.so",
            "libclient.so"
        };

        std::string line;
        while (std::getline(maps, line))
        {
            for (const auto &name : knownLibs)
            {
                if (line.find(name) != std::string::npos)
                    return true;
            }
        }
        return false;
    }

    // 等待 UE 库加载
    void WaitUnrealLib()
    {
        LOGI("等待游戏核心引擎库 (libUE4.so / libShadowTrackerExtra.so / libUnreal.so) 加载...");
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
        LOGE("等待超时：未检测到 UE 核心动态库，仍尝试继续执行。");
    }

    void HookWorker()
    {
        WaitUnrealLib();
        LOGI("正在初始化 UnrealMemoryTools (pid=%d)...", getpid());

        // 启动主流程（含悬浮窗尝试与后台自动 Dump 兜底）
        ExecutableMain();
    }
}  // namespace

// ============ 动态库加载入口 ============
__attribute__((constructor))
void UnrealMemoryTools_OnLoad()
{
    InstallCrashHandler();
    LOGI("UnrealMemoryTools (Hook 模式) 已注入，pid=%d, 构建: 2026-08-26n-nocapture", getpid());

    static bool started = false;
    if (started)
        return;
    started = true;

    std::thread(HookWorker).detach();
}
