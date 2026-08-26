#pragma once

#include <cstdarg>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

#ifndef kEXECUTABLE
#include <android/log.h>
#define LOG_TAG "UEDump3r"
#endif

namespace Logger
{
    using SinkFn = void (*)(char level, const char *message);

    inline SinkFn &GetSink()
    {
        static SinkFn sink = nullptr;
        return sink;
    }

    inline void SetSink(SinkFn sink)
    {
        GetSink() = sink;
    }

    inline void ForwardToSink(char level, const char *message)
    {
        if (auto sink = GetSink())
            sink(level, message);
    }

    // 注入模式下游戏进程的 log 会被 logd 过滤、logcat 抓不到，
    // 因此所有日志同时追加写入 /data/1/unrealmt.log（目录权限 777，游戏进程可写）。
    inline void LogToFile(char level, const char *message)
    {
        if (!message || !*message)
            return;
        int fd = open("/data/1/unrealmt.log", O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (fd < 0)
            return;
        char line[4224] = {0};
        int n = snprintf(line, sizeof(line), "%c: %s\n", level, message);
        if (n > 0)
        {
            if (n > (int)sizeof(line))
                n = (int)sizeof(line);
            write(fd, line, (size_t)n);
        }
        close(fd);
    }

#ifndef kEXECUTABLE
    inline int ToAndroidPriority(char level)
    {
        switch (level)
        {
            case 'V': return ANDROID_LOG_VERBOSE;
            case 'D': return ANDROID_LOG_DEBUG;
            case 'I': return ANDROID_LOG_INFO;
            case 'W': return ANDROID_LOG_WARN;
            case 'E': return ANDROID_LOG_ERROR;
            case 'F': return ANDROID_LOG_FATAL;
            default: return ANDROID_LOG_DEFAULT;
        }
    }
#endif

    inline void Log(char level, const char *fmt, ...)
    {
        char buffer[4096] = {0};

        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);

#ifdef kEXECUTABLE
        std::printf("%c: %s\n", level, buffer);
#else
        __android_log_print(ToAndroidPriority(level), LOG_TAG, "%s", buffer);
#endif

        LogToFile(level, buffer);
        ForwardToSink(level, buffer);
    }
}  // namespace Logger

#define LOGV(fmt, ...) ::Logger::Log('V', fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) ::Logger::Log('I', fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) ::Logger::Log('W', fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) ::Logger::Log('E', fmt, ##__VA_ARGS__)
#define LOGF(fmt, ...) ::Logger::Log('F', fmt, ##__VA_ARGS__)

#ifndef NDEBUG
#define LOGD(fmt, ...) ::Logger::Log('D', fmt, ##__VA_ARGS__)
#else
#define LOGD(...) do {} while (false)
#endif
