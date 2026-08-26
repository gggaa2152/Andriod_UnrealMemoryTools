// ============================================================================
//  EGL Overlay 实现（GOT hook + GLES overlay 渲染）
// ============================================================================
#include "draw_overlay.h"

#include "draw.h"            // Layout_tick_UI / init_My_drawdata / graphics
#include "Android_Graphics/OpenGLGraphics.h"
#include "imgui_impl_opengl3.h"
#include "my_imgui_impl_android.h"
#include "../../Utils/Logger.hpp"  // LOGI/LOGE（kEXECUTABLE 下写文件 + printf）
#include "../../UE/UEMemory.hpp"   // UEMemory::kMgr（DIRECT 模式）
#include "../native_surface/ANativeWindowCreator.h"  // GetDisplayInfo（屏幕物理分辨率）

#include <android/input.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <GLES3/gl3.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <atomic>
#include <string>
#include <vector>
#include <thread>

// 自动探针 + Dump（由 executable.cpp 提供）
extern void RunAutoProbeDump();

// aarch64 重定位类型（<elf.h> 未必带，安全起见自备）
#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT 1025
#endif
#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026
#endif

namespace
{
    std::atomic<bool> g_installed{false};
    std::atomic<bool> g_ready{false};
    bool g_menu_open = true;

    EGLDisplay g_dpy = EGL_NO_DISPLAY;
    EGLSurface g_srf = EGL_NO_SURFACE;
    int g_win_w = 0, g_win_h = 0;

    // ================= 符号 GOT hook =================
    // 只 hook 游戏渲染核心模块（调用 eglSwapBuffers 的位置在 libUE4 等），
    // 跳过腾讯保护库（libPx*）与系统库，避免触发反作弊完整性校验。
    bool IsRenderModule(const std::string &path)
    {
        return path.find("libUE4.so") != std::string::npos ||
               path.find("libUnreal.so") != std::string::npos ||
               path.find("libclient.so") != std::string::npos ||
               path.find("libShadowTrackerExtra.so") != std::string::npos;
    }

    bool HookPltSymbol(const char *module, const char *symName,
                       void *hookFn, void **origFn)
    {
        // 使用本地内存后端（DIRECT 进程内直读）。
        // 注意：不能依赖全局 UEMemory::kMgr —— overlay 安装发生在 ExecuteProbe 之前，
        // kMgr 此时尚未 initialize，_pMemOp 为空会导致 ElfScanner 全部解析失败（有效模块=0）。
        KittyMemoryMgr localMgr;
        if (!localMgr.initialize(getpid(), EK_MEM_OP_DIRECT, false))
        {
            LOGE("[OV] 本地内存后端初始化失败");
            return false;
        }

        void *handle = dlopen(module, RTLD_NOW);
        if (!handle)
        {
            LOGE("[OV] dlopen(%s) 失败", module);
            return false;
        }
        void *target = dlsym(handle, symName);
        if (!target)
        {
            LOGE("[OV] dlsym(%s) 失败", symName);
            return false;
        }
        if (origFn)
            *origFn = target;
        LOGI("[OV] %s::%s = %p", module, symName, target);

        const auto maps = KittyMemoryEx::getAllMaps(getpid());
        bool anyHooked = false;
        int relocTotal = 0;
        int scannedMods = 0, validMods = 0;

        for (const auto &m : maps)
        {
            if (m.pathname.find(".so") == std::string::npos)
                continue;
            if (!IsRenderModule(m.pathname))
                continue;   // 只处理游戏渲染核心模块
            scannedMods++;

            ElfScanner es = localMgr.elfScanner.createWithBase(m.startAddress);
            if (!es.isValid())
                continue;
            validMods++;

            const uintptr_t bias = es.loadBias();
            const uintptr_t strtab = es.stringTable();
            const uintptr_t symtab = es.symbolTable();
            if (!bias || !strtab || !symtab)
                continue;

            // 收集重定位表（DT_JMPREL -> .rela.plt，DT_RELA -> .rela.dyn）
            struct RelocTable
            {
                uintptr_t addr = 0;
                size_t size = 0;
            };
            RelocTable plt, dyn;

            for (const auto &d : es.dynamics())
            {
                if (d.d_tag == DT_JMPREL)
                    plt.addr = bias + d.d_un.d_ptr;
                else if (d.d_tag == DT_PLTRELSZ)
                    plt.size = d.d_un.d_val;
                else if (d.d_tag == DT_RELA)
                    dyn.addr = bias + d.d_un.d_ptr;
                else if (d.d_tag == DT_RELASZ)
                    dyn.size = d.d_un.d_val;
            }

            const RelocTable tables[2] = {plt, dyn};
            for (const auto &tbl : tables)
            {
                if (!tbl.addr || tbl.size < sizeof(Elf64_Rela))
                    continue;
                if (tbl.size > 16 * 1024 * 1024)   // 越界保护
                    continue;

                const size_t count = tbl.size / sizeof(Elf64_Rela);
                std::vector<Elf64_Rela> rels(count);
                if (!localMgr.readMem(tbl.addr, rels.data(), tbl.size))
                    continue;

                for (const auto &rel : rels)
                {
                    const unsigned type = (unsigned)(rel.r_info & 0xffffffff);
                    if (type != R_AARCH64_JUMP_SLOT && type != R_AARCH64_GLOB_DAT)
                        continue;

                    const size_t symIdx = (size_t)(rel.r_info >> 32);
                    Elf64_Sym sym{};
                    if (!localMgr.readMem(symtab + (uintptr_t)symIdx * sizeof(Elf64_Sym),
                                      &sym, sizeof(sym)))
                        continue;
                    if (!sym.st_name)
                        continue;

                    char name[128] = {0};
                    if (!localMgr.readMem(strtab + sym.st_name, name, sizeof(name) - 1))
                        continue;
                    if (strcmp(name, symName) != 0)
                        continue;

                    // GOT 槽 = bias + r_offset
                    const uintptr_t slot = bias + rel.r_offset;
                    uintptr_t cur = 0;
                    localMgr.readMem(slot, &cur, sizeof(cur));

                    // 不校验 cur == target：部分模块 lazy binding（槽未解析，指向 PLT stub），
                    // 直接改写槽即可，hook 函数内部会调用 dlsym 保存的原函数。
                    LOGI("[OV] 匹配 %s %s @ %p (cur=%p -> hook=%p)", m.pathname.c_str(),
                         symName, (void *)slot, (void *)cur, hookFn);

                    // 解除保护后写入；写完恢复【原页权限】而非强制只读——
                    // libUE4 的 GOT 页原为可写（懒绑定需继续写 GOT），
                    // 若强制 PROT_READ 会导致下一次懒绑定写 GOT 时 SEGV_ACCERR。
                    const long pgsz = sysconf(_SC_PAGESIZE);
                    const uintptr_t pg = slot & ~(uintptr_t)(pgsz - 1);
                    mprotect((void *)pg, pgsz, PROT_READ | PROT_WRITE);
                    *(void **)slot = hookFn;
                    __builtin___clear_cache((char *)slot, (char *)slot + sizeof(void *));

                    const auto slotMap = KittyMemoryEx::getAddressMap(maps, slot);
                    int origProt = PROT_NONE;
                    if (slotMap.readable) origProt |= PROT_READ;
                    if (slotMap.writeable) origProt |= PROT_WRITE;
                    if (slotMap.executable) origProt |= PROT_EXEC;
                    mprotect((void *)pg, pgsz, origProt);

                    anyHooked = true;
                    relocTotal++;
                }
            }
        }

        LOGI("[OV] %s hook 完成，改写槽数 = %d (扫描 .so 模块 %d / 有效 %d)",
             symName, relocTotal, scannedMods, validMods);
        return anyHooked;
    }

    // ================= overlay 触摸校准与全链路诊断 =================
    static float g_physLong = 3392.0f;
    static float g_physShort = 2400.0f;
    static int g_touchLogCount = 0;
    static int g_touchMode = 0; // 默认 0: 1:1直通(Android原生自带旋转)  1: 顺时针横屏90°  2: 逆时针横屏270°

    void OverlayInputTransform(float *x, float *y)
    {
        if (!x || !y || g_win_w <= 0 || g_win_h <= 0)
            return;

        // 【核心修复】Android 的 AInputQueue_getEvent 拿到的 AInputEvent (经 AMotionEvent_getX 提取) 
        // 已经是经过系统 InputDispatcher 处理过、映射到当前 Window / View 的相对坐标。
        // 它已经包含了屏幕旋转（横竖屏）的修正。
        // 绝大部分情况下，直接将这个坐标传给 ImGui 即可，不需要再次进行 g_physLong 的等比缩放或 XY 轴互换！
        
        // 我们提供一个配置项或者直接直通
        float rx = *x;
        float ry = *y;
        float targetX = rx;
        float targetY = ry;
        const char* modeStr = "绝对直通(不缩放不旋转)";

        if (g_touchMode == 1) {
            // 旧逻辑：顺时针90度 (强制物理比例)
            modeStr = "横屏90°(强制物理比例)";
            targetX = ry * ((float)g_win_w / 3392.0f);
            targetY = rx * ((float)g_win_h / 2400.0f);
        } else if (g_touchMode == 2) {
            // 旧逻辑：逆时针270度
            modeStr = "横屏270°(强制物理比例)";
            targetX = (3392.0f - ry) * ((float)g_win_w / 3392.0f);
            targetY = (2400.0f - rx) * ((float)g_win_h / 2400.0f);
        } else if (g_touchMode == 3) {
            // 旧逻辑：1:1 等比缩放 (如果窗口分辨率和事件分辨率不一致)
            modeStr = "直通等比缩放";
            targetX = rx * ((float)g_win_w / 3392.0f);
            targetY = ry * ((float)g_win_h / 2400.0f);
        } else {
            // 默认模式 0：绝对直通。完全信任 Android 系统的坐标映射。
            targetX = rx;
            targetY = ry;
        }

        // 依然保留合法边界保护，防止因为越界导致 ImGui 异常
        if (targetX < 0.0f) targetX = 0.0f;
        if (targetX > (float)g_win_w) targetX = (float)g_win_w;
        if (targetY < 0.0f) targetY = 0.0f;
        if (targetY > (float)g_win_h) targetY = (float)g_win_h;

        // 仅在最开始的 60 次触摸打印日志，方便用户使用 logcat 诊断
        if (g_touchLogCount < 60)
        {
            g_touchLogCount++;
            LOGI("[CHAIN-TOUCH] #%d [%s] 原始=(%.1f, %.1f) -> 映射ImGui=(%.1f, %.1f) | Surface=%dx%d",
                 g_touchLogCount, modeStr, rx, ry, targetX, targetY, g_win_w, g_win_h);
        }

        *x = targetX;
        *y = targetY;
    }

    void OverlayInit(EGLDisplay dpy, EGLSurface srf)
    {
        int w = 0, h = 0;
        eglQuerySurface(dpy, srf, EGL_WIDTH, &w);
        eglQuerySurface(dpy, srf, EGL_HEIGHT, &h);
        if (w <= 0 || h <= 0)
            return;

        g_dpy = dpy;
        g_srf = srf;
        g_win_w = w;
        g_win_h = h;

        LOGI("[OV] EGL Surface=%dx%d, 物理屏幕基准=%.0fx%.0f (全链路触控自适应+屏幕光标可视化就绪)",
             g_win_w, g_win_h, g_physLong, g_physShort);

        ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();
        // 逻辑系 = 渲染 surface 尺寸（等比不拉伸，字体清晰，点位精准）
        io.DisplaySize = ImVec2((float)g_win_w, (float)g_win_h);
        io.DisplayFramebufferScale = ImVec2(1.f, 1.f);
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;

        ImGui_ImplOpenGL3_Init("#version 300 es");
        My_ImGui_ImplAndroid_Init(nullptr);
        My_ImGui_ImplAndroid_SetInputTransform(OverlayInputTransform);

        // 计算当前 Overlay 分辨率下的 DPI 缩放比例
        float minDim = (g_win_w < g_win_h) ? (float)g_win_w : (float)g_win_h;
        float dpiScale = minDim / 1080.0f;
        if (dpiScale < 0.85f) dpiScale = 0.85f;
        if (dpiScale > 2.2f)  dpiScale = 2.2f;

        // 复用当前 GL context 做纹理加载（不创建独立 context）
        ::graphics = std::make_unique<OpenGLGraphics>();
        init_My_drawdata(dpiScale);

        // 触发自动探针 / Dump 线程
        std::thread(RunAutoProbeDump).detach();

        g_ready = true;
        LOGI("[OV] EGL Overlay 初始化完成，逻辑画布=%dx%d (scale=%.2f)", g_win_w, g_win_h, dpiScale);
    }

    void OverlayFrame()
    {
        if (!g_ready)
            return;

        My_ImGui_ImplAndroid_NewFrame();
        ImGui_ImplOpenGL3_NewFrame();

        // 逻辑系固定为 surface 尺寸（输入变换已完成等比缩放+居中）
        ImGuiIO &io = ImGui::GetIO();
        io.DisplaySize = ImVec2((float)g_win_w, (float)g_win_h);
        io.DisplayFramebufferScale = ImVec2(1.f, 1.f);

        ImGui::NewFrame();

        Layout_tick_UI(&g_menu_open);

        // 🎯 屏幕实时触控光标轨迹可视化
        if (io.MouseDown[0] || (io.MousePos.x >= 0.0f && io.MousePos.x <= (float)g_win_w && io.MousePos.y >= 0.0f && io.MousePos.y <= (float)g_win_h))
        {
            ImDrawList* fg = ImGui::GetForegroundDrawList();
            if (fg)
            {
                fg->AddCircleFilled(io.MousePos, 16.0f, IM_COL32(0, 255, 120, 180));
                fg->AddCircle(io.MousePos, 22.0f, IM_COL32(255, 255, 255, 240), 0, 2.5f);
                fg->AddLine(ImVec2(io.MousePos.x - 28, io.MousePos.y), ImVec2(io.MousePos.x + 28, io.MousePos.y), IM_COL32(255, 255, 0, 200), 1.5f);
                fg->AddLine(ImVec2(io.MousePos.x, io.MousePos.y - 28), ImVec2(io.MousePos.x, io.MousePos.y + 28), IM_COL32(255, 255, 0, 200), 1.5f);

                char tip[128];
                snprintf(tip, sizeof(tip), "Touch: (%.1f, %.1f) Down:%d", io.MousePos.x, io.MousePos.y, io.MouseDown[0]);
                fg->AddText(ImVec2(io.MousePos.x + 30, io.MousePos.y - 20), IM_COL32(255, 255, 0, 255), tip);
            }
        }

        // 🎯 屏幕右上角浮动快捷切换小药丸（单点直接切换 90°/270°/1:1）
        ImGui::SetNextWindowPos(ImVec2((float)g_win_w - 240.0f, 12.0f), 0);
        ImGui::SetNextWindowSize(ImVec2(230.0f, 42.0f), 0);
        ImGui::Begin("##TouchDirSwitch", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBackground);
        char btnText[64];
        snprintf(btnText, sizeof(btnText), "🔄 触控:%s", (g_touchMode == 2 ? "270°(口在左)" : (g_touchMode == 1 ? "90°(口在右)" : "1:1直通")));
        if (ImGui::Button(btnText, ImVec2(225.0f, 36.0f)))
        {
            g_touchMode = (g_touchMode == 1 ? 2 : (g_touchMode == 2 ? 0 : 1));
            LOGI("[OV-TOUCH] 快捷切换触控方向 -> %s", (g_touchMode == 2 ? "270°" : (g_touchMode == 1 ? "90°" : "1:1")));
        }
        ImGui::End();

        ImGui::Render();
        glViewport(0, 0, g_win_w, g_win_h);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    }

    // ================= hook 回调 =================
    static EGLBoolean (*real_eglSwapBuffers)(EGLDisplay, EGLSurface) = nullptr;

    EGLBoolean hook_eglSwapBuffers(EGLDisplay dpy, EGLSurface srf)
    {
        if (!g_ready)
        {
            // 游戏渲染线程 GL context 就绪后初始化一次
            if (eglGetCurrentContext() != EGL_NO_CONTEXT)
                OverlayInit(dpy, srf);
        }
        else
        {
            OverlayFrame();
        }
        return real_eglSwapBuffers(dpy, srf);
    }

    static int32_t (*real_AInputQueue_getEvent)(AInputQueue *, AInputEvent **) = nullptr;

    int32_t hook_AInputQueue_getEvent(AInputQueue *queue, AInputEvent **outEvent)
    {
        const int32_t ret = real_AInputQueue_getEvent(queue, outEvent);
        if (ret == 0 && outEvent && *outEvent && g_ready)
        {
            // 触摸转发给 ImGui（菜单可交互）
            My_ImGui_ImplAndroid_HandleInputEvent(*outEvent);

            // 注意：不能像金铲铲(Unity)那样用 WantCaptureMouse 置空事件截断——
            // UE4 对 null 事件不健壮，会把 null 传给 AInputQueue_finishEvent，
            // libandroid.so 内部解引用空指针直接 SEGV (fault=0x0)（实测 m-capture 崩溃）。
            // 因此只转发、绝不吞事件；游戏照常收到触摸（点菜单时游戏也响应，可接受）。
        }
        return ret;
    }
}  // namespace

namespace OverlayUI
{
    bool Install()
    {
        if (g_installed)
            return true;

        if (!HookPltSymbol("libEGL.so", "eglSwapBuffers",
                           (void *)hook_eglSwapBuffers,
                           (void **)&real_eglSwapBuffers))
        {
            LOGE("[OV] hook eglSwapBuffers 失败，无法叠加菜单");
            return false;
        }

        // 输入 hook：只转发不吞事件（TP 检测吞事件行为），让菜单可拖拽/点击
        HookPltSymbol("libandroid.so", "AInputQueue_getEvent",
                      (void *)hook_AInputQueue_getEvent,
                      (void **)&real_AInputQueue_getEvent);

        g_installed = true;
        LOGI("[OV] EGL overlay 安装成功：菜单将绘制在游戏画面上（输入=只转发不吞）");
        return true;
    }

    bool IsActive()
    {
        return g_installed;
    }
}  // namespace OverlayUI
