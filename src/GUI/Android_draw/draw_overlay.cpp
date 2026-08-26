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

#include <android/input.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <GLES3/gl3.h>
#include <cstring>
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

    // ================= overlay 渲染 =================
    // 坐标模型：ImGui 逻辑坐标系 = 触摸坐标系（物理屏，如 2400x2400）。
    // 触摸坐标【不换算】直接进 io（点哪是哪）；渲染时用 FramebufferScale
    // 把逻辑坐标映射到实际 framebuffer（surface 1520x1080）。
    float g_physW = 2400.f, g_physH = 2400.f;   // 物理屏尺寸（触摸学习收敛）

    void OverlayInputTransform(float *x, float *y)
    {
        static bool logged = false;
        // 仅学习物理分辨率，不修改坐标
        if (*x > g_physW) g_physW = *x;
        if (*y > g_physH) g_physH = *y;
        if (!logged && g_physW > 100.f && g_physH > 100.f && *x > 100.f && *y > 100.f)
        {
            logged = true;
            LOGI("[OV] 触摸物理分辨率 ≈ %.0fx%.0f -> surface %dx%d",
                 g_physW, g_physH, g_win_w, g_win_h);
        }
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

        ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();
        io.DisplaySize = ImVec2(g_physW, g_physH);   // 逻辑系 = 触摸系
        io.DisplayFramebufferScale = ImVec2((float)w / g_physW, (float)h / g_physH);
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;

        ImGui_ImplOpenGL3_Init("#version 300 es");
        My_ImGui_ImplAndroid_Init(nullptr);
        My_ImGui_ImplAndroid_SetInputTransform(OverlayInputTransform);   // 仅学习物理分辨率

        // 复用当前 GL context 做纹理加载（不创建自己的 EGL context）
        ::graphics = std::make_unique<OpenGLGraphics>();
        init_My_drawdata();

        g_ready = true;
        LOGI("[OV] overlay 初始化完成 %dx%d (复用游戏 GL context)", w, h);

        // 自动执行探针 + SDK Dump（后台线程，菜单实时显示进度）
        std::thread(RunAutoProbeDump).detach();
    }

    void OverlayFrame()
    {
        if (!g_ready)
            return;

        My_ImGui_ImplAndroid_NewFrame();
        ImGui_ImplOpenGL3_NewFrame();

        // 每帧同步逻辑坐标系（触摸学习可能更新物理分辨率）
        ImGuiIO &io = ImGui::GetIO();
        io.DisplaySize = ImVec2(g_physW, g_physH);
        io.DisplayFramebufferScale = ImVec2((float)g_win_w / g_physW, (float)g_win_h / g_physH);

        ImGui::NewFrame();

        Layout_tick_UI(&g_menu_open);

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
            // 只转发给 ImGui，绝不吞事件：
            // TP 反作弊监控输入事件流，吞事件（置空）会被识别为注入并 tgkill 杀进程；
            // 原样放行则输入流完整，TP 无异常可查，菜单（拖拽/点击）由 ImGui 处理。
            My_ImGui_ImplAndroid_HandleInputEvent(*outEvent);
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
